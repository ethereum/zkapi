package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTorCancelledQueuedRequestDoesNotRotateOrSpend(t *testing.T) {
	var leases atomic.Int32
	unblock := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-unblock
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	defer close(unblock)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeQueuedTestLease(w, upstream.URL, leases.Add(1)) }, upstream)
	c.config.TorMode = true
	c.config.KeyReuseWindow = time.Minute
	first, err := c.Complete(context.Background(), json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"first"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	identity := c.conversation.identity
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		response, err := c.Complete(ctx, json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"unrelated"}]}`))
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued cancellation blocked")
	}
	if leases.Load() != 1 || c.conversation.identity != identity {
		t.Fatal("queued request rotated identity or acquired key during stream")
	}
}
