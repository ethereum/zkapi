package zkapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func TestRewriterTorPreparationFailureDoesNotBuyLease(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		io.CopyN(io.Discard, conn, 3)
		conn.Write([]byte{5, 0})
	}()
	var leases, targets atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"{\"texts\":[\"normalized\"]}"}}]}`)
	}))
	defer s.Close()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targets.Add(1) }))
	defer upstream.Close()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { leases.Add(1) }, upstream)
	c.config.TorMode = true
	c.config.TorEndpoint = "tor://" + listener.Addr().String()
	c.config.Rewriter = rewriter.Config{URL: s.URL, Model: "m"}
	resp, err := c.Complete(context.Background(), json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"original"}]}`))
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || leases.Load() != 0 || targets.Load() != 0 {
		t.Fatal("route failure spent or reached target")
	}
}

func TestCancelledQueuedRequestNeverDisclosesToRewriter(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer s.Close()
	c := &Client{requestSlot: make(chan struct{}, 1), config: Config{Rewriter: rewriter.Config{URL: s.URL, Model: "m"}}}
	c.requestSlot <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Complete(ctx, json.RawMessage(`{"messages":[{"role":"user","content":"original"}]}`))
	if err != context.Canceled || calls.Load() != 0 {
		t.Fatal("canceled queued prompt disclosed")
	}
	<-c.requestSlot
}

func TestRewriteDoesNotChangeConversationHistoryDigests(t *testing.T) {
	original := json.RawMessage(`{"messages":[{"role":"user","content":"original"}]}`)
	c := &Client{}
	identity, err := c.selectConversation(original)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"{\"texts\":[\"normalized\"]}"}}]}`)
	}))
	defer s.Close()
	c.config.Rewriter = rewriter.Config{URL: s.URL, Model: "m"}
	if _, err := c.rewritePrompt(context.Background(), original, identity); err != nil {
		t.Fatal(err)
	}
	next := json.RawMessage(`{"messages":[{"role":"user","content":"original"},{"role":"assistant","content":"answer"},{"role":"user","content":"next"}]}`)
	continued, err := c.selectConversation(next)
	if err != nil || continued != identity || c.conversation.serial != 1 {
		t.Fatal("rewriting broke original-history conversation continuity")
	}
}
