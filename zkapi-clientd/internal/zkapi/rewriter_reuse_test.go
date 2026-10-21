package zkapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func TestRewrittenContinuationReusesORKeyAndHistory(t *testing.T) {
	var leases, rewrites atomic.Int32
	var mu sync.Mutex
	var keys, bodies []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rewrites.Add(1)
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"{\"texts\":[\"normalized\"]}"}}]}`)
	}))
	defer s.Close()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		keys = append(keys, r.Header.Get("Authorization"))
		bodies = append(bodies, string(b))
		mu.Unlock()
		io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeQueuedTestLease(w, upstream.URL, leases.Add(1)) }, upstream)
	c.config.Rewriter = rewriter.Config{URL: s.URL, Model: "m"}
	c.config.KeyReuseWindow = time.Minute
	for _, body := range []string{
		`{"model":"example/model","messages":[{"role":"user","content":"RAW_FIRST"}]}`,
		`{"model":"example/model","messages":[{"role":"user","content":"RAW_FIRST"},{"role":"assistant","content":"answer"},{"role":"user","content":"RAW_SECOND"}]}`,
		`{"model":"example/model","messages":[{"role":"user","content":"RAW_FIRST"},{"role":"assistant","content":"answer"},{"role":"user","content":"RAW_SECOND"},{"role":"tool","content":"result"}]}`,
	} {
		drainReuseResponse(t, c, context.Background(), json.RawMessage(body))
	}
	if leases.Load() != 1 || rewrites.Load() != 2 {
		t.Fatal("continuation spent a key or reread old user text", leases.Load(), rewrites.Load())
	}
	drainReuseResponse(t, c, context.Background(), json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"RAW_UNRELATED"}]}`))
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 4 || keys[0] != keys[1] || keys[1] != keys[2] || keys[2] == keys[3] {
		t.Fatal("conversation key reuse/isolation broken")
	}
	for _, b := range bodies {
		if strings.Contains(b, "RAW_") {
			t.Fatal("raw prompt leaked to target", b)
		}
	}
	if strings.Count(bodies[2], "normalized") != 2 {
		t.Fatal("tool continuation lost target transcript")
	}
}
