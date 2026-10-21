package zkapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestConversationPrefix(t *testing.T) {
	c := &Client{}
	selectID := func(messages string) string {
		t.Helper()
		id, err := c.selectConversation(json.RawMessage(`{"messages":` + messages + `}`))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := selectID(`[{"role":"user","content":"hi"}]`)
	c.cachedLease = &reusableLease{}
	if id := selectID(`[ {"content":"hi", "role":"user"} ]`); id != first || c.cachedLease == nil {
		t.Fatal("canonical retry rotated")
	}
	if id := selectID(`[{"role":"user","content":"hi"},{"role":"assistant","content":"hello"},{"role":"user","content":"next"}]`); id != first {
		t.Fatal("continuation rotated")
	}
	if id := selectID(`[{"role":"user","content":"hi"}]`); id == first || c.cachedLease != nil {
		t.Fatal("truncated history reused identity/key")
	}
	for _, pair := range [][2]string{
		{`[{"role":"system","content":"shared"},{"role":"user","content":"a"}]`, `[{"role":"system","content":"shared"},{"role":"user","content":"b"}]`},
		{`[{"role":"tool","tool_call_id":"a","content":"x"}]`, `[{"role":"tool","tool_call_id":"b","content":"x"}]`},
		{`[{"role":"user","content":[{"type":"image_url","image_url":{"url":"a"}}]}]`, `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"b"}}]}]`},
		{`[{"role":"user","content":9007199254740992}]`, `[{"role":"user","content":9007199254740993}]`},
	} {
		before := selectID(pair[0])
		if after := selectID(pair[1]); after == before {
			t.Fatal("changed message reused identity")
		}
	}
}

func TestTorConversationKeysAndExpiry(t *testing.T) {
	var leases atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) }))
	defer upstream.Close()
	now := time.Now()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"api_key": fmt.Sprintf("tor-key-%d", leases.Add(1)), "base_url": upstream.URL, "expires_at": now.Add(time.Hour).Unix(), "verified": true, "verification_status": "verified"})
	}, upstream)
	c.config.TorMode = true
	c.config.KeyReuseWindow = time.Minute
	c.now = func() time.Time { return now }
	run := func(messages string) {
		t.Helper()
		drainReuseResponse(t, c, context.Background(), json.RawMessage(`{"model":"example/model","messages":`+messages+`}`))
	}
	run(`[{"role":"user","content":"a"}]`)
	first := c.conversation.identity
	run(`[{"role":"user","content":"a"},{"role":"assistant","content":"b"}]`)
	if leases.Load() != 1 || c.conversation.identity != first {
		t.Fatal("continuation failed to reuse key/circuit")
	}
	now = now.Add(time.Minute)
	run(`[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"c"}]`)
	if leases.Load() != 2 || c.conversation.identity != first {
		t.Fatal("key expiry must preserve conversation identity")
	}
	run(`[{"role":"user","content":"unrelated"}]`)
	if leases.Load() != 3 || c.conversation.identity == first {
		t.Fatal("new conversation reused key/circuit")
	}
}

func TestInvalidConversationDoesNotChangeState(t *testing.T) {
	c := &Client{}
	first, err := c.selectConversation(json.RawMessage(`{"messages":[{"role":"user"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`null`, `{}`, `{"messages":[]}`, `{"messages":[null]}`} {
		if _, err := c.selectConversation(json.RawMessage(body)); err == nil {
			t.Fatal("accepted invalid history")
		}
		if c.conversation.identity != first {
			t.Fatal("invalid request changed conversation")
		}
	}
}
