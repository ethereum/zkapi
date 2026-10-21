package zkapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func TestRewriteBeforeLeaseAndTarget(t *testing.T) {
	for _, fail := range []bool{false, true} {
		var leases, targets atomic.Int32
		var rewritten atomic.Bool
		rewriterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if leases.Load() != 0 {
				t.Error("lease purchased before rewrite")
			}
			if fail {
				http.Error(w, "secret", 500)
				return
			}
			io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"{\"texts\":[\"normalized\"]}"}}]}`)
		}))
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targets.Add(1)
			raw, _ := io.ReadAll(r.Body)
			if strings.Contains(string(raw), "ORIGINAL") || !strings.Contains(string(raw), "normalized") {
				t.Error("original reached target")
			}
			if !rewritten.Load() {
				t.Error("target preceded preview")
			}
			io.WriteString(w, `{"choices":[]}`)
		}))
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeQueuedTestLease(w, upstream.URL, leases.Add(1)) }, upstream)
		c.config.Rewriter = rewriter.Config{URL: rewriterServer.URL, Model: "rewriter"}
		ctx := rewriter.WithNotice(context.Background(), func(n rewriter.Notice) error { rewritten.Store(true); return nil })
		resp, err := c.Complete(ctx, json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"ORIGINAL"}]}`))
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		rewriterServer.Close()
		upstream.Close()
		if fail {
			if err != rewriter.ErrFailed || leases.Load() != 0 || targets.Load() != 0 {
				t.Fatal("failed rewrite spent or inferred", err)
			}
		} else if err != nil || leases.Load() != 1 || targets.Load() != 1 {
			t.Fatal("missing rewritten inference", err)
		}
	}
}

func TestTorPreparationOverlapsRewriteAndPreviewPrecedesRouteReady(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	socksStarted := make(chan struct{})
	preview := make(chan struct{})
	socksDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			socksDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 3)
		_, err = io.ReadFull(conn, header)
		if err != nil {
			socksDone <- err
			return
		}
		if string(header) != string([]byte{5, 1, 2}) {
			t.Error("Tor auth downgrade")
		}
		close(socksStarted)
		// Rewriter waits for SOCKS start; SOCKS waits for the rewrite preview.
		// A serialized implementation deadlocks and fails the bounded test.
		select {
		case <-preview:
		case <-time.After(3 * time.Second):
			t.Error("rewrite did not overlap route preparation")
			return
		}
		conn.Write([]byte{5, 2})
		auth := make([]byte, 2)
		io.ReadFull(conn, auth)
		user := make([]byte, int(auth[1]))
		io.ReadFull(conn, user)
		if string(user) != "conversation-id" {
			t.Error("wrong conversation identity")
		}
		io.CopyN(io.Discard, conn, 2)
		conn.Write([]byte{1, 0})
		request := make([]byte, 5)
		io.ReadFull(conn, request)
		if request[3] != 3 {
			t.Error("destination DNS not delegated to Tor")
		}
		dest := make([]byte, int(request[4])+2)
		io.ReadFull(conn, dest)
		if string(dest[:len(dest)-2]) != "target.invalid" {
			t.Error("wrong prewarm destination")
		}
		conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		socksDone <- nil
	}()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-socksStarted:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"{\"texts\":[\"normalized\"]}"}}]}`)
	}))
	defer s.Close()
	c := &Client{config: Config{TorMode: true, TorEndpoint: "tor://" + listener.Addr().String(), InferenceBaseURL: "https://target.invalid/v1", Rewriter: rewriter.Config{URL: s.URL, Model: "model"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = rewriter.WithNotice(ctx, func(rewriter.Notice) error { close(preview); return nil })
	_, err = c.rewritePrompt(ctx, json.RawMessage(`{"messages":[{"role":"user","content":"original"}]}`), "conversation-id")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-socksDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("SOCKS preparation not joined")
	}
}
