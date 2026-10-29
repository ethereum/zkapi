package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

const delegationTestBase = "https://inference.test/v1"

var delegationTestBody = json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"identical task"}],"max_tokens":64,"stream":false}`)

// delegationFixture fakes the companion, provider and Tor preparation with
// in-process transports, recording what each request carried.
type delegationFixture struct {
	mu         sync.Mutex
	leases     int
	bridge     []string // companion paths and bodies, in order
	keys       []string // provider Authorization headers
	identities []string // Tor identity scoped to each provider request
	bodies     []string
	prepared   []string // identities passed to Tor preparation
	prepareErr error
	provider   func(*http.Request) (*http.Response, error)
}

func (f *delegationFixture) record(list *[]string, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*list = append(*list, value)
}

func newDelegationClient(t *testing.T, f *delegationFixture) *Client {
	t.Helper()
	c, err := New(Config{ClientURL: "http://127.0.0.1:1", BridgeToken: testBridgeToken, InferenceBaseURL: delegationTestBase, HTTPClient: &http.Client{}, TorMode: true, TorEndpoint: "tor://127.0.0.1:9050", KeyReuseWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.local.Transport = budgetTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer "+testBridgeToken {
			t.Error("bridge request did not authenticate")
		}
		body := ""
		if r.Body != nil {
			data, _ := io.ReadAll(r.Body)
			body = string(data)
		}
		f.record(&f.bridge, r.URL.Path+" "+body)
		var value any = map[string]any{}
		switch r.URL.Path {
		case "/oa/v1/status":
			value = testPolicy("mainnet")
		case "/oa/v1/lease":
			f.mu.Lock()
			f.leases++
			n := f.leases
			f.mu.Unlock()
			value = map[string]any{"api_key": fmt.Sprintf("delegation-key-%d", n), "base_url": delegationTestBase, "expires_at": time.Now().Add(time.Hour).Unix(), "verified": true, "verification_status": "verified"}
		case "/wallet/settle":
			value = map[string]any{"pending_request": false}
		}
		data, _ := json.Marshal(value)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data))), Request: r}, nil
	})
	c.inference.Transport = budgetTransport(func(r *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(r.Body)
		f.record(&f.keys, r.Header.Get("Authorization"))
		f.record(&f.identities, relay.TorIdentity(r.Context()))
		f.record(&f.bodies, string(data))
		if f.provider != nil {
			return f.provider(r)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"answer"},"finish_reason":"stop"}]}`)), Request: r}, nil
	})
	addTestModelPolicy(c, map[string]uint64{"example/model": 1}, nil)
	c.prepareTor = func(ctx context.Context, endpoint, destination, identity string) error {
		if endpoint != "tor://127.0.0.1:9050" || destination != delegationTestBase || identity == "" || relay.TorIdentity(ctx) != "" {
			t.Errorf("unexpected Tor preparation %q %q", endpoint, destination)
		}
		f.record(&f.prepared, identity)
		return f.prepareErr
	}
	return c
}

func drainDelegation(t *testing.T, c *Client, body json.RawMessage) {
	t.Helper()
	response, err := c.Delegate(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}

func distinct(values ...string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func TestDelegationRefusesWithoutTorBeforeAnyLease(t *testing.T) {
	for _, mode := range []string{"direct", "socks5", "tor_flag_without_tor_endpoint"} {
		t.Run(mode, func(t *testing.T) {
			f := &delegationFixture{}
			c := newDelegationClient(t, f)
			switch mode {
			case "direct":
				c.config.TorMode, c.config.TorEndpoint = false, ""
			case "socks5":
				c.config.TorMode, c.config.TorEndpoint = false, "socks5://127.0.0.1:9050"
			case "tor_flag_without_tor_endpoint":
				c.config.TorEndpoint = "socks5://127.0.0.1:9050"
			}
			_, err := c.Delegate(context.Background(), delegationTestBody)
			var remote *Error
			if !errors.As(err, &remote) || remote.Code != "delegation_requires_tor" {
				t.Fatalf("err = %v", err)
			}
			if len(f.bridge) != 0 || len(f.keys) != 0 || len(f.prepared) != 0 {
				t.Fatalf("refusal contacted the wallet, provider or Tor: %v %v %v", f.bridge, f.keys, f.prepared)
			}
		})
	}
}

func TestDelegationTorPreparationFailureSpendsNothing(t *testing.T) {
	f := &delegationFixture{prepareErr: errors.New("socks refused")}
	c := newDelegationClient(t, f)
	_, err := c.Delegate(context.Background(), delegationTestBody)
	var remote *Error
	if !errors.As(err, &remote) || remote.Code != "tor_preparation_failed" {
		t.Fatalf("err = %v", err)
	}
	if f.leases != 0 || len(f.keys) != 0 {
		t.Fatal("lease or inference after failed Tor preparation")
	}
}

func TestRepeatedIdenticalDelegationsUseFreshKeysAndIdentities(t *testing.T) {
	f := &delegationFixture{}
	c := newDelegationClient(t, f)
	for range 3 {
		drainDelegation(t, c, delegationTestBody)
		if c.cachedLease != nil {
			t.Fatal("delegation left a reusable key")
		}
	}
	if f.leases != 3 || !distinct(f.keys...) {
		t.Fatalf("identical delegations shared a key: leases=%d keys=%v", f.leases, f.keys)
	}
	if !distinct(f.identities...) || strings.Join(f.identities, ",") != strings.Join(f.prepared, ",") {
		t.Fatalf("identities not fresh per call or not the prepared ones: %v %v", f.identities, f.prepared)
	}
	if c.conversation.identity != "" {
		t.Fatal("delegation created chat conversation state")
	}
	for _, body := range f.bodies {
		if body != string(delegationTestBody) {
			t.Fatalf("provider body changed: %s", body)
		}
	}
	for _, entry := range f.bridge {
		if strings.Contains(entry, "identical task") || strings.Contains(entry, "example/model") {
			t.Fatalf("prompt or model reached the wallet: %s", entry)
		}
	}
}

func TestDelegationInterleavedWithChatSharesNoKeyOrIdentity(t *testing.T) {
	f := &delegationFixture{}
	c := newDelegationClient(t, f)
	chat := func(messages string) {
		t.Helper()
		drainReuseResponse(t, c, context.Background(), json.RawMessage(`{"model":"example/model","messages":`+messages+`}`))
	}
	first := `[{"role":"user","content":"identical task"}]`
	chat(first)
	chatState := c.conversation
	drainDelegation(t, c, delegationTestBody)
	if c.conversation.identity != chatState.identity || c.conversation.serial != chatState.serial {
		t.Fatal("delegation changed chat conversation state")
	}
	// The chat continues its own conversation and identity, but cannot pick
	// up the delegation's key; nor does a delegation take the chat's key.
	chat(`[{"role":"user","content":"identical task"},{"role":"assistant","content":"answer"},{"role":"user","content":"more"}]`)
	drainDelegation(t, c, delegationTestBody)
	chat(`[{"role":"user","content":"identical task"},{"role":"assistant","content":"answer"},{"role":"user","content":"more"},{"role":"assistant","content":"answer"}]`)
	if f.leases != 5 || !distinct(f.keys...) {
		t.Fatalf("chat and delegation shared keys: %v", f.keys)
	}
	ids := f.identities
	if ids[0] != ids[2] || ids[2] != ids[4] || !distinct(ids[0], ids[1], ids[3]) {
		t.Fatalf("identity separation broken: %v", ids)
	}
	if c.cachedLease == nil || c.cachedLease.APIKey != "delegation-key-5" {
		t.Fatal("chat key reuse should be unaffected after a chat request")
	}
}

func TestDelegationRejectsUnsafeBodiesBeforeLease(t *testing.T) {
	for _, body := range []string{
		`{"model":"example/model","messages":[],"plugins":[{"id":"web"}]}`,
		`{"model":"example/model:online","messages":[]}`,
		`{"model":"example/model","messages":[],"stream":true}`,
		`{"model":"example/model","messages":[],"tools":[]}`,
		`{"model":"example/model","messages":[],"metadata":{}}`,
		`{"model":"example/model","messages":[],"user":"stable-id"}`,
		`[]`,
	} {
		f := &delegationFixture{}
		c := newDelegationClient(t, f)
		_, err := c.Delegate(context.Background(), json.RawMessage(body))
		var remote *Error
		if !errors.As(err, &remote) || remote.Code != "invalid_delegation" || len(f.bridge) != 0 || len(f.prepared) != 0 {
			t.Fatalf("%s: err=%v bridge=%v", body, err, f.bridge)
		}
	}
}

func TestDelegationNeverRetriesInference(t *testing.T) {
	for _, mode := range []string{"transport_error", "provider_error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := &delegationFixture{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.provider = func(r *http.Request) (*http.Response, error) {
				switch mode {
				case "transport_error":
					return nil, errors.New("connection reset by secret-host.example")
				case "canceled":
					cancel()
					return nil, r.Context().Err()
				}
				return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
			}
			c := newDelegationClient(t, f)
			response, err := c.Delegate(ctx, delegationTestBody)
			switch mode {
			case "transport_error":
				var remote *Error
				if !errors.As(err, &remote) || remote.Code != "inference_transport_failed" || strings.Contains(err.Error(), "secret-host") {
					t.Fatalf("err = %v", err)
				}
			case "canceled":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v", err)
				}
			default:
				if err != nil || response.StatusCode != 503 {
					t.Fatalf("err=%v", err)
				}
				response.Body.Close()
			}
			if len(f.keys) != 1 || f.leases != 1 {
				t.Fatalf("attempts=%d leases=%d", len(f.keys), f.leases)
			}
			if c.cachedLease != nil {
				t.Fatal("failed delegation left a reusable key")
			}
			// The slot is released: a later chat can proceed.
			select {
			case c.requestSlot <- struct{}{}:
				<-c.requestSlot
			default:
				t.Fatal("request slot still held")
			}
		})
	}
}

// listenOrSkip skips only when the sandbox forbids local listeners.
func listenOrSkip(t *testing.T) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if errors.Is(err, syscall.EPERM) {
		t.Skip("local listeners are not permitted in this environment")
	}
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
}

func TestDelegationRewritesWithAFreshTranscriptOnly(t *testing.T) {
	listenOrSkip(t)
	var mu sync.Mutex
	var seen []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, string(data))
		mu.Unlock()
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"{\"texts\":[\"normalized\"]}"}}]}`)
	}))
	defer s.Close()
	f := &delegationFixture{}
	c := newDelegationClient(t, f)
	c.config.Rewriter = rewriter.Config{URL: s.URL, Model: "m"}
	chat := `{"model":"example/model","messages":[{"role":"user","content":"CHAT_TEXT"}]}`
	// Chat's own rewrite-time Tor preparation dials a real SOCKS listener;
	// run that request without Tor so only delegation uses the fake.
	c.config.TorMode = false
	drainReuseResponse(t, c, context.Background(), json.RawMessage(chat))
	c.config.TorMode = true
	before := c.rewriteTranscript
	drainDelegation(t, c, delegationTestBody)
	drainDelegation(t, c, delegationTestBody)
	if reflect.DeepEqual(before, rewriter.Transcript{}) || !reflect.DeepEqual(before, c.rewriteTranscript) {
		t.Fatal("delegation changed the chat rewrite transcript")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("identical delegations must each be rewritten independently, rewrites=%d", len(seen))
	}
	for _, request := range seen[1:] {
		if strings.Contains(request, "CHAT_TEXT") {
			t.Fatal("chat text reached a delegation rewrite")
		}
	}
	for _, body := range f.bodies[1:] {
		if strings.Contains(body, "identical task") || !strings.Contains(body, "normalized") {
			t.Fatalf("delegation body not rewritten: %s", body)
		}
	}
}
