package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	instantTier = map[string]any{"tier_id": 1, "tier_name": "Instant", "oa_tickets": 4, "price_micro_usd": 560000, "credit_limit_micro_usd": 3000000, "duration_seconds": 3600}
	premiumTier = map[string]any{"tier_id": 3, "tier_name": "Premium", "oa_tickets": 3, "price_micro_usd": 420000, "credit_limit_micro_usd": 4000000, "duration_seconds": 3600}
)

// ticketCompanion is a companion double that sells tickets: each POST
// /oa/v1/ticket hands out a distinct key (or, for a repeated purchase ID, the
// same one) and records releases.
type ticketCompanion struct {
	mu        sync.Mutex
	upstream  string
	tiers     []map[string]any
	purchases map[string]string // purchase ID -> key
	bodies    []map[string]any
	releases  []map[string]any
	events    []string
	dropReply int // lose this many /oa/v1/ticket replies after handing out
	// replyTier overrides the tier the companion reports handing out.
	replyTier map[string]any
	// termsChanged answers this many purchases with ticket_terms_changed,
	// replacing the catalog with newTiers.
	termsChanged int
	newTiers     []map[string]any
	// releaseAllFailures answers this many release-all calls with 503.
	releaseAllFailures int
}

func (s *ticketCompanion) handle(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/oa/v1/tickets":
			_ = json.NewEncoder(w).Encode(map[string]any{"catalog": map[string]any{"version": 1, "key_source": "oa_org", "tiers": s.tiers}, "inventory": []any{}})
		case "/oa/v1/ticket":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.bodies = append(s.bodies, body)
			s.events = append(s.events, "claim")
			if s.termsChanged > 0 {
				s.termsChanged--
				s.tiers = s.newTiers
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"error":{"code":"ticket_terms_changed","message":"private"}}`)
				return
			}
			id := body["purchase_id"].(string)
			key, ok := s.purchases[id]
			if !ok {
				key = fmt.Sprintf("ticket-key-%d", len(s.purchases))
				s.purchases[id] = key
			}
			if s.dropReply > 0 {
				s.dropReply--
				// The companion handed the ticket out; its reply never arrives.
				conn, _, _ := w.(http.Hijacker).Hijack()
				_ = conn.Close()
				return
			}
			tier := body["terms"]
			if s.replyTier != nil {
				tier = s.replyTier
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"client_request_id": "req-" + key, "purchase_id": id,
				"tier": tier, "price_units": 224000, "api_key": key, "bought_at": time.Now().Unix(),
				"base_url": s.upstream, "expires_at": time.Now().Unix() + 3000, "verified": true, "verification_status": "verified"})
		case "/oa/v1/ticket/release":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.releases = append(s.releases, body)
			_, _ = io.WriteString(w, `{"released":true}`)
		case "/oa/v1/tickets/release-all":
			s.events = append(s.events, "release-all")
			if s.releaseAllFailures > 0 {
				s.releaseAllFailures--
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":{"code":"companion_starting"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"released":0}`)
		default:
			t.Errorf("unexpected bridge path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func newTicketClient(t *testing.T, companion *ticketCompanion, upstream *httptest.Server, counts map[string]uint64) *Client {
	t.Helper()
	companion.upstream = upstream.URL
	companion.purchases = map[string]string{}
	if companion.tiers == nil {
		companion.tiers = []map[string]any{instantTier, premiumTier}
	}
	handler := companion.handle(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testBridgeToken {
			t.Error("bridge request did not authenticate")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/oa/v1/status" {
			policy := testPolicy("mainnet")
			policy["tickets_version"] = 1
			_ = json.NewEncoder(w).Encode(policy)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(local.Close)
	c, err := New(Config{ClientURL: local.URL, BridgeToken: testBridgeToken, InferenceBaseURL: upstream.URL, HTTPClient: upstream.Client(), BillingMode: BillingTicket})
	if err != nil {
		t.Fatal(err)
	}
	c.endpoints = &chainEndpoints{RPC: upstream.URL, Indexer: upstream.URL, ProtocolServer: testProtocolServerURL(t, "mainnet")}
	addTestModelPolicy(c, counts, nil)
	return c
}

func drain(t *testing.T, response *http.Response) {
	t.Helper()
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

// The first inference is still streaming while a second ticket is bought and
// its inference starts: ticket mode does not hold the request slot across
// inference, and each request has its own ticket's key, consumed after it.
func TestTicketModeRunsInferenceConcurrentlyWithDistinctKeys(t *testing.T) {
	var active, maximum atomic.Int32
	keys := make(chan string, 2)
	started := make(chan struct{}, 2)
	proceed := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for previous := maximum.Load(); current > previous; previous = maximum.Load() {
			if maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		keys <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		started <- struct{}{}
		select {
		case <-proceed:
		case <-r.Context().Done():
		}
		active.Add(-1)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	companion := &ticketCompanion{}
	client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 4})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := client.Complete(ctx, queuedTestPrompt)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	// The first response is open; the second request still gets through.
	second, err := client.Complete(ctx, queuedTestPrompt)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("the second inference waited for the first")
	}
	if maximum.Load() != 2 {
		t.Fatalf("provider concurrency=%d", maximum.Load())
	}
	close(proceed)
	drain(t, first)
	drain(t, second)
	if a, b := <-keys, <-keys; a == b {
		t.Fatal("two concurrent requests shared one ticket's key")
	}
	companion.mu.Lock()
	defer companion.mu.Unlock()
	if len(companion.bodies) != 2 || len(companion.releases) != 2 {
		t.Fatalf("purchases=%d releases=%d", len(companion.bodies), len(companion.releases))
	}
	for _, body := range companion.bodies {
		// The model's 4 OA tickets select Instant, with its exact terms; no
		// prompt crosses the bridge.
		terms, _ := json.Marshal(body["terms"])
		want, _ := json.Marshal(instantTier)
		if string(terms) != string(want) || len(body) != 2 || !strings.HasPrefix(body["purchase_id"].(string), "clientd-") {
			t.Fatalf("purchase body %v", body)
		}
	}
	for _, release := range companion.releases {
		// One ticket per request: consumed after it.
		if release["consume"] != true {
			t.Fatalf("a used ticket was not consumed: %v", release)
		}
	}
}

// A provider refusal is still a sent request: the ticket is consumed.
func TestTicketModeConsumesTheTicketWhateverTheOutcome(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, `{"error":"limit"}`)
	}))
	defer upstream.Close()
	companion := &ticketCompanion{}
	client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 3})
	response, err := client.Complete(context.Background(), queuedTestPrompt)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, response)
	companion.mu.Lock()
	defer companion.mu.Unlock()
	if len(companion.bodies) != 1 || companion.bodies[0]["terms"].(map[string]any)["tier_id"] != float64(3) {
		t.Fatalf("purchase %v", companion.bodies)
	}
	if len(companion.releases) != 1 || companion.releases[0]["consume"] != true {
		t.Fatalf("release %v", companion.releases)
	}
}

// A lost companion reply is retried with the same purchase ID, so the
// companion hands out the same ticket instead of buying a second one.
func TestTicketPurchaseRetriesALostReplyWithTheSamePurchaseID(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	companion := &ticketCompanion{dropReply: 1}
	client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 4})
	response, err := client.Complete(context.Background(), queuedTestPrompt)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, response)
	companion.mu.Lock()
	defer companion.mu.Unlock()
	if len(companion.bodies) != 2 || companion.bodies[0]["purchase_id"] != companion.bodies[1]["purchase_id"] || len(companion.purchases) != 1 {
		t.Fatalf("a lost reply bought again: %v", companion.bodies)
	}
}

// A companion that hands out another tier's ticket (another allowance) is
// refused; the unused ticket goes back unconsumed and no inference runs.
func TestTicketOfOtherTermsIsRefusedAndReturnedUnused(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inference ran with another tier's ticket")
	}))
	defer upstream.Close()
	richer := map[string]any{}
	for k, v := range instantTier {
		richer[k] = v
	}
	richer["credit_limit_micro_usd"] = 50000000
	for _, reply := range []map[string]any{premiumTier, richer} {
		companion := &ticketCompanion{replyTier: reply}
		client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 4})
		_, err := client.Complete(context.Background(), queuedTestPrompt)
		var failure *Error
		if !errors.As(err, &failure) || failure.Code != "invalid_verified_lease" {
			t.Fatalf("got %v", err)
		}
		companion.mu.Lock()
		if len(companion.releases) != 1 || companion.releases[0]["consume"] != false {
			t.Fatalf("release %v", companion.releases)
		}
		companion.mu.Unlock()
	}
}

// A repriced catalog: the companion refuses the old terms; the client reads
// the catalog again and buys at the current terms, once.
func TestTicketTermsChangeIsSelectedAgainOnce(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	repriced := map[string]any{}
	for k, v := range instantTier {
		repriced[k] = v
	}
	repriced["price_micro_usd"] = 600000
	companion := &ticketCompanion{termsChanged: 1, newTiers: []map[string]any{repriced, premiumTier}}
	client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 4})
	response, err := client.Complete(context.Background(), queuedTestPrompt)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, response)
	companion.mu.Lock()
	defer companion.mu.Unlock()
	if len(companion.bodies) != 2 || companion.bodies[1]["terms"].(map[string]any)["price_micro_usd"] != float64(600000) {
		t.Fatalf("purchases %v", companion.bodies)
	}
	// A second change in a row is reported, not chased.
	companion.termsChanged, companion.newTiers = 2, []map[string]any{instantTier, premiumTier}
	companion.mu.Unlock()
	_, err = client.Complete(context.Background(), queuedTestPrompt)
	companion.mu.Lock()
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "ticket_terms_changed" {
		t.Fatalf("got %v", err)
	}
}

// Startup recovery releases an earlier run's claims exactly once, before
// this process's first claim, even when the companion is not ready at
// first; a delayed startup call afterwards releases nothing, so it can
// never free the claim of a request in flight.
func TestTicketRecoveryRunsOnceBeforeTheFirstClaim(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	companion := &ticketCompanion{releaseAllFailures: 1}
	client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 4})
	// The delayed startup task's first attempt finds the companion starting.
	if err := client.ReleaseTicketClaims(context.Background()); err == nil {
		t.Fatal("a failed recovery reported success")
	}
	// A request arrives before the startup task retried: it recovers first.
	done := make(chan error, 1)
	go func() {
		response, err := client.Complete(context.Background(), queuedTestPrompt)
		if err == nil {
			drain(t, response)
		}
		done <- err
	}()
	<-started
	// The startup task's retry, while that request holds its ticket.
	if err := client.ReleaseTicketClaims(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	companion.mu.Lock()
	defer companion.mu.Unlock()
	want := []string{"release-all", "release-all", "claim"}
	if strings.Join(companion.events, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v", companion.events)
	}
}

func TestTicketModeRefusesModelsWithoutATier(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no inference without a ticket")
	}))
	defer upstream.Close()
	companion := &ticketCompanion{}
	client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 10})
	_, err := client.Complete(context.Background(), queuedTestPrompt)
	var failure *Error
	if err == nil || !errors.As(err, &failure) || failure.Code != "model_ticket_tier_unavailable" {
		t.Fatalf("got %v", err)
	}
	if len(companion.bodies) != 0 {
		t.Fatal("bought a ticket for a model without a tier")
	}
}

func TestBillingModeIsExplicit(t *testing.T) {
	if _, err := New(Config{ClientURL: "http://127.0.0.1:1", BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient, BillingMode: "prepaid"}); err == nil {
		t.Fatal("an unknown billing mode was accepted")
	}
	c, err := New(Config{ClientURL: "http://127.0.0.1:1", BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient})
	if err != nil || c.ticketMode() || c.config.BillingMode != BillingMetered {
		t.Fatal("the default is not metered")
	}
}

// In ticket mode a delegation buys its own ticket (never a metered lease),
// sends through its isolated Tor identity, and consumes the ticket.
func TestTicketModeDelegationBuysItsOwnTicket(t *testing.T) {
	var keys []string
	var mu sync.Mutex
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer upstream.Close()
	companion := &ticketCompanion{}
	client := newTicketClient(t, companion, upstream, map[string]uint64{"example/model": 4})
	client.config.TorMode, client.config.TorEndpoint = true, "tor://127.0.0.1:9050"
	prepared := 0
	client.prepareTor = func(context.Context, string, string, string) error {
		prepared++
		return nil
	}
	body := json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"private content"}],"stream":false}`)
	for range 2 {
		response, err := client.Delegate(context.Background(), body)
		if err != nil {
			t.Fatal(err)
		}
		drain(t, response)
	}
	companion.mu.Lock()
	defer companion.mu.Unlock()
	if prepared != 2 || len(companion.bodies) != 2 || len(companion.releases) != 2 {
		t.Fatalf("tor=%d purchases=%d releases=%d", prepared, len(companion.bodies), len(companion.releases))
	}
	for _, release := range companion.releases {
		if release["consume"] != true {
			t.Fatalf("a delegation's ticket was not consumed: %v", release)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("delegations did not use distinct ticket keys: %d", len(keys))
	}
}
