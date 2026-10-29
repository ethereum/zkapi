//go:build zkapi_live

package zkapi

// Opt-in live Sepolia test of ticket billing through the real Go request
// path: the real internal/server API around a real Client in BillingTicket
// mode, against a running companion (zkapi-walletd) whose loopback URL is
// given explicitly. Every proof, signed successor check, OA key
// verification, model and tier policy read, provider request and chain read
// is real. It SPENDS SEPOLIA TEST FUNDS (two tickets) and runs only with the
// zkapi_live build tag and ZKAPI_LIVE_TICKETS=spend-sepolia-test-funds.
//
//   ZKAPI_LIVE_COMPANION_URL  loopback companion URL, e.g. http://127.0.0.1:19595
//   ZKAPI_LIVE_PROFILE        zkapi-clientd profile directory; its config.json
//                             supplies the bridge token (never printed)
//   ZKAPI_LIVE_OUT            path of the sanitized JSON evidence
//   ZKAPI_LIVE_MODEL          default deepseek/deepseek-v4-flash
//   ZKAPI_LIVE_COUNT          default 1500; ZKAPI_LIVE_MAX_TOKENS default 8000
//
// No prompt, response text, key, proof secret or private key is logged or
// written: the evidence holds statuses, timings, counts, process-local key
// references, ticket prices and wallet balances.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
)

type liveStream struct {
	SentAt          float64 `json:"sent_at"`
	HeadersAt       float64 `json:"headers_at"`
	Status          int     `json:"status"`
	Verification    string  `json:"verification_status"`
	FirstDeltaAt    float64 `json:"first_delta_at"`
	LastDeltaAt     float64 `json:"last_delta_at"`
	EndedAt         float64 `json:"ended_at"`
	DoneMarker      bool    `json:"done_marker"`
	Deltas          int     `json:"deltas"`
	DeltaChars      int     `json:"delta_chars"`
	FinishReason    string  `json:"finish_reason,omitempty"`
	KeyRefs         []int   `json:"key_refs"`
	KeyReleased     bool    `json:"key_released"`
	ResponseDone    bool    `json:"key_released_response_complete"`
	ChargedGwei     int64   `json:"ticket_charged_gwei"`
	TicketTier      int     `json:"ticket_tier"`
	BalanceAtHeader int64   `json:"wallet_balance_at_headers_gwei"`
}

var purchaseLine = regexp.MustCompile(`^payment: key=(\d+) from ticket \(tier (\d+)\); charged (\d+) gwei at purchase$`)

func liveEnv(t *testing.T, name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	if fallback == "" {
		t.Fatalf("%s is required", name)
	}
	return fallback
}

func TestLiveSepoliaTicketAPIConcurrency(t *testing.T) {
	if os.Getenv("ZKAPI_LIVE_TICKETS") != "spend-sepolia-test-funds" {
		t.Skip("spends Sepolia test funds; set ZKAPI_LIVE_TICKETS=spend-sepolia-test-funds")
	}
	// TestMain installs the test fixtures; this test checks the companion,
	// model policy and RPC against the real embedded Sepolia profile.
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	companionURL := liveEnv(t, "ZKAPI_LIVE_COMPANION_URL", "")
	profile := liveEnv(t, "ZKAPI_LIVE_PROFILE", "")
	out := liveEnv(t, "ZKAPI_LIVE_OUT", "")
	model := liveEnv(t, "ZKAPI_LIVE_MODEL", "deepseek/deepseek-v4-flash")
	count, _ := strconv.Atoi(liveEnv(t, "ZKAPI_LIVE_COUNT", "1500"))
	maxTokens, _ := strconv.Atoi(liveEnv(t, "ZKAPI_LIVE_MAX_TOKENS", "8000"))
	if count < 1 || count > 4000 || maxTokens < 1 || maxTokens > 8000 {
		t.Fatal("ZKAPI_LIVE_COUNT must be 1-4000 and ZKAPI_LIVE_MAX_TOKENS 1-8000")
	}
	var profileConfig struct {
		ZKAPI struct {
			BridgeToken string `json:"bridge_token"`
		} `json:"zkapi"`
	}
	raw, err := os.ReadFile(filepath.Join(profile, "config.json"))
	if err != nil || json.Unmarshal(raw, &profileConfig) != nil || len(profileConfig.ZKAPI.BridgeToken) < 32 {
		t.Fatal("cannot read the bridge token from the profile's config.json")
	}
	client, err := New(Config{ClientURL: companionURL, BridgeToken: profileConfig.ZKAPI.BridgeToken, Network: "sepolia",
		HTTPClient: &http.Client{Timeout: 10 * time.Minute}, BillingMode: BillingTicket})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	evidence := map[string]any{"model": model, "count": count, "max_tokens": maxTokens, "billing_mode": BillingTicket}

	// Before any purchase: the companion serves Sepolia's packaged
	// deployment (chain, vault, circuit, setup, OA key source), the pinned
	// RPC independently answers chain 11155111, and the wallet is idle.
	if err := client.checkTickets(ctx); err != nil {
		t.Fatalf("companion check: %v", err)
	}
	deployment, _, err := deployedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	var chain string
	if err := (rpcCaller{url: deployment.RPC, client: &http.Client{Timeout: 30 * time.Second}}).call(ctx, "eth_chainId", []any{}, &chain); err != nil || !strings.EqualFold(chain, "0xaa36a7") {
		t.Fatalf("the pinned RPC is not Sepolia: %q %v", chain, err)
	}
	evidence["chain_id"] = 11155111
	evidence["deployment_id"] = deployment.ID
	evidence["vault"] = deployment.Contract
	walletState := func() (balance int64, pending bool, note uint32, err error) {
		data, err := client.WalletStatus(ctx)
		if err != nil {
			return 0, false, 0, err
		}
		var status struct {
			Pending bool `json:"pending_request"`
			Note    *struct {
				NoteID  uint32 `json:"note_id"`
				Balance int64  `json:"current_balance"`
			} `json:"note"`
		}
		if json.Unmarshal(data, &status) != nil || status.Note == nil {
			return 0, false, 0, fmt.Errorf("wallet status has no note")
		}
		return status.Note.Balance, status.Pending, status.Note.NoteID, nil
	}
	balance := func() (int64, bool) {
		balance, pending, note, err := walletState()
		if err != nil {
			t.Fatalf("wallet status: %v", err)
		}
		evidence["note_id"] = note
		return balance, pending
	}
	before, pending := balance()
	if pending {
		t.Fatal("the wallet has a pending request; recover it before this test")
	}
	evidence["balance_before_gwei"] = before

	// The tier the model selects, and its price at the current quote: the
	// note must afford both tickets before anything is bought.
	body := func() json.RawMessage {
		data, _ := json.Marshal(map[string]any{"model": model, "stream": true, "max_tokens": maxTokens,
			"messages": []map[string]string{{"role": "user", "content": fmt.Sprintf("Write the integers from 1 to %d in words, one per line, with no other text.", count)}}})
		return data
	}()
	tier, err := client.ticketTierFor(ctx, body)
	if err != nil {
		t.Fatalf("ticket tier: %v", err)
	}
	evidence["terms"] = tier
	quoteRaw, err := client.request(ctx, http.MethodGet, "/oa/v1/billing/quote", nil)
	if err != nil {
		t.Fatal(err)
	}
	var quote struct {
		Answer   string `json:"answer"`
		Decimals int    `json:"decimals"`
		Round    string `json:"round_id"`
	}
	if json.Unmarshal(quoteRaw, &quote) != nil || quote.Decimals != 8 {
		t.Fatal("invalid billing quote")
	}
	answer, ok := new(big.Int).SetString(quote.Answer, 10)
	if !ok || answer.Sign() <= 0 {
		t.Fatal("invalid quote answer")
	}
	// ceil(price_micro_usd * 1e9 * 1e8 / (answer * 1e6)), the server's conversion.
	numerator := new(big.Int).Mul(new(big.Int).SetUint64(tier.PriceMicroUSD), new(big.Int).Exp(big.NewInt(10), big.NewInt(17), nil))
	denominator := new(big.Int).Mul(answer, big.NewInt(1_000_000))
	expected, remainder := new(big.Int).QuoRem(numerator, denominator, new(big.Int))
	if remainder.Sign() != 0 {
		expected.Add(expected, big.NewInt(1))
	}
	evidence["quote"] = map[string]any{"round_id": quote.Round, "answer": quote.Answer, "decimals": quote.Decimals}
	evidence["expected_price_gwei"] = expected.Int64()
	if before < 2*expected.Int64() {
		t.Fatalf("balance %d gwei cannot pay two tickets of %d gwei", before, expected.Int64())
	}

	// The real API, with per-request activity capture: key references and
	// the fixed-format purchase diagnostic only. Other diagnostics stay in
	// memory and are discarded.
	key := make([]byte, 24)
	_, _ = rand.Read(key)
	api, err := server.New(client, hex.EncodeToString(key), 4)
	if err != nil {
		t.Fatal(err)
	}
	api.WebSearch = false
	t0 := time.Now()
	since := func() float64 { return float64(time.Since(t0).Microseconds()) / 1e6 }
	var mu sync.Mutex
	streams := map[string]*liveStream{"A": {}, "B": {}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Header.Get("X-Live-Stream")
		r.Header.Del("X-Live-Stream")
		stream := streams[name]
		var diagnostics bytes.Buffer
		logger := log.New(&diagnostics, "", 0)
		ctx := activity.WithDiagnostics(r.Context(), activity.SemiVerbose, logger)
		ctx = activity.WithReporter(ctx, func(event activity.Event) {
			mu.Lock()
			defer mu.Unlock()
			switch event.Kind {
			case activity.KeyFresh:
				stream.KeyRefs = append(stream.KeyRefs, int(event.Key))
			case activity.KeyReleased:
				stream.KeyReleased, stream.ResponseDone = true, event.Complete
			}
		})
		api.ServeHTTP(w, r.WithContext(ctx))
		mu.Lock()
		defer mu.Unlock()
		scanner := bufio.NewScanner(&diagnostics)
		for scanner.Scan() {
			if m := purchaseLine.FindStringSubmatch(scanner.Text()); m != nil {
				stream.TicketTier, _ = strconv.Atoi(m[2])
				stream.ChargedGwei, _ = strconv.ParseInt(m[3], 10, 64)
			}
		}
	})
	listener := httptest.NewServer(handler)
	defer listener.Close()

	firstDelta := map[string]chan struct{}{"A": make(chan struct{}), "B": make(chan struct{})}
	var wg sync.WaitGroup
	run := func(name string) {
		defer wg.Done()
		stream := streams[name]
		signalled := false
		signal := func() {
			if !signalled {
				signalled = true
				close(firstDelta[name])
			}
		}
		defer signal()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, listener.URL+"/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Live-Stream", name)
		mu.Lock()
		stream.SentAt = since()
		mu.Unlock()
		response, err := listener.Client().Do(req)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			return
		}
		defer response.Body.Close()
		headerBalance, _, _, _ := walletState()
		mu.Lock()
		stream.HeadersAt, stream.Status = since(), response.StatusCode
		stream.Verification = response.Header.Get("X-OA-Verification-Status")
		stream.BalanceAtHeader = headerBalance
		mu.Unlock()
		reader := bufio.NewReaderSize(response.Body, 1<<16)
		for {
			line, err := reader.ReadBytes('\n')
			line = bytes.TrimSpace(line)
			if data, ok := bytes.CutPrefix(line, []byte("data:")); ok {
				data = bytes.TrimSpace(data)
				if string(data) == "[DONE]" {
					mu.Lock()
					stream.DoneMarker = true
					mu.Unlock()
					continue
				}
				var event struct {
					Choices []struct {
						Delta struct {
							Content          string `json:"content"`
							Reasoning        string `json:"reasoning"`
							ReasoningContent string `json:"reasoning_content"`
						} `json:"delta"`
						FinishReason *string `json:"finish_reason"`
					} `json:"choices"`
				}
				if json.Unmarshal(data, &event) == nil {
					for _, choice := range event.Choices {
						text := choice.Delta.Content + choice.Delta.Reasoning + choice.Delta.ReasoningContent
						mu.Lock()
						if text != "" {
							stream.Deltas++
							stream.DeltaChars += len(text)
							if stream.FirstDeltaAt == 0 {
								stream.FirstDeltaAt = since()
							}
							stream.LastDeltaAt = since()
						}
						if choice.FinishReason != nil {
							stream.FinishReason = *choice.FinishReason
						}
						mu.Unlock()
						if text != "" {
							signal()
						}
					}
				}
			}
			if err != nil {
				break
			}
		}
		mu.Lock()
		stream.EndedAt = since()
		mu.Unlock()
	}
	wg.Add(1)
	go run("A")
	select {
	case <-firstDelta["A"]:
	case <-ctx.Done():
		t.Fatal("A produced no output")
	}
	launchB := since()
	wg.Add(1)
	go run("B")
	wg.Wait()
	after, pending := balance()

	inventory, _ := client.request(ctx, http.MethodGet, "/oa/v1/tickets", nil)
	var tickets struct {
		Inventory []struct {
			ClientRequestID string `json:"client_request_id"`
			Phase           string `json:"phase"`
			Claimed         bool   `json:"claimed"`
		} `json:"inventory"`
	}
	_ = json.Unmarshal(inventory, &tickets)
	A, B := streams["A"], streams["B"]
	overlap := minFloat(A.LastDeltaAt, B.LastDeltaAt) - maxFloat(A.FirstDeltaAt, B.FirstDeltaAt)
	evidence["A"], evidence["B"] = A, B
	evidence["B_launched_at"] = launchB
	evidence["balance_after_gwei"] = after
	evidence["balance_delta_gwei"] = before - after
	evidence["pending_after"] = pending
	evidence["inventory_after"] = tickets.Inventory
	evidence["overlap"] = map[string]any{
		"B_sent_while_A_streaming":          B.SentAt >= A.FirstDeltaAt && B.SentAt < A.LastDeltaAt,
		"B_first_delta_before_A_last_delta": B.FirstDeltaAt > 0 && B.FirstDeltaAt < A.LastDeltaAt,
		"concurrent_streaming_seconds":      overlap,
	}
	if data, err := json.MarshalIndent(evidence, "", "  "); err == nil {
		if err := os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
			t.Errorf("write evidence: %v", err)
		}
	}

	for _, name := range []string{"A", "B"} {
		s := streams[name]
		if s.Status != http.StatusOK || !s.DoneMarker || s.Deltas == 0 || len(s.KeyRefs) != 1 || !s.KeyReleased {
			t.Errorf("%s: status=%d done=%t deltas=%d key_refs=%v released=%t", name, s.Status, s.DoneMarker, s.Deltas, s.KeyRefs, s.KeyReleased)
		}
		if s.ChargedGwei != expected.Int64() || s.TicketTier != int(tier.TierID) {
			t.Errorf("%s: charged %d gwei for tier %d, expected %d for tier %d (a new oracle round between the quote and the purchase changes the price)", name, s.ChargedGwei, s.TicketTier, expected.Int64(), tier.TierID)
		}
		if s.Verification != "verified" {
			t.Errorf("%s: key verification %q", name, s.Verification)
		}
	}
	if len(A.KeyRefs) == 1 && len(B.KeyRefs) == 1 && A.KeyRefs[0] == B.KeyRefs[0] {
		t.Error("both requests used one key")
	}
	if before-after != A.ChargedGwei+B.ChargedGwei || pending {
		t.Errorf("balance fell by %d gwei, tickets charged %d; pending=%t", before-after, A.ChargedGwei+B.ChargedGwei, pending)
	}
	if !(B.SentAt < A.LastDeltaAt && B.FirstDeltaAt > 0 && B.FirstDeltaAt < A.LastDeltaAt) {
		t.Errorf("no overlap: B sent %.3f, B first output %.3f, A last output %.3f", B.SentAt, B.FirstDeltaAt, A.LastDeltaAt)
	}
	consumed := 0
	for _, ticket := range tickets.Inventory {
		if ticket.Phase == "consumed" {
			consumed++
		}
	}
	if consumed < 2 {
		t.Errorf("expected both tickets consumed, inventory %v", tickets.Inventory)
	}
	t.Logf("live ticket API: charged %d+%d gwei, balance %d -> %d, overlap %.1f s; evidence %s", A.ChargedGwei, B.ChargedGwei, before, after, overlap, out)
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
