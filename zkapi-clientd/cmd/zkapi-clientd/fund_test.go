package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestFundingAmountExactUnits(t *testing.T) {
	for value, want := range map[string]uint64{"0.10": 100000, "1": 1000000, "0.000001": 1, "1000000.000000": 1000000000000, "01.02": 1020000} {
		got, err := parseFundingAmount(value)
		if err != nil || got != want {
			t.Fatalf("%s: got %d, %v; want %d", value, got, err, want)
		}
	}
	for _, value := range []string{"", "0", "-1", "+1", "1e3", "1.0000001", "1000000.000001", "1.", ".1", " 1", "1.2.3", "18446744073709551615", "1\n", "１"} {
		if _, err := parseFundingAmount(value); err == nil {
			t.Fatalf("invalid amount %q accepted", value)
		}
	}
}

func fundingTestStatus(phase string) map[string]any {
	state := nativeFundingStatus()
	state["phase"], state["message"] = phase, "Payment progress saved locally."
	state["eth_balance"] = "1000000000000000"
	return state
}

func fundingTestConfig(s *httptest.Server) config.Config {
	return config.Config{Backend: "zkapi", Listen: strings.TrimPrefix(s.URL, "http://"), APIKey: strings.Repeat("a", 32), ManagementToken: withdrawalTestManagementToken, ZKAPI: config.ZKAPI{Network: "mainnet"}}
}

func configForUnreachableWallet() config.Config {
	return config.Config{Backend: "zkapi", Listen: "127.0.0.1:1", APIKey: strings.Repeat("a", 32), ManagementToken: withdrawalTestManagementToken, ZKAPI: config.ZKAPI{Network: "mainnet"}}
}

func fundingCLITestServer(t *testing.T, next http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/status" {
			if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) {
				t.Error("mode lookup omitted API authentication")
			}
			_, _ = io.WriteString(w, `{"backend":"zkapi","network":"mainnet","request_budget_policy":"model"}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/") && r.Header.Get("X-OA-Management-Token") != withdrawalTestManagementToken {
			t.Error("wallet request omitted owner-only authentication")
		}
		next.ServeHTTP(w, r)
	}))
}

const testQuoteID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func paymentTestQuote(kind string) zkapi.AddressPaymentQuote {
	q := zkapi.AddressPaymentQuote{ID: testQuoteID, Kind: kind, Address: "0x1111111111111111111111111111111111111111", ChainID: 1,
		Contract: "0x4386FDbdA35D995beB3BF8625118Ec5982ec81fe", DeploymentID: "zkapi-native-eth-mainnet-note-bound-v1-fresh-20260930",
		Amount: 750001, PrincipalWei: "750001000000000", BalanceWei: "1000000000000000", ExpectedFeeWei: "21000", RequiredFeeWei: "25000", FeeReserveWei: "30000", FeeBufferWei: "5000", RequiredTotalWei: "750001000025000", RecommendedTotalWei: "750001000030000", ShortfallWei: "0", RecommendedTopUpWei: "0",
		EstimatedGas: 21000, GasLimit: 25000, MaxFeePerGas: "1", MaxPriorityFeePerGas: "1", FeePolicy: "low", ExpiresAt: time.Now().Add(time.Minute).UnixMilli()}
	if kind == "withdrawal" {
		q.NoteID, q.Amount, q.PrincipalWei, q.Destination = 58, 99971, "0", withdrawalTestDestination
		q.RequiredTotalWei, q.RecommendedTotalWei = q.RequiredFeeWei, q.FeeReserveWei
	}
	if kind == "return" {
		q.Destination = withdrawalTestDestination
	}
	return q
}

func TestFundDefaultsToAddressWithoutBrowserOrSpending(t *testing.T) {
	requests := 0
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/admin/funding/address" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(fundingTestStatus("ready"))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runFunding(context.Background(), fundingTestConfig(s), nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Ethereum Mainnet", "0x1111111111111111111111111111111111111111", "0.001000000000000000 ETH", "fund --amount", "signing key stays"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out.String())
		}
	}
	if requests != 1 {
		t.Fatal("showing the address made additional funding requests")
	}
}

func TestFundAmountOnlyQuotesExactDeposit(t *testing.T) {
	var methods []string
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		phase := "ready"
		if r.Method == "POST" {
			var body map[string]uint64
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["amount"] != 100001000 || len(body) != 1 {
				t.Error("deposit amount was rounded or not sent exactly")
			}
			q := paymentTestQuote("deposit")
			q.Amount, q.PrincipalWei = 100001000, "100001000000000000"
			_ = json.NewEncoder(w).Encode(q)
			return
		}
		_ = json.NewEncoder(w).Encode(fundingTestStatus(phase))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runFunding(context.Background(), fundingTestConfig(s), []string{"--amount", "0.100001"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "GET /admin/funding/address,POST /admin/funding/quote" {
		t.Fatalf("wrong funding sequence: %v", methods)
	}
}

func TestFundJSONPrintsOnlyTheQuoteOnStandardOutput(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if r.URL.Path != "/admin/funding/quote" {
				t.Errorf("quoting authorized a transaction: %s", r.URL.Path)
			}
			q := paymentTestQuote("deposit")
			q.InputMicroUSD = 5_000_000
			_ = json.NewEncoder(w).Encode(q)
			return
		}
		_ = json.NewEncoder(w).Encode(fundingTestStatus("ready"))
	}))
	defer s.Close()
	var out, status bytes.Buffer
	previous := walletStatusOutput
	walletStatusOutput = &status
	defer func() { walletStatusOutput = previous }()
	if err := runFunding(context.Background(), fundingTestConfig(s), []string{"--usd", "5", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	quote := decodeScriptQuote(t, &out, "id", "kind", "network", "address", "amount_wei", "max_fee_wei", "required_total_wei", "shortfall_wei", "expires_at")
	if quote["id"] != testQuoteID || quote["kind"] != "fund" || quote["network"] != "mainnet" || quote["amount_wei"] != "750001000000000" || quote["max_fee_wei"] != "30000" || quote["required_total_wei"] != "750001000025000" || quote["shortfall_wei"] != "0" {
		t.Fatalf("unexpected quote: %v", quote)
	}
	if !strings.Contains(status.String(), "--approve "+testQuoteID) || !strings.Contains(status.String(), "Quoting does not sign") {
		t.Fatalf("status text missing: %s", status.String())
	}
}

// decodeScriptQuote requires exactly one JSON object with exactly the
// documented keys, so wallet internals cannot leak into script output.
func decodeScriptQuote(t *testing.T, out *bytes.Buffer, keys ...string) map[string]any {
	t.Helper()
	var quote map[string]any
	decoder := json.NewDecoder(out)
	if err := decoder.Decode(&quote); err != nil || decoder.More() {
		t.Fatalf("standard output is not exactly one JSON object: %v", err)
	}
	got := make([]string, 0, len(quote))
	for key := range quote {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(keys)
	if !reflect.DeepEqual(got, keys) {
		t.Fatalf("quote keys = %v, want %v", got, keys)
	}
	return quote
}

func TestFundJSONOnlyAppliesToQuotes(t *testing.T) {
	c := config.Config{Backend: "zkapi", Listen: "127.0.0.1:1"}
	for _, args := range [][]string{{"--json"}, {"--json", "--resume"}, {"--json", "--approve", testQuoteID}} {
		if err := runFunding(context.Background(), c, args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--json applies only") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestFundDisplaysSavedAmountForResumption(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("viewing saved progress authorized a transaction")
		}
		state := fundingTestStatus("deposit_pending")
		state["amount"] = 234567
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runFunding(context.Background(), fundingTestConfig(s), nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Saved deposit: 0.000234567 ETH") || !strings.Contains(out.String(), "fund --resume") {
		t.Fatalf("saved amount was not shown: %s", out.String())
	}
}

func TestFundRejectsNetworkMismatchBeforeDeposit(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("wrong network initiated a deposit")
		}
		state := fundingTestStatus("ready")
		state["chain_id"] = 11155111
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer s.Close()
	if err := runFunding(context.Background(), fundingTestConfig(s), []string{"--amount", "1"}, &bytes.Buffer{}); err == nil {
		t.Fatal("mismatched network accepted")
	}
}

func TestFundCancellationRetainsResumptionGuidance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := fundingTestStatus("deposit_pending")
		state["amount"] = 100000000
		_ = json.NewEncoder(w).Encode(state)
		if r.Method == "POST" {
			w.(http.Flusher).Flush()
			cancel()
		}
	}))
	defer s.Close()
	err := runFunding(ctx, fundingTestConfig(s), []string{"--resume"}, &bytes.Buffer{})
	if !errors.Is(err, errFundingWaitStopped) {
		t.Fatalf("cancellation lost recovery guidance: %v", err)
	}
}

func TestFundCancellationDuringDepositRequestDoesNotReportServiceUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			state := fundingTestStatus("deposit_pending")
			state["amount"] = 100000000
			_ = json.NewEncoder(w).Encode(state)
			return
		}
		// The daemon has received the authorized request but has not replied.
		// Cancellation only stops the CLI waiting; a transaction may exist.
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		<-r.Context().Done()
	}))
	defer s.Close()
	err := runFunding(ctx, fundingTestConfig(s), []string{"--resume"}, &bytes.Buffer{})
	if !errors.Is(err, errFundingWaitStopped) || !strings.Contains(err.Error(), "zkapi-clientd config") {
		t.Fatalf("in-flight cancellation lost accurate recovery guidance: %v", err)
	}
	if strings.Contains(err.Error(), "unavailable") || strings.Contains(err.Error(), "transaction canceled") {
		t.Fatalf("cancellation misreported the daemon or transaction state: %v", err)
	}
}

func TestFundReadOnlyCancellationDoesNotSuggestAuthorizingDeposit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/admin/funding/address" {
			t.Errorf("read-only funding lookup made an unexpected request: %s %s", r.Method, r.URL.Path)
		}
		cancel()
		<-r.Context().Done()
	}))
	defer s.Close()
	err := runFunding(ctx, fundingTestConfig(s), nil, &bytes.Buffer{})
	if !errors.Is(err, errFundingWaitStopped) || !strings.Contains(err.Error(), "inspect saved status") {
		t.Fatalf("read-only cancellation lost resumption guidance: %v", err)
	}
	if strings.Contains(err.Error(), "--amount") || strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("read-only cancellation suggested spending or a service outage: %v", err)
	}
}

func TestFundingUnavailableServiceKeepsConnectionFailureGuidance(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	c := fundingTestConfig(s)
	s.Close()
	_, err := requestFunding(context.Background(), c, http.MethodPost, "/admin/funding/deposit", map[string]uint64{"amount": 100000})
	if err == nil || errors.Is(err, errFundingWaitStopped) || !strings.Contains(err.Error(), "local funding service unavailable") {
		t.Fatalf("ordinary connection failure was misreported: %v", err)
	}
}

func TestFundStopsOnLegacyRecovery(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(fundingTestStatus("legacy_recovery"))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runFunding(context.Background(), fundingTestConfig(s), []string{"--amount", "0.10"}, &out); err == nil {
		t.Fatal("legacy recovery should stop instead of submitting repeatedly")
	}
}

func TestFundInvalidOptionsDoNotReachDaemon(t *testing.T) {
	c := config.Config{Backend: "zkapi", Listen: "127.0.0.1:1"}
	for _, args := range [][]string{{"--amount", "-1"}, {"--amount", "1", "--no-open"}, {"--browser", "--no-open"}, {"extra"}} {
		if err := runFunding(context.Background(), c, args, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("invalid options reached daemon: %v: %v", args, err)
		}
	}
}
