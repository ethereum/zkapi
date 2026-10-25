package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

const gaslessTestTransit = "0x9b3B91C51FC57DB1D42e4bfEFE282Bb9D42c5AC0"
const gaslessTestOpHash = "0x7fb1d6d3e234db1c3d82aae8b2e6d92038c902fdf9f8e9db469c1216f1637e02"

// payoutTestQuote is a payout quote (design 3.3) of the test withdrawal.
func payoutTestQuote(kind string) zkapi.AddressPaymentQuote {
	q := paymentTestQuote("withdrawal")
	q.FeePolicy, q.UserOpKind, q.UserOpNonce, q.TransitAccount, q.BundlerURL = "payout", kind, "18465190817783261167616", gaslessTestTransit, "https://bundler.example/rpc"
	q.FeeCapWei, q.FlatFeeWei, q.PayoutWei, q.MinimumReceivedWei, q.OwedWei, q.FinalizeReserveWei = "3300000000000000", "10000000000000", "99971000000000", "96671000000000", "0", "0"
	q.ExpectedFeeWei, q.RequiredFeeWei, q.FeeReserveWei, q.FeeBufferWei = "2000000000000000", "3300000000000000", "3300000000000000", "0"
	q.EstimatedGas, q.GasLimit = 1637500, 1637500
	q.MaxFeePerGas, q.MaxPriorityFeePerGas = "2001000000", "1000000"
	q.UserOpGas = &zkapi.GaslessQuoteGas{CallGasLimit: 687500, VerificationGasLimit: 180000, PreVerificationGas: 50000, PaymasterVerificationGasLimit: 450000, PaymasterPostOpGasLimit: 270000, InitCode: true}
	q.FeeBumpCapWei = q.FeeCapWei
	if kind == "escape" {
		// An initiation promises no floor: the finalization is estimated.
		q.MinimumReceivedWei, q.FinalizeReserveWei, q.FinalizeEstimateWei, q.EstimatedReceivedWei = "", "2040000000000000", "2260000000000000", "0"
	}
	return q
}

// authorizedPayoutTestQuote is a payout close quote with the bounded
// authorization (authorize once): the most the payout may lose under it
// (MaxTotalFeeWei, above the operation as built now) and the floor
// payout − MaxTotalFeeWei − owed.
func authorizedPayoutTestQuote() zkapi.AddressPaymentQuote {
	q := payoutTestQuote("close")
	q.Binding = strings.Repeat("b", 64)
	q.FeeCapWei, q.MinimumReceivedWei, q.ExpectedFeeWei, q.RequiredFeeWei, q.FeeReserveWei = "3300000000000", "96671000000000", "2000000000000", "3300000000000", "3300000000000"
	q.MaxTotalFeeWei, q.MinNetPayoutWei, q.FeeMayChange, q.FeeBumpCapWei = "4000000000000", "95971000000000", true, "4000000000000"
	return q
}

func gaslessTestStatus(phase string) map[string]any {
	state := withdrawalTestStatus(phase)
	state["fee_payer"], state["transit_account"] = "payout", gaslessTestTransit
	if phase != "ready" {
		state["user_op_hash"] = gaslessTestOpHash
	}
	return state
}

// A withdrawal sends no fee mode unless one is named (or a payout default is
// configured): the daemon applies the deployment's payout-only policy, and
// the payout quote prints its bounded terms. --fees payout carries the
// bundler, the fee cap and the expensive-gas acceptance; a named wallet fee
// reaches the daemon only on a deployment without sponsorship (the local
// refusal on a payout deployment is TestWithdrawWalletFeesRefusedLocallyForANewPayoutWithdrawal),
// and a configured wallet default is never sent.
func TestWithdrawFeesPayoutQuotesASponsoredOperation(t *testing.T) {
	for name, test := range map[string]struct {
		args   []string
		config func(*config.Config)
		policy string
		body   map[string]any
		payout bool
	}{
		"flag":               {args: []string{"--to", withdrawalTestDestination, "--fees", "payout"}, body: map[string]any{"fees": "payout"}, payout: true},
		"flag with options":  {args: []string{"--to", withdrawalTestDestination, "--fees", "payout", "--bundler-url", "https://bundler.example/rpc", "--fee-cap-gwei", "100", "--allow-expensive-gas"}, body: map[string]any{"fees": "payout", "bundler_url": "https://bundler.example/rpc", "fee_cap_gwei": float64(100), "allow_expensive_gas": true}, payout: true},
		"configured default": {args: []string{"--to", withdrawalTestDestination}, config: func(c *config.Config) { c.ZKAPI.WithdrawalFees, c.ZKAPI.BundlerURL = "payout", "http://127.0.0.1:4337" }, body: map[string]any{"fees": "payout", "bundler_url": "http://127.0.0.1:4337"}, payout: true},
		// The default on a payout deployment: nothing named, a payout quote.
		"default":                     {args: []string{"--to", withdrawalTestDestination}, policy: "payout", body: map[string]any{}, payout: true},
		"configured wallet default":   {args: []string{"--to", withdrawalTestDestination}, policy: "payout", config: func(c *config.Config) { c.ZKAPI.WithdrawalFees = "wallet" }, body: map[string]any{}, payout: true},
		"wallet without sponsorship":  {args: []string{"--to", withdrawalTestDestination, "--fees", "wallet"}, policy: "wallet", config: func(c *config.Config) { c.ZKAPI.WithdrawalFees = "payout" }, body: map[string]any{"fees": "wallet"}},
		"default without sponsorship": {args: []string{"--to", withdrawalTestDestination}, policy: "wallet", body: map[string]any{}},
	} {
		t.Run(name, func(t *testing.T) {
			var sequence []string
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sequence = append(sequence, r.Method+" "+r.URL.Path)
				if r.Method == http.MethodPost {
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil || body["destination"] != withdrawalTestDestination || body["note_id"] != float64(58) || len(body) != 2+len(test.body) {
						t.Errorf("wrong quote request: %+v", body)
					}
					for key, value := range test.body {
						if body[key] != value {
							t.Errorf("quote request %s = %v, want %v", key, body[key], value)
						}
					}
					if test.payout {
						_ = json.NewEncoder(w).Encode(authorizedPayoutTestQuote())
					} else {
						_ = json.NewEncoder(w).Encode(paymentTestQuote("withdrawal"))
					}
					return
				}
				state := withdrawalTestStatus("ready")
				if test.policy != "" {
					state["new_withdrawal_fees"] = test.policy
				}
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer s.Close()
			c := withdrawalTestConfig(s)
			if test.config != nil {
				test.config(&c)
			}
			var out bytes.Buffer
			if err := runWithdrawal(context.Background(), c, test.args, &out); err != nil {
				t.Fatal(err)
			}
			if strings.Join(sequence, ",") != "GET /admin/withdrawal,POST /admin/withdrawal/quote" {
				t.Fatalf("wrong sequence: %v", sequence)
			}
			if test.payout {
				for _, want := range []string{"Fee paid from the payout by a sponsored close operation", "Transit account: " + gaslessTestTransit, "Bundler: https://bundler.example/rpc", "Payout: 0.000099971000000000 ETH", "Estimated network fee: about 0.000002000000000000 ETH (an estimate; the actual fee may change)", "At most 0.000004000000000000 ETH may be taken from the payout", withdrawalTestDestination + " receives at least 0.000095971000000000 ETH", "This one approval covers this destination, note and transit account", "--approve " + testQuoteID, "Quoting does not sign or send"} {
					if !strings.Contains(out.String(), want) {
						t.Fatalf("missing %q in %s", want, out.String())
					}
				}
				if strings.Contains(out.String(), "Required top-up") || strings.Contains(out.String(), "Payment URI") || strings.Contains(out.String(), "--fees wallet") {
					t.Fatalf("a payout quote asked for ETH or a wallet fee: %s", out.String())
				}
			} else if !strings.Contains(out.String(), "Maximum approved fee allowance") {
				t.Fatalf("the wallet quote was not printed: %s", out.String())
			}
			if test.policy == "payout" && (!strings.Contains(out.String(), "Network fee: paid from the payout (this wallet needs no ETH)") || strings.Contains(out.String(), "Available for network fees")) {
				t.Fatalf("the payout policy header: %s", out.String())
			}
		})
	}
}

// Invalid gasless options never reach the daemon.
func TestWithdrawInvalidGaslessOptionsNeverReachDaemon(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("request reached the daemon") }))
	defer s.Close()
	c := withdrawalTestConfig(s)
	for _, args := range [][]string{
		{"--to", withdrawalTestDestination, "--fees", "sponsor"},
		{"--to", withdrawalTestDestination, "--fees", "payout", "--bundler-url", "http://bundler.example"},
		{"--to", withdrawalTestDestination, "--bundler-url", "https://user:pw@bundler.example"},
		{"--collect"},
		{"--sweep", "--approve", testQuoteID},
		{"--to", withdrawalTestDestination, "--collect", "--sweep"},
		{"--to", withdrawalTestDestination, "--claim-credit", "--resume"},
		{"--escape", "--to", withdrawalTestDestination, "--collect"},
		{"--to", withdrawalTestDestination, "--collect", "--confirm", "0x" + strings.Repeat("a", 64)},
	} {
		if err := runWithdrawal(context.Background(), c, args, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "local withdrawal request") {
			t.Fatalf("invalid options reached the daemon: %v: %v", args, err)
		}
	}
	// A configuration with an invalid default is refused the same way.
	c.ZKAPI.BundlerURL = "ftp://bundler.example"
	if err := runWithdrawal(context.Background(), c, []string{"--to", withdrawalTestDestination}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bundler URL") {
		t.Fatalf("an invalid configured bundler was accepted: %v", err)
	}
}

// --collect, --sweep and --claim-credit quote the delivery of a payout that
// waits in the transit account or the paymaster: a sponsored FORWARD, a
// wallet-paid sweep (or the account's creation), a wallet-paid claim.
func TestWithdrawTransitFlagsQuoteTheDelivery(t *testing.T) {
	for _, test := range []struct {
		flag, field string
		quote       zkapi.AddressPaymentQuote
		want        string
	}{
		{"--collect", "collect", payoutTestQuote("forward"), "sponsored forward operation"},
		{"--sweep", "sweep", func() zkapi.AddressPaymentQuote {
			q := paymentTestQuote("withdrawal")
			q.Kind = "transit_sweep"
			return q
		}(), "transit_sweep quote"},
		{"--sweep", "sweep", func() zkapi.AddressPaymentQuote {
			q := paymentTestQuote("withdrawal")
			q.Kind = "transit_create"
			return q
		}(), "transit_create quote"},
		{"--claim-credit", "claim_credit", func() zkapi.AddressPaymentQuote {
			q := paymentTestQuote("withdrawal")
			q.Kind = "gasless_claim"
			return q
		}(), "gasless_claim quote"},
	} {
		t.Run(test.flag+" "+test.quote.Kind, func(t *testing.T) {
			posts := 0
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
					var body map[string]any
					if r.URL.Path != "/admin/withdrawal/quote" || json.NewDecoder(r.Body).Decode(&body) != nil || body[test.field] != true || len(body) != 3 || body["destination"] != withdrawalTestDestination {
						t.Errorf("wrong delivery request %s: %+v", r.URL.Path, body)
					}
					_ = json.NewEncoder(w).Encode(test.quote)
					return
				}
				state := gaslessTestStatus("complete")
				state["funds_waiting_in_transit"] = true
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer s.Close()
			var out bytes.Buffer
			if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--to", withdrawalTestDestination, test.flag}, &out); err != nil {
				t.Fatal(err)
			}
			if posts != 1 || !strings.Contains(out.String(), test.want) || !strings.Contains(out.String(), "--approve "+testQuoteID) {
				t.Fatalf("posts=%d output %s", posts, out.String())
			}
		})
	}
	// Another saved destination is refused before any request.
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			t.Error("a delivery was quoted for another destination")
		}
		_ = json.NewEncoder(w).Encode(gaslessTestStatus("complete"))
	}))
	defer s.Close()
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--to", "0x4444444444444444444444444444444444444444", "--collect"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "another destination") {
		t.Fatalf("another destination: %v", err)
	}
}

// Approving a payout quote (or a delivery quote) goes through the
// withdrawal route; the command then follows the operation's phases until
// the bundle transaction is final and prints what reached the payout address.
func TestWithdrawApproveFollowsTheSponsoredOperation(t *testing.T) {
	var posts int
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin/escape/quote" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte("null"))
		case r.URL.Path == "/admin/withdrawal/quote" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(payoutTestQuote("close"))
		case r.URL.Path == "/admin/withdrawal/approve":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["quote_id"] != testQuoteID || len(body) != 1 {
				t.Error("approved another quote")
			}
			_ = json.NewEncoder(w).Encode(gaslessTestStatus("op_submitted"))
		case r.URL.Path == "/admin/withdrawal" && r.Method == http.MethodPost:
			posts++
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["destination"] != withdrawalTestDestination {
				t.Errorf("poll changed the request: %+v", body)
			}
			state := gaslessTestStatus("op_submitted")
			if posts >= 2 {
				state = gaslessTestStatus("withdrawal_pending")
				state["transaction_hash"] = "0x" + strings.Repeat("b", 64)
			}
			if posts >= 3 {
				state = gaslessTestStatus("complete")
				state["transaction_hash"] = "0x" + strings.Repeat("b", 64)
				state["received_wei"], state["charged_wei"], state["owed_paid_wei"] = "96671000000000", "3300000000000000", "0"
			}
			_ = json.NewEncoder(w).Encode(state)
		default:
			_ = json.NewEncoder(w).Encode(withdrawalTestStatus("ready"))
		}
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--approve", testQuoteID}, &out); err != nil {
		t.Fatal(err)
	}
	if posts != 3 {
		t.Fatalf("%d polls", posts)
	}
	for _, want := range []string{"Fee paid from the payout", "op_submitted:", "Operation: " + gaslessTestOpHash, "Fee: payout; transit account: " + gaslessTestTransit, "withdrawal_pending:", "Transaction: 0x" + strings.Repeat("b", 64), "complete:", "Received by the payout address: 0.000096671000000000 ETH (sponsored fee 0.003300000000000000 ETH"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out.String())
		}
	}
}

// A reverted operation, or a refusal that ends the approval, stops the
// command with the way out (never a wallet-paid fee); a refusal the daemon
// retries within the authorization is followed (TestWithdrawApproveFollowsARetryableRefusal).
// A reverted operation is proved again only by its hash.
func TestWithdrawGaslessFailuresStopAndRetryByTheOperationHash(t *testing.T) {
	for _, phase := range []string{"op_reverted", "gasless_refused"} {
		t.Run(phase, func(t *testing.T) {
			posts := 0
			s := withdrawalApprovalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
					state := gaslessTestStatus(phase)
					state["gasless_refusal"] = "payout_below_gas: the payout (1 wei) does not cover the sponsored fee; use --fees wallet"
					_ = json.NewEncoder(w).Encode(state)
					return
				}
				_ = json.NewEncoder(w).Encode(withdrawalTestStatus("ready"))
			}))
			defer s.Close()
			err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--approve", testQuoteID}, &bytes.Buffer{})
			if err == nil || posts != 1 || (phase == "gasless_refused" && (!strings.Contains(err.Error(), "payout_below_gas") || !strings.Contains(err.Error(), "rerun withdraw --to "+withdrawalTestDestination+" to review a new quote"))) || (phase == "op_reverted" && !strings.Contains(err.Error(), "reverted")) {
				t.Fatalf("%s did not stop with its reason: posts=%d %v", phase, posts, err)
			}
			if strings.Contains(err.Error(), "--fees wallet") {
				t.Fatalf("%s suggested a wallet-paid fee: %v", phase, err)
			}
		})
	}
	posts := 0
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			var body map[string]any
			if r.URL.Path != "/admin/withdrawal/quote" || json.NewDecoder(r.Body).Decode(&body) != nil || body["retry_transaction_hash"] != gaslessTestOpHash || body["fees"] != "payout" || len(body) != 4 {
				t.Errorf("the retry did not name the operation: %+v", body)
			}
			_ = json.NewEncoder(w).Encode(payoutTestQuote("close"))
			return
		}
		state := gaslessTestStatus("op_reverted")
		state["transaction_hash"] = "0x" + strings.Repeat("b", 64)
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer s.Close()
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--to", withdrawalTestDestination, "--fees", "payout"}, &bytes.Buffer{}); err != nil || posts != 1 {
		t.Fatalf("retry: %v posts=%d", err, posts)
	}
	// --resume follows a sent operation even before its transaction is known.
	resumes := 0
	s = fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			resumes++
			state := gaslessTestStatus("complete")
			state["received_wei"] = "1"
			_ = json.NewEncoder(w).Encode(state)
			return
		}
		_ = json.NewEncoder(w).Encode(gaslessTestStatus("op_built"))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--resume"}, &out); err != nil || resumes != 1 || !strings.Contains(out.String(), "complete:") {
		t.Fatalf("resume: %v resumes=%d %s", err, resumes, out.String())
	}
	// The read-only status names the resume command for an operation in flight.
	out.Reset()
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), nil, &out); err != nil || !strings.Contains(out.String(), "withdraw --resume") {
		t.Fatalf("status: %v %s", err, out.String())
	}
}

// Malformed gasless fields of a status are refused before any request.
func TestWithdrawRejectsMalformedGaslessStatus(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"operation hash": func(s map[string]any) { s["user_op_hash"] = "0x12" },
		"transit":        func(s map[string]any) { s["transit_account"] = "transit" },
		"received":       func(s map[string]any) { s["received_wei"] = "1.5" },
	} {
		t.Run(name, func(t *testing.T) {
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("malformed state authorized a request")
				}
				state := gaslessTestStatus("op_submitted")
				mutate(state)
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer s.Close()
			if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--resume"}, &bytes.Buffer{}); err == nil {
				t.Fatal("malformed status accepted")
			}
		})
	}
}

// The escape command carries the gasless options to its decision, quote and
// finalization requests, follows the sponsored phases, and quotes the
// forward of a payout a third party's finalization left in the transit
// account.
func TestEscapeCommandCarriesGaslessOptions(t *testing.T) {
	var bodies []map[string]any
	phase := "escape_initiated"
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			bodies = append(bodies, body)
			if r.URL.Path == "/admin/escape/quote" {
				if body["conceded"] != nil {
					q := payoutTestQuote("escape")
					q.Kind = "escape"
					_ = json.NewEncoder(w).Encode(q)
				} else if phase == "complete" {
					_ = json.NewEncoder(w).Encode(payoutTestQuote("forward"))
				} else {
					q := payoutTestQuote("finalize")
					q.Kind = "escape_finalize"
					_ = json.NewEncoder(w).Encode(q)
				}
				return
			}
		}
		state := gaslessTestStatus(phase)
		state["mode"] = "escape"
		state["challenge_deadline"] = 1
		if phase == "complete" {
			state["funds_waiting_in_transit"] = true
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--escape", "--to", withdrawalTestDestination, "--fees", "payout", "--bundler-url", "https://bundler.example/rpc"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0]["fees"] != "payout" || bodies[0]["bundler_url"] != "https://bundler.example/rpc" || bodies[1]["fees"] != "payout" || !strings.Contains(out.String(), "sponsored finalize operation") {
		t.Fatalf("escape requests: %+v %s", bodies, out.String())
	}
	bodies, out = nil, bytes.Buffer{}
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--escape", "--to", withdrawalTestDestination, "--conceded", "0", "--fees", "payout"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 || bodies[0]["conceded"] != float64(0) || bodies[0]["fees"] != "payout" || !strings.Contains(out.String(), "sponsored escape operation") {
		t.Fatalf("initiation quote: %+v %s", bodies, out.String())
	}
	phase, bodies, out = "complete", nil, bytes.Buffer{}
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--escape", "--to", withdrawalTestDestination}, &out); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0]["fees"] != nil || !strings.Contains(out.String(), "sponsored forward operation") {
		t.Fatalf("forward quote after a third-party finalization: %+v %s", bodies, out.String())
	}
	// --fees wallet named on the command line reaches the daemon (the
	// wallet fallback of a sponsored escape), even when the configured
	// default is the wallet.
	phase, bodies, out = "escape_initiated", nil, bytes.Buffer{}
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--escape", "--to", withdrawalTestDestination, "--fees", "wallet"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(bodies) == 0 || bodies[0]["fees"] != "wallet" {
		t.Fatalf("the named wallet fee mode was not sent: %+v", bodies)
	}
}

// zkapi-clientd config --bundler-url and --withdrawal-fees edit the saved
// configuration ('none' and 'wallet' clear them) and show it; invalid
// values are refused before anything is written.
func TestConfigureBundlerAndWithdrawalFeesFlags(t *testing.T) {
	dir, original := startTestConfig(t)
	var seen config.Config
	record := func(_ context.Context, _ string, c config.Config, action string, _ setupPrompter, _ io.Writer) error {
		seen = c
		return nil
	}
	ui := &startTestUI{}
	if err := configure(context.Background(), dir, []string{"--bundler-url", "https://bundler.example/rpc", "--withdrawal-fees", "payout"}, ui, &bytes.Buffer{}, record); err != nil {
		t.Fatal(err)
	}
	if seen.ZKAPI.BundlerURL != "https://bundler.example/rpc" || seen.ZKAPI.WithdrawalFees != "payout" || seen.APIKey != original.APIKey || seen.ZKAPI.ExitRPCURL != original.ZKAPI.ExitRPCURL {
		t.Fatalf("flags not applied: %+v", seen.ZKAPI)
	}
	loaded, err := config.Load(dir)
	if err != nil || loaded.ZKAPI.BundlerURL != "https://bundler.example/rpc" || loaded.ZKAPI.WithdrawalFees != "payout" {
		t.Fatalf("not saved: %+v %v", loaded.ZKAPI, err)
	}
	if !strings.Contains(ui.output.String(), "Bundler: https://bundler.example/rpc") || !strings.Contains(ui.output.String(), "paid from the payout by default") {
		t.Fatalf("summary: %s", ui.output.String())
	}
	if err := configure(context.Background(), dir, []string{"--bundler-url", "none", "--withdrawal-fees", "wallet"}, &startTestUI{}, &bytes.Buffer{}, record); err != nil {
		t.Fatal(err)
	}
	if seen.ZKAPI.BundlerURL != "" || seen.ZKAPI.WithdrawalFees != "" {
		t.Fatalf("not cleared: %+v", seen.ZKAPI)
	}
	for _, args := range [][]string{{"--bundler-url", "http://bundler.example"}, {"--bundler-url", "https://user:pw@bundler.example"}, {"--withdrawal-fees", "sponsor"}, {"--withdrawal-fees", ""}} {
		if err := configure(context.Background(), dir, args, &startTestUI{}, &bytes.Buffer{}, func(_ context.Context, _ string, c config.Config, _ string, _ setupPrompter, _ io.Writer) error {
			t.Errorf("invalid %v reached the action", args)
			return nil
		}); err == nil {
			t.Fatalf("invalid %v accepted", args)
		}
	}
}

// A legacy payout quote (no bounded authorization) labels the expected
// charge as an estimate beside the signed maximum; an authorized quote says
// the actual fee may change, states the maximum the payout may lose, the
// floor the destination receives and the approval's scope. For a payout
// address with code both state the credit case and its surcharge, which the
// floor deducts.
func TestPayoutQuotePrintsTheEstimateAndTheContractPayeeCase(t *testing.T) {
	q := payoutTestQuote("close")
	var out bytes.Buffer
	printPayoutQuote(&out, q)
	if !strings.Contains(out.String(), "Maximum fee taken from it: 0.003300000000000000 ETH (expected charge at today's base fee: about 0.002000000000000000 ETH, an estimate;") || strings.Contains(out.String(), "has code") || strings.Contains(out.String(), "This one approval") {
		t.Fatalf("plain payout quote: %s", out.String())
	}
	q.PayeeHasCode, q.CreditSurchargeWei, q.MinimumReceivedWei = true, "92046000000000", "4579000000000"
	out.Reset()
	printPayoutQuote(&out, q)
	for _, want := range []string{"The payout address receives at least: 0.000004579000000000 ETH", "The payout address has code", "surcharge of up to 0.000092046000000000 ETH", "--claim-credit --to " + q.Destination} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out.String())
		}
	}
	a := authorizedPayoutTestQuote()
	out.Reset()
	printPayoutQuote(&out, a)
	for _, want := range []string{"about 0.000002000000000000 ETH (an estimate; the actual fee may change)", "At most 0.000004000000000000 ETH may be taken from the payout", withdrawalTestDestination + " receives at least 0.000095971000000000 ETH", "This one approval covers this destination, note and transit account; fee changes within this maximum are handled without asking again; a new destination or note needs a new approval.", "Transit account: " + gaslessTestTransit, "Bundler: https://bundler.example/rpc"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Maximum fee taken from it") || strings.Contains(out.String(), "has code") {
		t.Fatalf("authorized quote printed the legacy terms: %s", out.String())
	}
	a.PayeeHasCode, a.CreditSurchargeWei = true, "92046000000000"
	out.Reset()
	printPayoutQuote(&out, a)
	if !strings.Contains(out.String(), "The payout address has code") || !strings.Contains(out.String(), "--claim-credit --to "+a.Destination) {
		t.Fatalf("authorized contract payee: %s", out.String())
	}
}

// A plain rerun keeps a saved withdrawal's fee mode: with zkapi.withdrawal_fees
// payout, the configured default is sent only for a new withdrawal, so a
// saved record the owner moved to the wallet is not switched back to the
// sponsored path; a named --fees is always sent for a saved record (the
// daemon decides: a wallet fee is explicit recovery there), also on a payout
// deployment.
func TestWithdrawConfiguredPayoutDefaultKeepsASavedWithdrawalsMode(t *testing.T) {
	for name, test := range map[string]struct {
		args []string
		want any
	}{
		"plain rerun":      {args: []string{"--to", withdrawalTestDestination}, want: nil},
		"named payout":     {args: []string{"--to", withdrawalTestDestination, "--fees", "payout"}, want: "payout"},
		"named wallet":     {args: []string{"--to", withdrawalTestDestination, "--fees", "wallet"}, want: "wallet"},
		"escape rerun":     {args: []string{"--escape", "--to", withdrawalTestDestination}, want: nil},
		"escape named pay": {args: []string{"--escape", "--to", withdrawalTestDestination, "--fees", "payout"}, want: "payout"},
	} {
		for _, policy := range []string{"", "payout"} {
			t.Run(name+" "+policy, func(t *testing.T) {
				posts := 0
				s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					saved := gaslessTestStatus("quoted")
					saved["fee_payer"], saved["user_op_hash"] = "wallet", nil
					if policy != "" {
						saved["new_withdrawal_fees"] = policy
					}
					if r.Method == http.MethodPost {
						posts++
						var body map[string]any
						_ = json.NewDecoder(r.Body).Decode(&body)
						if body["fees"] != test.want {
							t.Errorf("fees sent %v, want %v: %+v", body["fees"], test.want, body)
						}
						if r.URL.Path == "/admin/escape" {
							saved["mode"] = "escape"
							_ = json.NewEncoder(w).Encode(saved)
							return
						}
						_ = json.NewEncoder(w).Encode(paymentTestQuote("withdrawal"))
						return
					}
					_ = json.NewEncoder(w).Encode(saved)
				}))
				defer s.Close()
				c := withdrawalTestConfig(s)
				c.ZKAPI.WithdrawalFees = "payout"
				var out bytes.Buffer
				_ = runWithdrawal(context.Background(), c, test.args, &out)
				if posts == 0 {
					t.Fatal("no request reached the daemon")
				}
				// The record moved to the wallet pays its fee from the wallet.
				if !strings.Contains(test.args[0], "escape") && !strings.Contains(out.String(), "Available for network fees") {
					t.Fatalf("a wallet-bound record hid its fee balance: %s", out.String())
				}
			})
		}
	}
}
