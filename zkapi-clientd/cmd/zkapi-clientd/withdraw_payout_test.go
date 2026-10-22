package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// The withdraw command on a deployment that sponsors withdrawals: the payout
// pays a new withdrawal's fee (the only option), one approval covers the
// destination, note and transit account, and the daemon continues within
// the authorized maximum.

func payoutPolicyStatus(phase string) map[string]any {
	state := withdrawalTestStatus(phase)
	state["new_withdrawal_fees"] = "payout"
	return state
}

func authorizedTestStatus(phase string) map[string]any {
	state := gaslessTestStatus(phase)
	state["new_withdrawal_fees"] = "payout"
	if phase == "quoted" {
		delete(state, "user_op_hash")
	}
	state["authorized_max_fee_wei"], state["authorized_min_net_payout_wei"], state["estimated_fee_wei"] = "4000000000000", "95971000000000", "2000000000000"
	if phase == "gasless_refused" {
		state["gasless_retryable"], state["gasless_refusal"] = true, "bundler_unavailable: the bundler did not answer"
	}
	return state
}

func completedPayoutStatus() map[string]any {
	state := gaslessTestStatus("complete")
	state["new_withdrawal_fees"] = "payout"
	state["transaction_hash"] = "0x" + strings.Repeat("b", 64)
	state["received_wei"], state["charged_wei"], state["owed_paid_wei"] = "95971000000000", "3300000000000", "0"
	return state
}

// --fees wallet for a new withdrawal on a payout deployment is refused
// before any quote: the payout pays the fee and the wallet needs no ETH.
func TestWithdrawWalletFeesRefusedLocallyForANewPayoutWithdrawal(t *testing.T) {
	var sequence []string
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sequence = append(sequence, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet {
			t.Errorf("a refused wallet fee reached the daemon: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(payoutPolicyStatus("ready"))
	}))
	defer s.Close()
	err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--to", withdrawalTestDestination, "--fees", "wallet"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not available for a new withdrawal") || !strings.Contains(err.Error(), "needs no ETH") || strings.Contains(err.Error(), "recover saved progress") {
		t.Fatalf("wallet fee: %v", err)
	}
	if strings.Join(sequence, ",") != "GET /admin/withdrawal" {
		t.Fatalf("requests: %v", sequence)
	}
}

// A withdrawal saved wallet-paid before sponsorship finishes wallet-paid on
// a payout deployment: its quote shows the fee top-up, approval follows the
// transaction, and --resume recovers it.
func TestWithdrawSavedWalletRecordFinishesWalletPaid(t *testing.T) {
	var bodies []map[string]any
	phase := "waiting_funds"
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.Method + " " + r.URL.Path {
		case "GET /admin/escape/quote":
			_, _ = w.Write([]byte("null"))
		case "POST /admin/withdrawal/quote":
			bodies = append(bodies, body)
			q := paymentTestQuote("withdrawal")
			q.BalanceWei, q.ShortfallWei, q.RecommendedTopUpWei = "0", "25000", "30000"
			_ = json.NewEncoder(w).Encode(q)
		case "GET /admin/withdrawal/quote":
			_ = json.NewEncoder(w).Encode(paymentTestQuote("withdrawal"))
		case "POST /admin/withdrawal/approve", "POST /admin/withdrawal":
			state := payoutPolicyStatus("complete")
			state["transaction_hash"] = "0x" + strings.Repeat("a", 64)
			_ = json.NewEncoder(w).Encode(state)
		default:
			state := payoutPolicyStatus(phase)
			if phase == "withdrawal_pending" {
				state["transaction_hash"] = "0x" + strings.Repeat("a", 64)
			}
			_ = json.NewEncoder(w).Encode(state)
		}
	}))
	defer s.Close()
	c := withdrawalTestConfig(s)
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), c, []string{"--to", withdrawalTestDestination}, &out); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 || bodies[0]["fees"] != nil || !strings.Contains(out.String(), "Available for network fees") || !strings.Contains(out.String(), "Payment URI: ethereum:") || strings.Contains(out.String(), "paid from the payout") {
		t.Fatalf("wallet record quote: %+v %s", bodies, out.String())
	}
	out.Reset()
	if err := runWithdrawal(context.Background(), c, []string{"--approve", testQuoteID}, &out); err != nil || !strings.Contains(out.String(), "complete:") {
		t.Fatalf("approve: %v %s", err, out.String())
	}
	phase = "withdrawal_pending"
	out.Reset()
	if err := runWithdrawal(context.Background(), c, []string{"--resume"}, &out); err != nil || !strings.Contains(out.String(), "complete:") {
		t.Fatalf("resume: %v %s", err, out.String())
	}
}

// After --approve a refusal the daemon retries within the authorization is
// followed (no new approval, no wallet fee) to completion.
func TestWithdrawApproveFollowsARetryableRefusal(t *testing.T) {
	var polls []map[string]any
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.Method + " " + r.URL.Path {
		case "GET /admin/escape/quote":
			_, _ = w.Write([]byte("null"))
		case "GET /admin/withdrawal/quote":
			_ = json.NewEncoder(w).Encode(authorizedPayoutTestQuote())
		case "POST /admin/withdrawal/approve":
			_ = json.NewEncoder(w).Encode(authorizedTestStatus("gasless_refused"))
		case "POST /admin/withdrawal":
			polls = append(polls, body)
			_ = json.NewEncoder(w).Encode(completedPayoutStatus())
		default:
			_ = json.NewEncoder(w).Encode(payoutPolicyStatus("ready"))
		}
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--approve", testQuoteID}, &out); err != nil {
		t.Fatal(err)
	}
	if len(polls) != 1 || len(polls[0]) != 2 || polls[0]["destination"] != withdrawalTestDestination {
		t.Fatalf("polls: %+v", polls)
	}
	for _, want := range []string{"gasless_refused:", "your authorization still holds", "Approved: at most 0.000004000000000000 ETH may be taken from the payout; " + withdrawalTestDestination + " receives at least 0.000095971000000000 ETH", "Latest fee estimate: about 0.000002000000000000 ETH (an estimate; the actual fee may change)", "Received by the payout address: 0.000095971000000000 ETH (sponsored fee 0.000003300000000000 ETH"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out.String())
		}
	}
	if strings.Count(out.String(), "your authorization still holds") != 1 || strings.Contains(out.String(), "--fees wallet") {
		t.Fatalf("output: %s", out.String())
	}
}

// --resume continues a withdrawal approved within its maximum fee but not
// yet signed (a restart before signing), or a refusal retried within it;
// without an authorization it signs nothing.
func TestWithdrawResumeContinuesAnApprovedUnsignedWithdrawal(t *testing.T) {
	for name, test := range map[string]struct {
		status map[string]any
		posts  int
	}{
		"approved unsigned":  {status: authorizedTestStatus("quoted"), posts: 1},
		"retryable refusal":  {status: authorizedTestStatus("gasless_refused"), posts: 1},
		"unapproved quote":   {status: func() map[string]any { s := gaslessTestStatus("quoted"); delete(s, "user_op_hash"); return s }(), posts: 0},
		"ended refusal":      {status: gaslessTestStatus("gasless_refused"), posts: 0},
		"unsigned no record": {status: payoutPolicyStatus("ready"), posts: 0},
	} {
		t.Run(name, func(t *testing.T) {
			posts := 0
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
					var body map[string]any
					if r.URL.Path != "/admin/withdrawal" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 {
						t.Errorf("resume asked for more: %s %+v", r.URL.Path, body)
					}
					_ = json.NewEncoder(w).Encode(completedPayoutStatus())
					return
				}
				_ = json.NewEncoder(w).Encode(test.status)
			}))
			defer s.Close()
			var out bytes.Buffer
			err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--resume"}, &out)
			if posts != test.posts || (err == nil) != (test.posts == 1) {
				t.Fatalf("posts=%d err=%v %s", posts, err, out.String())
			}
			if test.posts == 1 && (!strings.Contains(out.String(), "Continuing the approved withdrawal within its maximum fee") || !strings.Contains(out.String(), "Received by the payout address")) {
				t.Fatalf("output: %s", out.String())
			}
		})
	}
	// The read-only status names --resume for an approved withdrawal.
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(authorizedTestStatus("quoted"))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), nil, &out); err != nil || !strings.Contains(out.String(), "approved within its maximum fee. To continue it, run zkapi-clientd withdraw --resume") {
		t.Fatalf("status: %v %s", err, out.String())
	}
}

// --to on a withdrawal approved within its maximum fee continues it instead
// of quoting again; new gasless options ask for a new quote (whose approval
// replaces the authorization); another destination is refused.
func TestWithdrawToOnAnApprovedWithdrawalFollowsInsteadOfQuoting(t *testing.T) {
	var sequence []string
	var bodies []map[string]any
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sequence = append(sequence, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			bodies = append(bodies, body)
			if r.URL.Path == "/admin/withdrawal/quote" {
				_ = json.NewEncoder(w).Encode(authorizedPayoutTestQuote())
				return
			}
			_ = json.NewEncoder(w).Encode(completedPayoutStatus())
			return
		}
		_ = json.NewEncoder(w).Encode(authorizedTestStatus("quoted"))
	}))
	defer s.Close()
	c := withdrawalTestConfig(s)
	c.ZKAPI.BundlerURL = "https://bundler.example/rpc" // A configured bundler is not a new option.
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), c, []string{"--to", withdrawalTestDestination}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sequence, ",") != "GET /admin/withdrawal,POST /admin/withdrawal" || len(bodies[0]) != 2 || !strings.Contains(out.String(), "no new approval is needed") {
		t.Fatalf("follow: %v %+v %s", sequence, bodies, out.String())
	}
	sequence, bodies = nil, nil
	if err := runWithdrawal(context.Background(), c, []string{"--to", withdrawalTestDestination, "--fee-cap-gwei", "5000"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sequence, ",") != "GET /admin/withdrawal,POST /admin/withdrawal/quote" || bodies[0]["fee_cap_gwei"] != float64(5000) {
		t.Fatalf("new options: %v %+v", sequence, bodies)
	}
	sequence = nil
	if err := runWithdrawal(context.Background(), c, []string{"--to", "0x4444444444444444444444444444444444444444"}, &out); err == nil || !strings.Contains(err.Error(), "different destination") || strings.Join(sequence, ",") != "GET /admin/withdrawal" {
		t.Fatalf("another destination: %v %v", err, sequence)
	}
}

// An approval refused with quote_changed saved nothing: the command says the
// quote expired or was replaced and to review a new one, without claiming a
// submitted withdrawal.
func TestWithdrawApproveQuoteChangedNeedsANewQuote(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /admin/escape/quote":
			_, _ = w.Write([]byte("null"))
		case "GET /admin/withdrawal/quote":
			_ = json.NewEncoder(w).Encode(authorizedPayoutTestQuote())
		case "POST /admin/withdrawal/approve":
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "zkAPI withdrawal quote changed; review a fresh quote", "code": zkapi.CodeQuoteChanged})
		default:
			_ = json.NewEncoder(w).Encode(payoutPolicyStatus("ready"))
		}
	}))
	defer s.Close()
	err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--approve", testQuoteID}, &bytes.Buffer{})
	if managementErrorCode(err) != zkapi.CodeQuoteChanged || !strings.Contains(err.Error(), "expired or was replaced") || !strings.Contains(err.Error(), "rerun withdraw --to "+withdrawalTestDestination) || strings.Contains(err.Error(), "recover saved progress") {
		t.Fatalf("quote changed: %v", err)
	}
}

// A withdrawal signer with no ETH: the status says the fee is paid from the
// payout, the quote asks for no top-up, and completion shows what was
// received and the fee taken.
func TestWithdrawZeroETHSignerPaysTheFeeFromThePayout(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /admin/escape/quote":
			_, _ = w.Write([]byte("null"))
		case "POST /admin/withdrawal/quote", "GET /admin/withdrawal/quote":
			_ = json.NewEncoder(w).Encode(authorizedPayoutTestQuote())
		case "POST /admin/withdrawal/approve":
			state := completedPayoutStatus()
			state["eth_balance"] = "0"
			_ = json.NewEncoder(w).Encode(state)
		default:
			state := payoutPolicyStatus("ready")
			state["eth_balance"] = "0"
			_ = json.NewEncoder(w).Encode(state)
		}
	}))
	defer s.Close()
	c := withdrawalTestConfig(s)
	for _, args := range [][]string{nil, {"--to", withdrawalTestDestination}} {
		var out bytes.Buffer
		if err := runWithdrawal(context.Background(), c, args, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Network fee: paid from the payout (this wallet needs no ETH)") {
			t.Fatalf("%v: %s", args, out.String())
		}
		for _, forbidden := range []string{"Available for network fees", "Payment URI", "Send at least", "top-up", "--fees wallet", "fund the signing address"} {
			if strings.Contains(out.String(), forbidden) {
				t.Fatalf("%v: a zero-ETH payout withdrawal showed %q: %s", args, forbidden, out.String())
			}
		}
	}
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), c, []string{"--approve", testQuoteID}, &out); err != nil || !strings.Contains(out.String(), "Received by the payout address: 0.000095971000000000 ETH (sponsored fee 0.000003300000000000 ETH") {
		t.Fatalf("completion: %v %s", err, out.String())
	}
}

// A payout withdrawal is never quoted wallet-paid behind the owner's back,
// and malformed authorization fields are refused before any request.
func TestWithdrawRefusesSilentWalletFeesAndMalformedAuthorization(t *testing.T) {
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(paymentTestQuote("withdrawal"))
			return
		}
		_ = json.NewEncoder(w).Encode(payoutPolicyStatus("ready"))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--to", withdrawalTestDestination}, &out); err == nil || !strings.Contains(err.Error(), "wallet-paid fee") || strings.Contains(out.String(), "--approve") {
		t.Fatalf("silent wallet quote: %v %s", err, out.String())
	}
	for name, mutate := range map[string]func(map[string]any){
		"maximum":    func(s map[string]any) { s["authorized_max_fee_wei"] = "1.5" },
		"floor":      func(s map[string]any) { s["authorized_min_net_payout_wei"] = "-1" },
		"estimate":   func(s map[string]any) { s["estimated_fee_wei"] = "0x10" },
		"policy":     func(s map[string]any) { s["new_withdrawal_fees"] = "sponsor" },
		"no transit": func(s map[string]any) { delete(s, "transit_account") },
		"retry no transit": func(s map[string]any) {
			delete(s, "transit_account")
			delete(s, "authorized_max_fee_wei")
			s["gasless_retryable"] = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("a malformed authorization reached a request")
				}
				state := authorizedTestStatus("quoted")
				mutate(state)
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer s.Close()
			if err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--resume"}, &bytes.Buffer{}); err == nil {
				t.Fatal("malformed authorization accepted")
			}
		})
	}
}

// A payout quote's bounded authorization is checked: both figures, decimal
// wei, a bound no lower than the operation as built now, and a floor equal
// to the payout less the bound and the debt.
func TestPayoutQuoteRejectsAnInvalidAuthorization(t *testing.T) {
	for name, mutate := range map[string]func(*zkapi.AddressPaymentQuote){
		"valid":           func(*zkapi.AddressPaymentQuote) {},
		"legacy":          func(q *zkapi.AddressPaymentQuote) { q.MaxTotalFeeWei, q.MinNetPayoutWei = "", "" },
		"decimal maximum": func(q *zkapi.AddressPaymentQuote) { q.MaxTotalFeeWei = "4e12" },
		"decimal floor":   func(q *zkapi.AddressPaymentQuote) { q.MinNetPayoutWei = "95971000000000.0" },
		"below the cap": func(q *zkapi.AddressPaymentQuote) {
			q.MaxTotalFeeWei, q.MinNetPayoutWei = "3000000000000", "96971000000000"
		},
		"wrong floor":        func(q *zkapi.AddressPaymentQuote) { q.MinNetPayoutWei = "95971000000001" },
		"floor ignores debt": func(q *zkapi.AddressPaymentQuote) { q.OwedWei = "1" },
		"maximum alone":      func(q *zkapi.AddressPaymentQuote) { q.MinNetPayoutWei = "" },
		"floor alone":        func(q *zkapi.AddressPaymentQuote) { q.MaxTotalFeeWei = "" },
		"above the payout":   func(q *zkapi.AddressPaymentQuote) { q.MaxTotalFeeWei, q.MinNetPayoutWei = "99972000000000", "0" },
	} {
		t.Run(name, func(t *testing.T) {
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := authorizedPayoutTestQuote()
				mutate(&q)
				_ = json.NewEncoder(w).Encode(q)
			}))
			defer s.Close()
			_, err := requestPaymentQuote(context.Background(), withdrawalTestConfig(s), http.MethodGet, "/admin/withdrawal/quote", "withdrawal", nil)
			if (err == nil) != (name == "valid" || name == "legacy") {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
}

// A refusal of the payout path at quote time stops the command with the
// daemon's reason and code; nothing falls back to a wallet-paid fee.
func TestWithdrawPayoutQuoteRefusalHasNoWalletFallback(t *testing.T) {
	for _, code := range []string{"bundler_unavailable", "payout_below_gas", "gas_above_paymaster_ceiling"} {
		t.Run(code, func(t *testing.T) {
			var posts []map[string]any
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					posts = append(posts, body)
					w.WriteHeader(http.StatusBadGateway)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": code + ": the sponsored path refused this withdrawal; use --fees wallet", "code": code})
					return
				}
				_ = json.NewEncoder(w).Encode(payoutPolicyStatus("ready"))
			}))
			defer s.Close()
			err := runWithdrawal(context.Background(), withdrawalTestConfig(s), []string{"--to", withdrawalTestDestination}, &bytes.Buffer{})
			if managementErrorCode(err) != code || !strings.Contains(err.Error(), "the sponsored path refused this withdrawal") || strings.Contains(err.Error(), "--fees wallet") || len(posts) != 1 || posts[0]["fees"] != nil {
				t.Fatalf("%s: %v %+v", code, err, posts)
			}
		})
	}
}
