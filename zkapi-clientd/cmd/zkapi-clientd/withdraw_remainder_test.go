package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestRemainderActions(t *testing.T) {
	closed := zkapi.AddressWithdrawalStatus{Phase: "complete", Address: "0x1111111111111111111111111111111111111111", Destination: withdrawalTestDestination, ChainID: 1}
	for _, test := range []struct{ phase, balance, destination, want string }{
		{"ready", "0", "", "empty"}, {"ready", "100", "", "quote"},
		{"quoted", "100", withdrawalTestDestination, "quote"},
		{"return_pending", "100", withdrawalTestDestination, "resume"},
		{"complete", "100", withdrawalTestDestination, "done"},
		{"return_pending", "100", closed.Address, ""},
		{"reverted", "100", withdrawalTestDestination, ""},
	} {
		state := zkapi.AddressReturnStatus{Phase: test.phase, ETHBalance: test.balance, Address: closed.Address, ChainID: 1, Destination: test.destination}
		got, err := remainderAction(closed, state)
		if got != test.want || (err != nil) != (test.want == "") {
			t.Fatal(test, got, err)
		}
	}
	closed.PayoutCredited = true
	state := zkapi.AddressReturnStatus{Phase: "ready", ETHBalance: "100", Address: closed.Address, ChainID: 1}
	if _, err := remainderAction(closed, state); err == nil {
		t.Fatal("sweeps fee funds before credited payout collection")
	}
	closed.PayoutCredited = false
	closed.PaymasterCredited = true
	if _, err := remainderAction(closed, state); err == nil {
		t.Fatal("sweeps fee funds before paymaster credit collection")
	}
	closed.PaymasterCredited = false
	closed.FundsWaitingInTransit = true
	if _, err := remainderAction(closed, state); err == nil {
		t.Fatal("sweeps fee funds before transit payout collection")
	}
	closed.FundsWaitingInTransit = false
	closed.Phase = "confirming"
	if _, err := remainderAction(closed, zkapi.AddressReturnStatus{}); err == nil {
		t.Fatal("sweeps before private completion")
	}
}

// After a payout withdrawal the remainder leg returns nothing from a wallet
// with no ETH and says why; dust that cannot pay its own return fee is
// reported, not an error; any other quote failure still is.
func TestRemainderAfterAPayoutWithdrawal(t *testing.T) {
	for name, test := range map[string]struct {
		balance, refusal, want string
		failed                 bool
	}{
		"no public ETH": {balance: "0", want: "No public ETH remains to return: the network fee was paid from the payout"},
		"dust":          {balance: "100", refusal: "send more ETH to the payment address for Ethereum network fees", want: "does not cover the network fee of returning it, so nothing was sent; return it later with zkapi-clientd withdraw --public"},
		"quote failure": {balance: "100", refusal: "the RPC did not answer", failed: true},
	} {
		t.Run(name, func(t *testing.T) {
			quotes := 0
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /admin/withdrawal":
					_ = json.NewEncoder(w).Encode(completedPayoutStatus())
				case "GET /admin/return":
					_ = json.NewEncoder(w).Encode(map[string]any{"address": "0x1111111111111111111111111111111111111111", "chain_id": 1, "eth_balance": test.balance, "phase": "ready", "message": "Return public ETH."})
				case "POST /admin/return/quote":
					quotes++
					w.WriteHeader(http.StatusBadGateway)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": test.refusal})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
			}))
			defer s.Close()
			u := &fundingWizardUI{}
			err := withdrawWithRemainder(context.Background(), withdrawalTestConfig(s), u)
			if (err != nil) != test.failed || (test.balance == "0") != (quotes == 0) || u.confirms != 0 {
				t.Fatalf("err=%v quotes=%d %s", err, quotes, u.String())
			}
			if test.want != "" && !strings.Contains(u.String(), test.want) {
				t.Fatalf("missing %q in %s", test.want, u.String())
			}
			if !strings.Contains(u.String(), "Withdrawal complete: 0.000095971000000000 ETH reached") {
				t.Fatalf("the private withdrawal's result was not shown: %s", u.String())
			}
		})
	}
}
