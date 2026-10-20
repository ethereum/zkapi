package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// --fees relay (or zkapi.withdrawal_fees relay) asks for a relayed close:
// the quote request names the relay and the relay quote is printed with its
// fee, the pre-approved wallet-paid fallback and the approval command.
func TestWithdrawFeesRelayQuotesARelayedClose(t *testing.T) {
	for name, configure := range map[string]func(*config.Config){
		"flag":               nil,
		"configured default": func(c *config.Config) { c.ZKAPI.WithdrawalFees = "relay" },
	} {
		t.Run(name, func(t *testing.T) {
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil || body["fees"] != "relay" {
						t.Errorf("the quote request does not name the relay: %+v", body)
					}
					q := paymentTestQuote("withdrawal")
					q.FeePolicy, q.RelayFeeUnits = "relay", "250000"
					_ = json.NewEncoder(w).Encode(q)
					return
				}
				_ = json.NewEncoder(w).Encode(withdrawalTestStatus("ready"))
			}))
			defer s.Close()
			c := withdrawalTestConfig(s)
			args := []string{"--to", withdrawalTestDestination}
			if configure == nil {
				args = append(args, "--fees", "relay")
			} else {
				configure(&c)
			}
			var out bytes.Buffer
			if err := runWithdrawal(context.Background(), c, args, &out); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"close relay lands the close in a batch for its fee of 0.000250000000000000 ETH", "submits it itself from the local signing address", "approving this quote authorizes that fallback too", "--approve " + testQuoteID, "Quoting does not pay, sign or send"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q in %s", want, out.String())
				}
			}
		})
	}
	// An unknown fee mode is refused before any request.
	if _, err := resolveGaslessOptions(config.Config{}, "relayed", 0, "", false, false, false, false); err == nil {
		t.Fatal("an unknown fee mode was accepted")
	}
}

// A relayed close in flight is followed by the poll loop until it completes,
// and --resume follows it too.
func TestWithdrawFollowsARelayedCloseUntilComplete(t *testing.T) {
	polls := 0
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := withdrawalTestStatus("relay_submitted")
		state["fee_payer"], state["relay_status"] = "relay", "queued"
		if r.Method == http.MethodPost {
			polls++
			if polls >= 2 {
				state["phase"], state["transaction_hash"] = "complete", "0x"+strings.Repeat("be", 32)
			}
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer s.Close()
	c := withdrawalTestConfig(s)
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), c, []string{"--resume"}, &out); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if polls < 2 || !strings.Contains(out.String(), "complete") {
		t.Fatalf("the relayed close was not followed to completion: %s", out.String())
	}
}
