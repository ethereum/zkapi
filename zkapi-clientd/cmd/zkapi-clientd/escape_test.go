package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func escapeTestStatus(phase string) map[string]any {
	state := withdrawalTestStatus(phase)
	state["destination"] = withdrawalTestDestination
	state["mode"] = "escape"
	state["state_balance"], state["conceded"], state["bound_at_state"], state["amount"] = 99971, 700, 1000, 99271
	state["reason"] = "at_deadline"
	return state
}

// The escape CLI: the first run shows the decision and asks nothing to be
// signed; --conceded confirms the decision's concession and quotes the
// initiation; --approve on that quote signs it through the escape route.
func TestWithdrawEscapeShowsTheDecisionThenQuotesTheConfirmedConcession(t *testing.T) {
	var sequence []string
	var bodies []map[string]any
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sequence = append(sequence, r.Method+" "+r.URL.Path)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method == http.MethodPost {
			bodies = append(bodies, body)
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /admin/escape":
			_ = json.NewEncoder(w).Encode(withdrawalTestStatus("ready"))
		case "POST /admin/escape":
			_ = json.NewEncoder(w).Encode(escapeTestStatus("escape_decision"))
		case "POST /admin/escape/quote":
			quote := paymentTestQuote("withdrawal")
			quote.Kind, quote.Amount = "escape", 99271
			_ = json.NewEncoder(w).Encode(quote)
		case "GET /admin/escape/quote":
			quote := paymentTestQuote("withdrawal")
			quote.Kind, quote.Amount = "escape", 99271
			_ = json.NewEncoder(w).Encode(quote)
		case "POST /admin/escape/approve":
			_ = json.NewEncoder(w).Encode(escapeTestStatus("escape_initiated"))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer s.Close()
	c := withdrawalTestConfig(s)
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), c, []string{"--escape", "--to", withdrawalTestDestination}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sequence, ",") != "GET /admin/escape,POST /admin/escape" || bodies[0]["conceded"] != nil {
		t.Fatalf("the decision run asked for more: %v %v", sequence, bodies)
	}
	for _, want := range []string{"concession: 0.000000700 ETH", "never settled in time", "escape_decision"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out.String())
		}
	}
	sequence, bodies, out = nil, nil, bytes.Buffer{}
	if err := runWithdrawal(context.Background(), c, []string{"--escape", "--to", withdrawalTestDestination, "--conceded", "700", "--early-exit", "bound"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sequence, ",") != "GET /admin/escape,POST /admin/escape/quote" || bodies[0]["conceded"] != float64(700) || bodies[0]["early_exit"] != "concede_bound" {
		t.Fatalf("wrong quote request: %v %v", sequence, bodies)
	}
	if !strings.Contains(out.String(), "--approve "+testQuoteID) || !strings.Contains(out.String(), "payout is 0.000099271 ETH") {
		t.Fatalf("no approvable quote: %s", out.String())
	}
	sequence, out = nil, bytes.Buffer{}
	if err := runWithdrawal(context.Background(), c, []string{"--approve", testQuoteID}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(sequence, ","), "POST /admin/escape/approve") {
		t.Fatalf("the escape quote was not approved through the escape route: %v", sequence)
	}
	for _, args := range [][]string{
		{"--escape"},
		{"--escape", "--to", withdrawalTestDestination, "--claim"},
		{"--conceded", "5", "--to", withdrawalTestDestination},
		{"--escape", "--to", withdrawalTestDestination, "--early-exit", "sometimes"},
		{"--escape", "--to", withdrawalTestDestination, "--conceded", "-1"},
	} {
		if err := runWithdrawal(context.Background(), c, args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

// --escape --cancel cancels an escape that released no exit proof (design
// §6.4 E6) through the escape route, and takes no other option.
func TestWithdrawEscapeCancel(t *testing.T) {
	var sequence []string
	s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sequence = append(sequence, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /admin/escape/cancel":
			state := withdrawalTestStatus("cancelled")
			state["message"] = "The escape was cancelled; no exit proof was released."
			_ = json.NewEncoder(w).Encode(state)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer s.Close()
	c := withdrawalTestConfig(s)
	var out bytes.Buffer
	if err := runWithdrawal(context.Background(), c, []string{"--escape", "--cancel"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sequence, ",") != "POST /admin/escape/cancel" || !strings.Contains(out.String(), "cancelled") {
		t.Fatalf("not cancelled through the escape route: %v %s", sequence, out.String())
	}
	for _, args := range [][]string{
		{"--cancel"},
		{"--escape", "--cancel", "--to", withdrawalTestDestination},
		{"--escape", "--cancel", "--conceded", "0"},
		{"--escape", "--cancel", "--claim"},
	} {
		if err := runWithdrawal(context.Background(), c, args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
