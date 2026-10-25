package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// A daemon from an older build names no new-withdrawal fee mode: nothing
// new is quoted or approved through it, while a signed withdrawal is still
// followed; a current daemon is never refused.
func TestOlderDaemonOnlyFollowsSignedWithdrawals(t *testing.T) {
	for _, phase := range []string{"ready", "quoted", "waiting_funds", "waiting_settlement", "reverted", "gasless_refused", "op_reverted", "recovery_required"} {
		if err := checkWithdrawalDaemon(zkapi.AddressWithdrawalStatus{Phase: phase}); !errors.Is(err, errDaemonPredatesPayoutOnly) {
			t.Fatalf("%s through an older daemon was not refused: %v", phase, err)
		}
	}
	for _, phase := range []string{"withdrawal_pending", "confirming", "complete", "no_note", "op_built", "op_submitted", "forward_op_built", "forward_op_submitted"} {
		if err := checkWithdrawalDaemon(zkapi.AddressWithdrawalStatus{Phase: phase}); err != nil {
			t.Fatalf("signed %s was not followed through an older daemon: %v", phase, err)
		}
	}
	for _, fees := range []string{"payout", "wallet"} {
		if err := checkWithdrawalDaemon(zkapi.AddressWithdrawalStatus{Phase: "ready", NewWithdrawalFees: fees}); err != nil {
			t.Fatalf("a current daemon (%s) was refused: %v", fees, err)
		}
	}
}

// Through a daemon an older build started, withdraw --to quotes nothing (no
// wallet-paid fallback, no claim of an authorization) and names the restart;
// a withdrawal that daemon signed is still followed with --resume.
func TestWithdrawThroughAnOlderDaemon(t *testing.T) {
	for name, test := range map[string]struct {
		phase string
		args  []string
		ok    bool
	}{
		"new withdrawal":           {phase: "ready", args: []string{"--to", withdrawalTestDestination}},
		"saved quote":              {phase: "quoted", args: []string{"--to", withdrawalTestDestination}},
		"approval":                 {phase: "quoted", args: []string{"--approve", testQuoteID}},
		"status only":              {phase: "ready", args: nil, ok: true},
		"signed wallet withdrawal": {phase: "withdrawal_pending", args: []string{"--resume"}, ok: true},
		"signed operation":         {phase: "op_submitted", args: []string{"--resume"}, ok: true},
	} {
		t.Run(name, func(t *testing.T) {
			posts := 0
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var state map[string]any
				if strings.HasPrefix(test.phase, "op_") {
					state = gaslessTestStatus(test.phase)
				} else {
					state = withdrawalTestStatus(test.phase)
					if test.phase == "withdrawal_pending" {
						state["transaction_hash"] = "0x" + strings.Repeat("c", 64)
					}
				}
				delete(state, "new_withdrawal_fees")
				if r.Method == http.MethodPost {
					posts++
					state["phase"] = "complete"
				}
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer s.Close()
			var out bytes.Buffer
			err := runWithdrawal(context.Background(), withdrawalTestConfig(s), test.args, &out)
			if test.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, errDaemonPredatesPayoutOnly) || posts != 0 || strings.Contains(out.String(), "--fees wallet") {
				t.Fatalf("an older daemon was used: %v posts=%d %s", err, posts, out.String())
			}
			if !strings.Contains(err.Error(), "start zkapi-clientd serve again with this build") {
				t.Fatalf("no restart instruction: %v", err)
			}
		})
	}
}

// The guided withdrawal through an older daemon asks nothing and quotes
// nothing; a signed withdrawal is followed.
func TestGuidedWithdrawalThroughAnOlderDaemon(t *testing.T) {
	f := &withdrawalWizardFixture{status: func(int) (zkapi.AddressWithdrawalStatus, error) {
		s := withdrawalWizardState("ready")
		s.NewWithdrawalFees = ""
		return s, nil
	}}
	u := &fundingWizardUI{answers: []string{withdrawalTestDestination}}
	err := guidedWithdrawal(context.Background(), f, u, func(context.Context) error { return nil })
	if !errors.Is(err, errDaemonPredatesPayoutOnly) || f.quoteCalls != 0 || f.approveCalls != 0 || len(u.answers) != 1 {
		t.Fatalf("an older daemon was used: %v quotes=%d", err, f.quoteCalls)
	}
	signed := &withdrawalWizardFixture{status: func(int) (zkapi.AddressWithdrawalStatus, error) {
		s := withdrawalWizardState("complete")
		s.NewWithdrawalFees = ""
		return s, nil
	}}
	if err := guidedWithdrawal(context.Background(), signed, &fundingWizardUI{}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("a completed withdrawal was not followed: %v", err)
	}
}
