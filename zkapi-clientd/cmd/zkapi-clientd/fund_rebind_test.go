package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestFundRebindFlagsAreExclusiveAndValidated(t *testing.T) {
	c := config.Config{Backend: "zkapi", Listen: "127.0.0.1:1"}
	for _, args := range [][]string{
		{"--rebind", "--resume"},
		{"--rebind", "--amount", "1"},
		{"--rebind", "--usd", "5"},
		{"--rebind", "--approve", testQuoteID},
		{"--note-id", "12"},
		{"--replace-note-id", "12"},
		{"--resume", "--note-id", "12"},
		{"--rebind", "--note-id", ""},
		{"--rebind", "--note-id", "-1"},
		{"--rebind", "--note-id", "+12"},
		{"--rebind", "--note-id", "0x0c"},
		{"--rebind", "--note-id", "4294967296"},
		{"--rebind", "--replace-note-id", "1e3"},
		{"--rebind", "extra"},
	} {
		if err := runFunding(context.Background(), c, args, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("invalid rebind options reached the daemon: %v: %v", args, err)
		}
	}
	for value, want := range map[string]uint64{"0": 0, "12": 12, "4294967295": 4294967295, "0042148": 42148} {
		if got, err := parseNoteID(value); err != nil || got != want {
			t.Fatalf("%s: got %d, %v", value, got, err)
		}
	}
}

func TestFundRebindPostsExplicitNoteIDs(t *testing.T) {
	for _, scenario := range []struct {
		args  []string
		body  map[string]uint64
		phase string
	}{
		{[]string{"--rebind"}, map[string]uint64{}, "active"},
		{[]string{"--rebind", "--note-id", "12"}, map[string]uint64{"note_id": 12}, "active"},
		{[]string{"--rebind", "--note-id", "12", "--replace-note-id", "42148"}, map[string]uint64{"note_id": 12, "replace_note_id": 42148}, "active"},
		{[]string{"--rebind", "--replace-note-id", "42148"}, map[string]uint64{"replace_note_id": 42148}, "verification_conflict"},
	} {
		t.Run(strings.Join(scenario.args, " "), func(t *testing.T) {
			var posts []map[string]uint64
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/admin/funding/address":
					_ = json.NewEncoder(w).Encode(fundingTestStatus("verification_conflict"))
				case r.Method == http.MethodPost && r.URL.Path == "/admin/funding/rebind":
					var body map[string]uint64
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("invalid rebind body")
					}
					posts = append(posts, body)
					state := fundingTestStatus(scenario.phase)
					state["message"] = "Rebind status from the daemon."
					_ = json.NewEncoder(w).Encode(state)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
			}))
			defer s.Close()
			var out bytes.Buffer
			err := runFunding(context.Background(), fundingTestConfig(s), scenario.args, &out)
			if (scenario.phase == "active") != (err == nil) {
				t.Fatalf("rebind result %v for phase %s", err, scenario.phase)
			}
			if len(posts) != 1 || len(posts[0]) != len(scenario.body) {
				t.Fatalf("rebind posted %v, want %v", posts, scenario.body)
			}
			for key, value := range scenario.body {
				if posts[0][key] != value {
					t.Fatalf("rebind posted %v, want %v", posts[0], scenario.body)
				}
			}
			if !strings.Contains(out.String(), scenario.phase+": Rebind status from the daemon.") {
				t.Fatalf("rebind progress was not printed: %s", out.String())
			}
		})
	}
}

func TestGuidedFundingShowsVerifyingStageAndStopsOnConflict(t *testing.T) {
	f := newWizardFixture()
	f.address = func() zkapi.AddressFundingStatus { return wizardState("confirming") }
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		if f.resumeCalls == 1 {
			state := wizardState("confirming")
			state.DepositStage = "verifying"
			return state, nil
		}
		return wizardState("verification_conflict"), nil
	}
	f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{} }
	ui := &fundingWizardUI{}
	err := guidedFunding(context.Background(), f, "", ui, immediateWizardPoll)
	if err == nil || !strings.Contains(err.Error(), "deposit needs attention") || !strings.Contains(err.Error(), "config --menu, then choose repair") {
		t.Fatalf("verification conflict did not stop guided funding with repair guidance: %v", err)
	}
	if !strings.Contains(ui.String(), "waiting for the zkAPI indexer to confirm it before activation") {
		t.Fatalf("verifying stage was not shown: %s", ui.String())
	}
	if f.resumeCalls != 2 || f.approveCalls != 0 || f.quoteCalls != 0 {
		t.Fatal("guided funding retried, requoted, or approved during verification")
	}
}

func TestGuidedFundingReverifiesSavedConflict(t *testing.T) {
	for _, resolved := range []bool{true, false} {
		f := newWizardFixture()
		f.address = func() zkapi.AddressFundingStatus { return wizardState("verification_conflict") }
		f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
			if resolved {
				return wizardState("active"), nil
			}
			return wizardState("verification_conflict"), nil
		}
		f.ready = func(call int) zkapi.WalletReadiness {
			if resolved && call > 1 {
				return zkapi.WalletReadiness{HasNote: true, Balance: 750001}
			}
			return zkapi.WalletReadiness{}
		}
		ui := &fundingWizardUI{}
		err := guidedFunding(context.Background(), f, "", ui, immediateWizardPoll)
		if resolved && (err != nil || !strings.Contains(ui.String(), "Deposit confirmed")) {
			t.Fatalf("a re-verified deposit did not activate: %v %s", err, ui.String())
		}
		if !resolved && (err == nil || !strings.Contains(err.Error(), "config --menu, then choose repair")) {
			t.Fatalf("a persisting conflict did not point to repair: %v", err)
		}
		if f.resumeCalls != 1 || f.quoteCalls != 0 || f.approveCalls != 0 {
			t.Fatal("a saved conflict was not re-verified exactly once without a new deposit")
		}
	}
}

// When a retry's quote or approval finds an earlier deposit of the note in
// the zkAPI indexer's tree, nothing is signed and setup points to repair.
func TestGuidedDepositPointsToRepairWhenEarlierDepositLanded(t *testing.T) {
	for _, step := range []string{"quote", "approval"} {
		t.Run(step, func(t *testing.T) {
			f := newWizardFixture()
			conflict := false
			f.address = func() zkapi.AddressFundingStatus {
				state := wizardState("waiting_funds")
				if conflict {
					state.Phase = "verification_conflict"
				}
				state.TransactionHash = ""
				return state
			}
			f.quote = func(call int, _, _ uint64) (zkapi.AddressPaymentQuote, error) {
				if step == "quote" && call == 2 {
					conflict = true
					return zkapi.AddressPaymentQuote{}, errors.New("the zkAPI indexer records this private note's deposit at note 12")
				}
				q := wizardQuote()
				q.ID = fmt.Sprintf("%064x", call)
				return q, nil
			}
			f.approve = func(string) (zkapi.AddressFundingStatus, error) {
				conflict = true
				return f.address(), nil
			}
			f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{} }
			err := guidedFunding(context.Background(), f, "", &fundingWizardUI{confirmations: []bool{true}}, immediateWizardPoll)
			if err == nil || !strings.Contains(err.Error(), "config --menu, then choose repair") {
				t.Fatalf("setup did not point to repair: %v", err)
			}
			if f.resumeCalls != 0 || f.approveCalls != map[string]int{"quote": 0, "approval": 1}[step] {
				t.Fatalf("unexpected flow after the conflict: resumes %d, approvals %d", f.resumeCalls, f.approveCalls)
			}
		})
	}
}

// A conflict about an earlier, retired deposit has no saved transaction. When
// the re-check clears it, setup says so instead of resuming a deposit that
// does not exist, and neither quotes nor approves in that run.
func TestGuidedFundingReportsClearedConflictWithoutSavedDeposit(t *testing.T) {
	f := newWizardFixture()
	f.address = func() zkapi.AddressFundingStatus {
		state := wizardState("verification_conflict")
		state.TransactionHash = ""
		return state
	}
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		state := wizardState("waiting_funds")
		state.TransactionHash = ""
		return state, nil
	}
	f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{} }
	err := guidedFunding(context.Background(), f, "", &fundingWizardUI{}, immediateWizardPoll)
	if err == nil || !strings.Contains(err.Error(), "no longer shows the earlier deposit") || strings.Contains(err.Error(), "preserve recovery files") {
		t.Fatalf("a cleared conflict was not reported plainly: %v", err)
	}
	if f.resumeCalls != 1 || f.quoteCalls != 0 || f.approveCalls != 0 {
		t.Fatal("a cleared conflict quoted, approved, or resumed again")
	}
}

func TestGuidedRepairPostsPromptedNoteIDsAfterConsent(t *testing.T) {
	for _, scenario := range []struct {
		answers []string
		consent bool
		body    map[string]uint64
		phase   string
	}{
		{[]string{"", ""}, true, map[string]uint64{}, "active"},
		{[]string{"12", "42148"}, true, map[string]uint64{"note_id": 12, "replace_note_id": 42148}, "active"},
		{[]string{"12", ""}, true, map[string]uint64{"note_id": 12}, "verification_conflict"},
		{[]string{"12", ""}, false, nil, ""},
		{[]string{"0x0c", ""}, true, nil, ""},
	} {
		var posts []map[string]uint64
		s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/admin/funding/rebind" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				return
			}
			var body map[string]uint64
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid rebind body")
			}
			posts = append(posts, body)
			state := fundingTestStatus(scenario.phase)
			state["message"] = "Rebind status from the daemon."
			_ = json.NewEncoder(w).Encode(state)
		}))
		ui := &fundingWizardUI{answers: scenario.answers, confirmations: []bool{scenario.consent}}
		err := runGuidedRepair(context.Background(), fundingTestConfig(s), ui)
		s.Close()
		if scenario.body == nil {
			if err == nil || len(posts) != 0 {
				t.Fatalf("%v: invalid input or refused consent reached the daemon: %v %v", scenario.answers, err, posts)
			}
			continue
		}
		if (scenario.phase == "active") != (err == nil) {
			t.Fatalf("%v: repair result %v for phase %s", scenario.answers, err, scenario.phase)
		}
		if len(posts) != 1 || len(posts[0]) != len(scenario.body) {
			t.Fatalf("%v: repair posted %v, want %v", scenario.answers, posts, scenario.body)
		}
		for key, value := range scenario.body {
			if posts[0][key] != value {
				t.Fatalf("%v: repair posted %v, want %v", scenario.answers, posts[0], scenario.body)
			}
		}
	}
}
