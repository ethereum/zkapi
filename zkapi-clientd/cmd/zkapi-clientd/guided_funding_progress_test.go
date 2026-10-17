package main

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// Capture the live display separately from the permanent transcript so the
// polling tests exercise the interactive contract, as well as the plain fallback.
type recordingSetupDisplay struct {
	fundingWizardUI
	progress         []string
	payments         []string
	active           string
	promptDuringWait bool
}

func (u *recordingSetupDisplay) Progress(message string) {
	u.progress = append(u.progress, message)
	u.active = message
}

func (u *recordingSetupDisplay) Payment(payment string) {
	u.payments = append(u.payments, payment)
}

func (u *recordingSetupDisplay) ClearProgress() { u.active = "" }

func (u *recordingSetupDisplay) Printf(format string, args ...any) {
	u.ClearProgress()
	u.fundingWizardUI.Printf(format, args...)
}

func (u *recordingSetupDisplay) Continue(ctx context.Context, question string) (bool, error) {
	u.promptDuringWait = u.promptDuringWait || u.active != ""
	return u.fundingWizardUI.Continue(ctx, question)
}

func TestGuidedDepositRefreshesPaymentInPlaceAndClearsCancelledWait(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardQuote()
	initial.BalanceWei = "0"
	initial.ShortfallWei = initial.RequiredTotalWei
	initial.RecommendedTopUpWei = initial.RecommendedTotalWei
	f.quote = func(call int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		q := initial
		// Network fees change while the receiving account remains unfunded.
		increase := big.NewInt(int64(call * 1000))
		if call == 2 {
			increase.SetInt64(20_000_000_000_000)
		}
		for _, field := range []*string{&q.RequiredFeeWei, &q.RequiredTotalWei, &q.ShortfallWei, &q.FeeReserveWei, &q.RecommendedTotalWei, &q.RecommendedTopUpWei} {
			value, _ := new(big.Int).SetString(*field, 10)
			*field = value.Add(value, increase).String()
		}
		return q, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := 0
	err := waitAndDeposit(ctx, f, initial, u, func(ctx context.Context) error {
		waits++
		if u.active != "" || !strings.Contains(u.payments[len(u.payments)-1], "Send at least:") {
			t.Fatal("polling must show the payment card without redundant status")
		}
		if waits == 1 && len(u.payments) != 1 {
			t.Fatal("unchanged rounded amount refreshed payment")
		}
		if waits == 2 {
			cancel()
		}
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || u.active != "" || f.approveCalls != 0 || u.continues != 0 {
		t.Fatalf("cancelled funding wait did not stop cleanly: %v, %+v", err, u)
	}
	if len(u.payments) != 2 || strings.Contains(u.String(), "Scan with") || strings.Contains(u.String(), "Payment information updated") || strings.Contains(u.String(), "Waiting for ETH:") {
		t.Fatal("polling appended payment cards or status to the permanent transcript")
	}
	if !strings.Contains(u.payments[1], "Payment information updated") || !strings.Contains(u.payments[1], "Send at least: 0.00078 ETH") || !strings.Contains(u.payments[1], "Payment URI:") {
		t.Fatal("refreshed payment lost its usable transfer instructions")
	}
}

func TestGuidedDepositRestoresFundingStatusAfterQuoteRetry(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardQuote()
	initial.BalanceWei = "0"
	initial.ShortfallWei = initial.RequiredTotalWei
	initial.RecommendedTopUpWei = initial.RecommendedTotalWei
	f.quote = func(call int, _, _ uint64) (zkapi.AddressPaymentQuote, error) {
		if call == 1 {
			return zkapi.AddressPaymentQuote{}, errors.New("temporary quote failure")
		}
		return initial, nil
	}
	f.address = func() zkapi.AddressFundingStatus {
		state := wizardState("waiting_funds")
		state.TransactionHash = ""
		return state
	}
	waits := 0
	err := waitAndDeposit(context.Background(), f, initial, u, func(context.Context) error {
		waits++
		if waits == 2 {
			if u.active != "" {
				t.Fatal("the recovered quote left a stale retry message visible")
			}
			return context.Canceled
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || u.active != "" || f.approveCalls != 0 {
		t.Fatal("quote retry changed cancellation or spending behavior")
	}
}

func TestGuidedDepositRestoresStageAfterInterruptedRecovery(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardState("confirming")
	initial.DepositStage = "activating"
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		if f.resumeCalls == 1 {
			return zkapi.AddressFundingStatus{}, errors.New("temporary response failure")
		}
		return wizardState("active"), nil
	}
	f.address = func() zkapi.AddressFundingStatus { return initial }
	if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	updates := strings.Join(u.progress, "\n")
	if strings.Count(updates, "Deposit confirmed; saving") != 2 || !strings.Contains(updates, "Could not confirm") || u.active != "" {
		t.Fatalf("stage did not recover after the interruption: %s", updates)
	}
	if strings.Contains(u.String(), "waiting") || !strings.Contains(u.String(), "Private inference balance activated") || f.approveCalls != 0 {
		t.Fatal("transient stages entered history or recovery authorized a transaction")
	}
}

func TestGuidedFundingClearsProgressBeforeDepositConsent(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{fundingWizardUI: fundingWizardUI{confirmations: []bool{false}}}
	err := guidedFunding(context.Background(), f, "20", u, immediateWizardPoll)
	if err == nil || !strings.Contains(err.Error(), "declined") || u.promptDuringWait || u.active != "" || f.approveCalls != 0 {
		t.Fatalf("progress interfered with explicit consent: %v, %+v", err, u)
	}
}

func TestGuidedDepositRestoresWaitAfterFundingFallsBelowApprovedAmount(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{fundingWizardUI: fundingWizardUI{confirmations: []bool{true}}}
	initial := wizardQuote()
	f.quote = func(call int, _, _ uint64) (zkapi.AddressPaymentQuote, error) {
		quote := initial
		if call > 1 {
			quote.BalanceWei = "0"
			quote.ShortfallWei = quote.RequiredTotalWei
			quote.RecommendedTopUpWei = quote.RecommendedTotalWei
		}
		return quote, nil
	}
	err := waitAndDeposit(context.Background(), f, initial, u, func(context.Context) error {
		if u.active != "" || !strings.Contains(u.payments[len(u.payments)-1], "Send at least:") {
			t.Fatal("balance loss must retain payment instructions without redundant status")
		}
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) || u.active != "" || f.approveCalls != 0 || u.continues != 1 {
		t.Fatal("balance loss did not revoke the previous deposit consent")
	}
}

func TestGuidedDepositConfirmsSuccessfulMiningWithoutFinalityWait(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{}
	initial := wizardState("deposit_pending")
	initial.DepositStage = "pending"
	stages := []struct{ phase, stage string }{
		{"deposit_pending", "fee_wait"},
		{"deposit_pending", "pending"},
		{"confirming", "activating"},
		{"active", "active"},
	}
	f.resume = func(amount uint64) (zkapi.AddressFundingStatus, error) {
		if amount != initial.Amount || f.resumeCalls > len(stages) {
			t.Fatal("recovery changed the deposit or did not finish")
		}
		next := stages[f.resumeCalls-1]
		state := wizardState(next.phase)
		state.DepositStage = next.stage
		state.Message = "untrusted remote details must stay hidden"
		return state, nil
	}
	if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	output := u.String()
	previous := -1
	for _, want := range []string{"waiting to be mined", "signed fee cap", "Deposit confirmed; saving", "Deposit confirmed. Private inference balance activated"} {
		index := strings.Index(output, want)
		if index <= previous {
			t.Fatalf("missing or out-of-order progress %q: %s", want, output)
		}
		previous = index
	}
	if strings.Count(output, "Deposit confirmed; saving") != 1 || strings.Contains(output, "untrusted remote") || strings.Contains(output, "finalit") || strings.Contains(output, "finalized") || strings.Contains(output, "15 minutes") {
		t.Fatal("successful deposit repeated progress, leaked remote data, or claimed a finality wait")
	}
	if f.approveCalls != 0 || f.resumeCalls != len(stages) {
		t.Fatal("progress changed the recovery authorization")
	}
}

func TestGuidedDepositStatusFailureDoesNotInventLostInclusion(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{}
	initial := wizardState("deposit_pending")
	initial.DepositStage = "finalizing"
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		if f.resumeCalls == 1 {
			return zkapi.AddressFundingStatus{}, errors.New("receipt RPC unavailable")
		}
		return wizardState("active"), nil
	}
	f.address = func() zkapi.AddressFundingStatus {
		// Durable transaction identity is known, but a failed RPC cannot tell
		// us whether the prior inclusion has changed.
		return wizardState("deposit_pending")
	}
	if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	output := u.String()
	if !strings.Contains(output, "Deposit mined;") || !strings.Contains(output, "Waiting for deposit confirmation;") || strings.Contains(output, "waiting to be mined") || strings.Contains(output, "fees exceed") {
		t.Fatalf("uncertain status misrepresented mining or fees: %s", output)
	}
	if f.resumeCalls != 2 || f.approveCalls != 0 {
		t.Fatal("uncertain progress changed recovery authorization")
	}
}

func TestGuidedDepositFailedReceiptWaitsForFinalityWithoutRetry(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardState("deposit_pending")
	initial.DepositStage = "failed_finalizing"
	waits := 0
	f.resume = func(amount uint64) (zkapi.AddressFundingStatus, error) {
		if amount != initial.Amount {
			t.Fatal("failed receipt changed the saved deposit")
		}
		if f.resumeCalls == 1 {
			return initial, nil
		}
		return wizardState("reverted"), nil
	}
	err := finishGuidedDeposit(context.Background(), f, initial, u, func(context.Context) error {
		waits++
		if !strings.Contains(u.active, "receipt reports failure") || !strings.Contains(u.active, "Ethereum finality before an explicit retry") {
			t.Fatal("failed receipt wait lost its live recovery status")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "reverted transaction is never retried automatically") || f.resumeCalls != 2 || f.approveCalls != 0 || waits != 2 {
		t.Fatalf("failed receipt was not stopped after finality: %v", err)
	}
	if len(u.progress) != 1 || u.active != "" || strings.Contains(u.String(), "activated") || strings.Contains(u.String(), "confirmed") {
		t.Fatal("failed receipt repeated transient output or claimed success")
	}
}

func TestGuidedDepositLegacyFinalityStageRemainsNeutral(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardState("deposit_pending")
	initial.DepositStage = "finalizing"
	err := finishGuidedDeposit(context.Background(), f, initial, u, func(context.Context) error { return context.Canceled })
	output := strings.Join(u.progress, "\n")
	if !errors.Is(err, context.Canceled) || !strings.Contains(output, "Deposit mined; waiting for Ethereum finality.") || strings.Contains(output, "failure") || strings.Contains(output, "failed") || f.resumeCalls+f.approveCalls != 0 || u.active != "" {
		t.Fatalf("older daemon finality stage was misclassified: %v; %s", err, output)
	}
}

// Review finding (clientd-flows 0, follow-up): a guided deposit the zkAPI
// indexer keeps waiting (it is down or withholds the note) does not sit at
// the verifying stage alone. Once that stage persists, a fixed label says
// that the owner's exit RPC can confirm the note and keep it escapable, and
// how to set one; the stage is shown again below it. Ordinary indexer lag
// shows no such guidance, and the daemon's text never enters the output.
func TestGuidedDepositExplainsTheExitRPCWhileTheIndexerKeepsItWaiting(t *testing.T) {
	const verifyingLabel = "Deposit mined; waiting for the zkAPI indexer to record it before saving the private note."
	if !strings.Contains(guidedIndexerWaitGuidance, "escape") || !strings.Contains(guidedIndexerWaitGuidance, "zkapi-clientd config --exit-rpc-url URL") {
		t.Fatal("the guidance does not name the escape or how to set an exit RPC")
	}
	for _, polls := range []int{guidedIndexerWaitPolls - 1, guidedIndexerWaitPolls + 3} {
		f := newWizardFixture()
		u := &recordingSetupDisplay{}
		initial := wizardState("confirming")
		initial.DepositStage = "activating"
		f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
			if f.resumeCalls > polls {
				return wizardState("active"), nil
			}
			state := wizardState("confirming")
			state.DepositStage = "verifying"
			state.Message = "untrusted remote details must stay hidden"
			return state, nil
		}
		if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
			t.Fatal(err)
		}
		output := u.String()
		want, stages := 0, 1
		if polls >= guidedIndexerWaitPolls {
			want, stages = 1, 2
		}
		if strings.Count(output, guidedIndexerWaitGuidance) != want {
			t.Fatalf("after %d checks waiting for the indexer the exit RPC guidance was shown %d times: %s", polls, strings.Count(output, guidedIndexerWaitGuidance), output)
		}
		if count := strings.Count(strings.Join(u.progress, "\n"), verifyingLabel); count != stages {
			t.Fatalf("the verifying stage was shown %d times, want %d: %v", count, stages, u.progress)
		}
		if strings.Contains(output, "untrusted remote") || strings.Contains(strings.Join(u.progress, "\n"), "untrusted remote") || f.approveCalls != 0 || f.resumeCalls != polls+1 {
			t.Fatal("the guidance leaked daemon text or changed the recovery")
		}
	}
}

// Review finding (clientd-fixes 0, follow-up): while the owner's exit RPC
// cannot check a deposit the indexer has not confirmed, the guided session
// shows a fixed label naming the remedy instead of the verifying stage, and
// never the guidance that the exit RPC will confirm the note; both return
// once the exit RPC works. The daemon's text never enters the output.
func TestGuidedDepositNamesAnExitRPCThatCannotCheckIt(t *testing.T) {
	const verifyingLabel = "Deposit mined; waiting for the zkAPI indexer to record it before saving the private note."
	// Past the indexer wait the guidance follows the label once the exit RPC
	// works; before it, only the verifying stage does.
	for _, polls := range []struct{ unusable, usable, guidance int }{{guidedIndexerWaitPolls + 2, 1, 1}, {2, 2, 0}} {
		f := newWizardFixture()
		// The plain transcript keeps labels and guidance in the order shown.
		u := &fundingWizardUI{}
		initial := wizardState("confirming")
		initial.DepositStage = "activating"
		f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
			if f.resumeCalls > polls.unusable+polls.usable {
				return wizardState("active"), nil
			}
			state := wizardState("confirming")
			state.DepositStage = "verifying"
			state.ExitRPCUnusable = f.resumeCalls <= polls.unusable
			state.Message = "untrusted remote details must stay hidden"
			return state, nil
		}
		if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
			t.Fatal(err)
		}
		output := u.String()
		label, verifying := strings.Index(output, guidedDepositExitRPCUnusableLabel), strings.Index(output, verifyingLabel)
		if strings.Count(output, guidedDepositExitRPCUnusableLabel) != 1 || strings.Count(output, verifyingLabel) != 1 || label < 0 || label > verifying {
			t.Fatalf("after %d checks the unusable exit RPC was not shown while it lasted, then the verifying stage: %s", polls.unusable, output)
		}
		if guidance := strings.Index(output, guidedIndexerWaitGuidance); strings.Count(output, guidedIndexerWaitGuidance) != polls.guidance || (guidance >= 0 && (guidance < label || guidance > verifying)) {
			t.Fatalf("after %d checks the exit RPC guidance was shown while the exit RPC could not check the deposit: %s", polls.unusable, output)
		}
		if !strings.Contains(guidedDepositExitRPCUnusableLabel, "config --exit-rpc-url URL") || strings.Contains(output, "untrusted remote") || f.approveCalls != 0 || f.resumeCalls != polls.unusable+polls.usable+1 {
			t.Fatal("the label does not name the remedy, leaked daemon text, or changed the recovery")
		}
	}
}

// Review finding (clientd-fixes5, low): a verification conflict the owner's
// exit RPC could not check at all (ExitRPCUnusable) stops the guided session
// with a fixed error naming the --exit-rpc-url remedy, not repair, which
// would need that RPC too: when it is reached while following a deposit and
// when a saved conflict is re-verified. The daemon's text never enters it.
func TestGuidedDepositConflictNamesAnExitRPCThatCannotCheckIt(t *testing.T) {
	conflict := func(unusable bool) zkapi.AddressFundingStatus {
		state := wizardState("verification_conflict")
		state.ExitRPCUnusable, state.Message = unusable, "untrusted remote details must stay hidden"
		return state
	}
	for _, unusable := range []bool{true, false} {
		want := map[bool]error{true: errGuidedDepositConflictExitRPCUnusable, false: errGuidedDepositConflict}[unusable]
		f := newWizardFixture()
		f.resume = func(uint64) (zkapi.AddressFundingStatus, error) { return conflict(unusable), nil }
		initial := wizardState("confirming")
		initial.DepositStage = "activating"
		if err := finishGuidedDeposit(context.Background(), f, initial, &fundingWizardUI{}, immediateWizardPoll); !errors.Is(err, want) {
			t.Fatalf("following a deposit, unusable %v: %v", unusable, err)
		}
		f = newWizardFixture()
		f.address = func() zkapi.AddressFundingStatus { return wizardState("verification_conflict") }
		f.resume = func(uint64) (zkapi.AddressFundingStatus, error) { return conflict(unusable), nil }
		f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{} }
		if err := guidedFunding(context.Background(), f, "", &fundingWizardUI{}, immediateWizardPoll); !errors.Is(err, want) {
			t.Fatalf("re-verifying a saved conflict, unusable %v: %v", unusable, err)
		}
	}
	if text := errGuidedDepositConflictExitRPCUnusable.Error(); !strings.Contains(text, "config --exit-rpc-url URL") || strings.Contains(text, "repair") {
		t.Fatalf("the error does not name the exit RPC remedy alone: %s", text)
	}
}

// A deposit is saved once the vault and the indexer record it; the
// operator's batch activates it later. Guided setup then says requests wait
// for that activation and withdrawals do not, never that it is activated.
func TestGuidedDepositReportsARecordedNoteAwaitingActivation(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardState("confirming")
	initial.DepositStage = "activating"
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		state := wizardState("active")
		state.DepositStage = "awaiting_activation"
		activated := false
		state.Activated = &activated
		return state, nil
	}
	if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if output := u.String(); strings.Contains(output, "activated.") || !strings.Contains(output, "Deposit confirmed. The private note is recorded") || !strings.Contains(output, "Withdrawals are available now") {
		t.Fatalf("a recorded note was not reported as awaiting activation: %s", output)
	}
}

// A saved note whose activation the companion has not read yet (its status
// omits activated) is reported as saved, never as activated.
func TestGuidedDepositNeverClaimsAnUnreadActivation(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardState("confirming")
	initial.DepositStage = "activating"
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		state := wizardState("active")
		state.Activated = nil
		return state, nil
	}
	if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if output := u.String(); strings.Contains(output, "activated.") || !strings.Contains(output, "Deposit confirmed. The private note is saved") || !strings.Contains(output, "withdrawals are available now") {
		t.Fatalf("an unread activation was reported as activated: %s", output)
	}
}

func TestGuidedDepositObservedSuccessMovesDirectlyToActivation(t *testing.T) {
	f := newWizardFixture()
	u := &recordingSetupDisplay{}
	initial := wizardState("deposit_pending")
	initial.DepositStage = "activating"
	if err := finishGuidedDeposit(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if len(u.progress) != 1 || u.progress[0] != "Deposit confirmed; saving your private note." || u.active != "" || !strings.Contains(u.String(), "Deposit confirmed. Private inference balance activated.") || f.approveCalls != 0 || f.resumeCalls != 1 {
		t.Fatal("observed success retained a finality wait or changed transaction recovery")
	}
}
