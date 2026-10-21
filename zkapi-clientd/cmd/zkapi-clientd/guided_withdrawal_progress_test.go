package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestGuidedWithdrawalRefreshesFeePaymentInPlace(t *testing.T) {
	f := &withdrawalWizardFixture{}
	u := &recordingSetupDisplay{fundingWizardUI: fundingWizardUI{answers: []string{withdrawalTestDestination}}}
	f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
		quote := withdrawalWizardQuote()
		switch call {
		case 1:
			withdrawalQuoteFunds(&quote, 0, 25000, 30000)
		case 2:
			withdrawalQuoteFunds(&quote, 0, 29000, 34000)
		default:
			withdrawalQuoteFunds(&quote, 0, 31000, 36000)
		}
		return quote, nil
	}
	waits := 0
	err := guidedWithdrawal(context.Background(), f, u, func(context.Context) error {
		waits++
		if u.active != "" || !strings.Contains(u.payments[len(u.payments)-1], "Send at least:") {
			t.Fatal("fee wait must show payment instructions without redundant status")
		}
		if waits == 3 {
			return context.Canceled
		}
		return nil
	}, "")
	if !errors.Is(err, context.Canceled) || u.active != "" || f.approveCalls != 0 || u.continues != 0 {
		t.Fatal("cancelling the fee wait did not stop cleanly")
	}
	if len(u.payments) != 2 || strings.Contains(u.String(), "Scan with") || strings.Contains(u.String(), "Waiting for ETH:") {
		t.Fatal("fee polling appended cards or live status to the permanent transcript")
	}
}

func TestGuidedWithdrawalRestoresStageAfterInterruptedRecovery(t *testing.T) {
	f := &withdrawalWizardFixture{}
	u := &recordingSetupDisplay{}
	initial := withdrawalWizardState("withdrawal_pending")
	f.resume = func(call int, _ string, _ uint64) (zkapi.AddressWithdrawalStatus, error) {
		if call == 1 {
			return zkapi.AddressWithdrawalStatus{}, errors.New("temporary response failure")
		}
		return withdrawalWizardState("complete"), nil
	}
	f.status = func(call int) (zkapi.AddressWithdrawalStatus, error) {
		if call == 1 {
			return zkapi.AddressWithdrawalStatus{}, errors.New("temporarily unavailable")
		}
		return initial, nil
	}
	if err := finishGuidedWithdrawal(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	updates := strings.Join(u.progress, "\n")
	if strings.Count(updates, "waiting for Ethereum finality") != 2 || !strings.Contains(updates, "temporarily unavailable") || u.active != "" {
		t.Fatalf("withdrawal stage did not recover after the interruption: %s", updates)
	}
	if strings.Contains(u.String(), "waiting") || !strings.Contains(u.String(), "Withdrawal complete:") || f.approveCalls != 0 {
		t.Fatal("transient stages entered history or recovery authorized a transaction")
	}
}

func TestGuidedWithdrawalClearsProgressBeforeConsent(t *testing.T) {
	f := &withdrawalWizardFixture{}
	u := &recordingSetupDisplay{fundingWizardUI: fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{false}}}
	err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll, "")
	if err == nil || !strings.Contains(err.Error(), "declined") || u.promptDuringWait || u.active != "" || f.approveCalls != 0 {
		t.Fatalf("progress interfered with explicit consent: %v, %+v", err, u)
	}
}

// A withdrawal completed by an escape whose payout the vault credited never
// reads as sent: the guided withdrawal and the withdraw command show the
// credited state with the claim call instead.
func TestCreditedEscapePayoutIsNeverReportedAsSent(t *testing.T) {
	credited := withdrawalWizardState("complete")
	credited.PayoutCredited = true
	credited.VaultAddress = "0x00000000000000000000000000000000000000aa"
	credited.ClaimCalldata = "0x88c10aee" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(credited.Destination, "0x"))
	credited.Message = "the vault holds the balance; call claimEscapePayout(" + credited.Destination + ") (selector 0x88c10aee)"
	f := &withdrawalWizardFixture{}
	u := &recordingSetupDisplay{}
	if err := finishGuidedWithdrawal(context.Background(), f, credited, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.String(), "Withdrawal complete") || strings.Contains(u.String(), "sent to") || !strings.Contains(u.String(), "was not delivered") || !strings.Contains(u.String(), "claimEscapePayout("+credited.Destination+")") {
		t.Fatalf("a credited payout was reported as sent: %s", u.String())
	}
	var out strings.Builder
	printWithdrawalProgress(&out, credited, "ETH")
	if !strings.Contains(out.String(), "payout credited, not delivered: ") || strings.Contains(out.String(), "complete:") {
		t.Fatalf("withdraw printed a credited payout as complete: %s", out.String())
	}
}

// Earlier escapes' credited payouts, whose withdrawal records a later deposit
// replaced, stay in view: the withdraw and fund commands and the guided
// withdrawal print each with its claim call.
func TestEarlierCreditedEscapePayoutsArePrinted(t *testing.T) {
	credit := zkapi.EscapePayoutCredit{Destination: "0xdest", Message: "An earlier escape (note 9) closed its note; call claimEscapePayout(0xdest) on the vault"}
	want := "Unclaimed escape payout: " + credit.Message
	withdrawal := withdrawalWizardState("no_note")
	withdrawal.EscapePayoutCredits = []zkapi.EscapePayoutCredit{credit}
	var out strings.Builder
	printWithdrawalProgress(&out, withdrawal, "ETH")
	if !strings.Contains(out.String(), want) {
		t.Fatalf("withdraw omitted the credit: %s", out.String())
	}
	out.Reset()
	printFundingProgress(&out, zkapi.AddressFundingStatus{Phase: "active", EscapePayoutCredits: withdrawal.EscapePayoutCredits})
	if !strings.Contains(out.String(), want) {
		t.Fatalf("fund omitted the credit: %s", out.String())
	}
	f := &withdrawalWizardFixture{}
	f.status = func(int) (zkapi.AddressWithdrawalStatus, error) { return withdrawal, nil }
	u := &fundingWizardUI{}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u.String(), want) {
		t.Fatalf("the guided withdrawal omitted the credit: %s", u.String())
	}
}
