package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// The guided withdrawal on a deployment that sponsors withdrawals: the fee is
// paid from the payout, the only option; one Enter approves the displayed
// terms; the daemon handles fee changes within the authorized maximum.

func payoutWizardState(phase string) zkapi.AddressWithdrawalStatus {
	s := withdrawalWizardState(phase)
	s.NewWithdrawalFees, s.TransactionHash = "payout", ""
	if phase != "ready" && phase != "no_note" {
		s.FeePayer, s.TransitAccount = "payout", gaslessTestTransit
	}
	switch phase {
	case "op_built", "op_submitted":
		s.UserOpHash = gaslessTestOpHash
	case "complete":
		s.UserOpHash, s.TransactionHash, s.ReceivedWei, s.ChargedWei = gaslessTestOpHash, "0x"+strings.Repeat("b", 64), "96671000000000", "3300000000000"
	}
	return s
}

// authorizedWizardState is a payout withdrawal approved within its maximum
// fee in phase (quoted after a restart before signing, or a refusal the
// daemon retries within the authorization).
func authorizedWizardState(phase string) zkapi.AddressWithdrawalStatus {
	s := payoutWizardState(phase)
	s.AuthorizedMaxFeeWei, s.AuthorizedMinNetPayoutWei, s.EstimatedFeeWei = "4000000000000", "95971000000000", "2000000000000"
	if phase == "gasless_refused" {
		s.GaslessRetryable, s.GaslessRefusal = true, "bundler_unavailable: the bundler did not answer; use --fees wallet or another --bundler-url"
	}
	return s
}

func payoutWizardQuote(call int) zkapi.AddressPaymentQuote {
	q := authorizedPayoutTestQuote()
	q.ID = fmt.Sprintf("%064x", call)
	return q
}

func payoutWizardFixture() *withdrawalWizardFixture {
	f := &withdrawalWizardFixture{availability: &zkapi.GaslessAvailability{Required: true, Available: true, BundlerURL: "https://bundler.example/rpc"}}
	f.status = func(int) (zkapi.AddressWithdrawalStatus, error) { return payoutWizardState("ready"), nil }
	f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
		return payoutWizardQuote(call), nil
	}
	f.approve = func(string) (zkapi.AddressWithdrawalStatus, error) { return payoutWizardState("op_submitted"), nil }
	f.resume = func(int, string, uint64) (zkapi.AddressWithdrawalStatus, error) {
		return payoutWizardState("complete"), nil
	}
	return f
}

func quoteChanged() error {
	return &managementError{message: "zkAPI withdrawal quote changed; review a fresh quote", code: zkapi.CodeQuoteChanged, scope: "withdrawal"}
}

func assertNoWalletFallback(t *testing.T, output string, err error) {
	t.Helper()
	text := output
	if err != nil {
		text += err.Error()
	}
	for _, forbidden := range []string{"--fees wallet", "Scan with an Ethereum wallet", "Payment URI", "Fees funded", "Add ETH for network fees", "wallet's public ETH", "wallet-paid"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("the payout withdrawal offered or showed %q: %s", forbidden, text)
		}
	}
}

// No fee question: the payout pays the fee. The terms (an estimate that may
// change, the maximum, the floor, the approval's scope) are shown once, one
// Enter approves the displayed quote ID, and fee drift up and down while
// the operation is followed (including a refusal retried within the
// authorization) never asks again.
func TestGuidedPayoutWithdrawalApprovesOnceAcrossFeeDrift(t *testing.T) {
	f := payoutWizardFixture()
	var approved []string
	f.approve = func(id string) (zkapi.AddressWithdrawalStatus, error) {
		approved = append(approved, id)
		s := authorizedWizardState("quoted")
		s.Phase, s.UserOpHash = "op_submitted", gaslessTestOpHash
		return s, nil
	}
	f.resume = func(call int, destination string, note uint64) (zkapi.AddressWithdrawalStatus, error) {
		if destination != withdrawalTestDestination || note != 58 {
			t.Fatalf("resume changed the withdrawal: %s %d", destination, note)
		}
		s := authorizedWizardState("quoted")
		s.Phase, s.UserOpHash = "op_submitted", gaslessTestOpHash
		switch call {
		case 1:
			s.EstimatedFeeWei = "3500000000000" // The fee rises within the bound.
		case 2:
			s = authorizedWizardState("gasless_refused")
		case 3:
			s.EstimatedFeeWei = "1000000000000" // And falls.
		default:
			s = payoutWizardState("complete")
		}
		return s, nil
	}
	u := &recordingSetupDisplay{fundingWizardUI: fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true}}}
	err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll)
	if err != nil {
		t.Fatal(err)
	}
	if u.asks != 1 || u.confirms != 0 || u.continues != 1 || f.availabilityCalls != 1 || f.quoteCalls != 1 || f.approveCalls != 1 || f.resumeCalls != 4 {
		t.Fatalf("calls: ui=%+v service=%+v", u.fundingWizardUI, f)
	}
	if len(approved) != 1 || approved[0] != payoutWizardQuote(1).ID || !f.options[0].payout || f.options[0].allowExpensiveGas {
		t.Fatalf("approved %v with options %+v", approved, f.options)
	}
	if len(u.questions) != 1 || !strings.Contains(u.questions[0], "Ethereum address") {
		t.Fatalf("asked more than the destination: %v", u.questions)
	}
	output := u.String()
	for _, want := range []string{"no ETH is needed from this wallet", "Transit account: " + gaslessTestTransit, "Estimated network fee: about 0.000002000000000000 ETH (an estimate; the actual fee may change)", "At most 0.000004000000000000 ETH may be taken from the payout", withdrawalTestDestination + " receives at least 0.000095971000000000 ETH", "This one approval covers this destination, note and transit account; fee changes within this maximum are handled without asking again", "Withdrawal complete: 0.000096671000000000 ETH reached " + withdrawalTestDestination + " after a sponsored network fee of 0.000003300000000000 ETH"} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q in %s", want, output)
		}
	}
	if progress := strings.Join(u.progress, "\n"); !strings.Contains(progress, "your authorization still holds") || strings.Contains(progress, "--fees wallet") {
		t.Fatalf("the retried refusal was not shown as waiting: %s", progress)
	}
	assertNoWalletFallback(t, output, nil)
}

// An approval refused because its quote expired or was replaced saved no
// authorization: the withdrawal is quoted again and approved without asking
// while the identity is the same and the bound is no looser (the estimate
// may move up or down); a higher maximum or a lower floor is shown and asked
// once.
func TestGuidedPayoutQuoteChangedRequotesWithinTheApprovedBound(t *testing.T) {
	for name, test := range map[string]struct {
		mutate    func(int, *zkapi.AddressPaymentQuote)
		continues int
	}{
		"within the bound": {mutate: func(call int, q *zkapi.AddressPaymentQuote) {
			switch call {
			case 2:
				q.ExpectedFeeWei = "3500000000000"
			case 3:
				q.ExpectedFeeWei, q.MaxTotalFeeWei, q.MinNetPayoutWei = "1000000000000", "3500000000000", "96471000000000"
			}
		}, continues: 1},
		"a higher maximum": {mutate: func(call int, q *zkapi.AddressPaymentQuote) {
			if call >= 2 {
				q.MaxTotalFeeWei, q.MinNetPayoutWei, q.FeeBumpCapWei = "5000000000000", "94971000000000", "5000000000000"
			}
		}, continues: 2},
		"a lower floor": {mutate: func(call int, q *zkapi.AddressPaymentQuote) {
			if call >= 2 {
				q.OwedWei, q.MinNetPayoutWei = "1000000000000", "94971000000000"
			}
		}, continues: 2},
	} {
		t.Run(name, func(t *testing.T) {
			f := payoutWizardFixture()
			f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
				q := payoutWizardQuote(call)
				test.mutate(call, &q)
				return q, nil
			}
			var approved []string
			f.approve = func(id string) (zkapi.AddressWithdrawalStatus, error) {
				approved = append(approved, id)
				if len(approved) < 3 {
					return zkapi.AddressWithdrawalStatus{}, quoteChanged()
				}
				return payoutWizardState("op_submitted"), nil
			}
			u := &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true, true}}
			if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err != nil {
				t.Fatal(err)
			}
			if u.continues != test.continues || f.quoteCalls != 3 || strings.Join(approved, ",") != strings.Join([]string{payoutWizardQuote(1).ID, payoutWizardQuote(2).ID, payoutWizardQuote(3).ID}, ",") {
				t.Fatalf("continues=%d quotes=%d approved=%v: %s", u.continues, f.quoteCalls, approved, u.String())
			}
			if test.continues == 2 && !strings.Contains(u.String(), "review the new terms") {
				t.Fatalf("the looser terms were not shown: %s", u.String())
			}
			assertNoWalletFallback(t, u.String(), nil)
		})
	}
	// Declining looser terms approves nothing more.
	f := payoutWizardFixture()
	f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
		q := payoutWizardQuote(call)
		if call >= 2 {
			q.MaxTotalFeeWei, q.MinNetPayoutWei = "5000000000000", "94971000000000"
		}
		return q, nil
	}
	f.approve = func(string) (zkapi.AddressWithdrawalStatus, error) {
		return zkapi.AddressWithdrawalStatus{}, quoteChanged()
	}
	u := &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true, false}}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err == nil || f.approveCalls != 1 || f.quoteCalls != 2 {
		t.Fatalf("declined looser terms: %v %+v", err, f)
	}
}

// A new destination, note, transit account or other identity in the
// refreshed quote needs a new approval: the guided withdrawal stops without
// approving it.
func TestGuidedPayoutQuoteIdentityChangeStopsWithoutApproving(t *testing.T) {
	for name, mutate := range map[string]func(*zkapi.AddressPaymentQuote){
		"destination": func(q *zkapi.AddressPaymentQuote) { q.Destination = "0x4444444444444444444444444444444444444444" },
		"note":        func(q *zkapi.AddressPaymentQuote) { q.NoteID++ },
		"transit":     func(q *zkapi.AddressPaymentQuote) { q.TransitAccount = "0x5555555555555555555555555555555555555555" },
		"amount":      func(q *zkapi.AddressPaymentQuote) { q.Amount++ },
		"binding":     func(q *zkapi.AddressPaymentQuote) { q.Binding = strings.Repeat("c", 64) },
		"deployment":  func(q *zkapi.AddressPaymentQuote) { q.DeploymentID += "changed" },
		"contract":    func(q *zkapi.AddressPaymentQuote) { q.Contract = withdrawalTestDestination },
		"wallet fee":  func(q *zkapi.AddressPaymentQuote) { *q = withdrawalWizardQuote() },
	} {
		t.Run(name, func(t *testing.T) {
			f := payoutWizardFixture()
			f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
				q := payoutWizardQuote(call)
				if call == 2 {
					mutate(&q)
				}
				return q, nil
			}
			f.approve = func(string) (zkapi.AddressWithdrawalStatus, error) {
				return zkapi.AddressWithdrawalStatus{}, quoteChanged()
			}
			u := &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true, true}}
			err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll)
			if err == nil || f.approveCalls != 1 || f.quoteCalls != 2 || u.continues != 1 || !strings.Contains(err.Error(), "stopped without approving") {
				t.Fatalf("identity change: %v %+v", err, f)
			}
			assertNoWalletFallback(t, u.String(), err)
		})
	}
}

// When the payout cannot pay the fee (the pre-flight fails, or the quote is
// refused: no bundler, a fee above the paymaster's ceiling, sponsorship
// paused) the guided withdrawal stops with the reason and what to do; there
// is no QR and no wallet-paid option.
func TestGuidedPayoutStopsWhenThePayoutPathIsUnavailable(t *testing.T) {
	f := payoutWizardFixture()
	f.availability = &zkapi.GaslessAvailability{Required: true, Reason: "bundler_unavailable", Message: "the bundler https://bundler.example/rpc did not answer; use --fees wallet or another --bundler-url"}
	u := &fundingWizardUI{}
	err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll)
	if err == nil || !strings.Contains(err.Error(), "did not answer") || !strings.Contains(err.Error(), "config --bundler-url") || !strings.Contains(err.Error(), "Nothing was reserved or signed") || f.quoteCalls != 0 || u.asks != 0 {
		t.Fatalf("pre-flight: %v %+v", err, f)
	}
	assertNoWalletFallback(t, u.String(), err)
	f = payoutWizardFixture()
	f.availability = nil
	f.status = func(int) (zkapi.AddressWithdrawalStatus, error) { return payoutWizardState("ready"), nil }
	if err := guidedWithdrawal(context.Background(), f, &fundingWizardUI{}, immediateWizardPoll); err == nil || f.quoteCalls != 0 {
		t.Fatalf("an unavailable pre-flight did not stop: %v", err)
	}
	for _, code := range []string{"bundler_unavailable", "gas_above_paymaster_ceiling", "sponsorship_paused", "payout_below_gas", "fee_above_cap"} {
		t.Run(code, func(t *testing.T) {
			f := payoutWizardFixture()
			f.quote = func(int, string, uint64, string) (zkapi.AddressPaymentQuote, error) {
				return zkapi.AddressPaymentQuote{}, &managementError{message: code + ": the sponsored path refused; use --fees wallet", code: code}
			}
			u := &fundingWizardUI{answers: []string{withdrawalTestDestination}}
			err := guidedWithdrawal(context.Background(), f, u, func(context.Context) error { return errors.New("waited") })
			if managementErrorCode(err) != code || !strings.Contains(err.Error(), code+": the sponsored path refused") || f.quoteCalls != 1 || f.approveCalls != 0 || u.continues != 0 {
				t.Fatalf("%s: %v %+v", code, err, f)
			}
			if (code == "bundler_unavailable") != strings.Contains(err.Error(), "config --bundler-url") {
				t.Fatalf("%s remedy: %v", code, err)
			}
			assertNoWalletFallback(t, u.String(), err)
		})
	}
}

// A fee above the deployment's uneconomic fraction is explained and asked
// about once; accepted, it is quoted again with the acceptance and its terms
// are approved with one Enter.
func TestGuidedPayoutUneconomicFeeAsksOnce(t *testing.T) {
	uneconomic := &managementError{message: "gasless_uneconomic: the sponsored fee may reach 9 wei, more than 10% of the 50 wei payout; pass --allow-expensive-gas to accept it, or use --fees wallet", code: "gasless_uneconomic"}
	for _, accept := range []bool{true, false} {
		f := payoutWizardFixture()
		f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
			if !f.options[call-1].allowExpensiveGas {
				return zkapi.AddressPaymentQuote{}, uneconomic
			}
			return payoutWizardQuote(call), nil
		}
		u := &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{accept, true}}
		err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll)
		if !strings.Contains(u.String(), "unusually high") || u.confirms != 1 {
			t.Fatalf("%t: not explained or asked once: %s", accept, u.String())
		}
		if !accept {
			if err == nil || f.quoteCalls != 1 || f.approveCalls != 0 {
				t.Fatalf("declined: %v %+v", err, f)
			}
			continue
		}
		if err != nil || f.quoteCalls != 2 || !f.options[1].allowExpensiveGas || u.continues != 1 || f.approveCalls != 1 {
			t.Fatalf("accepted: %v %+v", err, f)
		}
		assertNoWalletFallback(t, u.String(), err)
	}
	// Refused again after the acceptance: it stops instead of asking again.
	f := payoutWizardFixture()
	f.quote = func(int, string, uint64, string) (zkapi.AddressPaymentQuote, error) {
		return zkapi.AddressPaymentQuote{}, uneconomic
	}
	u := &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true}}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err == nil || u.confirms != 1 || f.quoteCalls != 2 {
		t.Fatalf("repeated refusal: %v %+v", err, f)
	}
}

// A destination that cannot receive a sponsored payout is asked for again
// before anything is reserved for it; a saved destination cannot change.
func TestGuidedPayoutInvalidPayeeAsksForAnotherDestination(t *testing.T) {
	contract := "0x6666666666666666666666666666666666666666"
	f := payoutWizardFixture()
	f.quote = func(call int, destination string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
		if destination == contract {
			return zkapi.AddressPaymentQuote{}, &managementError{message: "invalid_payee: the payout address cannot receive a sponsored payout", code: zkapi.CodeInvalidPayee}
		}
		return payoutWizardQuote(call), nil
	}
	u := &fundingWizardUI{answers: []string{contract, withdrawalTestDestination}, confirmations: []bool{true}}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if u.asks != 2 || f.quoteCalls != 2 || f.approveCalls != 1 || !strings.Contains(u.String(), contract+" cannot receive this payout") {
		t.Fatalf("calls: ui=%+v service=%+v %s", u, f, u.String())
	}
	f = payoutWizardFixture()
	f.status = func(int) (zkapi.AddressWithdrawalStatus, error) { return payoutWizardState("quoted"), nil }
	f.quote = func(int, string, uint64, string) (zkapi.AddressPaymentQuote, error) {
		return zkapi.AddressPaymentQuote{}, &managementError{message: "invalid_payee: the payout address cannot receive a sponsored payout", code: zkapi.CodeInvalidPayee}
	}
	u = &fundingWizardUI{}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); managementErrorCode(err) != zkapi.CodeInvalidPayee || u.asks != 0 || f.approveCalls != 0 {
		t.Fatalf("saved destination: %v ui=%+v", err, u)
	}
}

// After a restart an approved withdrawal continues within its authorization
// without any prompt or new quote: approved but unsigned (quoted), a refusal
// the daemon retries, or an operation in flight.
func TestGuidedPayoutRestartContinuesWithoutPrompting(t *testing.T) {
	for name, initial := range map[string]zkapi.AddressWithdrawalStatus{
		"approved unsigned": authorizedWizardState("quoted"),
		"retryable refusal": authorizedWizardState("gasless_refused"),
		"built":             payoutWizardState("op_built"),
		"submitted":         payoutWizardState("op_submitted"),
	} {
		t.Run(name, func(t *testing.T) {
			f := payoutWizardFixture()
			f.status = func(int) (zkapi.AddressWithdrawalStatus, error) { return initial, nil }
			u := &fundingWizardUI{}
			if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err != nil {
				t.Fatal(err)
			}
			if u.asks != 0 || u.confirms != 0 || u.continues != 0 || f.quoteCalls != 0 || f.approveCalls != 0 || f.availabilityCalls != 0 || f.resumeCalls != 1 || !strings.Contains(u.String(), "Withdrawal complete") {
				t.Fatalf("restart: ui=%+v service=%+v %s", u, f, u.String())
			}
			if initial.AuthorizedMaxFeeWei != "" && !strings.Contains(u.String(), "Continuing the approved withdrawal to "+withdrawalTestDestination+" within its maximum fee: at most 0.000004000000000000 ETH") {
				t.Fatalf("the authorization was not shown: %s", u.String())
			}
			assertNoWalletFallback(t, u.String(), nil)
		})
	}
	// A refusal that ends the approval while it is followed stops with the
	// reason; a new quote is reviewed next time.
	f := payoutWizardFixture()
	f.status = func(int) (zkapi.AddressWithdrawalStatus, error) { return authorizedWizardState("quoted"), nil }
	f.resume = func(int, string, uint64) (zkapi.AddressWithdrawalStatus, error) {
		s := payoutWizardState("gasless_refused")
		s.GaslessRefusal = "gasless_attempts_exhausted: this state used its sponsored attempts; use --fees wallet"
		return s, nil
	}
	err := guidedWithdrawal(context.Background(), f, &fundingWizardUI{}, immediateWizardPoll)
	if err == nil || !strings.Contains(err.Error(), "gasless_attempts_exhausted") || !strings.Contains(err.Error(), "review a new quote") || f.approveCalls != 0 {
		t.Fatalf("ended approval: %v", err)
	}
	assertNoWalletFallback(t, "", err)
	// A saved sponsored withdrawal whose approval ended is quoted again
	// from the payout and approved with one Enter.
	f = payoutWizardFixture()
	f.status = func(int) (zkapi.AddressWithdrawalStatus, error) {
		s := payoutWizardState("gasless_refused")
		s.GaslessRefusal = "sponsorship_paused: the paymaster has paused sponsorship"
		return s, nil
	}
	u := &fundingWizardUI{confirmations: []bool{true}}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err != nil || u.asks != 0 || u.continues != 1 || !f.options[0].payout || f.approveCalls != 1 {
		t.Fatalf("requote of a refused withdrawal: %v ui=%+v service=%+v", err, u, f)
	}
}

// A lost approval reply is followed only through the saved authorization.
func TestGuidedPayoutLostApprovalReplyFollowsTheSavedAuthorization(t *testing.T) {
	f := payoutWizardFixture()
	f.status = func(call int) (zkapi.AddressWithdrawalStatus, error) {
		if call == 1 {
			return payoutWizardState("ready"), nil
		}
		return authorizedWizardState("quoted"), nil
	}
	f.approve = func(string) (zkapi.AddressWithdrawalStatus, error) {
		return zkapi.AddressWithdrawalStatus{}, errors.New("lost reply")
	}
	u := &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true}}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if f.approveCalls != 1 || f.quoteCalls != 1 || f.resumeCalls != 1 || u.continues != 1 {
		t.Fatalf("lost reply: %+v", f)
	}
	// Nothing saved: it stops instead of approving another quote.
	f = payoutWizardFixture()
	f.approve = func(string) (zkapi.AddressWithdrawalStatus, error) {
		return zkapi.AddressWithdrawalStatus{}, errors.New("lost reply")
	}
	u = &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true}}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err == nil || !strings.Contains(err.Error(), "was not confirmed") || f.approveCalls != 1 || f.resumeCalls != 0 {
		t.Fatalf("unsaved approval: %v %+v", err, f)
	}
}

// A withdrawal reserved wallet-paid before sponsorship (no transit account),
// or moved to the wallet as recovery, keeps the QR, Enter and approval flow
// on a payout deployment, says why once, and is never switched to the payout.
func TestGuidedWithdrawalSavedWalletRecordKeepsTheQRFlow(t *testing.T) {
	for name, saved := range map[string]func() zkapi.AddressWithdrawalStatus{
		"reserved before sponsorship": func() zkapi.AddressWithdrawalStatus {
			s := withdrawalWizardState("waiting_funds")
			s.NewWithdrawalFees = "payout"
			return s
		},
		"moved to the wallet": func() zkapi.AddressWithdrawalStatus {
			s := withdrawalWizardState("waiting_funds")
			s.NewWithdrawalFees, s.FeePayer, s.TransitAccount = "payout", "wallet", gaslessTestTransit
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := &withdrawalWizardFixture{availability: &zkapi.GaslessAvailability{Required: true, Available: true}}
			f.status = func(int) (zkapi.AddressWithdrawalStatus, error) { return saved(), nil }
			f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
				q := withdrawalWizardQuote()
				q.ID = fmt.Sprintf("%064x", call)
				if call == 1 {
					withdrawalQuoteFunds(&q, 0, 25000, 30000)
				}
				return q, nil
			}
			u := &fundingWizardUI{confirmations: []bool{true}}
			if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err != nil {
				t.Fatal(err)
			}
			if u.asks != 0 || u.continues != 1 || f.availabilityCalls != 0 || f.approveCalls != 1 || f.options[0].payout || !strings.Contains(u.String(), "Scan with an Ethereum wallet") || !strings.Contains(u.String(), "finishes that way") {
				t.Fatalf("wallet record: ui=%+v service=%+v %s", u, f, u.String())
			}
		})
	}
	// A deployment without sponsorship never runs the pre-flight.
	f := &withdrawalWizardFixture{availability: &zkapi.GaslessAvailability{Available: true}}
	u := &fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{true}}
	if err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll); err != nil || f.availabilityCalls != 0 || f.options[0].payout || u.asks != 1 {
		t.Fatalf("wallet deployment: %v %+v", err, f)
	}
}
