package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

type fundingWizardUI struct {
	bytes.Buffer
	answers                   []string
	confirmations             []bool
	asks, confirms, continues int
	beforeContinue            func()
	// questions records what was asked, in order.
	questions []string
}

func (u *fundingWizardUI) Printf(format string, args ...any) { fmt.Fprintf(&u.Buffer, format, args...) }
func (u *fundingWizardUI) Ask(_ context.Context, question, _ string) (string, error) {
	u.asks++
	u.questions = append(u.questions, question)
	if len(u.answers) == 0 {
		return "", errors.New("unexpected input request")
	}
	answer := u.answers[0]
	u.answers = u.answers[1:]
	return answer, nil
}
func (u *fundingWizardUI) Confirm(context.Context, string) (bool, error) {
	u.confirms++
	if len(u.confirmations) == 0 {
		return false, errors.New("unexpected approval request")
	}
	result := u.confirmations[0]
	u.confirmations = u.confirmations[1:]
	return result, nil
}

func (u *fundingWizardUI) Continue(context.Context, string) (bool, error) {
	u.continues++
	if u.beforeContinue != nil {
		u.beforeContinue()
	}
	if len(u.confirmations) == 0 {
		return false, errors.New("unexpected deposit continuation")
	}
	result := u.confirmations[0]
	u.confirmations = u.confirmations[1:]
	return result, nil
}

type wizardFundingFixture struct {
	quoteCalls, approveCalls, resumeCalls, readinessCalls int
	ready                                                 func(int) zkapi.WalletReadiness
	address                                               func() zkapi.AddressFundingStatus
	addressResult                                         func() (zkapi.AddressFundingStatus, error)
	quote                                                 func(int, uint64, uint64) (zkapi.AddressPaymentQuote, error)
	approve                                               func(string) (zkapi.AddressFundingStatus, error)
	resume                                                func(uint64) (zkapi.AddressFundingStatus, error)
	withdrawal                                            string
	withdrawalStatus                                      func() zkapi.AddressWithdrawalStatus
}

func wizardState(phase string) zkapi.AddressFundingStatus {
	q := wizardQuote()
	return zkapi.AddressFundingStatus{Phase: phase, Address: q.Address, ChainID: q.ChainID, DeploymentID: q.DeploymentID, BillingAsset: "native_eth", Amount: q.Amount, ETHBalance: q.BalanceWei, TransactionHash: "0x" + strings.Repeat("a", 64)}
}
func wizardQuote() zkapi.AddressPaymentQuote {
	q := paymentTestQuote("deposit")
	q.Commitment = "0x1234"
	return q
}
func newWizardFixture() *wizardFundingFixture {
	return &wizardFundingFixture{}
}
func (f *wizardFundingFixture) Readiness(context.Context) (zkapi.WalletReadiness, error) {
	f.readinessCalls++
	if f.ready != nil {
		return f.ready(f.readinessCalls), nil
	}
	return zkapi.WalletReadiness{HasNote: f.readinessCalls > 1, Balance: 750001}, nil
}
func (f *wizardFundingFixture) Address(context.Context) (zkapi.AddressFundingStatus, error) {
	if f.addressResult != nil {
		return f.addressResult()
	}
	if f.address != nil {
		return f.address(), nil
	}
	s := wizardState("ready")
	s.Amount = 0
	s.TransactionHash = ""
	return s, nil
}
func (f *wizardFundingFixture) Withdrawal(context.Context) (zkapi.AddressWithdrawalStatus, error) {
	if f.withdrawalStatus != nil {
		return f.withdrawalStatus(), nil
	}
	phase := f.withdrawal
	if phase == "" {
		phase = "no_note"
	}
	return zkapi.AddressWithdrawalStatus{Phase: phase}, nil
}
func (f *wizardFundingFixture) Quote(_ context.Context, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
	f.quoteCalls++
	if f.quote != nil {
		return f.quote(f.quoteCalls, amount, usd)
	}
	q := wizardQuote()
	q.ID = fmt.Sprintf("%064x", f.quoteCalls)
	q.InputMicroUSD = usd
	return q, nil
}
func (f *wizardFundingFixture) Approve(_ context.Context, id string) (zkapi.AddressFundingStatus, error) {
	f.approveCalls++
	if f.approve != nil {
		return f.approve(id)
	}
	return wizardState("active"), nil
}
func (f *wizardFundingFixture) Resume(_ context.Context, amount uint64) (zkapi.AddressFundingStatus, error) {
	f.resumeCalls++
	if f.resume != nil {
		return f.resume(amount)
	}
	return wizardState("active"), nil
}
func immediateWizardPoll(ctx context.Context) error { return ctx.Err() }

func TestGuidedFundingWaitsForMoneyThenApprovesFreshFixedQuote(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{answers: []string{"20"}, confirmations: []bool{true}}
	f.quote = func(call int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		if call == 1 {
			if usd != 20_000_000 || amount != 0 {
				t.Fatal("initial USD selection changed")
			}
		} else if amount != 750001 || usd != 0 {
			t.Fatal("refresh repriced or changed the fixed principal")
		}
		q := wizardQuote()
		q.InputMicroUSD = usd
		q.ID = fmt.Sprintf("%064x", call)
		if call < 4 {
			q.BalanceWei = "0"
			q.ShortfallWei = q.RequiredTotalWei
			q.RecommendedTopUpWei = q.RecommendedTotalWei
		}
		return q, nil
	}
	f.approve = func(id string) (zkapi.AddressFundingStatus, error) {
		if id != fmt.Sprintf("%064x", 5) {
			t.Fatal("approved a stale quote")
		}
		return wizardState("deposit_pending"), nil
	}
	polls := 0
	err := guidedFunding(context.Background(), f, "", u, func(context.Context) error { polls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if f.approveCalls != 1 || f.resumeCalls != 1 || f.quoteCalls != 5 || polls != 3 || u.confirms != 0 || u.continues != 1 || u.asks != 1 {
		t.Fatalf("unexpected flow: %+v polls=%d UI=%+v", f, polls, u)
	}
	for _, want := range []string{"To:", "Send at least:", "Funds available.", "Deposit confirmed.", "Private balance:"} {
		if !strings.Contains(u.String(), want) {
			t.Fatalf("missing %q", want)
		}
	}
}

// Before a new deposit replaces a credited escape's withdrawal record, and
// while earlier credited payouts stay unclaimed, the guided setup names them
// with their claim call. A paid withdrawal adds nothing.
func TestGuidedFundingNamesUnclaimedEscapePayoutsBeforeANewDeposit(t *testing.T) {
	for _, credited := range []bool{true, false} {
		f := newWizardFixture()
		current := "An escape of this note finalized and closed it, but the vault could not deliver the payout; call claimEscapePayout(0xdest) on the vault"
		earlier := "An earlier escape (note 9) closed its note; call claimEscapePayout(0xother) on the vault"
		f.withdrawalStatus = func() zkapi.AddressWithdrawalStatus {
			return zkapi.AddressWithdrawalStatus{Phase: "complete", PayoutCredited: credited, Message: current}
		}
		f.address = func() zkapi.AddressFundingStatus {
			s := wizardState("ready")
			s.Amount, s.TransactionHash = 0, ""
			if credited {
				s.EscapePayoutCredits = []zkapi.EscapePayoutCredit{{Destination: "0xother", Message: earlier}}
			}
			return s
		}
		u := &fundingWizardUI{answers: []string{"20"}, confirmations: []bool{true}}
		if err := guidedFunding(context.Background(), f, "", u, immediateWizardPoll); err != nil {
			t.Fatal(err)
		}
		output := u.String()
		for _, message := range []string{current, earlier} {
			shown := strings.Index(output, "Unclaimed escape payout: "+message)
			if (shown >= 0) != credited || (credited && shown > strings.Index(output, "Ready to deposit")) {
				t.Fatalf("credited=%v: the reminder %q is missing or follows the deposit: %s", credited, message, output)
			}
		}
	}
}

func TestGuidedFundingReadyWalletDoesNotAskOrDeposit(t *testing.T) {
	f := newWizardFixture()
	f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{HasNote: true, Balance: 1} }
	u := &fundingWizardUI{}
	if err := guidedFunding(context.Background(), f, "", u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if u.asks+u.confirms+u.continues+f.quoteCalls+f.approveCalls != 0 {
		t.Fatal("ready wallet triggered funding")
	}
	if !strings.Contains(u.String(), "Private balance: 0.000000001 ETH.") || strings.Contains(u.String(), "model") {
		t.Fatal("wallet status depended on a model or omitted its positive balance")
	}
}

func TestGuidedFundingAmountPromptAndExplicitAmount(t *testing.T) {
	for _, test := range []struct {
		name, explicit, input string
		want                  uint64
		prompts               int
	}{
		{"enter accepts default", "", "\n", 20_000_000, 1},
		{"small deposit", "", "0.50\n", 500_000, 1},
		{"custom", "", " 12.50 \n", 12_500_000, 1},
		{"invalid then custom", "", "abc\n0\n-5\n1.0000001\n1000001\n3.000001\n", 3_000_001, 6},
		{"explicit", "0.50", "", 500_000, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newWizardFixture()
			f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
				if (n == 1 && (amount != 0 || usd != test.want)) || (n > 1 && (amount != 750001 || usd != 0)) {
					t.Fatal("wrong selected deposit")
				}
				q := wizardQuote()
				q.InputMicroUSD = usd
				return q, nil
			}
			var output bytes.Buffer
			u := &terminalSetupPrompter{out: &output, input: bufio.NewReader(strings.NewReader(test.input + "no\n"))}
			err := guidedFunding(context.Background(), f, test.explicit, u, immediateWizardPoll)
			if err == nil || !strings.Contains(err.Error(), "declined") || f.quoteCalls != 2 || f.approveCalls+f.resumeCalls != 0 {
				t.Fatal("amount selection did not stop at declined consent", err)
			}
			if strings.Count(output.String(), "Deposit amount in USD (network fees are extra) [20]: ") != test.prompts {
				t.Fatal("incorrect amount prompt or default")
			}
		})
	}
}

func TestGuidedFundingAmountInputEndsBeforeQuoting(t *testing.T) {
	for _, input := range []string{"", "invalid\n"} {
		f := newWizardFixture()
		var output bytes.Buffer
		u := &terminalSetupPrompter{out: &output, input: bufio.NewReader(strings.NewReader(input))}
		err := guidedFunding(context.Background(), f, "", u, immediateWizardPoll)
		if err == nil || !strings.Contains(err.Error(), "input ended") || f.quoteCalls+f.approveCalls+f.resumeCalls != 0 {
			t.Fatal("ended amount input prepared or authorized a deposit", err)
		}
	}
}

func TestGuidedFundingRejectsEmptyOrReservedWallet(t *testing.T) {
	for _, kind := range []string{"empty balance", "companion reservation", "local reservation"} {
		t.Run(kind, func(t *testing.T) {
			f := newWizardFixture()
			balance := uint64(1)
			want := "a private withdrawal is reserved"
			if kind == "empty balance" {
				balance, want = 0, "the private balance is empty"
			}
			f.ready = func(int) zkapi.WalletReadiness {
				return zkapi.WalletReadiness{HasNote: true, Balance: balance, WithdrawalPending: kind == "companion reservation"}
			}
			if kind == "local reservation" {
				f.withdrawal = "quoted"
				want = "a withdrawal needs attention"
			}
			err := guidedFunding(context.Background(), f, "", &fundingWizardUI{}, immediateWizardPoll)
			if err == nil || !strings.Contains(err.Error(), want) || f.quoteCalls+f.approveCalls != 0 {
				t.Fatal("wallet guard failed or silently topped up", err)
			}
		})
	}
}

func TestGuidedFundingWaitsForSettlement(t *testing.T) {
	f := newWizardFixture()
	f.ready = func(n int) zkapi.WalletReadiness {
		return zkapi.WalletReadiness{HasNote: true, Balance: 750001, PendingRequest: n < 3}
	}
	polls := 0
	if err := guidedFunding(context.Background(), f, "", &fundingWizardUI{}, func(context.Context) error { polls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if polls != 2 || f.approveCalls != 0 {
		t.Fatal("pending settlement was not waited out")
	}
}

func TestGuidedFundingDeclineNeverApproves(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{confirmations: []bool{false}}
	if err := guidedFunding(context.Background(), f, "2", u, immediateWizardPoll); err == nil {
		t.Fatal("decline did not stop")
	}
	if f.approveCalls != 0 || f.quoteCalls != 2 || u.confirms != 0 || u.continues != 1 {
		t.Fatal("decline authorized funding")
	}
}

func TestSetupDepositDoesNotDisplayInconsistentPayment(t *testing.T) {
	q := wizardQuote()
	q.RecommendedTopUpWei = "1"
	ui := &fundingWizardUI{}
	if err := showSetupDeposit(ui, q); err == nil || ui.Len() != 0 {
		t.Fatal("inconsistent quote displayed payment instructions")
	}
}

func TestGuidedFundingAffordableFeeIncreaseKeepsSingleEnter(t *testing.T) {
	for _, test := range []struct {
		name                      string
		required, reserve, funded int64
	}{
		{name: "higher optional reserve", required: 25000, reserve: 31000, funded: 30000},
		{name: "required fee uses funded buffer", required: 28000, reserve: 33000, funded: 30000},
		{name: "required fee exceeds original reserve", required: 35000, reserve: 40000, funded: 45000},
		{name: "exact required balance", required: 35000, reserve: 40000, funded: 35000},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newWizardFixture()
			u := &fundingWizardUI{confirmations: []bool{true}}
			u.beforeContinue = func() {
				if !strings.Contains(u.String(), "Network fees adjust automatically while the receiving balance covers this deposit and its fees.") {
					t.Fatal("automatic fee adjustment was not explained before Enter")
				}
			}
			f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
				q := wizardQuote()
				q.InputMicroUSD, q.ID = usd, fmt.Sprintf("%064x", n)
				principal, _ := new(big.Int).SetString(q.PrincipalWei, 10)
				q = wizardBalance(q, principal.Add(principal, big.NewInt(test.funded)).String())
				if n > 2 {
					q = wizardFees(q, test.required, test.reserve)
				}
				return q, nil
			}
			f.approve = func(id string) (zkapi.AddressFundingStatus, error) {
				if id != fmt.Sprintf("%064x", 3) {
					t.Fatal("increased fees used a stale quote")
				}
				return wizardState("active"), nil
			}
			if err := guidedFunding(context.Background(), f, "2", u, immediateWizardPoll); err != nil {
				t.Fatal(err)
			}
			if u.confirms != 0 || u.continues != 1 || f.approveCalls != 1 || f.quoteCalls != 3 {
				t.Fatalf("affordable fee increase requested renewed consent: enters=%d approvals=%d quotes=%d", u.continues, f.approveCalls, f.quoteCalls)
			}
			if strings.Contains(u.String(), "Network fees increased; review") {
				t.Fatal("affordable fee increase requested another fee review")
			}
		})
	}
}

func TestGuidedFundingRejectsChangedOperation(t *testing.T) {
	changes := map[string]func(*zkapi.AddressPaymentQuote){
		"principal":   func(q *zkapi.AddressPaymentQuote) { q.Amount++ },
		"network":     func(q *zkapi.AddressPaymentQuote) { q.ChainID++ },
		"deployment":  func(q *zkapi.AddressPaymentQuote) { q.DeploymentID = "other" },
		"contract":    func(q *zkapi.AddressPaymentQuote) { q.Contract = q.Address },
		"address":     func(q *zkapi.AddressPaymentQuote) { q.Address = q.Contract },
		"commitment":  func(q *zkapi.AddressPaymentQuote) { q.Commitment = "0xabcd" },
		"nonce":       func(q *zkapi.AddressPaymentQuote) { q.Nonce++ },
		"revert":      func(q *zkapi.AddressPaymentQuote) { q.RetryHash = "0x" + strings.Repeat("b", 64) },
		"destination": func(q *zkapi.AddressPaymentQuote) { q.Destination = q.Address },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newWizardFixture()
			u := &fundingWizardUI{confirmations: []bool{true}}
			f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
				q := wizardQuote()
				q.InputMicroUSD = usd
				if n > 1 {
					change(&q)
				}
				return q, nil
			}
			if err := guidedFunding(context.Background(), f, "2", u, immediateWizardPoll); err == nil || f.approveCalls != 0 {
				t.Fatal("changed deposit was authorized")
			}
		})
	}
}

func TestGuidedFundingCancellationLeavesUnsignedIntent(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{confirmations: []bool{true}}
	f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		q := wizardQuote()
		q.InputMicroUSD = usd
		q.BalanceWei = "1"
		q.ShortfallWei = "750001000024999"
		q.RecommendedTopUpWei = "750001000029999"
		return q, nil
	}
	err := guidedFunding(context.Background(), f, "2", u, func(context.Context) error { return context.Canceled })
	if !errors.Is(err, context.Canceled) || f.approveCalls != 0 || u.confirms+u.continues != 0 {
		t.Fatal("cancellation authorized an unsigned deposit")
	}
}

func TestGuidedFundingRestartRecoversOnlySavedTransaction(t *testing.T) {
	f := newWizardFixture()
	f.address = func() zkapi.AddressFundingStatus { return wizardState("deposit_pending") }
	u := &fundingWizardUI{}
	if err := guidedFunding(context.Background(), f, "2", u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if f.resumeCalls != 1 || f.quoteCalls+f.approveCalls+u.confirms+u.continues+u.asks != 0 {
		t.Fatal("restart created a new deposit")
	}
}

func TestGuidedFundingSavedUnsignedPrincipalIsPreserved(t *testing.T) {
	f := newWizardFixture()
	f.address = func() zkapi.AddressFundingStatus { s := wizardState("waiting_funds"); s.TransactionHash = ""; return s }
	f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		if amount != 750001 || usd != 0 {
			t.Fatal("saved principal changed")
		}
		return wizardQuote(), nil
	}
	u := &fundingWizardUI{confirmations: []bool{true}}
	if err := guidedFunding(context.Background(), f, "3", u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if u.asks != 0 || u.confirms != 0 || u.continues != 1 {
		t.Fatal("saved intent did not require fresh consent")
	}
}

func TestGuidedFundingAmbiguousApprovalInspectsDurableState(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprint(signed), func(t *testing.T) {
			f := newWizardFixture()
			u := &fundingWizardUI{confirmations: []bool{true}}
			f.approve = func(string) (zkapi.AddressFundingStatus, error) {
				if f.approveCalls > 1 {
					return wizardState("active"), nil
				}
				return zkapi.AddressFundingStatus{}, errors.New("lost reply")
			}
			f.address = func() zkapi.AddressFundingStatus {
				s := wizardState("waiting_funds")
				s.TransactionHash = ""
				if f.approveCalls == 0 {
					s.Amount = 0
					s.Phase = "ready"
				} else if signed {
					s = wizardState("deposit_pending")
				}
				return s
			}
			err := guidedFunding(context.Background(), f, "2", u, immediateWizardPoll)
			wantApprovals := 2
			if signed {
				wantApprovals = 1
			}
			if err != nil || f.approveCalls != wantApprovals || u.continues != 1 {
				t.Fatalf("ambiguous approval repeated or lost recovery: %v", err)
			}
			if signed && f.resumeCalls != 1 {
				t.Fatal("signed transaction not recovered")
			}
		})
	}
}

func TestGuidedFundingNeverRetriesRevertAfterLostResumeReply(t *testing.T) {
	f := newWizardFixture()
	f.address = func() zkapi.AddressFundingStatus {
		if f.resumeCalls > 0 {
			return wizardState("reverted")
		}
		return wizardState("deposit_pending")
	}
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		return zkapi.AddressFundingStatus{}, errors.New("lost reply after persisting revert")
	}
	if err := guidedFunding(context.Background(), f, "", &fundingWizardUI{}, immediateWizardPoll); err == nil {
		t.Fatal("revert automatically retried")
	}
	if f.resumeCalls != 1 || f.approveCalls != 0 {
		t.Fatal("revert was replayed or reapproved")
	}
}

func TestGuidedFundingLostResumeAndStatusRepliesDoNotRepeatRecovery(t *testing.T) {
	f := newWizardFixture()
	reads := 0
	f.addressResult = func() (zkapi.AddressFundingStatus, error) {
		reads++
		if reads == 1 {
			return wizardState("deposit_pending"), nil
		}
		if reads == 2 {
			return zkapi.AddressFundingStatus{}, errors.New("status unavailable")
		}
		return wizardState("reverted"), nil
	}
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		return zkapi.AddressFundingStatus{}, errors.New("lost reply after persisting revert")
	}
	if err := guidedFunding(context.Background(), f, "", &fundingWizardUI{}, immediateWizardPoll); err == nil {
		t.Fatal("revert automatically retried")
	}
	if f.resumeCalls != 1 || f.approveCalls != 0 || reads != 3 {
		t.Fatal("failed status read allowed another transaction recovery call")
	}
}

// Keep quote arithmetic valid while exercising receiving-account changes.
func wizardBalance(q zkapi.AddressPaymentQuote, balance string) zkapi.AddressPaymentQuote {
	q.BalanceWei = balance
	b, _ := new(big.Int).SetString(balance, 10)
	remaining := func(total string) string {
		n, _ := new(big.Int).SetString(total, 10)
		n.Sub(n, b)
		if n.Sign() < 0 {
			n.SetInt64(0)
		}
		return n.String()
	}
	q.ShortfallWei, q.RecommendedTopUpWei = remaining(q.RequiredTotalWei), remaining(q.RecommendedTotalWei)
	return q
}

func wizardFees(q zkapi.AddressPaymentQuote, required, reserve int64) zkapi.AddressPaymentQuote {
	principal, _ := new(big.Int).SetString(q.PrincipalWei, 10)
	q.RequiredFeeWei, q.FeeReserveWei = fmt.Sprint(required), fmt.Sprint(reserve)
	q.FeeBufferWei = fmt.Sprint(reserve - required)
	q.RequiredTotalWei = new(big.Int).Add(principal, big.NewInt(required)).String()
	q.RecommendedTotalWei = new(big.Int).Add(principal, big.NewInt(reserve)).String()
	return wizardBalance(q, q.BalanceWei)
}

func TestGuidedFundingPartialPaymentsAndFeesUpdateWithoutPrompting(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{}
	f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		q := wizardQuote()
		q.InputMicroUSD = usd
		balance := "0"
		if n >= 2 {
			balance = "100000000000000"
		}
		if n >= 3 {
			q.FeeReserveWei, q.FeeBufferWei = "31000", "6000"
			q.RecommendedTotalWei = "750001000031000"
		}
		return wizardBalance(q, balance), nil
	}
	polls := 0
	err := guidedFunding(context.Background(), f, "20", u, func(context.Context) error {
		polls++
		if u.continues+u.confirms+f.approveCalls != 0 {
			t.Fatal("waiting for funds asked for consent or signed a transaction")
		}
		if polls == 2 {
			return context.Canceled
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || f.quoteCalls != 3 {
		t.Fatal("waiting did not poll automatically", err)
	}
	for _, want := range []string{
		"Send at least: 0.00076 ETH",
		"Send at least: 0.00066 ETH (account already has 0.00010 ETH)",
		"?value=650001000030000",
	} {
		if !strings.Contains(u.String(), want) {
			t.Fatalf("missing updated payment information %q", want)
		}
	}
}

func TestGuidedFundingBalanceDropRequiresAnotherEnter(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{confirmations: []bool{true, true}}
	f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		q := wizardQuote()
		q.InputMicroUSD, q.ID = usd, fmt.Sprintf("%064x", n)
		if n == 3 {
			// Funds disappear after the first Enter, before signing.
			return wizardBalance(q, "0"), nil
		}
		return q, nil
	}
	f.approve = func(id string) (zkapi.AddressFundingStatus, error) {
		if u.continues != 2 || id != fmt.Sprintf("%064x", 5) {
			t.Fatal("old consent or a stale quote authorized the deposit")
		}
		return wizardState("active"), nil
	}
	polls := 0
	if err := guidedFunding(context.Background(), f, "20", u, func(context.Context) error { polls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if polls != 1 || f.approveCalls != 1 || u.confirms != 0 || !strings.Contains(u.String(), "Waiting for ETH again") {
		t.Fatal("balance drop did not return to automatic waiting")
	}
}

func TestGuidedFundingValidatesFreshQuoteAfterEnter(t *testing.T) {
	for _, change := range []string{"amount", "balance arithmetic", "fee arithmetic"} {
		t.Run(change, func(t *testing.T) {
			f := newWizardFixture()
			u := &fundingWizardUI{confirmations: []bool{true}}
			f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
				q := wizardQuote()
				q.InputMicroUSD = usd
				if n >= 3 {
					switch change {
					case "amount":
						q.Amount++
					case "balance arithmetic":
						q.BalanceWei = "0" // Deliberately retain the old zero shortfall.
					case "fee arithmetic":
						q.FeeReserveWei = "1"
					}
				}
				return q, nil
			}
			err := guidedFunding(context.Background(), f, "20", u, immediateWizardPoll)
			if err == nil || f.approveCalls != 0 || u.continues != 1 || f.quoteCalls != 3 {
				t.Fatal("post-Enter quote was not independently validated", err)
			}
		})
	}
}

func TestGuidedFundingRefreshFailurePreservesVisibleBalanceWithoutApproval(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{}
	f.quote = func(n int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		if n > 1 {
			return zkapi.AddressPaymentQuote{}, errors.New("network unavailable")
		}
		q := wizardBalance(wizardQuote(), "100000000000000")
		q.InputMicroUSD = usd
		return q, nil
	}
	f.address = func() zkapi.AddressFundingStatus {
		s := wizardState("waiting_funds")
		s.TransactionHash = ""
		return s
	}
	err := guidedFunding(context.Background(), f, "20", u, func(context.Context) error { return context.Canceled })
	if !errors.Is(err, context.Canceled) || f.approveCalls+u.continues+u.confirms != 0 ||
		!strings.Contains(u.String(), "account already has 0.00010 ETH") ||
		!strings.Contains(u.String(), "Could not refresh the funding quote") {
		t.Fatal("refresh failure hid the last balance or authorized a transaction", err)
	}
}

func TestGuidedFundingUnsignedApprovalWaitsAndRefreshesSameConsent(t *testing.T) {
	for _, phase := range []string{"ready", "waiting_funds"} {
		for _, lost := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/lost=%v", phase, lost), func(t *testing.T) {
				f := newWizardFixture()
				u := &fundingWizardUI{confirmations: []bool{true}}
				polls, reads := 0, 0
				f.address = func() zkapi.AddressFundingStatus {
					reads++
					s := wizardState(phase)
					s.TransactionHash = ""
					return s
				}
				f.approve = func(id string) (zkapi.AddressFundingStatus, error) {
					if f.approveCalls > 1 {
						if polls != f.approveCalls-1 || id != fmt.Sprintf("%064x", f.approveCalls+2) {
							t.Fatal("retry did not wait and refresh quote")
						}
						if lost && reads != f.approveCalls {
							t.Fatal("ambiguous approval retried before serialized status read")
						}
					}
					if f.approveCalls == 3 {
						return wizardState("active"), nil
					}
					if lost {
						return zkapi.AddressFundingStatus{}, errors.New("reply lost before or after signing")
					}
					s := wizardState(phase)
					s.TransactionHash = ""
					return s, nil
				}
				if err := guidedFunding(context.Background(), f, "20", u, func(context.Context) error { polls++; return nil }); err != nil {
					t.Fatal(err)
				}
				if f.approveCalls != 3 || f.resumeCalls != 0 || polls != 2 || u.continues != 1 || f.quoteCalls != 5 {
					t.Fatalf("bad unsigned recovery: approvals=%d resumes=%d waits=%d enters=%d quotes=%d", f.approveCalls, f.resumeCalls, polls, u.continues, f.quoteCalls)
				}
				if strings.Count(u.String(), "No deposit transaction was sent.") != 1 {
					t.Fatal("unsigned progress repeated or missing")
				}
			})
		}
	}
}

func TestGuidedFundingUnsignedApprovalRecoveryRejectsChangedState(t *testing.T) {
	changes := map[string]func(*zkapi.AddressFundingStatus){
		"hash in waiting state":           func(s *zkapi.AddressFundingStatus) { s.TransactionHash = "0x" + strings.Repeat("a", 64) },
		"malformed hash in waiting state": func(s *zkapi.AddressFundingStatus) { s.TransactionHash = "invalid" },
		"wrong asset":                     func(s *zkapi.AddressFundingStatus) { s.BillingAsset = "token" },
		"wrong amount":                    func(s *zkapi.AddressFundingStatus) { s.Amount++ },
		"wrong address":                   func(s *zkapi.AddressFundingStatus) { s.Address = wizardQuote().Contract },
		"wrong chain":                     func(s *zkapi.AddressFundingStatus) { s.ChainID++ },
		"wrong deployment":                func(s *zkapi.AddressFundingStatus) { s.DeploymentID = "other" },
		"invalid balance":                 func(s *zkapi.AddressFundingStatus) { s.ETHBalance = "invalid" },
		"negative balance":                func(s *zkapi.AddressFundingStatus) { s.ETHBalance = "-1" },
		"overflow balance":                func(s *zkapi.AddressFundingStatus) { s.ETHBalance = new(big.Int).Lsh(big.NewInt(1), 256).String() },
		"reverted": func(s *zkapi.AddressFundingStatus) {
			s.Phase = "reverted"
			s.TransactionHash = "0x" + strings.Repeat("a", 64)
		},
		"unknown phase":             func(s *zkapi.AddressFundingStatus) { s.Phase = "unknown" },
		"pending without hash":      func(s *zkapi.AddressFundingStatus) { s.Phase = "deposit_pending" },
		"confirming malformed hash": func(s *zkapi.AddressFundingStatus) { s.Phase = "confirming"; s.TransactionHash = "invalid" },
		"active without hash":       func(s *zkapi.AddressFundingStatus) { s.Phase = "active" },
	}
	for name, change := range changes {
		for _, lost := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/lost=%v", name, lost), func(t *testing.T) {
				f := newWizardFixture()
				u := &fundingWizardUI{confirmations: []bool{true}}
				changed := wizardState("waiting_funds")
				changed.TransactionHash = ""
				change(&changed)
				f.address = func() zkapi.AddressFundingStatus {
					if f.approveCalls > 0 {
						return changed
					}
					s := wizardState("ready")
					s.TransactionHash = ""
					return s
				}
				f.approve = func(string) (zkapi.AddressFundingStatus, error) {
					if lost {
						return zkapi.AddressFundingStatus{}, errors.New("lost reply")
					}
					return changed, nil
				}
				if err := guidedFunding(context.Background(), f, "20", u, immediateWizardPoll); err == nil {
					t.Fatal("unsafe approval state accepted")
				}
				if f.approveCalls != 1 || f.resumeCalls != 0 {
					t.Fatal("unsafe approval was retried")
				}
			})
		}
	}
}

func TestGuidedFundingUnsignedApprovalRechecksEntireQuoteBinding(t *testing.T) {
	changes := map[string]func(*zkapi.AddressPaymentQuote){
		"commitment": func(q *zkapi.AddressPaymentQuote) { q.Commitment = "0x5678" },
		"nonce":      func(q *zkapi.AddressPaymentQuote) { q.Nonce++ },
		"amount":     func(q *zkapi.AddressPaymentQuote) { q.Amount++ },
		"principal":  func(q *zkapi.AddressPaymentQuote) { q.PrincipalWei = "1" },
		"contract":   func(q *zkapi.AddressPaymentQuote) { q.Contract = q.Address },
		"deployment": func(q *zkapi.AddressPaymentQuote) { q.DeploymentID = "other" },
		"chain":      func(q *zkapi.AddressPaymentQuote) { q.ChainID++ },
		"address":    func(q *zkapi.AddressPaymentQuote) { q.Address = q.Contract },
		"retry hash": func(q *zkapi.AddressPaymentQuote) { q.RetryHash = "0x" + strings.Repeat("b", 64) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newWizardFixture()
			u := &fundingWizardUI{confirmations: []bool{true}}
			f.approve = func(string) (zkapi.AddressFundingStatus, error) {
				s := wizardState("waiting_funds")
				s.TransactionHash = ""
				return s, nil
			}
			f.quote = func(n int, _, usd uint64) (zkapi.AddressPaymentQuote, error) {
				q := wizardQuote()
				q.InputMicroUSD = usd
				if n > 3 {
					change(&q)
				}
				return q, nil
			}
			if err := guidedFunding(context.Background(), f, "20", u, immediateWizardPoll); err == nil {
				t.Fatal("changed intent was approved")
			}
			if f.approveCalls != 1 || f.resumeCalls != 0 {
				t.Fatal("changed intent was retried")
			}
		})
	}
}

func TestGuidedFundingUnsignedApprovalRetainsConsentWhileFundedAndRenewsAfterShortage(t *testing.T) {
	for _, reason := range []string{"expired quote", "fee increase", "returned balance drop", "fresh balance drop", "fee increase causes shortfall"} {
		t.Run(reason, func(t *testing.T) {
			f := newWizardFixture()
			u := &fundingWizardUI{confirmations: []bool{true, true}}
			f.address = func() zkapi.AddressFundingStatus { s := wizardState("ready"); s.TransactionHash = ""; return s }
			f.approve = func(id string) (zkapi.AddressFundingStatus, error) {
				if id != fmt.Sprintf("%064x", f.quoteCalls) {
					t.Fatal("unsigned approval retry used a stale quote")
				}
				if f.approveCalls > 1 {
					return wizardState("active"), nil
				}
				if reason == "expired quote" {
					return zkapi.AddressFundingStatus{}, errors.New("quote expired before signing")
				}
				if reason == "fee increase" {
					return zkapi.AddressFundingStatus{}, errors.New("network fees changed before signing")
				}
				s := wizardState("waiting_funds")
				s.TransactionHash = ""
				if reason == "returned balance drop" {
					s.ETHBalance = "0"
				}
				return s, nil
			}
			f.quote = func(n int, _, usd uint64) (zkapi.AddressPaymentQuote, error) {
				q := wizardQuote()
				q.ID = fmt.Sprintf("%064x", n)
				q.InputMicroUSD = usd
				if n > 3 && reason == "fee increase" {
					q = wizardFees(q, 35000, 40000)
				}
				if n == 4 && reason == "fresh balance drop" {
					q = wizardBalance(q, "0")
				}
				if reason == "fee increase causes shortfall" {
					q = wizardBalance(q, "750001000030000")
					if n > 3 {
						q = wizardFees(q, 35000, 40000)
					}
					if n > 4 {
						q = wizardBalance(q, "750001000040000")
					}
				}
				return q, nil
			}
			polls := 0
			if err := guidedFunding(context.Background(), f, "20", u, func(context.Context) error { polls++; return nil }); err != nil {
				t.Fatal(err)
			}
			wantEnter := 2
			if reason == "expired quote" || reason == "fee increase" {
				wantEnter = 1
			}
			if u.continues != wantEnter || f.approveCalls != 2 || polls < 1 || f.resumeCalls != 0 {
				t.Fatalf("lost fee/funding consent: enters=%d approvals=%d polls=%d", u.continues, f.approveCalls, polls)
			}
			if reason == "fee increase" && f.quoteCalls != 4 {
				t.Fatal("funded fee retry asked for another quote or Enter")
			}
		})
	}
}

func TestGuidedFundingAmbiguousUnsignedApprovalWaitsForReadableJournal(t *testing.T) {
	f := newWizardFixture()
	u := &fundingWizardUI{confirmations: []bool{true}}
	reads, polls := 0, 0
	f.addressResult = func() (zkapi.AddressFundingStatus, error) {
		reads++
		if reads == 2 || reads == 3 {
			return zkapi.AddressFundingStatus{}, errors.New("temporarily unreadable")
		}
		s := wizardState("waiting_funds")
		s.TransactionHash = ""
		return s, nil
	}
	f.approve = func(string) (zkapi.AddressFundingStatus, error) {
		if f.approveCalls == 1 {
			return zkapi.AddressFundingStatus{}, errors.New("lost reply")
		}
		if reads != 4 || polls != 3 {
			t.Fatal("approval retried before a successful durable read and delayed re-quote")
		}
		return wizardState("active"), nil
	}
	if err := guidedFunding(context.Background(), f, "20", u, func(context.Context) error { polls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if f.approveCalls != 2 || f.resumeCalls != 0 || u.continues != 1 {
		t.Fatal("wrong unsigned recovery")
	}
}
