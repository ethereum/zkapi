package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

type lifecycleBudget struct{ model string }

func (b *lifecycleBudget) ModelRequestBudget(_ context.Context, model string) (uint64, error) {
	b.model = model
	return 1_000_000, nil
}
func (b *lifecycleBudget) NativeUSDQuote(context.Context) (zkapi.NativeUSDQuote, error) {
	return zkapi.NativeUSDQuote{Asset: "native_eth", UnitsPerETH: 1_000_000_000, Decimals: 8, Answer: "200000000000", ExpiresAt: uint64(time.Now().Unix() + 600)}, nil
}

func TestServeRecommendationUsesModelAndGasWithoutApproving(t *testing.T) {
	for _, test := range []struct {
		model              string
		fee                string
		first, recommended uint64
	}{
		{"chosen/model", "100000000000000", 500000, 1500000},
		{"chosen/model", "1000000000000000", 500000, 10000000},
		{"", "100000000000000", 3000000, 9000000},
	} {
		f := newWizardFixture()
		budget := &lifecycleBudget{}
		stopped := errors.New("stop before signing")
		f.quote = func(call int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
			if usd != 0 {
				t.Fatal("unexpected USD request")
			}
			if call == 1 {
				if amount != test.first {
					t.Fatal("wrong model conversion", amount)
				}
				q := wizardQuote()
				q.Amount = amount
				q.ExpectedFeeWei = test.fee
				return q, nil
			}
			if amount != test.recommended {
				t.Fatal("wrong recommendation", amount)
			}
			return zkapi.AddressPaymentQuote{}, stopped
		}
		ctx := context.WithValue(context.Background(), serveModelKey{}, test.model)
		if err := serveFunding(ctx, f, budget, &fundingWizardUI{}); !errors.Is(err, stopped) {
			t.Fatal(err)
		}
		if budget.model != test.model || f.approveCalls != 0 {
			t.Fatal("model mismatch or premature signing")
		}
	}
}

func TestRecommendedDeposit(t *testing.T) {
	for _, test := range []struct {
		units uint64
		fee   string
		want  uint64
	}{
		{100, "1", 300}, {100, "100000000000", 1000}, {1, "300000001", 4},
	} {
		got, err := recommendedDeposit(test.units, test.fee)
		if err != nil || got != test.want {
			t.Fatalf("%+v got %d: %v", test, got, err)
		}
	}
	for _, fee := range []string{"", "-1", "not-a-number", "1000000000000000000000000000000"} {
		if _, err := recommendedDeposit(1, fee); err == nil {
			t.Fatal("accepted", fee)
		}
	}
	if _, err := recommendedDeposit(^uint64(0), "1"); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestServeFundingExistingNoteDoesNotPrepareOrApprove(t *testing.T) {
	f := newWizardFixture()
	f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{HasNote: true, Balance: 750001} }
	ui := &fundingWizardUI{}
	if err := serveFunding(context.Background(), f, nil, ui); err != nil {
		t.Fatal(err)
	}
	if f.quoteCalls != 0 || f.approveCalls != 0 {
		t.Fatal("existing note mutated")
	}
}

func TestServeFundingRefusesReservedWithdrawal(t *testing.T) {
	f := newWizardFixture()
	f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{HasNote: true, WithdrawalPending: true} }
	if err := serveFunding(context.Background(), f, nil, &fundingWizardUI{}); err == nil {
		t.Fatal("expected stop")
	}
	if f.approveCalls != 0 {
		t.Fatal("approved reserved funds")
	}
}

func TestAutomaticDepositApprovalIsNarrowAndCancellable(t *testing.T) {
	ui := automaticDepositUI{&fundingWizardUI{}}
	if ok, err := ui.Continue(context.Background(), "Press Enter to continue with this deposit, or type cancel"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := ui.Continue(context.Background(), "Press Enter to withdraw, or type cancel"); ok || err == nil {
		t.Fatal("withdrawal auto-approved")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := ui.Continue(ctx, "Press Enter to continue with this deposit, or type cancel"); ok || err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestServeFundingMinimumWithoutSurplusAndNoTerminal(t *testing.T) {
	f := newWizardFixture()
	f.address = func() zkapi.AddressFundingStatus { s := wizardState("waiting_funds"); s.TransactionHash = ""; return s }
	f.quote = func(_ int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		q := wizardQuote()
		q = wizardBalance(q, q.RecommendedTotalWei)
		if amount != q.Amount || usd != 0 {
			t.Fatal("saved amount replaced")
		}
		return q, nil
	}
	ui := &fundingWizardUI{}
	if err := serveFunding(context.Background(), f, nil, ui); err != nil {
		t.Fatal(err)
	}
	if f.approveCalls != 1 || ui.continues != 0 || !strings.Contains(ui.String(), "Resuming unsigned deposit threshold") {
		t.Fatal(f.approveCalls, ui.String())
	}
}
