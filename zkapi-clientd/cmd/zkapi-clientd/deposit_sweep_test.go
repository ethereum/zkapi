package main

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestSweepDepositAmount(t *testing.T) {
	q := zkapi.AddressPaymentQuote{BalanceWei: "8817812823798211", FeeReserveWei: "654387910833575"}
	got, err := sweepDepositAmount(q)
	if err != nil || got != 8163424 {
		t.Fatal(got, err)
	}
	q.BalanceWei = "1"
	if got, err := sweepDepositAmount(q); err != nil || got != 0 {
		t.Fatal(got, err)
	}
	q.BalanceWei = "-1"
	if _, err := sweepDepositAmount(q); err == nil {
		t.Fatal("negative balance")
	}
}

func sweepFixture() (*wizardFundingFixture, *zkapi.AddressPaymentQuote) {
	f := newWizardFixture()
	current := wizardQuote()
	f.address = func() zkapi.AddressFundingStatus {
		s := wizardState("waiting_funds")
		s.Amount = current.Amount
		s.TransactionHash = ""
		return s
	}
	f.quote = func(_ int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		q := current
		q.Amount = amount
		q.PrincipalWei = new(big.Int).Mul(new(big.Int).SetUint64(amount), big.NewInt(1_000_000_000)).String()
		principal, _ := new(big.Int).SetString(q.PrincipalWei, 10)
		fee, _ := new(big.Int).SetString(q.RequiredFeeWei, 10)
		reserve, _ := new(big.Int).SetString(q.FeeReserveWei, 10)
		q.RequiredTotalWei = new(big.Int).Add(principal, fee).String()
		q.RecommendedTotalWei = new(big.Int).Add(principal, reserve).String()
		q = wizardBalance(q, current.BalanceWei)
		current = q
		return q, nil
	}
	return f, &current
}

func TestMaximizeUnsignedDepositAndRejectPending(t *testing.T) {
	f, q := sweepFixture()
	before := *q
	resized, err := maximizeUnsignedDeposit(context.Background(), f, *q)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := sweepDepositAmount(before)
	if resized.Amount != want || resized.Amount <= before.Amount || f.approveCalls != 0 {
		t.Fatal("not maximized", resized.Amount, want)
	}
	f, q = sweepFixture()
	f.address = func() zkapi.AddressFundingStatus { return wizardState("deposit_pending") }
	if _, err := maximizeUnsignedDeposit(context.Background(), f, *q); err == nil || f.quoteCalls != 0 {
		t.Fatal("resized pending transaction")
	}
}

func TestAutomaticDepositApprovesResizedIntent(t *testing.T) {
	f, q := sweepFixture()
	initial := *q
	want, _ := sweepDepositAmount(initial)
	f.approve = func(string) (zkapi.AddressFundingStatus, error) {
		s := wizardState("active")
		s.Amount = q.Amount
		return s, nil
	}
	if err := waitAndDeposit(context.Background(), f, initial, automaticDepositUI{&fundingWizardUI{}}, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if f.approveCalls != 1 || q.Amount != want {
		t.Fatal("wrong approved amount", q.Amount, want)
	}
}

func TestSweepRequotesHigherFeesBeforeApproval(t *testing.T) {
	f, q := sweepFixture()
	initial := *q
	quote := f.quote
	f.quote = func(call int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		if call == 1 {
			q.FeeReserveWei = "1000030000"
			q.FeeBufferWei = "1000005000"
		}
		return quote(call, amount, usd)
	}
	resized, err := maximizeUnsignedDeposit(context.Background(), f, initial)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := sweepDepositAmount(resized)
	if f.quoteCalls != 2 || resized.Amount != want || f.approveCalls != 0 {
		t.Fatal("fee increase not requoted", f.quoteCalls, resized.Amount, want)
	}
}

func TestSweepRejectsChangedNonce(t *testing.T) {
	f, q := sweepFixture()
	quote := f.quote
	f.quote = func(call int, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
		next, err := quote(call, amount, usd)
		next.Nonce++
		return next, err
	}
	if _, err := maximizeUnsignedDeposit(context.Background(), f, *q); err == nil || f.approveCalls != 0 {
		t.Fatal("changed nonce accepted")
	}
}

func TestManualDepositDoesNotSweep(t *testing.T) {
	f, q := sweepFixture()
	initial := *q
	f.approve = func(string) (zkapi.AddressFundingStatus, error) {
		s := wizardState("active")
		s.Amount = q.Amount
		return s, nil
	}
	if err := waitAndDeposit(context.Background(), f, initial, &fundingWizardUI{confirmations: []bool{true}}, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	if q.Amount != initial.Amount {
		t.Fatal("explicit manual amount resized")
	}
}
