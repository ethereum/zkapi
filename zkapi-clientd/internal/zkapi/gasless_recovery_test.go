package zkapi

import (
	"context"
	"math/big"
	"strings"
	"testing"
)

// sponsoredCloseWithCap approves a gasless close quoted with a fee cap of
// 0.004 ETH (one fee bump fits under it) and returns the sent hash.
func (f *withdrawalFixture) sponsoredCloseWithCap(t *testing.T) string {
	t.Helper()
	return f.sponsoredCloseWith(t, addressWithdrawalOptions{Fees: "payout", FeeCapGwei: 4_000_000})
}

// createTransitAccount gives the transit account code, as a third party
// calling the permissionless factory with the initCode's owner and payee.
func (g *gaslessFixture) createTransitAccount(t *testing.T, account string) {
	t.Helper()
	g.f.mu.Lock()
	defer g.f.mu.Unlock()
	g.codes[strings.ToLower(account)] = g.vectors.TransitRuntimeCode
}

func (g *gaslessFixture) sentOp(t *testing.T, hash string) *gaslessUserOp {
	t.Helper()
	g.f.mu.Lock()
	encoded, ok := g.ops[hash]
	g.f.mu.Unlock()
	if !ok {
		t.Fatalf("the bundler never accepted %s", hash)
	}
	op, _ := gasfromJSON(t, encoded)
	return op
}

// A bundler refuses an initCode whose sender exists ("AA10 sender already
// constructed"): that is not an accepted re-send. The operation the bundler
// forgot is rebuilt without initCode and sent; the one it holds is followed
// to completion.
func TestGaslessResendRefusedForAnExistingAccountDropsInitCode(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	first := f.sponsoredClose(t)
	u := f.journal(t).Withdrawal.UserOp
	if !u.InitCode {
		t.Fatal("the first operation carries no initCode")
	}
	g.createTransitAccount(t, f.journal(t).Withdrawal.Transit.Account)
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first] = false
	status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash == first {
		t.Fatalf("the AA10 refusal was taken for an accepted re-send: %+v %v", status, err)
	}
	u = f.journal(t).Withdrawal.UserOp
	sent := g.sentOp(t, u.Hash)
	if u.InitCode || len(sent.InitCode) != 0 || g.sends[len(g.sends)-1] != u.Hash || len(u.Hashes) != 2 || u.Hashes[0] != first {
		t.Fatalf("the operation was not rebuilt without initCode: %+v", u)
	}
	old := g.sentOp(t, first)
	if sent.MaxFeePerGas.Cmp(old.MaxFeePerGas) != 0 || sent.Nonce.Cmp(old.Nonce) != 0 {
		t.Fatal("the rebuilt operation changed more than its initCode")
	}
	g.mineUserOp(t, u.Hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
		t.Fatalf("%+v %v", status, err)
	}
}

// A bump of an operation the bundler dropped for its fees is dry-run before
// it is journaled: an account created meanwhile drops initCode from the
// raised copy (the identical initCode would be refused as AA10 forever).
func TestGaslessFeeBumpAfterTheAccountWasCreatedDropsInitCode(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	first := f.sponsoredCloseWithCap(t)
	g.createTransitAccount(t, f.journal(t).Withdrawal.Transit.Account)
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first], g.refuseResend = false, true
	status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash == first {
		t.Fatalf("no bump: %+v %v", status, err)
	}
	u := f.journal(t).Withdrawal.UserOp
	bumped, old := g.sentOp(t, u.Hash), g.sentOp(t, first)
	if u.InitCode || len(bumped.InitCode) != 0 || bumped.MaxFeePerGas.Cmp(old.MaxFeePerGas) <= 0 || g.sends[len(g.sends)-1] != u.Hash {
		t.Fatalf("the bumped copy kept initCode or was not sent: %+v", u)
	}
	// The dry run caught it before anything was journaled or sent: no
	// copy with the stale initCode reached the bundler.
	if len(u.Hashes) != 2 || u.Hashes[0] != first || u.Hashes[1] != u.Hash {
		t.Fatalf("a copy with the stale initCode was signed: %v", u.Hashes)
	}
	g.refuseResend = false
	g.mineUserOp(t, u.Hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
		t.Fatalf("%+v %v", status, err)
	}
}

// The account created between the dry run and the send: the bundler's AA10
// refusal of the first send rebuilds the operation without initCode.
func TestGaslessFirstSendRefusedForAnExistingAccountDropsInitCode(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	quote, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	g.accountSeen = true
	status, err := f.h.ApproveAddressWithdrawal(ctx, quote.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	u := f.journal(t).Withdrawal.UserOp
	if sent := g.sentOp(t, u.Hash); u.InitCode || len(sent.InitCode) != 0 || len(g.sends) != 1 || g.sends[0] != u.Hash {
		t.Fatalf("the refused operation was journaled as submitted: %+v %v", u, g.sends)
	}
}

// A re-signed copy the bundler refuses leaves the record gasless_refused,
// but the earlier copy it took may still land: the next run looks for every
// journaled copy and follows the one included instead of proving again.
func TestGaslessRefusedBumpedCopyStillFollowsALateEarlierCopy(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	first := f.sponsoredCloseWithCap(t)
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first], g.refuse, g.refuseMessage = false, true, "maxFeePerGas too low"
	status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "gasless_refused" {
		t.Fatalf("the refused copy: %+v %v", status, err)
	}
	if u := f.journal(t).Withdrawal.UserOp; u == nil || len(u.Hashes) != 2 || u.Hashes[0] != first || u.SubmittedAt != 0 {
		t.Fatalf("the journal does not hold both copies: %+v", u)
	}
	g.refuse = false
	g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	prepares := len(f.prepareBodies)
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.UserOpHash != first || f.confirmCalls != 1 {
		t.Fatalf("the late copy was not followed: %+v %v", status, err)
	}
	if len(f.prepareBodies) != prepares {
		t.Fatal("the close was proved again")
	}
}

// --fees wallet after fee_bump_needs_quote: an operation included late is
// found before the fallback discards it. The wallet quote is refused with
// the resume command (a wallet-paid close of a closed note would revert and
// pay gas), the journal keeps every hash, and the resume completes.
func TestGaslessWalletFallbackFollowsALateOperation(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	first := f.sponsoredClose(t)
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first], g.refuseResend = false, true
	status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "gasless_refused" || !strings.Contains(status.GaslessRefusal, "fee_bump_needs_quote") {
		t.Fatalf("no stop: %+v %v", status, err)
	}
	g.refuseResend = false
	g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	prepares := len(f.prepareBodies)
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	if quote, err := f.h.QuoteAddressWithdrawal(wallet, withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "included after all") {
		t.Fatalf("a wallet quote over a late operation: %+v %v", quote, err)
	}
	w := f.journal(t).Withdrawal
	if w.FeePayer != "payout" || w.UserOp == nil || w.UserOp.Hash != first || w.Phase != "op_submitted" || len(f.prepareBodies) != prepares || f.journal(t).Pending != nil {
		t.Fatalf("the fallback discarded the operation: %+v", w)
	}
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.UserOpHash != first || f.confirmCalls != 1 || len(f.prepareBodies) != prepares {
		t.Fatalf("the late operation was not followed: %+v %v", status, err)
	}
}

// A sponsored close stopped as gasless_refused (fee_bump_needs_quote) that
// the bundler included after all is not turned into an escape: withdraw
// --escape looks for the dropped operation first. A quote request is
// refused with the resume command (the close is then in flight, which the
// escape refuses as well, until withdraw --to completes it); a plain run
// follows the close to its completion. Either way the companion is told the
// bundle transaction and no escape is prepared.
func TestGaslessEscapeOverARefusedCloseFollowsALateOperation(t *testing.T) {
	for _, quoted := range []bool{false, true} {
		t.Run(map[bool]string{false: "resume", true: "quoted"}[quoted], func(t *testing.T) {
			f, g := newGaslessEscapeFixture(t)
			first := f.sponsoredClose(t)
			f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
			g.known[first], g.refuseResend = false, true
			status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "gasless_refused" || !strings.Contains(status.GaslessRefusal, "fee_bump_needs_quote") {
				t.Fatalf("no stop: %+v %v", status, err)
			}
			g.refuseResend = false
			g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
			if quoted {
				if quote, err := f.h.QuoteAddressEscape(context.Background(), withdrawalTestDestination, f.noteID, nil, ""); err == nil || !strings.Contains(err.Error(), "included after all") || !strings.Contains(err.Error(), "withdraw --to") {
					t.Fatalf("an escape quote over a late close: %+v %v", quote, err)
				}
				if w := f.journal(t).Withdrawal; w.Mode != "" || w.UserOp == nil || w.UserOp.Hash != first || w.Phase != "op_submitted" {
					t.Fatalf("the escape discarded the close operation: %+v", w)
				}
				if _, err := f.h.EscapeAddress(context.Background(), withdrawalTestDestination, f.noteID, nil, ""); err == nil || !strings.Contains(err.Error(), "withdraw --to") {
					t.Fatalf("an escape over the close in flight: %v", err)
				}
				status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			} else {
				status, err = f.h.EscapeAddress(context.Background(), withdrawalTestDestination, f.noteID, nil, "")
			}
			if err != nil || status.Phase != "complete" || status.Mode != "" || status.UserOpHash != first || f.confirmCalls != 1 || len(f.escape.prepares) != 0 {
				t.Fatalf("the late close was not followed: %+v %v", status, err)
			}
			if w := f.journal(t).Withdrawal; w.Mode != "" || w.UserOp == nil || w.UserOp.Hash != first {
				t.Fatalf("record: %+v", w)
			}
		})
	}
}

// Without a quote request the --fees wallet fallback follows the late
// operation at once.
func TestGaslessWalletFallbackResumeFollowsALateOperation(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	first := f.sponsoredClose(t)
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first], g.refuseResend = false, true
	if status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "gasless_refused" {
		t.Fatalf("no stop: %+v %v", status, err)
	}
	g.refuseResend = false
	g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	status, err := f.h.WithdrawAddress(payoutContext(addressWithdrawalOptions{Fees: "wallet"}), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.UserOpHash != first || f.journal(t).Withdrawal.FeePayer != "payout" {
		t.Fatalf("the fallback did not follow the late operation: %+v %v", status, err)
	}
}
