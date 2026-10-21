package zkapi

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// replayClosedForForward is TestGaslessWithdrawalRevertedByAReplayIsCollected
// up to the FORWARD's quote: a replay closed the note and paid the transit
// account, the sponsored close reverted, and --collect adopted the replay
// (the record complete, the companion told once) and quoted the forward.
func replayClosedForForward(t *testing.T) (*withdrawalFixture, *gaslessFixture, AddressPaymentQuote) {
	t.Helper()
	f, g := newGaslessWithdrawalFixture(t)
	hash := f.sponsoredClose(t)
	transit := common.HexToAddress(f.journal(t).Withdrawal.Transit.Account)
	replay := "0x" + strings.Repeat("c", 64)
	closeLog := map[string]any{"address": addressTestVault, "topics": []string{withdrawalEventTopic, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressWord(transit), "transactionHash": replay}
	f.mu.Lock()
	f.logs = append(f.logs, closeLog)
	f.receipts[replay] = map[string]any{"transactionHash": replay, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": addressTestVault, "logs": []map[string]any{closeLog}}
	f.closeNote(uint32(f.reservedNoteID))
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int).Set(gaslessPayoutWei)
	f.mu.Unlock()
	g.mineUserOp(t, hash, false, fixtureSettlement{Charged: big.NewInt(9)})
	if status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "op_reverted" {
		t.Fatalf("revert: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Collect: true}), withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.UserOpKind != "forward" {
		t.Fatalf("forward quote: %+v %v", quote, err)
	}
	if w := f.journal(t).Withdrawal; w.Phase != "complete" || !w.FundsWaitingInTransit || w.SettlementHash != replay || f.confirmCalls != 1 {
		t.Fatalf("the replay was not adopted: %+v", w)
	}
	return f, g, quote
}

// refusedForward approves the forward while the bundler refuses
// eth_sendUserOperation: the note is closed, so the record stays complete
// with the payout waiting in the transit account and the refusal shown,
// never gasless_refused (which would treat the closed note as a close to
// prove again); the forward's operation stays journaled.
func refusedForward(t *testing.T, f *withdrawalFixture, g *gaslessFixture, quote AddressPaymentQuote) string {
	t.Helper()
	f.mu.Lock()
	g.refuse, g.refuseMessage = true, "paymaster stake too low"
	f.mu.Unlock()
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(addressWithdrawalOptions{Collect: true}), quote.ID)
	if err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit || !strings.Contains(status.GaslessRefusal, "bundler_refused") || !strings.Contains(status.Message, "--collect") {
		t.Fatalf("refused forward: %+v %v", status, err)
	}
	record := f.journal(t)
	w := record.Withdrawal
	if w.Phase != "complete" || !w.FundsWaitingInTransit || w.UserOp == nil || w.UserOp.Kind != "forward" || w.UserOp.Hash == "" || w.UserOp.TransactionHash != "" || record.Phase != "ready" || f.confirmCalls != 1 {
		t.Fatalf("the refused forward moved the record: %+v %+v", record.Phase, w)
	}
	f.mu.Lock()
	g.refuse, g.refuseMessage = false, ""
	f.mu.Unlock()
	return w.UserOp.Hash
}

// A FORWARD the bundler refuses at eth_sendUserOperation leaves the
// completed withdrawal complete: a plain resume after a restart is a no-op,
// and --collect quotes a new forward without adopting the close again (the
// companion is told once).
func TestGaslessForwardRefusedAtSendKeepsTheRecordComplete(t *testing.T) {
	f, g, quote := replayClosedForForward(t)
	refusedForward(t, f, g, quote)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit || f.confirmCalls != 1 {
		t.Fatalf("plain resume: %+v %v", status, err)
	}
	if w := f.journal(t).Withdrawal; w.Phase != "complete" || w.UserOp == nil || w.UserOp.Kind != "forward" {
		t.Fatalf("plain resume changed the record: %+v", w)
	}
	collect := payoutContext(addressWithdrawalOptions{Collect: true})
	quote, err = f.h.QuoteAddressWithdrawal(collect, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.UserOpKind != "forward" || f.confirmCalls != 1 {
		t.Fatalf("collect again: %+v %v (confirm calls %d)", quote, err, f.confirmCalls)
	}
	status, err = f.h.ApproveAddressWithdrawal(collect, quote.ID)
	if err != nil || status.Phase != "forward_op_submitted" {
		t.Fatalf("forward: %+v %v", status, err)
	}
	charged := big.NewInt(300_000_000_000_000)
	paidOut := new(big.Int).Sub(gaslessPayoutWei, charged)
	g.mineUserOp(t, g.sends[len(g.sends)-1], true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: paidOut})
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.FundsWaitingInTransit || status.ReceivedWei != paidOut.String() || f.confirmCalls != 1 {
		t.Fatalf("forward completion: %+v %v", status, err)
	}
}

// A FORWARD the bundler refused but that was included after all (another
// bundler's mempool, say) is followed by the next --collect: the quote is
// refused with the resume command and the resume completes the record from
// the forward's settlement, instead of quoting a forward of an empty
// transit account.
func TestGaslessRefusedForwardIncludedAfterAllIsFollowed(t *testing.T) {
	f, g, quote := replayClosedForForward(t)
	hash := refusedForward(t, f, g, quote)
	var encoded gaslessUserOpJSON
	if err := json.Unmarshal(f.journal(t).Withdrawal.UserOp.JSON, &encoded); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	g.ops[hash] = encoded
	f.mu.Unlock()
	charged := big.NewInt(300_000_000_000_000)
	paidOut := new(big.Int).Sub(gaslessPayoutWei, charged)
	bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: paidOut})
	collect := payoutContext(addressWithdrawalOptions{Collect: true})
	if quote, err := f.h.QuoteAddressWithdrawal(collect, withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "included after all") {
		t.Fatalf("collect over a late forward: %+v %v", quote, err)
	}
	if w := f.journal(t).Withdrawal; w.Phase != "forward_op_submitted" || w.UserOp.Hash != hash {
		t.Fatalf("the late forward was not adopted: %+v", w)
	}
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.FundsWaitingInTransit || status.ReceivedWei != paidOut.String() || status.GaslessRefusal != "" || f.confirmCalls != 1 {
		t.Fatalf("late forward completion: %+v %v", status, err)
	}
	if w := f.journal(t).Withdrawal; len(w.CollectHashes) != 1 || w.CollectHashes[0] != bundle {
		t.Fatalf("collect hashes: %+v", w.CollectHashes)
	}
}

// The factory's InvalidPayee rule: a payout address the factory never
// accepts (the EntryPoint, the paymaster, the factory) is refused before
// anything is reserved, for a close and an escape alike.
func TestGaslessRefusesAPayeeTheFactoryRejects(t *testing.T) {
	for _, target := range []string{"entry point", "paymaster", "factory"} {
		t.Run(target, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			payee := map[string]common.Address{"entry point": g.entryPoint, "paymaster": g.paymaster, "factory": g.factory}[target]
			ctx := payoutContext(payoutFees)
			_, err := f.h.QuoteAddressWithdrawal(ctx, payee.Hex(), f.noteID, "", false)
			if err == nil || !strings.Contains(err.Error(), "invalid_payee") || len(f.prepareBodies) != 0 || f.journal(t).Withdrawal != nil {
				t.Fatalf("close to the %s: %v", target, err)
			}
			if _, err := f.h.WithdrawAddress(ctx, payee.Hex(), f.noteID); err == nil || !strings.Contains(err.Error(), "invalid_payee") {
				t.Fatalf("close to the %s: %v", target, err)
			}
			f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
			if _, err := f.h.EscapeAddress(ctx, payee.Hex(), f.noteID, nil, ""); err == nil || !strings.Contains(err.Error(), "invalid_payee") || len(f.escape.prepares) != 0 {
				t.Fatalf("escape to the %s: %v", target, err)
			}
			if f.journal(t).Withdrawal != nil {
				t.Fatal("a reservation was saved")
			}
		})
	}
	profile := gaslessProfile{EntryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032", Paymaster: "0x00000000000000000000000000000000000000aa", Factory: "0x00000000000000000000000000000000000000bb"}
	for _, payee := range []string{"0x0000000000000000000000000000000000000000", addressTestVault, "0x0000000071727de22e5e9d8baf0edac6f37da032"} {
		if err := checkGaslessPayee(profile, addressTestVault, payee); err == nil {
			t.Fatalf("%s accepted", payee)
		}
	}
	if err := checkGaslessPayee(profile, addressTestVault, withdrawalTestDestination); err != nil {
		t.Fatal(err)
	}
}
