package zkapi

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func newGaslessEscapeFixture(t *testing.T) (*withdrawalFixture, *gaslessFixture) {
	t.Helper()
	f, g := newGaslessWithdrawalFixture(t)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	return f, g
}

// sponsoredEscape decides, quotes and approves a gasless escape initiation
// and returns the sent operation's hash.
func (f *withdrawalFixture) sponsoredEscape(t *testing.T) string {
	t.Helper()
	ctx := payoutContext(payoutFees)
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_decision" {
		t.Fatalf("no decision: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil {
		t.Fatal(err)
	}
	status, err = f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash == "" {
		t.Fatalf("the initiation was not sent: %+v %v", status, err)
	}
	return status.UserOpHash
}

// Design 3.3 and 5.3: a gasless escape. The decision reserves the exit for
// the transit account; the initiation quote includes the finalization
// reserve; the sponsored initiation leaves the initiation's charge as the
// transit account's debt (EscapeInitiationOwed), reported to the companion
// with the bundle transaction; after the challenge deadline the finalization
// quote deducts that debt and the sponsored finalization settles it, and the
// record closes with the paymaster's figures.
func TestGaslessEscapeInitiatesFinalizesAndSettlesTheDebt(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_decision" || status.FeePayer != "payout" || status.TransitAccount == "" {
		t.Fatalf("decision: %+v %v", status, err)
	}
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	if w.Mode != "escape" || w.ProofDestination != transit.Hex() || len(f.escape.prepares) != 1 || !strings.EqualFold(fmt.Sprint(f.escape.prepares[0]["destination"]), transit.Hex()) {
		t.Fatalf("the escape was not reserved for the transit account: %+v %+v", w, f.escape.prepares)
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil {
		t.Fatal(err)
	}
	if quote.Kind != "escape" || quote.FeePolicy != "payout" || quote.UserOpKind != "escape" || quote.OwedWei != "0" || quote.Amount != gaslessTestBalance || quote.Binding == "" {
		t.Fatalf("initiation quote: %+v", quote)
	}
	reserve, _ := new(big.Int).SetString(quote.FinalizeReserveWei, 10)
	maxFee, _ := new(big.Int).SetString(quote.MaxFeePerGas, 10)
	if reserve.Cmp(new(big.Int).Mul(new(big.Int).SetUint64(g.profile.GasPolicy.FinalizeReserveGas), maxFee)) != 0 {
		t.Fatalf("the finalization reserve is %s at %s wei per gas", reserve, maxFee)
	}
	// An initiation promises no floor: the finalization is a later
	// operation at its own fees, so the quote estimates it the way it
	// estimates the initiation's charge (the paymaster's chargeFor at the
	// finalize shape's validation floors and measured execution, at the fee
	// paid now), and the payout received as the payout less both expected
	// charges and the debt. The maxima stay separate bounds.
	feeCap, _ := new(big.Int).SetString(quote.FeeCapWei, 10)
	expected, _ := new(big.Int).SetString(quote.ExpectedFeeWei, 10)
	estimate, _ := new(big.Int).SetString(quote.FinalizeEstimateWei, 10)
	estimated, _ := new(big.Int).SetString(quote.EstimatedReceivedWei, 10)
	// At the fee paid now (base fee plus tip, at most maxFeePerGas), not at
	// the operation's ceiling.
	baseFee, _ := new(big.Int).SetString(strings.TrimPrefix(f.gasPrice, "0x"), 16)
	tip, _ := new(big.Int).SetString(quote.MaxPriorityFeePerGas, 10)
	feeNow := new(big.Int).Add(baseFee, tip)
	if feeNow.Cmp(maxFee) >= 0 {
		t.Fatalf("the fixture's fee now %s is not below the ceiling %s", feeNow, maxFee)
	}
	policy := g.profile.GasPolicy
	finalizeOp := gaslessShapeOp(policy, gaslessKindFinalize, false, g.paymaster, g.flatFee, 0)
	floor, _, _ := policy.callLimits(gaslessKindFinalize)
	execution := floor - 20_000 - policy.AccountCallOverheadGas
	actual := finalizeOp.PreVerificationGas + policy.VerificationFloor + policy.PMVerificationFloor + execution + policy.AccountCallOverheadGas
	// The fixture's payout address is a fresh account.
	wantEstimate := gaslessChargeFor(policy, gaslessKindFinalize, actual, execution, finalizeOp.CallGasLimit, finalizeOp.PaymasterPostOpGasLimit, false, true, feeNow)
	wantEstimate.Add(wantEstimate, g.flatFee)
	wantReceived := new(big.Int).Sub(new(big.Int).Sub(gaslessPayoutWei, expected), wantEstimate)
	if quote.MinimumReceivedWei != "" || estimate == nil || estimated == nil || expected == nil || estimate.Cmp(wantEstimate) != 0 || estimated.Cmp(wantReceived) != 0 || expected.Cmp(feeCap) >= 0 {
		t.Fatalf("finalization estimate %s (want %s), estimated payout %s (want %s): %+v", estimate, wantEstimate, estimated, wantReceived, quote)
	}
	// The finalization's estimate is below its signed limits at the same
	// fee: the figure is an estimate, not the near-worst case.
	signedAtNow := new(big.Int).Mul(new(big.Int).SetUint64(finalizeOp.PreVerificationGas+finalizeOp.VerificationGasLimit+finalizeOp.CallGasLimit+finalizeOp.PaymasterVerificationGasLimit+finalizeOp.PaymasterPostOpGasLimit), feeNow)
	if new(big.Int).Sub(estimate, g.flatFee).Cmp(signedAtNow) >= 0 {
		t.Fatalf("the finalize estimate %s is not below its signed limits at today's fee %s", estimate, signedAtNow)
	}
	status, err = f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "op_submitted" || len(g.sends) != 1 || len(f.accepted) != 1 {
		t.Fatalf("initiation: %+v %v", status, err)
	}
	hash := status.UserOpHash
	sent, _ := gasfromJSON(t, g.ops[hash])
	vaultCall, _ := vaultCallOfTransitCallData(sent.CallData)
	if len(vaultCall) != withdrawalCalldataLength || hex.EncodeToString(vaultCall[:4]) != escapeSelector || hex.EncodeToString(vaultCall[4+10*32+12:4+11*32]) != strings.ToLower(transit.Hex()[2:]) {
		t.Fatal("the operation does not carry the escape bound to the transit account")
	}
	w = f.journal(t).Withdrawal
	if err := validateSignedEscape(vaultCall, fundingConfig{ChainID: 1, Contract: addressTestVault}, w, time.Now()); err != nil {
		t.Fatal(err)
	}
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "op_submitted" {
		t.Fatalf("poll: %+v %v", status, err)
	}
	charged := big.NewInt(1_500_000_000_000_000)
	bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Charged: charged})
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_initiated" || status.TransactionHash != bundle || status.InitiationDebtWei != charged.String() || status.ChallengeDeadline != f.escape.deadline {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	if len(f.escape.submitted) == 0 || !strings.EqualFold(f.escape.submitted[len(f.escape.submitted)-1], bundle) || g.owedOf(transit).Cmp(charged) != 0 {
		t.Fatal("the companion was not told the bundle transaction, or the debt was not recorded")
	}
	if _, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, ""); err == nil {
		t.Fatal("finalization quoted before the deadline")
	}
	// Restart: the saved initiation survives.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	f.escape.deadline, f.escape.payout = uint64(time.Now().Unix())-1, gaslessTestBalance
	quote, err = f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" || quote.UserOpKind != "finalize" || quote.OwedWei != charged.String() || quote.FinalizeReserveWei != "0" {
		t.Fatalf("finalization quote: %+v %v", quote, err)
	}
	feeCap, _ = new(big.Int).SetString(quote.FeeCapWei, 10)
	minimum, _ := new(big.Int).SetString(quote.MinimumReceivedWei, 10)
	if new(big.Int).Add(new(big.Int).Add(minimum, feeCap), charged).Cmp(gaslessPayoutWei) != 0 {
		t.Fatalf("the finalization's minimum does not deduct the debt: %+v", quote)
	}
	status, err = f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "finalize_op_submitted" || len(g.sends) != 2 {
		t.Fatalf("finalization: %+v %v", status, err)
	}
	finalize, _ := gasfromJSON(t, g.ops[g.sends[1]])
	if call, err := vaultCallOfTransitCallData(finalize.CallData); err != nil || "0x"+hex.EncodeToString(call) != finalizeEscapeCalldata(f.noteID) || new(big.Int).Rsh(finalize.Nonce, 64).Cmp(new(big.Int).SetBytes(common.FromHex(w.Nullifier))) != 0 || len(finalize.InitCode) != 0 {
		t.Fatalf("not the sponsored finalization: %+v", finalize)
	}
	finalizeCharge := big.NewInt(400_000_000_000_000)
	paidOut := new(big.Int).Sub(new(big.Int).Sub(gaslessPayoutWei, finalizeCharge), charged)
	bundle = g.mineUserOp(t, g.sends[1], true, fixtureSettlement{Received: gaslessPayoutWei, Charged: finalizeCharge, OwedPaid: charged, PaidOut: paidOut})
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "complete" || status.ChargedWei != finalizeCharge.String() || status.OwedPaidWei != charged.String() || status.ReceivedWei != paidOut.String() || status.FundsWaitingInTransit || status.PayoutCredited || status.Amount != gaslessTestBalance {
		t.Fatalf("completion: %+v %v", status, err)
	}
	if len(f.escape.finalized) != 1 || !strings.EqualFold(f.escape.finalized[0], bundle) || f.active || !strings.Contains(status.Message, "sponsored network fee") {
		t.Fatalf("the companion was not told the finalization: %v %s", f.escape.finalized, status.Message)
	}
	if record := f.journal(t); record.Withdrawal.FinalizeHash != bundle || record.Pending != nil || record.Phase != "ready" || len(f.accepted) != 1 {
		t.Fatalf("record: %+v", record.Withdrawal)
	}
}

// A sponsored escape finalized by someone else (the companion's chain view
// says closed, the vault paid the transit account): the record completes
// from that finalization, its payout waits in the transit account, and the
// same command quotes the sponsored FORWARD at once; its approval and
// settlement deliver the payout less the initiation's debt.
func TestGaslessEscapeFinalizedByAThirdPartyIsForwarded(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredEscape(t)
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	charged := big.NewInt(1_500_000_000_000_000)
	g.mineUserOp(t, hash, true, fixtureSettlement{Charged: charged})
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_initiated" {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	// A third party finalized the escape; the vault paid the transit account.
	third := "0x" + strings.Repeat("d", 64)
	finalized := map[string]any{"address": addressTestVault, "topics": []string{escapeFinalizedEventTopic, fmt.Sprintf("0x%064x", f.noteID)}, "data": "0x" + addressABIWord(w.Nullifier) + fmt.Sprintf("%064x", gaslessTestBalance) + addressWord(transit), "transactionHash": third}
	f.mu.Lock()
	f.logs = append(f.logs, finalized)
	f.receipts[third] = map[string]any{"transactionHash": third, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": addressTestVault, "logs": []map[string]any{finalized}}
	f.closeNote(uint32(f.noteID))
	delete(g.pending, uint32(f.noteID))
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int).Set(gaslessPayoutWei)
	f.mu.Unlock()
	f.escape.chainPhase, f.escape.deadline, f.escape.payout = "closed", uint64(time.Now().Unix())-1, gaslessTestBalance
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	w = record.Withdrawal
	if w.Phase != "complete" || !w.FundsWaitingInTransit || w.FinalizeHash != third || w.InitiationDebtWei != charged.String() || len(f.escape.finalized) != 1 || f.active {
		t.Fatalf("the third-party finalization was not adopted: %+v", w)
	}
	if quote.Kind != "withdrawal" || quote.UserOpKind != "forward" || quote.FeePolicy != "payout" || quote.OwedWei != charged.String() || quote.PayoutWei != gaslessPayoutWei.String() {
		t.Fatalf("forward quote: %+v", quote)
	}
	status, err := f.h.AddressWithdrawal(context.Background())
	if err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit || !strings.Contains(status.Message, "--collect") {
		t.Fatalf("status: %+v %v", status, err)
	}
	collect := payoutContext(addressWithdrawalOptions{Collect: true})
	status, err = f.h.ApproveAddressWithdrawal(collect, quote.ID)
	if err != nil || status.Phase != "forward_op_submitted" || len(g.sends) != 2 {
		t.Fatalf("forward: %+v %v", status, err)
	}
	forwardCharge := big.NewInt(300_000_000_000_000)
	paidOut := new(big.Int).Sub(new(big.Int).Sub(gaslessPayoutWei, forwardCharge), charged)
	g.mineUserOp(t, g.sends[1], true, fixtureSettlement{Received: gaslessPayoutWei, Charged: forwardCharge, OwedPaid: charged, PaidOut: paidOut})
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.FundsWaitingInTransit || status.ReceivedWei != paidOut.String() || status.OwedPaidWei != charged.String() || status.Mode != "escape" {
		t.Fatalf("forward completion: %+v %v", status, err)
	}
	if g.owedOf(transit).Sign() != 0 {
		t.Fatal("the debt was not settled")
	}
	// The escape command reports the same completion.
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "complete" || status.ReceivedWei != paidOut.String() {
		t.Fatalf("escape status: %+v %v", status, err)
	}
}

// A sponsored escape whose concession the operator raised and that someone
// else finalized: the record completes with the lowered payout, and the
// initiation's operation (which authorized the proof's B − c, no longer the
// record's Amount) is retired, so the journal still loads on the next run
// and the payout waiting in the transit account can be forwarded.
func TestGaslessEscapeRaisedAndFinalizedByAThirdPartyKeepsTheJournalValid(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredEscape(t)
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	g.mineUserOp(t, hash, true, fixtureSettlement{Charged: big.NewInt(1_500_000_000_000_000)})
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_initiated" {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	if w = f.journal(t).Withdrawal; w.UserOp == nil || w.UserOp.Kind != "escape" {
		t.Fatalf("the fixture no longer journals the initiation's operation: %+v", w.UserOp)
	}
	// The operator raised the concession by 900; a third party finalized
	// and the vault paid the lowered payout to the transit account.
	const raised = 900
	paid := uint64(gaslessTestBalance - raised)
	third := "0x" + strings.Repeat("d", 64)
	raise := map[string]any{"address": addressTestVault, "topics": []string{escapeConcessionRaisedTopic, fmt.Sprintf("0x%064x", f.noteID)}, "data": "0x" + addressABIWord(w.Nullifier) + fmt.Sprintf("%064x%064x", raised, paid), "removed": false}
	finalized := map[string]any{"address": addressTestVault, "topics": []string{escapeFinalizedEventTopic, fmt.Sprintf("0x%064x", f.noteID)}, "data": "0x" + addressABIWord(w.Nullifier) + fmt.Sprintf("%064x", paid) + addressWord(transit), "transactionHash": third}
	paidWei := new(big.Int).Mul(new(big.Int).SetUint64(paid), big.NewInt(1_000_000_000))
	f.mu.Lock()
	f.logs = append(f.logs, raise, finalized)
	f.receipts[third] = map[string]any{"transactionHash": third, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": addressTestVault, "logs": []map[string]any{finalized}}
	f.closeNote(uint32(f.noteID))
	delete(g.pending, uint32(f.noteID))
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int).Set(paidWei)
	f.mu.Unlock()
	f.escape.chainPhase, f.escape.deadline, f.escape.payout = "closed", uint64(time.Now().Unix())-1, paid
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "complete" || status.Amount != paid || !status.FundsWaitingInTransit {
		t.Fatalf("the raised third-party finalization was not adopted: %+v %v", status, err)
	}
	if w := f.journal(t).Withdrawal; w.Amount != paid || w.FinalizeHash != third || w.InitiateHash == "" {
		t.Fatalf("record: %+v", w)
	}
	// The next run loads the journal (every funding and withdrawal command
	// starts from it), and the payout in the transit account is forwarded.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if status, err := f.h.AddressWithdrawal(context.Background()); err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit {
		t.Fatalf("the journal no longer loads: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Collect: true}), withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.UserOpKind != "forward" || quote.PayoutWei != paidWei.String() {
		t.Fatalf("forward quote: %+v %v", quote, err)
	}
}

// The automatic forward after a third-party finalization is an operation
// like any other: when its fee may exceed the uneconomic fraction of what
// the transit account holds, it is refused as gasless_uneconomic (naming
// --allow-expensive-gas and --sweep) unless the command passed
// --allow-expensive-gas, which the quote then records.
func TestGaslessEscapeForwardAfterAThirdPartyFinalizationKeepsTheUneconomicRefusal(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredEscape(t)
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	charged := big.NewInt(100_000_000_000_000)
	g.mineUserOp(t, hash, true, fixtureSettlement{Charged: charged})
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_initiated" {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	// A third party finalized the escape; a small balance reached S.
	small := big.NewInt(5_000_000_000_000_000)
	third := "0x" + strings.Repeat("d", 64)
	finalized := map[string]any{"address": addressTestVault, "topics": []string{escapeFinalizedEventTopic, fmt.Sprintf("0x%064x", f.noteID)}, "data": "0x" + addressABIWord(w.Nullifier) + fmt.Sprintf("%064x", gaslessTestBalance) + addressWord(transit), "transactionHash": third}
	f.mu.Lock()
	f.logs = append(f.logs, finalized)
	f.receipts[third] = map[string]any{"transactionHash": third, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": addressTestVault, "logs": []map[string]any{finalized}}
	f.closeNote(uint32(f.noteID))
	delete(g.pending, uint32(f.noteID))
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int).Set(small)
	f.mu.Unlock()
	f.escape.chainPhase, f.escape.deadline, f.escape.payout = "closed", uint64(time.Now().Unix())-1, gaslessTestBalance
	refused, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if GaslessRefusalCode(err) != "gasless_uneconomic" || !strings.Contains(err.Error(), "--allow-expensive-gas") {
		t.Fatalf("the uneconomic forward was quoted: %+v %v", refused, err)
	}
	if w := f.journal(t).Withdrawal; w.Phase != "complete" || !w.FundsWaitingInTransit || (w.UserOp != nil && w.UserOp.Kind == "forward") || len(g.sends) != 1 {
		t.Fatalf("the refusal changed more than it should: %+v", w)
	}
	status, err := f.h.AddressWithdrawal(context.Background())
	if err != nil || !status.FundsWaitingInTransit || !strings.Contains(status.Message, "--sweep") {
		t.Fatalf("the way out is not shown: %+v %v", status, err)
	}
	// Accepted explicitly: quoted, and the quote records the acceptance.
	quote, err := f.h.QuoteAddressEscape(payoutContext(addressWithdrawalOptions{Fees: "payout", AllowExpensiveGas: true}), withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.UserOpKind != "forward" || !quote.AllowExpensiveGas || quote.PayoutWei != small.String() {
		t.Fatalf("the accepted forward: %+v %v", quote, err)
	}
	feeCap, _ := new(big.Int).SetString(quote.FeeCapWei, 10)
	if new(big.Int).Mul(feeCap, big.NewInt(100)).Cmp(new(big.Int).Mul(small, big.NewInt(25))) <= 0 {
		t.Fatalf("the fixture's forward fee %s is not uneconomic for %s", feeCap, small)
	}
}

// Escapes the paymaster does not sponsor (escapes disabled after the
// reservation): the initiation is refused with the way out, --fees wallet
// initiates it from the funding address bound to the transit account, and
// --fees payout on the initiated escape takes the sponsored path back for
// its finalization, which settles from the transit account.
func TestGaslessEscapeDisabledIsInitiatedWalletPaidAndFinalizedSponsored(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_decision" || status.FeePayer != "payout" {
		t.Fatalf("decision: %+v %v", status, err)
	}
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	g.escapesEnabled = false
	_, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if GaslessRefusalCode(err) != "escapes_disabled" || !strings.Contains(err.Error(), "--fees wallet") || !strings.Contains(err.Error(), "--fees payout") {
		t.Fatalf("initiation with escapes disabled: %v", err)
	}
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	if status, err := f.h.EscapeAddress(wallet, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_decision" || status.FeePayer != "wallet" {
		t.Fatalf("wallet decision: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil || quote.Kind != "escape" || quote.FeePolicy != "low" {
		t.Fatalf("wallet quote: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressEscape(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	w = record.Withdrawal
	initiate := f.accepted[record.Pending.Hash]
	if record.Pending.Kind != "escape" || hex.EncodeToString(initiate.Data()[4+10*32+12:4+11*32]) != strings.ToLower(transit.Hex()[2:]) {
		t.Fatal("the wallet-paid initiation is not bound to the transit account")
	}
	// --fees payout cannot take over while the initiation is pending.
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("the fee payer changed under a pending transaction: %v", err)
	}
	f.mine(t, record.Pending.Hash, false)
	f.mu.Lock()
	g.pending[uint32(f.noteID)] = fixturePending{nullifier: new(big.Int).SetBytes(common.FromHex(w.Nullifier)), finalBalance: gaslessTestBalance, destination: transit}
	f.mu.Unlock()
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	if status, err := f.h.EscapeAddress(wallet, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_initiated" || status.FeePayer != "wallet" {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	// Once the escape is on chain --fees payout takes the sponsored path
	// back for the finalization (pre-flight first).
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_initiated" || status.FeePayer != "payout" || f.journal(t).Withdrawal.FeePayer != "payout" {
		t.Fatalf("the sponsored path did not take over: %+v %v", status, err)
	}
	f.escape.deadline, f.escape.payout = uint64(time.Now().Unix())-1, gaslessTestBalance
	quote, err = f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" || quote.UserOpKind != "finalize" || quote.FeePolicy != "payout" || quote.OwedWei != "0" {
		t.Fatalf("finalization quote: %+v %v", quote, err)
	}
	status, err = f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "finalize_op_submitted" || len(g.sends) != 1 || len(f.accepted) != 2 {
		t.Fatalf("finalization: %+v %v", status, err)
	}
	finalizeCharge := big.NewInt(400_000_000_000_000)
	paidOut := new(big.Int).Sub(gaslessPayoutWei, finalizeCharge)
	g.mineUserOp(t, g.sends[0], true, fixtureSettlement{Received: gaslessPayoutWei, Charged: finalizeCharge, PaidOut: paidOut})
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "complete" || status.ReceivedWei != paidOut.String() || status.FundsWaitingInTransit || status.OwedPaidWei != "0" {
		t.Fatalf("completion: %+v %v", status, err)
	}
}

// Escapes disabled from the start (the published default): the first
// --fees payout run is refused as escapes_disabled, but the escape is still
// reserved for the transit account (the sponsored finalization passed its
// pre-flight), so the advice holds: --fees wallet initiates the escape bound
// to the transit account, and --fees payout on the escape on chain
// finalizes it sponsored and delivers the payout to the destination.
func TestGaslessEscapeDisabledFromTheStartIsStillFinalizedSponsored(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	g.escapesEnabled = false
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if GaslessRefusalCode(err) != "escapes_disabled" || !strings.Contains(err.Error(), "--fees wallet") || !strings.Contains(err.Error(), "--fees payout") {
		t.Fatalf("a fresh escape with escapes disabled: %+v %v", status, err)
	}
	w := f.journal(t).Withdrawal
	if w == nil || w.Transit == nil || w.FeePayer != "payout" || w.ProofDestination != w.Transit.Account || w.Phase != "escape_decision" || len(f.escape.prepares) != 0 {
		t.Fatalf("the escape was not reserved for the transit account: %+v", w)
	}
	transit := common.HexToAddress(w.Transit.Account)
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	if status, err := f.h.EscapeAddress(wallet, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_decision" || status.FeePayer != "wallet" {
		t.Fatalf("wallet decision: %+v %v", status, err)
	}
	if len(f.escape.prepares) != 1 || !strings.EqualFold(fmt.Sprint(f.escape.prepares[0]["destination"]), transit.Hex()) {
		t.Fatalf("the companion did not reserve the exit for the transit account: %+v", f.escape.prepares)
	}
	quote, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil || quote.Kind != "escape" || quote.FeePolicy != "low" {
		t.Fatalf("wallet quote: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressEscape(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	w = record.Withdrawal
	if initiate := f.accepted[record.Pending.Hash]; record.Pending.Kind != "escape" || hex.EncodeToString(initiate.Data()[4+10*32+12:4+11*32]) != strings.ToLower(transit.Hex()[2:]) {
		t.Fatal("the wallet-paid initiation is not bound to the transit account")
	}
	f.mine(t, record.Pending.Hash, false)
	f.mu.Lock()
	g.pending[uint32(f.noteID)] = fixturePending{nullifier: new(big.Int).SetBytes(common.FromHex(w.Nullifier)), finalBalance: gaslessTestBalance, destination: transit}
	f.mu.Unlock()
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	if status, err := f.h.EscapeAddress(wallet, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_initiated" {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.FeePayer != "payout" {
		t.Fatalf("the sponsored path did not take over: %+v %v", status, err)
	}
	f.escape.deadline, f.escape.payout = uint64(time.Now().Unix())-1, gaslessTestBalance
	quote, err = f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" || quote.UserOpKind != "finalize" || quote.FeePolicy != "payout" {
		t.Fatalf("finalization quote: %+v %v", quote, err)
	}
	if status, err := f.h.ApproveAddressEscape(ctx, quote.ID); err != nil || status.Phase != "finalize_op_submitted" {
		t.Fatalf("finalization: %+v %v", status, err)
	}
	finalizeCharge := big.NewInt(400_000_000_000_000)
	paidOut := new(big.Int).Sub(gaslessPayoutWei, finalizeCharge)
	g.mineUserOp(t, g.sends[0], true, fixtureSettlement{Received: gaslessPayoutWei, Charged: finalizeCharge, PaidOut: paidOut})
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "complete" || status.ReceivedWei != paidOut.String() || status.FundsWaitingInTransit {
		t.Fatalf("completion: %+v %v", status, err)
	}
}

// When escapes are disabled and a sponsored finalization would be refused
// too (here: its fee would take too much of a small payout), nothing is
// reserved and the refusal names only --fees wallet, which then escapes to
// the payout address.
func TestGaslessEscapeDisabledWithoutASponsoredFinalizationReservesNothing(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	f.walletBalance, f.planBalance = 8_000_000, 8_000_000
	g.escapesEnabled = false
	_, err := f.h.EscapeAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, nil, "")
	if GaslessRefusalCode(err) != "escapes_disabled" || !strings.Contains(err.Error(), "--fees wallet") || strings.Contains(err.Error(), "--fees payout") || !strings.Contains(err.Error(), "gasless_uneconomic") {
		t.Fatalf("refusal: %v", err)
	}
	if w := f.journal(t).Withdrawal; w != nil || len(f.escape.prepares) != 0 {
		t.Fatalf("something was reserved: %+v", w)
	}
	status, err := f.h.EscapeAddress(payoutContext(addressWithdrawalOptions{Fees: "wallet"}), withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_decision" || status.TransitAccount != "" || !strings.EqualFold(fmt.Sprint(f.escape.prepares[0]["destination"]), withdrawalTestDestination) {
		t.Fatalf("wallet decision: %+v %v", status, err)
	}
}

// A sponsored initiation that reverts (or is refused) is decided and proved
// again, like a reverted wallet-paid initiation; --fees wallet falls back to
// the wallet-paid initiation bound to the transit account.
func TestGaslessEscapeRevertedInitiationIsDecidedAgain(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredEscape(t)
	g.mineUserOp(t, hash, false, fixtureSettlement{Charged: big.NewInt(1)})
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "op_reverted" {
		t.Fatalf("revert: %+v %v", status, err)
	}
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_decision" || f.journal(t).Withdrawal.UserOp != nil {
		t.Fatalf("no fresh decision: %+v %v", status, err)
	}
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	quote, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil || quote.Kind != "escape" || quote.FeePolicy != "low" {
		t.Fatalf("wallet quote: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressEscape(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "escape" || record.Withdrawal.FeePayer != "wallet" {
		t.Fatalf("no wallet-paid initiation: %+v", record.Withdrawal)
	}
	tx := f.accepted[record.Pending.Hash]
	if hex.EncodeToString(tx.Data()[4+10*32+12:4+11*32]) != strings.ToLower(record.Withdrawal.Transit.Account[2:]) {
		t.Fatal("the wallet-paid initiation is not bound to the transit account")
	}
}

// A sponsored initiation that was mined and followed is not a dropped
// operation: when the finalization's quote is refused (the paymaster
// paused sponsorship, standing for any refusal), the record stops as
// gasless_refused with the initiation's operation still journaled, and
// --fees wallet must then sign the wallet-paid finalization instead of
// adopting the initiation's inclusion as a "late" operation.
func TestGaslessEscapeRefusedFinalizationFallsBackToTheWallet(t *testing.T) {
	f, g := newGaslessEscapeFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredEscape(t)
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	charged := big.NewInt(1_500_000_000_000_000)
	bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Charged: charged})
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_initiated" {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	f.escape.deadline, f.escape.payout = uint64(time.Now().Unix())-1, gaslessTestBalance
	f.mu.Lock()
	g.sponsorshipPaused = true
	f.mu.Unlock()
	if _, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, ""); GaslessRefusalCode(err) != "sponsorship_paused" {
		t.Fatalf("the finalization was quoted while sponsorship is paused: %v", err)
	}
	w = f.journal(t).Withdrawal
	if w.Phase != "gasless_refused" || w.UserOp == nil || w.UserOp.Kind != "escape" || !strings.EqualFold(w.UserOp.TransactionHash, bundle) {
		t.Fatalf("refused finalization: %+v", w)
	}
	// A plain resume asks for the finalization again (and is refused
	// again): the initiation is not followed a second time.
	finalizedBefore := len(f.escape.finalized)
	if _, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, ""); GaslessRefusalCode(err) != "sponsorship_paused" {
		t.Fatalf("resume: %v", err)
	}
	if w := f.journal(t).Withdrawal; w.Phase != "gasless_refused" || w.FeePayer != "payout" {
		t.Fatalf("resume: %+v", w)
	}
	// --fees wallet: the wallet-paid finalization, quoted and signed.
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	quote, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" || quote.FeePolicy != "low" {
		t.Fatalf("wallet finalization quote: %+v %v", quote, err)
	}
	w = f.journal(t).Withdrawal
	if w.FeePayer != "wallet" || w.UserOp != nil || w.Phase != "escape_initiated" || w.InitiateHash != bundle || w.TransactionHash != bundle {
		t.Fatalf("the fallback did not switch the fee payer: %+v", w)
	}
	if _, err := f.h.ApproveAddressEscape(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "escape_finalize" || record.Withdrawal.FeePayer != "wallet" {
		t.Fatalf("no wallet-paid finalization: %+v %+v", record.Pending, record.Withdrawal)
	}
	if tx := f.accepted[record.Pending.Hash]; tx == nil || "0x"+hex.EncodeToString(tx.Data()) != finalizeEscapeCalldata(f.noteID) {
		t.Fatal("the wallet-paid transaction is not finalizeEscapeWithdrawal")
	}
	if len(f.escape.finalized) != finalizedBefore || g.owedOf(transit).Cmp(charged) != 0 {
		t.Fatal("the initiation's inclusion was reported or settled again")
	}
}
