package zkapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// installGaslessProfile replaces the packaged mainnet profile, for the rest
// of the test, with one whose gasless object is edit's answer: nil publishes
// gasless: null (the paymaster's retirement), an edited copy pins other
// contracts.
func installGaslessProfile(t *testing.T, edit func(gasless map[string]any) any) {
	t.Helper()
	files := fstest.MapFS{}
	for _, network := range []string{"mainnet", "sepolia"} {
		raw, err := os.ReadFile(filepath.Join("testdata", "deployed", "deployments", network+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if network == "mainnet" {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var manifest map[string]any
			if err := decoder.Decode(&manifest); err != nil {
				t.Fatal(err)
			}
			gasless, _ := manifest["gasless"].(map[string]any)
			manifest["gasless"] = edit(gasless)
			if raw, err = json.Marshal(manifest); err != nil {
				t.Fatal(err)
			}
		}
		files["deployments/"+network+".json"] = &fstest.MapFile{Data: raw}
	}
	t.Cleanup(SetPackagedDeploymentsForTesting(files))
}

// retireGasless publishes gasless: null.
func retireGasless(t *testing.T) {
	t.Helper()
	installGaslessProfile(t, func(map[string]any) any { return nil })
}

// otherPaymasterProfile pins another paymaster than the records were made
// under.
func otherPaymasterProfile(t *testing.T) string {
	t.Helper()
	other := common.HexToAddress("0x" + strings.Repeat("7e", 20)).Hex()
	installGaslessProfile(t, func(gasless map[string]any) any {
		gasless["withdrawal_paymaster_address"] = other
		return gasless
	})
	return other
}

// sweepTransitAccount runs --sweep to completion: the account's creation
// first when it has no code, then the sweep; it returns the sweep's hash.
func sweepTransitAccount(t *testing.T, f *withdrawalFixture, g *gaslessFixture, transit common.Address) string {
	t.Helper()
	sweep := payoutContext(addressWithdrawalOptions{Sweep: true})
	for round := 0; round < 2; round++ {
		quote, err := f.h.QuoteAddressWithdrawal(sweep, withdrawalTestDestination, f.noteID, "", false)
		if err != nil || (quote.Kind != "transit_create" && quote.Kind != "transit_sweep") {
			t.Fatalf("sweep quote: %+v %v", quote, err)
		}
		if _, err := f.h.ApproveAddressWithdrawal(sweep, quote.ID); err != nil {
			t.Fatal(err)
		}
		record := f.journal(t)
		tx := f.accepted[record.Pending.Hash]
		if record.Pending.Kind == "transit_create" {
			if !strings.EqualFold(tx.To().Hex(), g.factory.Hex()) {
				t.Fatal("the creation is not on the journaled factory")
			}
			f.mu.Lock()
			f.receipts[record.Pending.Hash] = map[string]any{"transactionHash": record.Pending.Hash, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": g.factory.Hex(), "logs": []map[string]any{}}
			f.nonce = fmt.Sprintf("0x%x", tx.Nonce()+1)
			g.codes[strings.ToLower(transit.Hex())] = g.vectors.TransitRuntimeCode
			f.mu.Unlock()
			continue
		}
		if record.Pending.Kind != "transit_sweep" || !strings.EqualFold(tx.To().Hex(), transit.Hex()) || hex.EncodeToString(tx.Data()) != selectorTransitSweep {
			t.Fatal("the sweep is not sweep() on the journaled transit account")
		}
		f.mu.Lock()
		f.receipts[record.Pending.Hash] = map[string]any{"transactionHash": record.Pending.Hash, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": transit.Hex(), "logs": []map[string]any{{"address": g.paymaster.Hex(), "topics": []string{paymasterCollectedTopic, "0x" + addressWord(transit), "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": "0x" + wordHex(gaslessPayoutWei) + wordHex(big.NewInt(0)) + wordHex(gaslessPayoutWei)}}}
		f.nonce = fmt.Sprintf("0x%x", tx.Nonce()+1)
		f.mu.Unlock()
		return record.Pending.Hash
	}
	t.Fatal("the sweep was never quoted")
	return ""
}

// Phase D: once the profile publishes gasless: null, the payout sitting in
// a transit account is still delivered by --sweep through the contracts
// journaled with the record (a forward the bundler refused stays journaled,
// and its late-inclusion look reads the journaled EntryPoint), while the
// sponsored --collect is refused with gasless_record_not_pinned, which names
// the sweep.
func TestGaslessRetiredProfileKeepsTheSweepAndRefusesTheSponsoredCollect(t *testing.T) {
	f, g, quote := replayClosedForForward(t)
	refusedForward(t, f, g, quote)
	transit := common.HexToAddress(f.journal(t).Withdrawal.Transit.Account)
	retireGasless(t)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	collect := payoutContext(addressWithdrawalOptions{Collect: true})
	_, err := f.h.QuoteAddressWithdrawal(collect, withdrawalTestDestination, f.noteID, "", false)
	if GaslessRefusalCode(err) != GaslessRecordNotPinned || !strings.Contains(err.Error(), "--sweep") || !strings.Contains(err.Error(), "publishes no gasless paymaster") {
		t.Fatalf("a sponsored collect under a retired profile: %v", err)
	}
	sends := len(g.sends)
	hash := sweepTransitAccount(t, f, g, transit)
	status, err := f.h.WithdrawAddress(payoutContext(addressWithdrawalOptions{}), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.FundsWaitingInTransit || status.ReceivedWei != gaslessPayoutWei.String() || f.journal(t).Withdrawal.SweepHash != strings.ToLower(hash) {
		t.Fatalf("sweep completion under a retired profile: %+v %v", status, err)
	}
	if len(g.sends) != sends {
		t.Fatal("the sweep contacted the bundler")
	}
}

// S.sweep() is permissionless: when someone else emptied the transit
// account after the profile was retired, --sweep finds nothing to sweep,
// signs nothing and stops waiting for the payout (the sponsored --collect
// is refused under a retired profile), so a new deposit can be funded.
func TestGaslessRetiredProfileSweepOfAnEmptiedTransitAccountStopsWaiting(t *testing.T) {
	f, g, quote := replayClosedForForward(t)
	refusedForward(t, f, g, quote)
	transit := common.HexToAddress(f.journal(t).Withdrawal.Transit.Account)
	retireGasless(t)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	f.mu.Lock()
	g.codes[strings.ToLower(transit.Hex())] = g.vectors.TransitRuntimeCode
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int)
	f.mu.Unlock()
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); !errors.Is(err, errWithdrawalPayoutWaiting) {
		t.Fatalf("a deposit while the payout waits: %v", err)
	}
	sweep := payoutContext(addressWithdrawalOptions{Sweep: true})
	if _, err := f.h.QuoteAddressWithdrawal(sweep, withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "holds nothing to sweep") {
		t.Fatalf("a sweep of an empty transit account: %v", err)
	}
	record := f.journal(t)
	if w := record.Withdrawal; record.Pending != nil || w.FundsWaitingInTransit || w.Phase != "complete" {
		t.Fatalf("the record still waits for the payout: %+v", w)
	}
	if status, err := f.h.AddressWithdrawal(context.Background()); err != nil || status.FundsWaitingInTransit {
		t.Fatalf("status: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); errors.Is(err, errWithdrawalPayoutWaiting) {
		t.Fatalf("a deposit after the third-party sweep: %v", err)
	}
}

// Without the profile's creation code, the journaled factory's getAddress is
// what binds the journaled account: a journal naming another account for
// the owner and payout address is refused before anything is signed.
func TestGaslessRetiredProfileSweepChecksTheJournaledFactory(t *testing.T) {
	f, g, quote := replayClosedForForward(t)
	refusedForward(t, f, g, quote)
	retireGasless(t)
	record := f.journal(t)
	// An edited journal naming another account (and proof destination):
	// the journaled factory derives the real one for its owner and payee.
	forged := common.HexToAddress("0x" + strings.Repeat("5d", 20)).Hex()
	record.Withdrawal.Transit.Account, record.Withdrawal.ProofDestination, record.Withdrawal.UserOp = forged, forged, nil
	if err := f.h.saveAddress(&record); err != nil {
		t.Fatal(err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	accepted := len(f.accepted)
	if _, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Sweep: true}), withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "factory derives another account") {
		t.Fatalf("a sweep of an account the journaled factory does not derive: %v", err)
	}
	if len(f.accepted) != accepted || f.journal(t).Pending != nil {
		t.Fatal("something was signed")
	}
}

// A payout the paymaster credited is claimed from the journaled paymaster
// after the profile retired its pins.
func TestGaslessRetiredProfileKeepsTheCreditClaim(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	hash := f.sponsoredClose(t)
	charged := big.NewInt(11)
	credited := new(big.Int).Sub(gaslessPayoutWei, charged)
	g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, Credited: credited})
	if status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID); err != nil || !status.PaymasterCredited {
		t.Fatalf("credited: %+v %v", status, err)
	}
	retireGasless(t)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	claim := payoutContext(addressWithdrawalOptions{ClaimCredit: true})
	quote, err := f.h.QuoteAddressWithdrawal(claim, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.Kind != "gasless_claim" {
		t.Fatalf("claim quote under a retired profile: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressWithdrawal(claim, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	tx := f.accepted[record.Pending.Hash]
	if record.Pending.Kind != "gasless_claim" || !strings.EqualFold(tx.To().Hex(), g.paymaster.Hex()) || "0x"+hex.EncodeToString(tx.Data()) != record.Withdrawal.transitClaimCalldata() {
		t.Fatal("the claim is not claimCredit(Y) on the journaled paymaster")
	}
	f.mu.Lock()
	f.receipts[record.Pending.Hash] = map[string]any{"transactionHash": record.Pending.Hash, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": g.paymaster.Hex(), "logs": []map[string]any{{"address": g.paymaster.Hex(), "topics": []string{paymasterCreditClaimedTopic, "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": "0x" + wordHex(credited)}}}
	f.nonce = fmt.Sprintf("0x%x", tx.Nonce()+1)
	f.mu.Unlock()
	status, err := f.h.WithdrawAddress(payoutContext(addressWithdrawalOptions{}), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.ReceivedWei != credited.String() || f.journal(t).Withdrawal.ClaimHash != strings.ToLower(record.Pending.Hash) {
		t.Fatalf("claim completion under a retired profile: %+v %v", status, err)
	}
}

// escapeAwaitingFinalization is a sponsored escape whose initiation landed
// and whose challenge period is over.
func escapeAwaitingFinalization(t *testing.T) (*withdrawalFixture, *gaslessFixture, string) {
	t.Helper()
	f, g := newGaslessEscapeFixture(t)
	hash := f.sponsoredEscape(t)
	bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Charged: big.NewInt(1_500_000_000_000_000)})
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	if status, err := f.h.EscapeAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_initiated" {
		t.Fatalf("initiated: %+v %v", status, err)
	}
	f.escape.deadline, f.escape.payout = uint64(time.Now().Unix())-1, gaslessTestBalance
	return f, g, bundle
}

// A sponsored escape whose profile then retired its pins: the sponsored
// finalization is refused with gasless_record_not_pinned (naming --fees
// wallet), and --fees wallet signs the plain vault finalization.
func TestGaslessRetiredProfileRefusesTheSponsoredFinalizationAndKeepsTheWalletOne(t *testing.T) {
	f, g, bundle := escapeAwaitingFinalization(t)
	retireGasless(t)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	sends := len(g.sends)
	_, err := f.h.QuoteAddressEscape(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, nil, "")
	if GaslessRefusalCode(err) != GaslessRecordNotPinned || !strings.Contains(err.Error(), "--fees wallet") {
		t.Fatalf("a sponsored finalization under a retired profile: %v", err)
	}
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	quote, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" || quote.FeePolicy != "low" {
		t.Fatalf("wallet finalization quote under a retired profile: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressEscape(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "escape_finalize" || record.Withdrawal.FeePayer != "wallet" || record.Withdrawal.InitiateHash != bundle {
		t.Fatalf("no wallet-paid finalization: %+v %+v", record.Pending, record.Withdrawal)
	}
	if tx := f.accepted[record.Pending.Hash]; tx == nil || !strings.EqualFold(tx.To().Hex(), addressTestVault) || "0x"+hex.EncodeToString(tx.Data()) != finalizeEscapeCalldata(f.noteID) {
		t.Fatal("the wallet-paid transaction is not finalizeEscapeWithdrawal on the vault")
	}
	if len(g.sends) != sends {
		t.Fatal("an operation was sent")
	}
}

// A profile whose pins name another paymaster than the record's refuses
// the record's sponsored recovery the same way (a FORWARD, a FINALIZE, and
// switching a wallet-paid record back to sponsored), while the sweep keeps
// using the journaled contracts.
func TestGaslessProfileWithAnotherPaymasterRefusesSponsoredRecovery(t *testing.T) {
	t.Run("collect", func(t *testing.T) {
		f, g, quote := replayClosedForForward(t)
		refusedForward(t, f, g, quote)
		transit := common.HexToAddress(f.journal(t).Withdrawal.Transit.Account)
		other := otherPaymasterProfile(t)
		f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
		_, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Collect: true}), withdrawalTestDestination, f.noteID, "", false)
		if GaslessRefusalCode(err) != GaslessRecordNotPinned || !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), g.paymaster.Hex()) {
			t.Fatalf("a sponsored collect under another paymaster: %v", err)
		}
		sweepTransitAccount(t, f, g, transit)
	})
	t.Run("finalize", func(t *testing.T) {
		f, _, _ := escapeAwaitingFinalization(t)
		otherPaymasterProfile(t)
		f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
		if _, err := f.h.QuoteAddressEscape(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, nil, ""); GaslessRefusalCode(err) != GaslessRecordNotPinned {
			t.Fatalf("a sponsored finalization under another paymaster: %v", err)
		}
		// Back to the wallet, then asking for the sponsored path again is
		// refused before the fee payer changes.
		wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
		if quote, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, nil, ""); err != nil || quote.Kind != "escape_finalize" {
			t.Fatalf("wallet finalization quote under another paymaster: %+v %v", quote, err)
		}
		if _, err := f.h.QuoteAddressEscape(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, nil, ""); GaslessRefusalCode(err) != GaslessRecordNotPinned {
			t.Fatalf("switching back to sponsored under another paymaster: %v", err)
		}
		if w := f.journal(t).Withdrawal; w.FeePayer != "wallet" {
			t.Fatalf("the refused switch changed the fee payer: %+v", w)
		}
	})
}

// sponsoredFinalization quotes and approves the sponsored finalization of
// an escape awaiting it and returns the sent operation's hash.
func sponsoredFinalization(t *testing.T, f *withdrawalFixture, g *gaslessFixture) string {
	t.Helper()
	ctx := payoutContext(payoutFees)
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.UserOpKind != "finalize" {
		t.Fatalf("finalization quote: %+v %v", quote, err)
	}
	if status, err := f.h.ApproveAddressEscape(ctx, quote.ID); err != nil || status.Phase != "finalize_op_submitted" {
		t.Fatalf("finalization: %+v %v", status, err)
	}
	return g.sends[len(g.sends)-1]
}

// ageInFlightOperation backdates the journaled operation's build and send
// by an hour, long past the time a bundler takes to include it (the tab or
// process that sent it was closed meanwhile).
func ageInFlightOperation(t *testing.T, f *withdrawalFixture) {
	t.Helper()
	hourAgo := time.Now().Add(-time.Hour).Unix()
	f.editJournal(t, func(record *addressFundingRecord) {
		record.Withdrawal.UserOp.SubmittedAt, record.Withdrawal.UserOp.BuiltAt = hourAgo, hourAgo
	})
}

// Phase D follow-up: a sponsored operation already sent when the profile
// retired its pins is followed through the journaled contracts. Included,
// the record settles from its inclusion like any other; nothing is sent.
func TestGaslessRetiredProfileFollowsAnOperationInFlightToItsSettlement(t *testing.T) {
	plain := payoutContext(addressWithdrawalOptions{})
	t.Run("close", func(t *testing.T) {
		f, g := newGaslessWithdrawalFixture(t)
		hash := f.sponsoredClose(t)
		retireGasless(t)
		f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
		sends := len(g.sends)
		charged := big.NewInt(2_000_000_000_000_000)
		paidOut := new(big.Int).Sub(gaslessPayoutWei, charged)
		bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: paidOut})
		f.finalized = "0x20"
		status, err := f.h.WithdrawAddress(plain, withdrawalTestDestination, f.noteID)
		if err != nil || status.Phase != "complete" || status.TransactionHash != bundle || status.ChargedWei != charged.String() || status.ReceivedWei != paidOut.String() || status.FundsWaitingInTransit || f.confirmCalls != 1 {
			t.Fatalf("an included close under a retired profile: %+v %v", status, err)
		}
		if len(g.sends) != sends {
			t.Fatal("an operation was sent")
		}
	})
	t.Run("finalize", func(t *testing.T) {
		f, g, _ := escapeAwaitingFinalization(t)
		hash := sponsoredFinalization(t, f, g)
		retireGasless(t)
		f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
		sends := len(g.sends)
		charged, owed := big.NewInt(400_000_000_000_000), big.NewInt(1_500_000_000_000_000)
		paidOut := new(big.Int).Sub(new(big.Int).Sub(gaslessPayoutWei, charged), owed)
		bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, OwedPaid: owed, PaidOut: paidOut})
		status, err := f.h.EscapeAddress(plain, withdrawalTestDestination, f.noteID, nil, "")
		if err != nil || status.Phase != "complete" || status.ChargedWei != charged.String() || status.ReceivedWei != paidOut.String() || status.FundsWaitingInTransit {
			t.Fatalf("an included finalization under a retired profile: %+v %v", status, err)
		}
		if f.journal(t).Withdrawal.FinalizeHash != bundle || len(g.sends) != sends {
			t.Fatal("the finalization was not settled from its inclusion, or an operation was sent")
		}
	})
}

// Phase D follow-up: a sponsored finalization sent, then left (the process
// stopped), then the profile retires its pins. The resume follows it on
// chain without re-sending it; once a bundler would have included it, it is
// released (gasless_record_not_pinned, naming --fees wallet), and the
// wallet-paid finalization proceeds. Before the release the wallet path
// waits for the operation in flight.
func TestGaslessRetiredProfileReleasesAFinalizationInFlightForTheWallet(t *testing.T) {
	f, g, initiation := escapeAwaitingFinalization(t)
	sponsoredFinalization(t, f, g)
	retireGasless(t)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	sends := len(g.sends)
	plain := payoutContext(addressWithdrawalOptions{})
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	// Just sent: it is followed, not released.
	if status, err := f.h.EscapeAddress(plain, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "finalize_op_submitted" {
		t.Fatalf("a fresh operation under a retired profile: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, nil, ""); err == nil || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("a wallet finalization over an operation in flight: %v", err)
	}
	ageInFlightOperation(t, f)
	calls := len(g.bundlerCalls)
	status, err := f.h.EscapeAddress(plain, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "gasless_refused" || !strings.HasPrefix(status.GaslessRefusal, GaslessRecordNotPinned+":") || !strings.Contains(status.GaslessRefusal, "--escape --to "+withdrawalTestDestination+" --fees wallet") {
		t.Fatalf("the operation was not released: %+v %v", status, err)
	}
	// As docs/deployment.md states: under a retired profile the resume still
	// asks the bundler it sent the operation to for a receipt (read-only),
	// and sends nothing to it.
	asked := false
	for _, method := range g.bundlerCalls[calls:] {
		if method == "eth_getUserOperationReceipt" {
			asked = true
		}
		if method == "eth_sendUserOperation" {
			t.Fatal("an operation was sent to the bundler under a retired profile")
		}
	}
	if !asked {
		t.Fatalf("the resume did not ask the bundler for a receipt: %v", g.bundlerCalls[calls:])
	}
	if w := f.journal(t).Withdrawal; w.UserOp == nil || w.InitiateHash != initiation {
		t.Fatalf("the release dropped the journaled operation or the initiation: %+v", w)
	}
	quote, err := f.h.QuoteAddressEscape(wallet, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" || quote.FeePolicy != "low" {
		t.Fatalf("wallet finalization quote after the release: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressEscape(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "escape_finalize" || record.Withdrawal.FeePayer != "wallet" || record.Withdrawal.UserOp != nil {
		t.Fatalf("no wallet-paid finalization: %+v %+v", record.Pending, record.Withdrawal)
	}
	if tx := f.accepted[record.Pending.Hash]; tx == nil || !strings.EqualFold(tx.To().Hex(), addressTestVault) || "0x"+hex.EncodeToString(tx.Data()) != finalizeEscapeCalldata(f.noteID) {
		t.Fatal("the wallet-paid transaction is not finalizeEscapeWithdrawal on the vault")
	}
	if len(g.sends) != sends {
		t.Fatal("an operation was sent or re-sent")
	}
}

// The same for a sponsored close and a sponsored FORWARD in flight: the
// released close is closed again from the wallet, and the released forward
// leaves the payout waiting in the transit account for --sweep.
func TestGaslessRetiredProfileReleasesACloseAndAForwardInFlight(t *testing.T) {
	plain := payoutContext(addressWithdrawalOptions{})
	t.Run("close", func(t *testing.T) {
		f, g := newGaslessWithdrawalFixture(t)
		f.sponsoredClose(t)
		retireGasless(t)
		f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
		sends := len(g.sends)
		ageInFlightOperation(t, f)
		status, err := f.h.WithdrawAddress(plain, withdrawalTestDestination, f.noteID)
		if err != nil || status.Phase != "gasless_refused" || !strings.HasPrefix(status.GaslessRefusal, GaslessRecordNotPinned+":") || !strings.Contains(status.GaslessRefusal, "--to "+withdrawalTestDestination+" --fees wallet") {
			t.Fatalf("the close was not released: %+v %v", status, err)
		}
		// Rerunning without --fees wallet is refused, and the refusal names
		// the wallet-paid close first: the note is still open, so neither
		// --sweep, --claim-credit nor a wallet finalization applies yet.
		closeFromWallet := "close the note from the local signing address with zkapi-clientd withdraw --to " + withdrawalTestDestination + " --fees wallet"
		if _, err := f.h.QuoteAddressWithdrawal(plain, withdrawalTestDestination, f.noteID, "", false); GaslessRefusalCode(err) != GaslessRecordNotPinned || !strings.Contains(err.Error(), closeFromWallet) {
			t.Fatalf("a sponsored rerun of a released close: %v", err)
		}
		wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
		quote, err := f.h.QuoteAddressWithdrawal(wallet, withdrawalTestDestination, f.noteID, "", false)
		if err != nil || quote.Kind != "withdrawal" || quote.FeePolicy != "low" {
			t.Fatalf("wallet close after the release: %+v %v", quote, err)
		}
		if len(g.sends) != sends {
			t.Fatal("an operation was sent or re-sent")
		}
	})
	t.Run("forward", func(t *testing.T) {
		f, g, quote := replayClosedForForward(t)
		if status, err := f.h.ApproveAddressWithdrawal(payoutContext(addressWithdrawalOptions{Collect: true}), quote.ID); err != nil || status.Phase != "forward_op_submitted" {
			t.Fatalf("forward: %+v %v", status, err)
		}
		transit := common.HexToAddress(f.journal(t).Withdrawal.Transit.Account)
		retireGasless(t)
		f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
		sends := len(g.sends)
		ageInFlightOperation(t, f)
		status, err := f.h.WithdrawAddress(plain, withdrawalTestDestination, f.noteID)
		if err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit || !strings.HasPrefix(status.GaslessRefusal, GaslessRecordNotPinned+":") || !strings.Contains(status.GaslessRefusal, "--sweep") {
			t.Fatalf("the forward was not released: %+v %v", status, err)
		}
		sweepTransitAccount(t, f, g, transit)
		if len(g.sends) != sends {
			t.Fatal("an operation was sent or re-sent")
		}
	})
}

// The wallet-paid alternatives a gasless_record_not_pinned refusal names
// lead with the wallet-paid close or escape initiation while the record's
// exit is not on chain yet, and leave it out once it is.
func TestWalletRecoveryAlternativesNameTheWalletPaidExitWhileTheNoteIsOpen(t *testing.T) {
	const y = withdrawalTestDestination
	closeFromWallet := "withdraw --to " + y + " --fees wallet"
	initiateFromWallet := "initiate the escape from the local signing address with zkapi-clientd withdraw --escape --to " + y + " --fees wallet"
	for _, c := range []struct {
		name     string
		w        addressWithdrawalRecord
		wantExit string
	}{
		{"close quoted", addressWithdrawalRecord{Destination: y, Phase: "quoted"}, closeFromWallet},
		{"close released", addressWithdrawalRecord{Destination: y, Phase: "gasless_refused"}, closeFromWallet},
		{"close reverted", addressWithdrawalRecord{Destination: y, Phase: "op_reverted", TransactionHash: "0x" + strings.Repeat("ab", 32)}, closeFromWallet},
		{"close included", addressWithdrawalRecord{Destination: y, Phase: "op_submitted", TransactionHash: "0x" + strings.Repeat("ab", 32)}, ""},
		{"close complete in transit", addressWithdrawalRecord{Destination: y, Phase: "complete", FundsWaitingInTransit: true}, ""},
		{"escape not initiated", addressWithdrawalRecord{Destination: y, Mode: "escape", Phase: "gasless_refused"}, initiateFromWallet},
		{"escape initiated", addressWithdrawalRecord{Destination: y, Mode: "escape", Phase: "gasless_refused", InitiateHash: "0x" + strings.Repeat("cd", 32)}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := walletRecoveryAlternatives(&c.w)
			if !strings.Contains(got, "--sweep --to "+y) || !strings.Contains(got, "--claim-credit") || !strings.Contains(got, "--escape --to "+y+" --fees wallet") {
				t.Fatalf("the sweep, credit claim and wallet finalization are missing: %s", got)
			}
			if c.wantExit != "" && !strings.Contains(got, c.wantExit) {
				t.Fatalf("the wallet-paid exit is missing: %s", got)
			}
			if c.wantExit == "" && (strings.Contains(got, "close the note") || strings.Contains(got, "initiate the escape")) {
				t.Fatalf("a wallet-paid exit is named for an exit already on chain: %s", got)
			}
		})
	}
}

// A new sponsored withdrawal under a retired profile (gasless: null) is
// refused with gasless_unavailable, not gasless_record_not_pinned, which is
// only returned for an existing record (docs/deployment.md, step 3).
func TestGaslessRetiredProfileRefusesANewSponsoredWithdrawalAsUnavailable(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	retireGasless(t)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	payout := payoutContext(payoutFees)
	_, err := f.h.QuoteAddressWithdrawal(payout, withdrawalTestDestination, f.noteID, "", false)
	if GaslessRefusalCode(err) != "gasless_unavailable" || !strings.Contains(err.Error(), "publishes no gasless paymaster") {
		t.Fatalf("a new sponsored close under a retired profile: %v", err)
	}
	if _, err := f.h.QuoteAddressEscape(payout, withdrawalTestDestination, f.noteID, nil, ""); GaslessRefusalCode(err) != "gasless_unavailable" {
		t.Fatalf("a new sponsored escape under a retired profile: %v", err)
	}
	if len(g.sends) != 0 {
		t.Fatal("an operation was sent")
	}
}
