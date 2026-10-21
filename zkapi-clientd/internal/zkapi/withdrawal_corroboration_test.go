package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestWithdrawalRequiresClearanceOwnershipCapability(t *testing.T) {
	t.Run("the concession deployment requires the capability", func(t *testing.T) {
		f := newWithdrawalFixture(t)
		f.withdraw(t) // The companion reports clearance_ownership_proof_version 1.
		if f.prepareCalls != 1 {
			t.Fatal("a capable companion could not withdraw")
		}
	})
	for _, capability := range []deploymentCapabilities{{VaultRevision: 3, ClearanceOwnershipProof: "required"}, {VaultRevision: 2}, {ClearanceOwnershipProof: "optional"}} {
		t.Run(fmt.Sprintf("%+v", capability), func(t *testing.T) {
			f := newWithdrawalFixture(t)
			f.ownershipProofVersion = 0
			f.h.client.capabilities = &capability
			before := f.journal(t)
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err == nil || !strings.Contains(err.Error(), "ownership proofs") {
				t.Fatalf("outdated companion was allowed to reserve the note: %v", err)
			}
			after := f.journal(t)
			if f.prepareCalls != 0 || f.reservedDestination != "" || after.Withdrawal != nil || after.Phase != before.Phase {
				t.Fatal("refused withdrawal reserved the note or saved intent")
			}
			if _, err := f.h.AddressWithdrawal(context.Background()); err != nil {
				t.Fatalf("status reads require the clearance capability: %v", err)
			}
			// A saved withdrawal without a proof plan is gated at prepare.
			f.ownershipProofVersion, f.pending = 1, true
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "waiting_settlement" {
				t.Fatalf("capable companion could not save the withdrawal: %+v %v", status, err)
			}
			f.ownershipProofVersion, f.pending = 0, false
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err == nil || f.prepareCalls != 0 {
				t.Fatal("a downgraded companion reached prepare for an unplanned withdrawal")
			}
			f.ownershipProofVersion = 1
			hash := f.withdraw(t)
			// Finishing an already signed withdrawal never needs the gate.
			f.ownershipProofVersion = 0
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.prepareCalls != 1 {
				t.Fatalf("the gate blocked finality bookkeeping: %+v %v", status, err)
			}
		})
	}
}

// Review root cause on the withdrawal side: one RPC must not decide that the
// note closed. A forged MutualClose receipt never deletes the companion's
// note state or archives the deposit recovery file.
func TestForgedMutualCloseReceiptNeverClosesNote(t *testing.T) {
	for _, vault := range []string{"forged closed", "honest active"} {
		t.Run(vault, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			hash := f.withdraw(t)
			f.mu.Lock()
			leaf := new(big.Int).Set(f.leaves[12])
			f.mu.Unlock()
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			f.mu.Lock()
			f.setLeaf(12, leaf) // The indexer never saw a close.
			if vault == "honest active" {
				note := f.vaultNotes[12]
				note.status = noteActive
				f.vaultNotes[12] = note
			}
			f.mu.Unlock()
			for range 2 {
				status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
				if err != nil || status.Phase != "withdrawal_pending" || status.Message != withdrawalVerifyingMessage {
					t.Fatalf("forged close was not held pending: %+v %v", status, err)
				}
			}
			if f.confirmCalls != 0 || !f.active || f.journal(t).Pending == nil || f.journal(t).Withdrawal.Phase != "withdrawal_pending" {
				t.Fatal("forged close reached the companion or retired the signed withdrawal")
			}
			if _, err := os.Stat(f.h.statePath); err != nil {
				t.Fatal("forged close archived the deposit recovery file")
			}
			f.mu.Lock()
			f.closeNote(12)
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
				t.Fatalf("corroborated close did not complete: %+v %v", status, err)
			}
		})
	}
}

// An ownership proof sent for clearance is a valid escape proof. If anyone
// escapes the reserved note with it, the finalized escape of exactly this
// reservation is payout evidence, but only as an independently relayed one.
func TestAddressWithdrawalAcceptsFinalizedEscapeOfSameReservation(t *testing.T) {
	escape := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
	for _, destination := range []string{withdrawalTestDestination, addressTestToken} {
		t.Run(destination, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			original := f.withdraw(t)
			f.mineWithdrawal(t, original, withdrawalTestDestination, true)
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
				t.Fatalf("revert not reported: %+v %v", status, err)
			}
			other := "0x" + strings.Repeat("c", 64)
			f.mu.Lock()
			logs := []map[string]any{{"address": addressTestVault, "topics": []string{escape, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(destination)}}
			f.receipts[other] = map[string]any{"transactionHash": other, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestToken, "logs": logs}
			f.closeNote(12)
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", other)
			if destination != withdrawalTestDestination {
				if err == nil || f.confirmCalls != 0 {
					t.Fatal("an escape to another destination was accepted")
				}
				return
			}
			if err != nil || status.Phase != "complete" || f.journal(t).Withdrawal.SettlementHash != other {
				t.Fatalf("finalized escape of the reservation was not accepted: %+v %v", status, err)
			}
			// Our own signed transaction can only be evidenced by MutualClose.
			receipt := &addressReceipt{Status: "0x1", To: addressTestVault}
			raw, _ := json.Marshal(logs)
			_ = json.Unmarshal(raw, &receipt.Logs)
			if _, err := validateWithdrawalReceipt(receipt, fundingConfig{Contract: addressTestVault}, f.journal(t).Withdrawal, false); err == nil {
				t.Fatal("an escape event was accepted as our own mutual close")
			}
		})
	}
}

// On a vault_revision 2 vault a finalized escape whose push to the
// destination failed (the address rejected ETH or needed more than 100,000
// gas) still closes the note, but the vault only credits the balance to
// escapePayoutCredits(destination) and emits EscapePayoutDeferred before
// EscapeWithdrawalFinalized. Such an escape is never reported as paid: the
// withdrawal completes its bookkeeping with a credited state that names the
// claimEscapePayout(destination) call that delivers the credit.
func TestAddressWithdrawalReportsCreditedEscapePayoutWithItsClaim(t *testing.T) {
	deferredTopic := crypto.Keccak256Hash([]byte("EscapePayoutDeferred(uint32,address,uint128)")).Hex()
	if deferredTopic != "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942" {
		t.Fatal("EscapePayoutDeferred topic drifted from the vault's")
	}
	if hex.EncodeToString(crypto.Keccak256([]byte("claimEscapePayout(address)"))[:4]) != claimEscapePayoutSelector {
		t.Fatal("claimEscapePayout selector drifted from the vault's")
	}
	escape := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
	other := "0x" + strings.Repeat("c", 64)
	destinationWord := "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))
	type mutation func(log map[string]any, f *withdrawalFixture)
	for _, test := range []struct {
		name     string
		deferral mutation
		// companion reports escape_payout_credited for the receipt.
		companion bool
		credited  bool
	}{
		{"deferred for this note and destination", func(map[string]any, *withdrawalFixture) {}, false, true},
		{"only the companion saw the deferral", nil, true, true},
		{"no deferral", nil, false, false},
		{"deferral for another note", func(log map[string]any, f *withdrawalFixture) {
			log["topics"].([]string)[1] = fmt.Sprintf("0x%064x", f.reservedNoteID+1)
		}, false, false},
		{"deferral for another destination", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"].([]string)[2] = "0x" + addressABIWord(addressTestToken)
		}, false, false},
		{"deferral from another emitter", func(log map[string]any, _ *withdrawalFixture) {
			log["address"] = addressTestToken
		}, false, false},
		{"removed deferral", func(log map[string]any, _ *withdrawalFixture) {
			log["removed"] = true
		}, false, false},
		// Exactly the deferral's three topics, under its own topic0.
		{"deferral without its destination topic", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"] = log["topics"].([]string)[:2]
		}, false, false},
		{"deferral with a fourth topic", func(log map[string]any, _ *withdrawalFixture) {
			topics := log["topics"].([]string)
			log["topics"] = append(append([]string{}, topics...), topics[2])
		}, false, false},
		{"a claimed payout instead of a deferral", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"].([]string)[0] = crypto.Keccak256Hash([]byte("EscapePayoutClaimed(address,uint128)")).Hex()
		}, false, false},
		{"deferral with one topic", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"] = log["topics"].([]string)[:1]
		}, false, false},
		{"deferral without topics", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"] = []string{}
		}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			original := f.withdraw(t)
			f.mineWithdrawal(t, original, withdrawalTestDestination, true)
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
				t.Fatalf("revert not reported: %+v %v", status, err)
			}
			f.mu.Lock()
			finalized := map[string]any{"address": addressTestVault, "topics": []string{escape, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(withdrawalTestDestination)}
			logs := []map[string]any{finalized}
			if test.deferral != nil {
				deferred := map[string]any{"address": addressTestVault, "topics": []string{deferredTopic, fmt.Sprintf("0x%064x", f.reservedNoteID), destinationWord}, "data": fmt.Sprintf("0x%064x", f.reservedBalance)}
				test.deferral(deferred, f)
				logs = []map[string]any{deferred, finalized}
			}
			f.receipts[other] = map[string]any{"transactionHash": other, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestVault, "logs": logs}
			f.closeNote(12)
			f.companionCredited = test.companion
			// The first confirmation reply is lost after the credit was saved.
			f.confirmFailure = true
			f.mu.Unlock()
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", other); err == nil {
				t.Fatal("a failed companion confirmation completed the withdrawal")
			}
			if saved := f.journal(t).Withdrawal; saved.Phase != "confirming" || saved.PayoutCredited != (test.credited && !test.companion) {
				t.Fatalf("the receipt's credit was not saved before confirmation: %+v", saved)
			}
			f.confirmFailure = false
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" {
				t.Fatalf("the finalized escape did not complete the withdrawal: %+v %v", status, err)
			}
			read, err := f.h.AddressWithdrawal(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, reported := range []AddressWithdrawalStatus{status, read} {
				if reported.PayoutCredited != test.credited || f.journal(t).Withdrawal.PayoutCredited != test.credited {
					t.Fatalf("credited = %v, want %v: %+v", reported.PayoutCredited, test.credited, reported)
				}
				if !test.credited {
					if reported.ClaimCalldata != "" || strings.Contains(reported.Message, "claimEscapePayout") {
						t.Fatalf("a paid escape was reported as credited: %+v", reported)
					}
					continue
				}
				claim := "0x88c10aee" + addressABIWord(strings.ToLower(withdrawalTestDestination))
				if reported.ClaimCalldata != claim || !strings.EqualFold(reported.VaultAddress, addressTestVault) {
					t.Fatalf("the claim call is missing: %+v", reported)
				}
				for _, part := range []string{"claimEscapePayout(" + withdrawalTestDestination + ")", "0x88c10aee", reported.VaultAddress, claim, "nothing has arrived"} {
					if !strings.Contains(reported.Message, part) {
						t.Fatalf("the credited message lacks %q: %s", part, reported.Message)
					}
				}
				if strings.Contains(reported.Message, "was withdrawn") || reported.Message == "The remaining private balance was withdrawn and the private note is closed." {
					t.Fatalf("a credited escape was reported as paid: %s", reported.Message)
				}
			}
		})
	}
}

// completeCreditedEscape completes the fixture's withdrawal through a relayed
// escape whose payout the vault credited, and returns its transaction hash.
func completeCreditedEscape(t *testing.T, f *withdrawalFixture) string {
	t.Helper()
	original := f.withdraw(t)
	f.mineWithdrawal(t, original, withdrawalTestDestination, true)
	if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not reported: %+v %v", status, err)
	}
	settlement := "0x" + strings.Repeat("c", 64)
	escape := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
	f.mu.Lock()
	finalized := map[string]any{"address": addressTestVault, "topics": []string{escape, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(withdrawalTestDestination)}
	deferred := map[string]any{"address": addressTestVault, "topics": []string{escapePayoutDeferredEventTopic, fmt.Sprintf("0x%064x", f.reservedNoteID), "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": fmt.Sprintf("0x%064x", f.reservedBalance)}
	f.receipts[settlement] = map[string]any{"transactionHash": settlement, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestVault, "logs": []map[string]any{deferred, finalized}}
	f.closeNote(12)
	f.mu.Unlock()
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", settlement)
	if err != nil || status.Phase != "complete" || !status.PayoutCredited {
		t.Fatalf("the credited escape did not complete: %+v %v", status, err)
	}
	return settlement
}

// A credited escape payout outlives its withdrawal record. A later deposit
// (a new funding request, a native deposit quote, adopting a note deposited
// elsewhere, or repairing such a deposit's note binding) replaces that
// record, but the funding and withdrawal statuses keep listing the credit
// with its claimEscapePayout call while the vault still holds it, also after
// a restart, and stop once it reads zero.
func TestCreditedEscapePayoutStaysReportedAfterTheNextDeposit(t *testing.T) {
	ctx := context.Background()
	for _, replace := range []string{"refill", "quote", "adoption", "rebind"} {
		t.Run(replace, func(t *testing.T) {
			f := newWithdrawalFixture(t, replace == "quote")
			settlement := completeCreditedEscape(t, f)
			destination := strings.ToLower(withdrawalTestDestination)
			f.mu.Lock()
			f.escapeCredits = map[string]string{destination: fmt.Sprintf("0x%x", f.reservedBalance)}
			f.mu.Unlock()
			if before, err := f.h.Address(ctx); err != nil || len(before.EscapePayoutCredits) != 0 {
				t.Fatalf("the current withdrawal's credit was listed twice: %+v %v", before, err)
			}
			switch replace {
			case "refill":
				refill, err := f.h.FundAddress(ctx, 50000)
				if err != nil || len(refill.EscapePayoutCredits) != 1 {
					t.Fatalf("the refill does not report the credit: %+v %v", refill, err)
				}
			case "quote":
				if _, err := f.h.QuoteAddressDeposit(ctx, 50000); err != nil {
					t.Fatal(err)
				}
			case "adoption":
				config, err := f.h.config(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.h.adoptPostWithdrawalDeposit(config, depositRecord{Amount: 50000, Commitment: "0x1234"}, 13); err != nil {
					t.Fatal(err)
				}
			case "rebind":
				// A deposit through the legacy funding API whose activation
				// never ran (say its receipt was misreported) is repaired to
				// the note the vault and the indexer agree on.
				if _, err := f.h.prepare(ctx, 50000); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				f.registerDeposit(13, "0x5678", 50000, bucketedExpiry())
				f.mu.Unlock()
				note := uint64(13)
				repaired, err := f.h.RebindDeposit(ctx, &note, nil)
				if err != nil || repaired.Phase != "active" || f.activated != 2 || f.noteID != 13 || len(repaired.EscapePayoutCredits) != 1 {
					t.Fatalf("the repair did not activate note 13 and report the credit: %+v %v", repaired, err)
				}
			}
			record := f.journal(t)
			want := addressCreditedPayout{NoteID: f.reservedNoteID, Destination: withdrawalTestDestination, Amount: f.reservedBalance, SettlementHash: settlement}
			if record.Withdrawal != nil || len(record.CreditedPayouts) != 1 || record.CreditedPayouts[0] != want {
				t.Fatalf("the credited payout was not kept: %+v", record)
			}
			claim := "0x88c10aee" + addressABIWord(destination)
			check := func(label string, credits []EscapePayoutCredit) {
				t.Helper()
				if len(credits) != 1 {
					t.Fatalf("%s: credits %+v", label, credits)
				}
				c := credits[0]
				if !strings.EqualFold(c.Destination, withdrawalTestDestination) || c.ClaimCalldata != claim || !strings.EqualFold(c.VaultAddress, addressTestVault) || c.CreditedAmount != fmt.Sprint(f.reservedBalance) || len(c.NoteIDs) != 1 || c.NoteIDs[0] != f.reservedNoteID || len(c.TransactionHashes) != 1 || c.TransactionHashes[0] != settlement {
					t.Fatalf("%s: credit %+v", label, c)
				}
				unit := "token units"
				if replace == "quote" {
					unit = "gwei"
				}
				for _, part := range []string{"claimEscapePayout(" + c.Destination + ")", "0x88c10aee", claim, c.VaultAddress, "nothing has arrived", fmt.Sprintf("a credit of %d %s", f.reservedBalance, unit), fmt.Sprintf("(note %d)", f.reservedNoteID)} {
					if !strings.Contains(c.Message, part) {
						t.Fatalf("%s: the message lacks %q: %s", label, part, c.Message)
					}
				}
			}
			for restarted := range 2 {
				if restarted == 1 {
					f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
				}
				funding, err := f.h.Address(ctx)
				if err != nil {
					t.Fatal(err)
				}
				check("funding", funding.EscapePayoutCredits)
				withdrawal, err := f.h.AddressWithdrawal(ctx)
				if err != nil {
					t.Fatal(err)
				}
				check("withdrawal", withdrawal.EscapePayoutCredits)
			}
			// Claimed: the vault holds nothing for the destination any more.
			f.mu.Lock()
			f.escapeCredits = nil
			f.mu.Unlock()
			funding, err := f.h.Address(ctx)
			if err != nil || len(funding.EscapePayoutCredits) != 0 {
				t.Fatalf("a claimed credit is still reported: %+v %v", funding, err)
			}
			if len(f.journal(t).CreditedPayouts) != 1 {
				t.Fatal("a zero read removed the saved credit")
			}
			// A damaged saved credit is refused, not silently dropped.
			raw, err := os.ReadFile(f.h.addressStatePath())
			if err != nil {
				t.Fatal(err)
			}
			for field, value := range map[string]any{"destination": "0x0000000000000000000000000000000000000000", "note_id": uint64(1) << 32, "settlement_hash": "0x12"} {
				var saved map[string]any
				if err := json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				saved["credited_payouts"].([]any)[0].(map[string]any)[field] = value
				damaged, _ := json.Marshal(saved)
				if err := os.WriteFile(f.h.addressStatePath(), damaged, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := f.h.Address(ctx); err == nil || !strings.Contains(err.Error(), "credited escape payout recovery data is invalid") {
					t.Fatalf("%s: a damaged credit was accepted: %v", field, err)
				}
			}
		})
	}
}

// Retiring keeps only a complete credited withdrawal, once.
func TestRetireWithdrawalKeepsOnlyCreditedPayoutsOnce(t *testing.T) {
	credited := &addressWithdrawalRecord{NoteID: 7, Destination: withdrawalTestDestination, Amount: 5, Phase: "complete", SettlementHash: "0x" + strings.Repeat("AB", 32), PayoutCredited: true}
	record := &addressFundingRecord{Withdrawal: credited}
	retireWithdrawal(record)
	again := *credited
	record.Withdrawal = &again
	retireWithdrawal(record)
	if record.Withdrawal != nil || len(record.CreditedPayouts) != 1 || record.CreditedPayouts[0].SettlementHash != "0x"+strings.Repeat("ab", 32) {
		t.Fatalf("credited payout: %+v", record.CreditedPayouts)
	}
	for _, w := range []addressWithdrawalRecord{{Phase: "complete", SettlementHash: "0x" + strings.Repeat("cd", 32)}, {Phase: "confirming", PayoutCredited: true, SettlementHash: "0x" + strings.Repeat("ef", 32)}} {
		record.Withdrawal = &w
		retireWithdrawal(record)
		if record.Withdrawal != nil || len(record.CreditedPayouts) != 1 {
			t.Fatalf("an uncredited or unfinished withdrawal was kept: %+v", record.CreditedPayouts)
		}
	}
}

// Our own signed mutual close pays in full or reverts; a deferral log in its
// receipt, or a companion claiming one, never marks it credited, and the
// saved record stays loadable.
func TestOwnMutualCloseIsNeverReportedAsCredited(t *testing.T) {
	f := newWithdrawalFixture(t)
	hash := f.withdraw(t)
	f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
	f.mu.Lock()
	receipt := f.receipts[hash]
	deferred := map[string]any{"address": addressTestVault, "topics": []string{escapePayoutDeferredEventTopic, fmt.Sprintf("0x%064x", f.reservedNoteID), "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": fmt.Sprintf("0x%064x", f.reservedBalance)}
	receipt["logs"] = append([]map[string]any{deferred}, receipt["logs"].([]map[string]any)...)
	f.companionCredited = true
	f.mu.Unlock()
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.PayoutCredited {
		t.Fatalf("own mutual close was not completed as paid: %+v %v", status, err)
	}
	if read, err := f.h.AddressWithdrawal(context.Background()); err != nil || read.PayoutCredited || f.journal(t).Withdrawal.PayoutCredited {
		t.Fatalf("own mutual close was saved as credited: %+v %v", read, err)
	}
}
