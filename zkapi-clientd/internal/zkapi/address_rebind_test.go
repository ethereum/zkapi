package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Review regressions 2 and 4: an RPC that reports a wrong note ID is refused,
// and once the chain view is honest, rebind binds the note secret to the
// note the finalized vault and the indexer agree on.
func TestWrongNoteIDReceiptIsRefusedAndRebindRecoversCorrectNote(t *testing.T) {
	f, hash := minedNativeDeposit(t)
	f.mu.Lock()
	expiry := f.vaultNotes[12].expiry
	f.receipts[hash]["logs"] = depositEventReceipt(addressTestVault, 0xA4A4, "0x1234", 100000, expiry).Logs
	f.vaultNotes[0xA4A4] = f.vaultNotes[12] // The hostile RPC also forges notes().
	f.mu.Unlock()
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "verification_conflict" || f.activated != 0 {
		t.Fatalf("wrong note ID was not refused: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil {
		t.Fatal("a conflicting deposit allowed a fresh deposit quote")
	}
	f.mu.Lock()
	f.receipts[hash]["logs"] = depositEventReceipt(addressTestVault, 12, "0x1234", 100000, expiry).Logs
	delete(f.vaultNotes, 0xA4A4)
	f.finalized = "0x20"
	f.mu.Unlock()
	status, err = f.h.RebindDeposit(context.Background(), nil, nil)
	if err != nil || status.Phase != "active" || f.activated != 1 || f.resetCalls != 0 {
		t.Fatalf("rebind did not activate the verified note: %+v %v", status, err)
	}
	body := f.confirmBodies[0]
	if body["note_id"] != float64(12) || body["expiry_ts"] != float64(expiry) || body["amount"] != float64(100000) || body["secret"] != "0xabcdef" {
		t.Fatalf("companion bound to the wrong note: %+v", body)
	}
	record := f.savedDeposit(t)
	if !record.Active || record.Binding == nil || record.Binding.NoteID != 12 || record.Binding.ExpiryTs != expiry || record.Rebind != nil || record.Secret != "0xabcdef" || record.Commitment != "0x1234" || record.TransactionHash != hash {
		t.Fatalf("rebind changed note material or lost the binding: %+v", record)
	}
	if address := f.savedAddress(t); address.Phase != "active" || address.Pending == nil || address.Pending.Hash != hash {
		t.Fatalf("the verified deposit transaction was not kept: %+v", address)
	}
	if again, err := f.h.FundAddress(context.Background(), 100000); err != nil || again.Phase != "active" || f.activated != 1 || len(f.accepted) != 1 {
		t.Fatalf("rebound note was activated twice or replaced: %+v %v", again, err)
	}
}

// activatedWithWrongCompanionNote is a pre-fix wallet: the deposit is note 12
// on chain, but the companion was initialized at the RPC's note 0xA4A4.
func activatedWithWrongCompanionNote(t *testing.T) (*addressFixture, uint64) {
	t.Helper()
	f, _ := minedNativeDeposit(t)
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "active" {
		t.Fatalf("fixture did not activate: %+v %v", status, err)
	}
	f.finalized = "0x20"
	record := f.savedDeposit(t)
	record.Binding = nil // Older releases kept no binding.
	if err := f.h.save(record); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	expiry := f.vaultNotes[12].expiry
	f.walletNote = map[string]any{"note_id": 0xA4A4, "deposit_amount": 100000, "current_balance": 100000, "expiry_ts": expiry, "is_genesis": true}
	f.activated, f.confirmBodies = 0, nil
	return f, expiry
}

func TestRebindReplacesOnlyNamedGenesisCompanionNote(t *testing.T) {
	f, expiry := activatedWithWrongCompanionNote(t)
	wrong, other := uint64(0xA4A4), uint64(7)
	for name, refusal := range map[string]struct {
		replace *uint64
		mutate  func()
		restore func()
	}{
		"unnamed":       {nil, func() {}, func() {}},
		"wrong id":      {&other, func() {}, func() {}},
		"not genesis":   {&wrong, func() { f.walletNote["is_genesis"] = false }, func() { f.walletNote["is_genesis"] = true }},
		"spent balance": {&wrong, func() { f.walletNote["current_balance"] = 99999 }, func() { f.walletNote["current_balance"] = 100000 }},
		"other amount": {&wrong, func() { f.walletNote["deposit_amount"], f.walletNote["current_balance"] = 99999, 99999 }, func() {
			f.walletNote["deposit_amount"], f.walletNote["current_balance"] = 100000, 100000
		}},
		"pending request": {&wrong, func() { f.walletPending = true }, func() { f.walletPending = false }},
		// The companion refuses to release a reservation the server knows.
		"reservation with server state": {&wrong, func() {
			f.withdrawalPhase, f.releaseRefusal = reservedWithdrawal(0xA4A4), "withdrawal_pending"
		}, func() { f.withdrawalPhase, f.releaseRefusal = nil, "" }},
		// ... or one with a prepared withdrawal plan.
		"planned reservation": {&wrong, func() {
			f.withdrawalPhase, f.releaseRefusal = reservedWithdrawal(0xA4A4), "withdrawal_conflict"
		}, func() { f.withdrawalPhase, f.releaseRefusal = nil, "" }},
		// ... or one whose ownership proof was sent (on a legacy vault).
		"reservation whose ownership proof was sent": {&wrong, func() {
			f.withdrawalPhase, f.releaseRefusal = reservedWithdrawal(0xA4A4), "ownership_proof_sent"
		}, func() { f.withdrawalPhase, f.releaseRefusal = nil, "" }},
		"reservation of another note": {&wrong, func() { f.withdrawalPhase = reservedWithdrawal(7) }, func() { f.withdrawalPhase = nil }},
	} {
		f.mu.Lock()
		refusal.mutate()
		releases := len(f.releaseBodies)
		f.mu.Unlock()
		_, err := f.h.RebindDeposit(context.Background(), nil, refusal.replace)
		f.mu.Lock()
		refusal.restore()
		released := len(f.releaseBodies) - releases
		f.mu.Unlock()
		if err == nil {
			t.Fatalf("%s: rebind replaced the companion note", name)
		}
		if name == "unnamed" && !strings.Contains(err.Error(), "--replace-note-id 42148") {
			t.Fatalf("unnamed replacement did not explain the flag: %v", err)
		}
		if refusedRelease := name == "reservation with server state" || name == "planned reservation" || name == "reservation whose ownership proof was sent"; refusedRelease != (released == 1) || released > 1 {
			t.Fatalf("%s: unexpected withdrawal release attempts: %d", name, released)
		}
		if released == 1 && !strings.Contains(err.Error(), "finish that withdrawal") {
			t.Fatalf("%s: refused release did not explain the withdrawal: %v", name, err)
		}
		var coded *Error
		if name == "reservation whose ownership proof was sent" && (!strings.Contains(err.Error(), "may have sent, its ownership proof") || !errors.As(err, &coded) || coded.Code != "ownership_proof_sent") {
			t.Fatalf("%s: refused release did not name the sent ownership proof with its code: %v", name, err)
		}
		if f.resetCalls != 0 || f.activated != 0 || f.savedDeposit(t).Rebind != nil {
			t.Fatalf("%s: refused rebind reset, confirmed, or journaled a replacement", name)
		}
	}
	status, err := f.h.RebindDeposit(context.Background(), nil, &wrong)
	if err != nil || status.Phase != "active" || f.resetCalls != 1 || f.activated != 1 {
		t.Fatalf("named genesis note was not replaced exactly once: %+v %v", status, err)
	}
	if body := f.confirmBodies[0]; body["note_id"] != float64(12) || body["expiry_ts"] != float64(expiry) {
		t.Fatalf("replacement used the wrong binding: %+v", body)
	}
	if record := f.savedDeposit(t); record.Rebind != nil || record.Binding == nil || record.Binding.NoteID != 12 || !record.Active {
		t.Fatalf("replacement was not committed: %+v", record)
	}
}

// Repair's refused release crosses the management boundary with its code:
// ownership_proof_sent, beside the explanation, and no companion detail.
// Other refusals carry only their explanation.
func TestRebindForwardsTheOwnershipProofRefusalCode(t *testing.T) {
	f, _ := activatedWithWrongCompanionNote(t)
	for refusal, code := range map[string]string{"ownership_proof_sent": "ownership_proof_sent", "withdrawal_pending": ""} {
		f.mu.Lock()
		f.withdrawalPhase, f.releaseRefusal = reservedWithdrawal(0xA4A4), refusal
		f.mu.Unlock()
		r := httptest.NewRequest("POST", "http://127.0.0.1:8787/admin/funding/rebind", strings.NewReader(`{"replace_note_id":42148}`))
		r.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.h.ServeAdminHTTP(recorder, r)
		var failure struct{ Error, Code string }
		if recorder.Code != http.StatusBadGateway || json.Unmarshal(recorder.Body.Bytes(), &failure) != nil || failure.Code != code || !strings.Contains(failure.Error, "finish that withdrawal") || strings.Contains(failure.Error, "private reservation detail") {
			t.Fatalf("%s: management refusal: %d %s", refusal, recorder.Code, recorder.Body.String())
		}
		if f.resetCalls != 0 || f.activated != 0 {
			t.Fatalf("%s: a refused release replaced the note", refusal)
		}
	}
}

func reservedWithdrawal(noteID uint32) map[string]any {
	return map[string]any{"phase": "reserved", "note_id": noteID, "destination": withdrawalTestDestination, "final_balance": "100000", "withdrawal_nullifier": "0x123"}
}

// A withdrawal reservation of the note being replaced that never obtained a
// plan or a server clearance is released through the companion before the
// reset; the release names exactly the reserved note and nullifier.
func TestRebindReleasesAnUnplannedReservationOfTheReplacedNote(t *testing.T) {
	f, expiry := activatedWithWrongCompanionNote(t)
	f.mu.Lock()
	f.withdrawalPhase = reservedWithdrawal(0xA4A4)
	f.mu.Unlock()
	wrong := uint64(0xA4A4)
	status, err := f.h.RebindDeposit(context.Background(), nil, &wrong)
	if err != nil || status.Phase != "active" || f.resetCalls != 1 || f.activated != 1 {
		t.Fatalf("an unplanned reservation blocked the named replacement: %+v %v", status, err)
	}
	if len(f.releaseBodies) != 1 || len(f.releaseBodies[0]) != 2 || f.releaseBodies[0]["note_id"] != float64(0xA4A4) || f.releaseBodies[0]["withdrawal_nullifier"] != "0x123" {
		t.Fatalf("release did not name exactly the reserved note and nullifier: %+v", f.releaseBodies)
	}
	if steps := strings.Join(f.companionSteps, ","); steps != "release,reset" {
		t.Fatalf("the reservation was not released before the reset: %s", steps)
	}
	if body := f.confirmBodies[0]; body["note_id"] != float64(12) || body["expiry_ts"] != float64(expiry) {
		t.Fatalf("replacement used the wrong binding: %+v", body)
	}
	if record := f.savedDeposit(t); record.Rebind != nil || record.Binding == nil || record.Binding.NoteID != 12 || !record.Active {
		t.Fatalf("replacement was not committed: %+v", record)
	}
}

func TestRebindResumesAfterCrashBetweenResetAndConfirm(t *testing.T) {
	for _, failing := range []string{"/funding/api/deposit/confirm", "/wallet/reset"} {
		t.Run(failing, func(t *testing.T) {
			f, expiry := activatedWithWrongCompanionNote(t)
			upstream := f.h.client.local.Transport
			f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == failing {
					return withdrawalJSONResponse(r, 503, map[string]any{"error": "interrupted"}), nil
				}
				return upstream.RoundTrip(r)
			})
			wrong := uint64(0xA4A4)
			if _, err := f.h.RebindDeposit(context.Background(), nil, &wrong); err == nil {
				t.Fatal("interrupted rebind reported success")
			}
			journal := f.savedDeposit(t).Rebind
			if journal == nil || journal.FromNoteID != 0xA4A4 || journal.ToNoteID != 12 || journal.ExpiryTs != expiry {
				t.Fatalf("replacement was not journaled before reset: %+v", journal)
			}
			f.h.client.local.Transport = upstream
			// The resumed rebind needs no flags and replays nothing extra.
			status, err := f.h.RebindDeposit(context.Background(), nil, nil)
			if err != nil || status.Phase != "active" || f.activated != 1 || f.resetCalls != 1 {
				t.Fatalf("interrupted rebind did not resume once: %+v %v (reset %d)", status, err, f.resetCalls)
			}
			if record := f.savedDeposit(t); record.Rebind != nil || record.Binding == nil || record.Binding.NoteID != 12 {
				t.Fatalf("resumed rebind was not committed: %+v", record)
			}
			other := uint64(13)
			if _, err := f.h.RebindDeposit(context.Background(), &other, nil); err == nil {
				t.Fatal("a completed rebind accepted an unverified note")
			}
		})
	}
}

// The automatic repair searches from the earliest slot a deposit of this
// note was signed for. Here an indexer view that was later reorganized moved
// the latest prepared slot past the one where the withheld deposit landed.
func TestRebindSearchesFromTheEarliestSignedSlot(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, true) // forged revert; deposit withheld
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not recorded: %+v %v", status, err)
	}
	f.mu.Lock()
	f.setLeaf(12, noteLeaf(12, fieldValue("0x5678"), 7, bucketedExpiry())) // A deposit on a short-lived fork.
	f.mu.Unlock()
	_, _ = f.h.FundAddress(context.Background(), 100000) // Retires the revert; prepares slot 13 unsigned.
	if slot := f.savedDeposit(t).Slot; slot == nil || slot.NoteID != 13 {
		t.Fatalf("fixture did not move the prepared slot past the signed one: %+v", slot)
	}
	f.mu.Lock()
	f.leaves = f.leaves[:12] // The fork is reorganized away ...
	f.leafVersion++
	commitment := "0x" + hex.EncodeToString(f.accepted[first.TransactionHash].Data())[8:72]
	f.registerDeposit(12, commitment, 100000, bucketedExpiry()) // ... and the withheld deposit lands.
	f.mu.Unlock()
	status, err := f.h.RebindDeposit(context.Background(), nil, nil)
	if err != nil || status.Phase != "active" || f.activated != 1 || f.confirmBodies[0]["note_id"] != float64(12) {
		t.Fatalf("repair did not find the deposit from its signed slot: %+v %v", status, err)
	}
	if len(f.accepted) != 1 {
		t.Fatal("repair signed a deposit")
	}
}

// Repair waits while an earlier deposit of this note, retired after a
// reported revert, has no final receipt: the RPC can still relay it and
// create a second note. Its final receipt then identifies the note.
func TestRebindWaitsForRetiredDepositToBeFinal(t *testing.T) {
	f, hash, commitment := retiredWithheldDeposit(t)
	f.mu.Lock()
	f.registerDeposit(12, commitment, 100000, bucketedExpiry())
	expiry := f.vaultNotes[12].expiry
	delete(f.receipts, hash) // The RPC now reports the retired deposit as unmined.
	f.mu.Unlock()
	note := uint64(12)
	if _, err := f.h.RebindDeposit(context.Background(), &note, nil); err == nil || !strings.Contains(err.Error(), "second note") {
		t.Fatalf("rebind ignored a retired deposit without a final receipt: %v", err)
	}
	if f.activated != 0 || f.resetCalls != 0 || f.savedDeposit(t).Active {
		t.Fatal("refused rebind changed the companion or deposit")
	}
	f.mu.Lock()
	f.receipts[hash] = map[string]any{"transactionHash": hash, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestVault, "logs": depositEventReceipt(addressTestVault, 12, commitment, 100000, expiry).Logs}
	f.mu.Unlock()
	status, err := f.h.RebindDeposit(context.Background(), nil, nil)
	if err != nil || status.Phase != "active" || f.activated != 1 || f.confirmBodies[0]["note_id"] != float64(12) {
		t.Fatalf("the retired deposit's final receipt did not identify its note: %+v %v", status, err)
	}
	if record := f.savedDeposit(t); record.TransactionHash != hash || record.Binding == nil || record.Binding.NoteID != 12 {
		t.Fatalf("rebind did not record the deposit that created the note: %+v", record)
	}
}

// Without a usable receipt, only our exact leaf near the slot the signed
// calldata targeted identifies the note; anything else needs --note-id.
func TestRebindAutoSelectsOnlyOurLeafNearPreparedSlot(t *testing.T) {
	for _, landed := range []string{"foreign", "next slot"} {
		t.Run(landed, func(t *testing.T) {
			f := newAddressFixture(t, true)
			first, err := f.fundNative(t, 100000)
			if err != nil {
				t.Fatal(err)
			}
			f.mine(t, first.TransactionHash, true) // The RPC reports a revert.
			f.mu.Lock()
			f.registerDeposit(12, "0x1234", 1, bucketedExpiry()) // A foreign 1 gwei copy.
			if landed == "next slot" {
				// Identical siblings after a close let the calldata land one slot later.
				f.registerDeposit(13, "0x1234", 100000, bucketedExpiry())
			}
			f.mu.Unlock()
			status, err := f.h.RebindDeposit(context.Background(), nil, nil)
			if landed == "foreign" {
				if err == nil || !strings.Contains(err.Error(), "--note-id") || f.activated != 0 {
					t.Fatalf("a foreign deposit was adopted: %+v %v", status, err)
				}
				note := uint64(12)
				if _, err := f.h.RebindDeposit(context.Background(), &note, nil); err == nil || f.activated != 0 {
					t.Fatal("an explicit foreign 1 gwei note was adopted")
				}
				return
			}
			if err != nil || status.Phase != "active" || f.confirmBodies[0]["note_id"] != float64(13) {
				t.Fatalf("our leaf after the prepared slot was not recovered: %+v %v", status, err)
			}
		})
	}
}
