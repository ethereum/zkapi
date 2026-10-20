package zkapi

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Vault revision 4: an exit binds the note's stored leaf and needs no Merkle
// path, so a deposit neither fetches nor keeps one, and activation hands the
// companion only the note: its secret, note ID, amount and expiry.
func TestDepositActivationHandsOverOnlyTheNote(t *testing.T) {
	f, hash := minedNativeDeposit(t)
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "active" || len(f.confirmBodies) != 1 {
		t.Fatalf("deposit did not activate: %+v %v", status, err)
	}
	body := f.confirmBodies[0]
	id := f.mined[hash]
	want := map[string]any{"secret": "0xabcdef", "note_id": float64(id), "amount": float64(100000), "expiry_ts": float64(f.minedExpiry[id])}
	if len(body) != len(want) {
		t.Fatalf("activation carried more than the note: %+v", body)
	}
	for key, value := range want {
		if body[key] != value {
			t.Fatalf("activation %s = %v, want %v", key, body[key], value)
		}
	}
	if f.paths != 0 {
		t.Fatal("the deposit fetched a Merkle path")
	}
	raw, err := os.ReadFile(f.h.statePath)
	if err != nil || strings.Contains(string(raw), "zero_path") {
		t.Fatalf("the deposit record keeps a path: %s %v", raw, err)
	}
}

// A NoteDeposited log of revision 3 (three data words, the last a root) is
// not a deposit event of this vault; only the two-word event is.
func TestDepositEventHasTwoDataWords(t *testing.T) {
	record := depositRecord{Contract: addressTestVault, Commitment: "0x1234", Amount: 100000}
	expiry := bucketedExpiry()
	receipt := depositEventReceipt(addressTestVault, 12, "0x1234", 100000, expiry)
	if id, got, err := matchDepositEvent(receipt, record, 0); err != nil || id != 12 || got != expiry {
		t.Fatalf("the revision-4 event was not matched: %d %d %v", id, got, err)
	}
	receipt.Logs[0].Data += fmt.Sprintf("%064x", 7)
	if _, _, err := matchDepositEvent(receipt, record, 0); err == nil {
		t.Fatal("a three-word NoteDeposited was matched")
	}
}
