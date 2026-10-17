package zkapi

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
)

// A recorded note needs no Merkle path to exit, so the companion receives
// only the note: its secret, ID, amount and expiry.
func TestDepositConfirmationSendsOnlyTheNote(t *testing.T) {
	f, _ := minedNativeDeposit(t)
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "active" || len(f.confirmBodies) != 1 {
		t.Fatalf("deposit was not saved: %+v %v", status, err)
	}
	if keys := slices.Sorted(maps.Keys(f.confirmBodies[0])); !slices.Equal(keys, []string{"amount", "expiry_ts", "note_id", "secret"}) {
		t.Fatalf("the confirmation carried more than the note: %v", keys)
	}
}

// NoteDeposited of vault revision 4 carries two data words (amount and
// expiry); the revision-3 event with a trailing newRoot is not this vault's.
func TestDepositReceiptMatchesTheTwoWordNoteDepositedEvent(t *testing.T) {
	record := depositRecord{Contract: addressTestVault, Commitment: "0x1234", Amount: 100000}
	expiry := bucketedExpiry()
	receipt := depositEventReceipt(addressTestVault, 12, record.Commitment, record.Amount, expiry)
	if id, matched, err := matchDepositEvent(receipt, record, 1); err != nil || id != 12 || matched != expiry {
		t.Fatalf("the two-word event was not matched: %d %d %v", id, matched, err)
	}
	var revision3 ethReceipt
	raw := fmt.Sprintf(`{"status":"0x1","logs":[{"address":%q,"topics":[%q,"0x%064x","0x%s"],"data":"0x%064x%064x%064x"}]}`, addressTestVault, depositEventTopic, 12, addressABIWord(record.Commitment), record.Amount, expiry, 7)
	if err := json.Unmarshal([]byte(raw), &revision3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := matchDepositEvent(revision3, record, 1); err == nil {
		t.Fatal("an event with a third data word was matched")
	}
	if depositEventTopic != topicOf("NoteDeposited(uint32,bytes32,uint128,uint64)") {
		t.Fatal("the deposit topic is not NoteDeposited(uint32,bytes32,uint128,uint64)")
	}
}

// Design C: a deposit only records its note, and an operator batch activates
// it later. The recorded note exits at once: the funding status reports it
// as awaiting activation, and a mutual close of it is proved, checked and
// signed without any activation.
func TestRecordedNoteWithdrawsBeforeActivation(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	funding, err := f.h.Address(context.Background())
	if err != nil || funding.Phase != "active" || funding.DepositStage != "awaiting_activation" || funding.Activated == nil || *funding.Activated {
		t.Fatalf("the recorded note was not awaiting activation: %+v %v", funding, err)
	}
	f.mu.Lock()
	activated := f.cursor > uint32(f.noteID)
	f.mu.Unlock()
	if activated {
		t.Fatal("the fixture activated the note")
	}
	hash := f.withdraw(t)
	tx := f.accepted[hash]
	if tx == nil || len(tx.Data()) != withdrawalCalldataLength {
		t.Fatal("the close of a recorded note was not signed")
	}
	f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" {
		t.Fatalf("the close of a recorded note did not complete: %+v %v", status, err)
	}
}
