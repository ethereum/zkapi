package zkapi

import (
	"context"
	"fmt"
	"math/big"
	"testing"
)

// Amendment A1: the companion keeps the deposit-time Merkle path, so an exit
// needs no indexer and no log rebuild. Activation hands it the root the
// deposit set and the zero path the deposit was signed with, only when they
// prove the note's leaf.
func TestDepositActivationSendsTheDepositTimePath(t *testing.T) {
	f, hash := minedNativeDeposit(t)
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "active" || len(f.confirmBodies) != 1 {
		t.Fatalf("deposit did not activate: %+v %v", status, err)
	}
	body := f.confirmBodies[0]
	record := f.savedDeposit(t)
	if body["deposit_root"] != fmt.Sprintf("0x%064x", f.minedRoot[hash]) {
		t.Fatalf("activation did not carry NoteDeposited.newRoot: %+v", body)
	}
	siblings, _ := body["deposit_siblings"].([]any)
	if len(siblings) != merkleDepth || len(record.ZeroPath) != merkleDepth {
		t.Fatalf("activation did not carry the deposit's zero path: %+v", body)
	}
	for i, sibling := range siblings {
		if sibling != record.ZeroPath[i] {
			t.Fatalf("sibling %d is not the signed zero path: %v", i, sibling)
		}
	}
	commitment, _ := parseFieldElement(record.Commitment)
	if merkleRoot(addressTestFirstNote, noteLeaf(addressTestFirstNote, commitment, record.Amount, f.minedExpiry[addressTestFirstNote]), parseFieldElements(t, record.ZeroPath)).Cmp(f.minedRoot[hash]) != 0 {
		t.Fatal("the fixture's deposit root is not the note's root")
	}
}

func TestDepositActivationWithoutAProvingRootSendsNoPath(t *testing.T) {
	f, hash := minedNativeDeposit(t)
	f.mu.Lock()
	id := f.mined[hash]
	// A receipt whose newRoot is not the note's root under the signed path.
	f.receipts[hash]["logs"] = depositEventReceipt(addressTestVault, id, "0x1234", 100000, f.minedExpiry[id]).Logs
	f.mu.Unlock()
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "active" || len(f.confirmBodies) != 1 {
		t.Fatalf("deposit did not activate: %+v %v", status, err)
	}
	if _, ok := f.confirmBodies[0]["deposit_root"]; ok {
		t.Fatalf("a path that proves nothing was sent: %+v", f.confirmBodies[0])
	}
	if _, ok := f.confirmBodies[0]["deposit_siblings"]; ok {
		t.Fatalf("a path that proves nothing was sent: %+v", f.confirmBodies[0])
	}
}

func parseFieldElements(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		parsed, ok := parseFieldElement(value)
		if !ok {
			t.Fatalf("invalid field %q", value)
		}
		out[i] = parsed
	}
	return out
}
