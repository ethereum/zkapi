package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// minedNativeDeposit signs a native deposit and includes it at note 12 in
// both corroboration sources, leaving activation to the caller.
func minedNativeDeposit(t *testing.T) (*addressFixture, string) {
	t.Helper()
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, false)
	f.finalized = "0x1" // A successful native deposit activates before finality.
	return f, first.TransactionHash
}

func (f *addressFixture) savedDeposit(t *testing.T) depositRecord {
	t.Helper()
	raw, err := os.ReadFile(f.h.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var record depositRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func (f *addressFixture) savedAddress(t *testing.T) addressFundingRecord {
	t.Helper()
	raw, err := os.ReadFile(f.h.addressStatePath())
	if err != nil {
		t.Fatal(err)
	}
	var record addressFundingRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

// bucketedExpiry is the expiry the vault assigns to a deposit mined now.
func bucketedExpiry() uint64 {
	return (uint64(time.Now().Unix()) + 2592000 + vaultExpiryBucket - 1) / vaultExpiryBucket * vaultExpiryBucket
}

func TestDepositActivationRequiresVaultAndIndexerAgreement(t *testing.T) {
	commitment := "0x" + addressABIWord("0x1234")
	conflicts := map[string]func(f *addressFixture){
		"vault commitment": func(f *addressFixture) {
			note := f.vaultNotes[12]
			note.commitment = "0x" + addressABIWord("0x5678")
			f.vaultNotes[12] = note
		},
		"vault amount": func(f *addressFixture) { note := f.vaultNotes[12]; note.amount++; f.vaultNotes[12] = note },
		"vault expiry": func(f *addressFixture) { note := f.vaultNotes[12]; note.expiry++; f.vaultNotes[12] = note },
		"vault pending withdrawal": func(f *addressFixture) {
			note := f.vaultNotes[12]
			note.status = notePendingWithdrawal
			f.vaultNotes[12] = note
		},
		"vault closed":   func(f *addressFixture) { note := f.vaultNotes[12]; note.status = noteClosed; f.vaultNotes[12] = note },
		"indexer absent": func(f *addressFixture) { f.leaves = f.leaves[:12]; f.leafVersion++ },
		"indexer other leaf": func(f *addressFixture) {
			f.setLeaf(12, noteLeaf(12, fieldValue("0x5678"), 100000, f.vaultNotes[12].expiry))
		},
		"indexer other amount": func(f *addressFixture) {
			f.setLeaf(12, noteLeaf(12, fieldValue("0x1234"), 100001, f.vaultNotes[12].expiry))
		},
		"indexer other expiry": func(f *addressFixture) {
			f.setLeaf(12, noteLeaf(12, fieldValue("0x1234"), 100000, f.vaultNotes[12].expiry+1))
		},
		"indexer closed": func(f *addressFixture) { f.setLeaf(12, new(big.Int)) },
	}
	for name, mutate := range conflicts {
		t.Run("conflict/"+name, func(t *testing.T) {
			f, hash := minedNativeDeposit(t)
			f.mu.Lock()
			mutate(f)
			f.mu.Unlock()
			status, err := f.h.FundAddress(context.Background(), 100000)
			if err != nil || status.Phase != "verification_conflict" || !strings.Contains(status.Message, "config --menu, then choose repair") {
				t.Fatalf("disagreement was not reported as a conflict: %+v %v", status, err)
			}
			if f.activated != 0 || len(f.confirmBodies) != 0 {
				t.Fatal("the note secret reached the companion without agreement")
			}
			if f.savedDeposit(t).TransactionHash != hash || f.savedAddress(t).Pending == nil || f.savedAddress(t).Phase != "verification_conflict" {
				t.Fatal("conflict discarded the saved transaction")
			}
			if read, err := f.h.Address(context.Background()); err != nil || read.Phase != "verification_conflict" {
				t.Fatalf("durable status lost the conflict: %+v %v", read, err)
			}
			if len(f.accepted) != 1 {
				t.Fatal("conflict signed another transaction")
			}
		})
	}
	pending := map[string]func(f *addressFixture){
		"indexer 503":           func(f *addressFixture) { f.indexerStatus = http.StatusServiceUnavailable },
		"indexer 404":           func(f *addressFixture) { f.indexerStatus = http.StatusNotFound },
		"indexer down":          func(f *addressFixture) { f.indexer.Close() },
		"indexer without block": func(f *addressFixture) { f.indexerWithoutBlock = true },
		"indexer behind":        func(f *addressFixture) { f.indexerBlock = 0xf },
		"indexer forked":        func(f *addressFixture) { f.indexerHash = "0x" + strings.Repeat("c", 64) },
		"indexer malformed":     func(f *addressFixture) { f.leaves[3] = new(big.Int).Set(bn254ScalarModulus); f.leafVersion++ },
		"indexer inconsistent":  func(f *addressFixture) { f.indexerStatus = -1 },
		"vault uninitialized":   func(f *addressFixture) { delete(f.vaultNotes, 12) },
	}
	for name, mutate := range pending {
		t.Run("pending/"+name, func(t *testing.T) {
			f, hash := minedNativeDeposit(t)
			f.mu.Lock()
			mutate(f)
			f.mu.Unlock()
			status, err := f.h.FundAddress(context.Background(), 100000)
			if err != nil || status.Phase != "confirming" || status.DepositStage != "verifying" || status.TransactionHash != hash {
				t.Fatalf("unverified deposit did not wait: %+v %v", status, err)
			}
			if f.activated != 0 || f.savedDeposit(t).Active {
				t.Fatal("deposit activated without corroboration")
			}
		})
	}
	t.Run("pending/vault read fails", func(t *testing.T) {
		f, _ := minedNativeDeposit(t)
		upstream := f.h.client.inference.Transport
		f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
			raw, _ := ioReadAndRestore(r)
			if strings.Contains(string(raw), notesSelector) {
				return withdrawalJSONResponse(r, 502, map[string]any{"error": "sensitive"}), nil
			}
			return upstream.RoundTrip(r)
		})
		status, err := f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.DepositStage != "verifying" || f.activated != 0 || strings.Contains(status.Message, "sensitive") {
			t.Fatalf("vault read failure activated or leaked: %+v %v", status, err)
		}
	})
	t.Run("agreement activates with the binding", func(t *testing.T) {
		f, hash := minedNativeDeposit(t)
		status, err := f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.Phase != "active" || f.activated != 1 {
			t.Fatalf("agreeing sources did not activate: %+v %v", status, err)
		}
		binding := f.savedDeposit(t).Binding
		if binding == nil || binding.NoteID != 12 || binding.ExpiryTs != f.vaultNotes[12].expiry || binding.BlockNumber != 0x10 || binding.BlockHash != addressTestBlock || binding.IndexerBlock != 0x20 {
			t.Fatalf("binding not persisted: %+v", binding)
		}
		if f.confirmBodies[0]["note_id"] != float64(12) || f.confirmBodies[0]["expiry_ts"] != float64(f.vaultNotes[12].expiry) || f.savedDeposit(t).TransactionHash != hash {
			t.Fatalf("activation used another binding: %+v", f.confirmBodies[0])
		}
		for _, at := range f.vaultReadsAt {
			if !strings.EqualFold(at, addressTestBlock) {
				t.Fatalf("vault state read at %s instead of the receipt block hash", at)
			}
		}
		if !strings.EqualFold(f.vaultNotes[12].commitment, commitment) {
			t.Fatal("fixture registered the wrong commitment")
		}
	})
	t.Run("conflict is re-checked on resume", func(t *testing.T) {
		f, _ := minedNativeDeposit(t)
		f.mu.Lock()
		saved := f.vaultNotes[12]
		f.vaultNotes[12] = fixtureNote{commitment: saved.commitment, amount: saved.amount + 1, expiry: saved.expiry, status: noteActive}
		f.mu.Unlock()
		if status, _ := f.h.FundAddress(context.Background(), 100000); status.Phase != "verification_conflict" {
			t.Fatalf("fixture conflict not detected: %+v", status)
		}
		f.mu.Lock()
		f.vaultNotes[12] = saved
		f.mu.Unlock()
		status, err := f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.Phase != "active" || f.activated != 1 || len(f.accepted) != 1 {
			t.Fatalf("a resolved conflict did not re-verify and activate: %+v %v", status, err)
		}
	})
}

// Full nodes prune old state. Once the receipt block is final, the vault is
// read at the finalized block hash instead of waiting forever.
func TestDepositActivationReadsFinalizedStateWhenReceiptStateIsPruned(t *testing.T) {
	for _, final := range []bool{true, false} {
		t.Run(map[bool]string{true: "final", false: "not final"}[final], func(t *testing.T) {
			f, _ := minedNativeDeposit(t)
			if final {
				f.finalized = "0x20"
			}
			finalizedHash := "0x" + strings.Repeat("f", 64)
			var prunedReads, finalizedReads int
			upstream := f.h.client.inference.Transport
			f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
				raw, _ := ioReadAndRestore(r)
				var request struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				_ = json.Unmarshal(raw, &request)
				switch {
				case request.Method == "eth_getBlockByNumber" && string(request.Params[0]) == `"finalized"`:
					f.mu.Lock()
					number := f.finalized
					f.mu.Unlock()
					return withdrawalJSONResponse(r, 200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]string{"number": number, "hash": finalizedHash}}), nil
				case request.Method == "eth_call" && strings.Contains(string(raw), notesSelector) && strings.Contains(string(raw), addressTestBlock[2:]):
					prunedReads++
					return withdrawalJSONResponse(r, 200, map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32000, "message": "missing trie node"}}), nil
				case request.Method == "eth_call" && strings.Contains(string(raw), finalizedHash[2:]):
					finalizedReads++
					rewritten := strings.ReplaceAll(string(raw), finalizedHash[2:], addressTestBlock[2:])
					clone := r.Clone(r.Context())
					clone.Body, clone.ContentLength = io.NopCloser(strings.NewReader(rewritten)), int64(len(rewritten))
					return upstream.RoundTrip(clone)
				}
				return upstream.RoundTrip(r)
			})
			status, err := f.h.FundAddress(context.Background(), 100000)
			if !final {
				if err != nil || status.DepositStage != "verifying" || f.activated != 0 || finalizedReads != 0 {
					t.Fatalf("pruned receipt state was bypassed before finality: %+v %v", status, err)
				}
				return
			}
			if err != nil || status.Phase != "active" || f.activated != 1 || prunedReads == 0 || finalizedReads == 0 {
				t.Fatalf("finalized state was not used for a pruned receipt block: %+v %v", status, err)
			}
		})
	}
}

// Review regressions 1 and 3: an RPC that withholds the deposit and forges
// its receipt (and even notes()) never activates it or learns the secret.
func TestForgedReceiptForUnrelayedDepositNeverActivates(t *testing.T) {
	for _, forged := range []struct {
		name   string
		noteID uint32
		vault  bool
	}{{"forged vault and receipt", 12, true}, {"forged far note", 999999, true}, {"honest vault", 12, false}} {
		t.Run(forged.name, func(t *testing.T) {
			f := newAddressFixture(t, true)
			first, err := f.fundNative(t, 100000)
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			// The hostile RPC learns the commitment from the raw transaction
			// it was asked to relay, relays nothing, and fabricates evidence.
			data := hex.EncodeToString(f.accepted[first.TransactionHash].Data())
			commitment := "0x" + data[8:72]
			expiry := bucketedExpiry()
			receipt := depositEventReceipt(addressTestVault, forged.noteID, commitment, 100000, expiry)
			f.receipts[first.TransactionHash] = map[string]any{"transactionHash": first.TransactionHash, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestVault, "logs": receipt.Logs}
			if forged.vault {
				f.vaultNotes[forged.noteID] = fixtureNote{commitment: commitment, amount: 100000, expiry: expiry, status: noteActive}
			}
			f.nonce = "0x1"
			f.mu.Unlock()
			for range 3 {
				status, err := f.h.FundAddress(context.Background(), 100000)
				if err != nil || status.Phase == "active" {
					t.Fatalf("forged receipt activated: %+v %v", status, err)
				}
				want := "verification_conflict"
				if !forged.vault {
					want = "confirming"
				}
				if status.Phase != want {
					t.Fatalf("forged receipt phase %s, want %s", status.Phase, want)
				}
			}
			if f.activated != 0 || len(f.confirmBodies) != 0 {
				t.Fatal("the note secret was posted to the companion")
			}
			if record := f.savedDeposit(t); record.Active || record.Binding != nil || record.Secret != "0xabcdef" {
				t.Fatalf("forged receipt changed the private note record: %+v", record)
			}
			if len(f.accepted) != 1 {
				t.Fatal("forged receipt caused another signed transaction")
			}
		})
	}
}

// The companion's refreshed empty-leaf path must prove the indexer's next
// slot before a deposit is signed; the slot is journaled with the note.
func TestDepositPathMustMatchIndexerTree(t *testing.T) {
	f := newAddressFixture(t, true)
	quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	upstream := f.h.client.local.Transport
	f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oa/v1/deposit/path" {
			path := make([]string, 32)
			for i := range path {
				path[i] = "0xa"
			}
			return withdrawalJSONResponse(r, 200, map[string]any{"zero_path": path}), nil
		}
		return upstream.RoundTrip(r)
	})
	if _, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID); err == nil || !strings.Contains(err.Error(), "witness does not match") {
		t.Fatalf("an unbound deposit witness was accepted: %v", err)
	}
	if len(f.accepted) != 0 || f.savedDeposit(t).Slot != nil {
		t.Fatal("deposit signed or slot recorded without a matching witness")
	}
	f.h.client.local.Transport = upstream
	quote, err = f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID); err != nil {
		t.Fatal(err)
	}
	slot := f.savedDeposit(t).Slot
	if len(f.accepted) != 1 || slot == nil || slot.NoteID != 12 || slot.PreparedAt == 0 {
		t.Fatalf("matching witness did not sign with its slot: %+v", slot)
	}
	for _, tx := range f.accepted {
		if depositPathDigest(tx.Data()) != slot.PathSHA256 {
			t.Fatal("recorded slot does not describe the signed calldata")
		}
	}
}

// Only signed deposits keep their slot: a path prepared but never signed adds
// none, so repeated attempts cannot grow the record. A record saved before
// signed slots were kept still counts its current slot when a saved deposit
// transaction carries exactly that path.
func TestSignedSlotsKeepOnlySignedDeposits(t *testing.T) {
	t.Run("unsigned paths", func(t *testing.T) {
		f, _, _ := retiredWithheldDeposit(t)
		signed := f.savedDeposit(t).SignedSlots
		for id := uint32(12); id < 15; id++ {
			// Another deposit takes the next slot; a resume prepares a path
			// for the one after it and signs nothing without a quote.
			f.mu.Lock()
			f.setLeaf(id, noteLeaf(id, fieldValue("0x5678"), 7, bucketedExpiry()))
			f.mu.Unlock()
			_, _ = f.h.FundAddress(context.Background(), 100000)
		}
		record := f.savedDeposit(t)
		if len(signed) != 1 || len(record.SignedSlots) != 1 || record.SignedSlots[0] != signed[0] || signed[0].NoteID != 12 || record.Slot == nil || record.Slot.NoteID != 15 || len(f.accepted) != 1 {
			t.Fatalf("unsigned paths changed the signed slots: %+v", record)
		}
	})
	t.Run("record without signed slots", func(t *testing.T) {
		f, _, commitment := retiredWithheldDeposit(t)
		record := f.savedDeposit(t)
		record.SignedSlots = nil
		if err := f.h.save(record); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.registerDeposit(12, commitment, 100000, bucketedExpiry())
		f.mu.Unlock()
		if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "at note 12") {
			t.Fatalf("the slot of the saved deposit was not searched: %v", err)
		}
		if len(f.accepted) != 1 {
			t.Fatal("a second deposit was signed for the same note")
		}
	})
}

// Signed slots are written only by this daemon. A malformed one means the
// record was damaged; it is preserved rather than acted on.
func TestMalformedSignedSlotIsPreserved(t *testing.T) {
	for name, slot := range map[string]depositSlot{
		"path":        {NoteID: 12, PathSHA256: "0x12", PreparedAt: 1},
		"preparation": {NoteID: 12, PathSHA256: "0x" + strings.Repeat("f", 64)},
		"empty run":   {NoteID: 12, PathSHA256: "0x" + strings.Repeat("f", 64), PreparedAt: 1, EmptyBefore: 13},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAddressFixture(t, true)
			if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err != nil {
				t.Fatal(err)
			}
			record := f.savedDeposit(t)
			record.SignedSlots = []depositSlot{slot}
			if err := f.h.save(record); err != nil {
				t.Fatal(err)
			}
			if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "preserve") {
				t.Fatalf("a malformed signed slot was accepted: %v", err)
			}
			if len(f.accepted) != 0 {
				t.Fatal("a damaged record was used to sign")
			}
		})
	}
}

// Calldata built for a slot can land later only where every slot in between
// is empty. The search skips emptied slots without counting them and
// compares at most depositRevertScanSlots occupied ones.
func TestDepositLeafSearchSkipsEmptiedSlots(t *testing.T) {
	commitment, expiry := fieldValue("0x1234"), bucketedExpiry()
	slot := &depositSlot{NoteID: 12, PathSHA256: "0x" + strings.Repeat("f", 64), PreparedAt: time.Now().Unix()}
	search := func(fill string, between int) (uint32, bool) {
		leaves := make([]string, 0, 12+between+1)
		for i := range 12 {
			leaves = append(leaves, fmt.Sprintf("0x%x", 0x1000+i))
		}
		for range between {
			leaves = append(leaves, fill)
		}
		id := uint32(len(leaves))
		leaves = append(leaves, fmt.Sprintf("0x%x", noteLeaf(id, commitment, 100000, expiry)))
		return findDepositLeaf(&treeSnapshot{NextNoteID: uint32(len(leaves)), Leaves: leaves}, slot, commitment, 100000, 2592000, time.Now().Unix())
	}
	if id, found := search("0x0", 200); !found || id != 212 {
		t.Fatalf("our leaf after emptied slots was not found: %d %v", id, found)
	}
	if id, found := search("0x5", depositRevertScanSlots-1); !found || id != 12+depositRevertScanSlots-1 {
		t.Fatalf("our leaf within the occupied-slot bound was not found: %d %v", id, found)
	}
	if _, found := search("0x5", depositRevertScanSlots); found {
		t.Fatal("the search compared more occupied slots than its bound")
	}
}

// Calldata lands below its slot only in the run of slots that were empty
// right below it when it was built. That run is searched under its own
// bound, so leaves restored in it never hide a landing at or after the slot.
// A record without a run (written before runs were kept) searches only from
// its slot.
func TestDepositLeafSearchCoversTheEmptyRunBelowItsSlot(t *testing.T) {
	commitment, expiry := fieldValue("0x1234"), bucketedExpiry()
	const run = depositRevertScanSlots + 6 // Slots [12, 82) were empty below slot 82.
	search := func(landing uint32, restored int, emptyBefore uint32) (uint32, bool) {
		leaves := make([]string, 0, 12+run+depositRevertScanSlots+1)
		for i := range 12 {
			leaves = append(leaves, fmt.Sprintf("0x%x", 0x1000+i))
		}
		for i := range run + depositRevertScanSlots {
			leaf := "0x0"
			if id := 12 + i; id >= 12+run || i < restored {
				leaf = fmt.Sprintf("0x%x", 0x5000+id) // Restored in the run, or later deposits.
			}
			leaves = append(leaves, leaf)
		}
		leaves[landing] = fmt.Sprintf("0x%x", noteLeaf(landing, commitment, 100000, expiry))
		slot := &depositSlot{NoteID: 12 + run, PathSHA256: "0x" + strings.Repeat("f", 64), PreparedAt: time.Now().Unix(), EmptyBefore: emptyBefore}
		return findDepositLeaf(&treeSnapshot{NextNoteID: uint32(len(leaves)), Leaves: leaves}, slot, commitment, 100000, 2592000, time.Now().Unix())
	}
	if id, found := search(12, 0, run); !found || id != 12 {
		t.Fatalf("a landing at the start of the run was not found: %d %v", id, found)
	}
	if id, found := search(12+run, run, run); !found || id != 12+run {
		t.Fatalf("leaves restored in the run hid a landing at the slot: %d %v", id, found)
	}
	if id, found := search(12+depositRevertScanSlots-1, depositRevertScanSlots-1, run); !found || id != 12+depositRevertScanSlots-1 {
		t.Fatalf("a landing within the run's bound was not found: %d %v", id, found)
	}
	if _, found := search(12+depositRevertScanSlots, depositRevertScanSlots, run); found {
		t.Fatal("the run's search compared more occupied slots than its bound")
	}
	if _, found := search(12, 0, 0); found {
		t.Fatal("a slot recorded without a run was searched below itself")
	}
}

// A finalized revert is retired or requoted only after the indexer shows
// this note did not land at the slot its calldata targeted.
func TestRevertedDepositRetryRequiresIndexerToShowNoDeposit(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	// The RPC reports a finalized revert, but the deposit landed at its slot.
	f.mine(t, first.TransactionHash, true)
	f.mu.Lock()
	f.registerDeposit(12, "0x1234", 100000, bucketedExpiry())
	f.mu.Unlock()
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "reverted" {
		t.Fatalf("finalized revert not reported: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "at note 12") {
		t.Fatalf("requote ignored the indexer's deposit: %v", err)
	}
	if record := f.savedAddress(t); record.Quote != nil || record.Pending == nil || record.Phase != "reverted" {
		t.Fatal("refused requote changed state")
	}
	for range 2 {
		status, err = f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.Phase != "verification_conflict" || !strings.Contains(status.Message, "note 12") {
			t.Fatalf("landed deposit was not a conflict: %+v %v", status, err)
		}
		if record := f.savedAddress(t); record.Pending == nil || record.Pending.Hash != first.TransactionHash || len(record.History) != 0 {
			t.Fatal("conflicting revert was retired")
		}
	}
	if read, err := f.h.Address(context.Background()); err != nil || read.Phase != "verification_conflict" {
		t.Fatalf("conflict is not durable: %+v %v", read, err)
	}
	// While the indexer is behind the receipt block, the retry waits.
	f.mu.Lock()
	f.setLeaf(12, noteLeaf(12, fieldValue("0x9999"), 5, 1))
	f.indexerBlock = 0xf
	f.mu.Unlock()
	status, err = f.h.FundAddress(context.Background(), 100000)
	if err != nil || !strings.Contains(status.Message, "waiting for the zkAPI indexer") || f.savedAddress(t).Pending == nil {
		t.Fatalf("lagging indexer allowed a retry: %+v %v", status, err)
	}
	// Another deposit took the slot: the revert is genuine and retryable.
	f.mu.Lock()
	f.indexerBlock = 0x20
	f.mu.Unlock()
	status, err = f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "reverted" {
		t.Fatalf("genuine revert did not become retryable: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err == nil {
		_, err = f.h.ApproveAddressDeposit(context.Background(), quote.ID)
	}
	if err != nil || len(f.accepted) != 2 || f.savedAddress(t).Pending.Hash == first.TransactionHash {
		t.Fatalf("genuine revert could not be retried: %v", err)
	}
	if record := f.savedAddress(t); len(record.History) != 1 || !record.History[0].FinalizedRevert {
		t.Fatal("retired revert was not journaled")
	}
}

// A third party can copy the public commitment from the reverted calldata
// and deposit 1 gwei with it. That leaf is not ours and must not block the
// requote, the retirement, or the public return.
func TestForeignDepositReusingCommitmentDoesNotBlockRetry(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, true)
	f.mu.Lock()
	f.registerDeposit(12, "0x1234", 1, bucketedExpiry())
	f.registerDeposit(13, "0x1234", 1, bucketedExpiry())
	f.mu.Unlock()
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not reported: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err != nil || quote.RetryHash != first.TransactionHash {
		t.Fatalf("foreign deposit blocked the requote: %+v %v", quote, err)
	}
	// Resuming retires the failed transaction; no new deposit is signed
	// without an approved quote.
	_, _ = f.h.FundAddress(context.Background(), 100000)
	record := f.savedAddress(t)
	if record.Pending != nil || len(record.History) != 1 || !record.History[0].FinalizedRevert || len(f.accepted) != 1 {
		t.Fatalf("foreign deposit blocked retirement: %+v", record)
	}
	if _, err := f.h.QuoteAddressReturn(context.Background(), withdrawalTestDestination, "1000000000"); err != nil {
		t.Fatalf("foreign deposit blocked the public return: %v", err)
	}
}

// Review regression 3: a forged finalized revert plus an advanced nonce
// must not lead to a second deposit of the same note secret.
func TestForgedRevertWithAdvancedNonceSignsNoSecondDeposit(t *testing.T) {
	t.Run("deposit landed", func(t *testing.T) {
		f := newAddressFixture(t, true)
		first, err := f.fundNative(t, 100000)
		if err != nil {
			t.Fatal(err)
		}
		f.mine(t, first.TransactionHash, true) // forged revert; nonce advanced
		f.mu.Lock()
		f.registerDeposit(12, "0x1234", 100000, bucketedExpiry())
		f.mu.Unlock()
		_, _ = f.h.FundAddress(context.Background(), 100000)
		if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil {
			t.Fatal("forged revert allowed a new deposit quote")
		}
		if status, _ := f.h.FundAddress(context.Background(), 100000); status.Phase != "verification_conflict" {
			t.Fatalf("forged revert not reported: %+v", status)
		}
		if len(f.accepted) != 1 || f.prepared != 1 {
			t.Fatal("a second deposit was signed for the same note")
		}
		// Rebind finds the landed note from the journaled slot.
		status, err := f.h.RebindDeposit(context.Background(), nil, nil)
		if err != nil || status.Phase != "active" || f.activated != 1 || f.confirmBodies[0]["note_id"] != float64(12) {
			t.Fatalf("rebind did not recover the landed note: %+v %v", status, err)
		}
		record := f.savedAddress(t)
		if record.Pending != nil || len(record.History) != 1 || record.History[0].Hash != first.TransactionHash || !record.History[0].FinalizedRevert {
			t.Fatal("rebind did not retire the reported revert into history")
		}
	})
	t.Run("deposit withheld", func(t *testing.T) {
		// Retired while withheld, the deposit is relayed and lands at its
		// slot before the retry is quoted.
		f, hash, commitment := retiredWithheldDeposit(t)
		f.mu.Lock()
		f.registerDeposit(12, commitment, 100000, bucketedExpiry())
		f.mu.Unlock()
		if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "at note 12") || !strings.Contains(err.Error(), "config --menu, then choose repair") {
			t.Fatalf("a retry was quoted after the withheld deposit landed: %v", err)
		}
		if record := f.savedAddress(t); record.Quote != nil || record.Phase != "verification_conflict" {
			t.Fatalf("the refused retry left an approvable quote or no conflict: %+v", record)
		}
		for range 2 {
			status, err := f.h.FundAddress(context.Background(), 100000)
			if err != nil || status.Phase != "verification_conflict" || !strings.Contains(status.Message, "note 12") {
				t.Fatalf("resuming did not re-check the landed deposit: %+v %v", status, err)
			}
		}
		if read, err := f.h.Address(context.Background()); err != nil || read.Phase != "verification_conflict" {
			t.Fatalf("conflict is not durable: %+v %v", read, err)
		}
		if len(f.accepted) != 1 || f.prepared != 1 {
			t.Fatal("a second deposit was signed for the same note")
		}
		f.repairBindsNote(t, 12, hash)
		if len(f.accepted) != 1 {
			t.Fatal("repair signed a deposit")
		}
	})
	t.Run("deposit lands between quote and approval", func(t *testing.T) {
		f, hash, commitment := retiredWithheldDeposit(t)
		quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.registerDeposit(12, commitment, 100000, bucketedExpiry())
		f.mu.Unlock()
		// The approval builds the retry for slot 13 from a tree that shows
		// the earlier deposit at 12.
		status, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID)
		if err != nil || status.Phase != "verification_conflict" || !strings.Contains(status.Message, "at note 12") || !strings.Contains(status.Message, "config --menu, then choose repair") {
			t.Fatalf("the approval did not stop at the landed deposit: %+v %v", status, err)
		}
		if len(f.accepted) != 1 || f.savedDeposit(t).Slot.NoteID != 12 {
			t.Fatal("a second deposit was signed or its slot recorded")
		}
		f.repairBindsNote(t, 12, hash)
		if len(f.accepted) != 1 {
			t.Fatal("repair signed a deposit")
		}
	})
	t.Run("deposit lands during the approval", func(t *testing.T) {
		f := newAddressFixture(t, true)
		first, err := f.fundNative(t, 100000)
		if err != nil {
			t.Fatal(err)
		}
		f.mine(t, first.TransactionHash, true) // forged revert; deposit withheld
		if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
			t.Fatalf("revert not recorded: %+v %v", status, err)
		}
		quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		commitment := "0x" + hex.EncodeToString(f.accepted[first.TransactionHash].Data())[8:72]
		f.mu.Unlock()
		// The approval's revert check reads an indexer view without the
		// deposit. The RPC stalls the canonical lookup of that view's block
		// while the deposit lands, so the stale view retires it.
		relayed := false
		upstream := f.h.client.inference.Transport
		f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
			raw, _ := ioReadAndRestore(r)
			var request struct {
				Method string            `json:"method"`
				Params []json.RawMessage `json:"params"`
			}
			_ = json.Unmarshal(raw, &request)
			if !relayed && request.Method == "eth_getBlockByNumber" && len(request.Params) > 0 && string(request.Params[0]) == `"0x20"` && f.savedAddress(t).Pending != nil {
				relayed = true
				f.mu.Lock()
				f.registerDeposit(12, commitment, 100000, bucketedExpiry())
				f.mu.Unlock()
			}
			return upstream.RoundTrip(r)
		})
		status, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID)
		if !relayed {
			t.Fatal("the fixture did not land the deposit during the revert check")
		}
		if err != nil || status.Phase != "verification_conflict" || !strings.Contains(status.Message, "at note 12") {
			t.Fatalf("the retry was not stopped by the tree it is built from: %+v %v", status, err)
		}
		if len(f.accepted) != 1 {
			t.Fatal("a second deposit was signed for the same note")
		}
		f.h.client.inference.Transport = upstream
		f.repairBindsNote(t, 12, first.TransactionHash)
		if len(f.accepted) != 1 {
			t.Fatal("repair signed a deposit")
		}
	})
}

// retiredWithheldDeposit signs a native deposit whose payment RPC withholds
// it, forges its finalized revert and advances the nonce. A plain resume
// retires it, because the indexer shows nothing yet, and signs nothing
// without an approved quote.
func retiredWithheldDeposit(t *testing.T) (*addressFixture, string, string) {
	t.Helper()
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, true)
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not recorded: %+v %v", status, err)
	}
	_, _ = f.h.FundAddress(context.Background(), 100000)
	if record := f.savedAddress(t); record.Pending != nil || len(record.History) != 1 || !record.History[0].FinalizedRevert || len(f.accepted) != 1 {
		t.Fatalf("the withheld deposit was not retired: %+v", record)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f, first.TransactionHash, "0x" + hex.EncodeToString(f.accepted[first.TransactionHash].Data())[8:72]
}

// repairBindsNote runs the menu's repair, a rebind without IDs, and requires
// it to activate noteID once and keep the retired deposit in history.
func (f *addressFixture) repairBindsNote(t *testing.T, noteID uint32, retired string) {
	t.Helper()
	status, err := f.h.RebindDeposit(context.Background(), nil, nil)
	if err != nil || status.Phase != "active" || f.activated != 1 || f.confirmBodies[0]["note_id"] != float64(noteID) {
		t.Fatalf("repair did not bind the landed note: %+v %v", status, err)
	}
	record := f.savedAddress(t)
	if record.Pending != nil || record.Phase != "active" || len(record.History) == 0 || record.History[0].Hash != retired || !record.History[0].FinalizedRevert {
		t.Fatalf("repair did not keep the retired deposit journal: %+v", record)
	}
	if binding := f.savedDeposit(t).Binding; binding == nil || binding.NoteID != noteID {
		t.Fatalf("repair saved another binding: %+v", binding)
	}
	if again, err := f.h.FundAddress(context.Background(), 100000); err != nil || again.Phase != "active" || f.activated != 1 {
		t.Fatalf("the repaired note was activated again or replaced: %+v %v", again, err)
	}
}

// The conflict is re-checked on every resume. If the indexer no longer shows
// the earlier deposit (its block was reorganized away), funding continues
// only through a fresh quote, whose retry again targets its still-empty slot.
func TestLandedDepositConflictClearsWhenIndexerNoLongerShowsIt(t *testing.T) {
	f, _, commitment := retiredWithheldDeposit(t)
	f.mu.Lock()
	f.registerDeposit(12, commitment, 100000, bucketedExpiry())
	f.mu.Unlock()
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "verification_conflict" {
		t.Fatalf("the landed deposit was not a conflict: %+v %v", status, err)
	}
	f.mu.Lock()
	f.indexerStatus = http.StatusServiceUnavailable
	f.mu.Unlock()
	if status, err := f.h.FundAddress(context.Background(), 100000); err == nil || status.Phase != "verification_conflict" {
		t.Fatalf("an unavailable indexer cleared the conflict: %+v %v", status, err)
	}
	f.mu.Lock()
	f.indexerStatus = 0
	f.leaves = f.leaves[:12]
	f.leafVersion++
	delete(f.vaultNotes, 12)
	f.mu.Unlock()
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "waiting_funds" || len(f.accepted) != 1 {
		t.Fatalf("the cleared conflict did not wait for a fresh quote: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	if status, err = f.h.ApproveAddressDeposit(context.Background(), quote.ID); err != nil || status.Phase != "deposit_pending" {
		t.Fatalf("the retry was not signed: %+v %v", status, err)
	}
	var paths []string
	for _, tx := range f.accepted {
		paths = append(paths, depositPathDigest(tx.Data()))
	}
	if len(paths) != 2 || paths[0] != paths[1] {
		t.Fatal("the retry did not target the earlier deposit's empty slot")
	}
}

// While a withheld deposit has not landed, a retry is built for its still
// empty slot. If the withheld deposit lands first, the retry cannot also
// land, and its revert is a conflict that signs nothing more.
func TestRetryOfWithheldDepositTargetsItsEmptySlot(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, true) // forged revert; deposit withheld
	_, _ = f.h.FundAddress(context.Background(), 100000)
	quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID)
	if err != nil || retry.Phase != "deposit_pending" {
		t.Fatalf("the retry was not signed: %+v %v", retry, err)
	}
	var paths []string
	for _, tx := range f.accepted {
		paths = append(paths, depositPathDigest(tx.Data()))
	}
	if len(paths) != 2 || paths[0] != paths[1] {
		t.Fatal("retry of a withheld deposit targeted a different slot")
	}
	f.mu.Lock()
	commitment := "0x" + hex.EncodeToString(f.accepted[first.TransactionHash].Data())[8:72]
	f.registerDeposit(12, commitment, 100000, bucketedExpiry())
	f.mu.Unlock()
	f.mine(t, retry.TransactionHash, true) // Its slot is taken: the retry reverts.
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("the retry's revert was not recorded: %+v %v", status, err)
	}
	for range 2 {
		status, err := f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.Phase != "verification_conflict" || !strings.Contains(status.Message, "note 12") {
			t.Fatalf("the landed deposit was not a conflict: %+v %v", status, err)
		}
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil {
		t.Fatal("a third deposit was quoted")
	}
	f.repairBindsNote(t, 12, first.TransactionHash)
	notes := 0
	for _, note := range f.vaultNotes {
		if strings.EqualFold(note.commitment, commitment) {
			notes++
		}
	}
	if len(f.accepted) != 2 || notes != 1 {
		t.Fatalf("signed %d deposits, %d of them on chain", len(f.accepted), notes)
	}
}

// The indexer serves a head view, which can be a short fork. A deposit built
// on a fork whose slot 12 was deposited and emptied again targets slot 13,
// and its calldata is just as valid at slot 12 of the canonical tree once
// that fork is orphaned. Its slot is saved with the run of empty slots below
// it, which every search covers too, so the revert check, quotes and repair
// find it there, and no second deposit of the note is signed.
func TestDepositBuiltOnForkedViewIsFoundBelowItsSlot(t *testing.T) {
	f := newAddressFixture(t, true)
	f.mu.Lock()
	f.setLeaf(12, new(big.Int)) // The fork's slot 12, deposited and emptied.
	f.mu.Unlock()
	first, err := f.fundNative(t, 100000)
	if err != nil || first.Phase != "deposit_pending" {
		t.Fatalf("deposit was not signed: %+v %v", first, err)
	}
	f.mu.Lock()
	f.leaves = f.leaves[:12] // The fork is orphaned: the canonical next slot is 12.
	f.leafVersion++
	root, _ := f.tree()
	_ = root
	data := f.accepted[first.TransactionHash].Data()
	commitment := "0x" + hex.EncodeToString(data[4:36])
	f.mu.Unlock()
	// The vault appends at its own next slot, 12, while the RPC reports a finalized revert.
	f.mine(t, first.TransactionHash, true)
	f.mu.Lock()
	f.registerDeposit(12, commitment, 100000, bucketedExpiry())
	f.mu.Unlock()
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not recorded: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "at note 12") {
		t.Fatalf("a retry was quoted: %v", err)
	}
	for range 2 {
		status, err := f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.Phase != "verification_conflict" || !strings.Contains(status.Message, "note 12") {
			t.Fatalf("the deposit that landed below its slot was retired: %+v %v", status, err)
		}
	}
	if len(f.accepted) != 1 {
		t.Fatal("a second deposit was signed for the same note")
	}
	f.repairBindsNote(t, 12, first.TransactionHash)
}

// Guided setup quotes again every five seconds while it waits for funds. A
// retry quote searches the indexer's tree for the note's earlier deposits,
// but downloads a tree it already searched only once; later quotes read its
// root. A deposit that lands changes the root, so the next quote searches
// the new tree and refuses.
func TestRetryQuotesDownloadAnUnchangedTreeOnce(t *testing.T) {
	f, hash, commitment := retiredWithheldDeposit(t)
	reads := func() (int, int) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.snapshotReads, f.rootReads
	}
	snapshots, roots := reads()
	for i := range 12 {
		if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err != nil {
			t.Fatalf("retry quote %d: %v", i, err)
		}
	}
	if s, r := reads(); s-snapshots != 1 || r-roots != 11 {
		t.Fatalf("12 quotes of one tree downloaded it %d times and read its root %d times", s-snapshots, r-roots)
	}
	f.mu.Lock()
	f.registerDeposit(12, commitment, 100000, bucketedExpiry()) // The withheld deposit lands.
	f.mu.Unlock()
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "at note 12") {
		t.Fatalf("the quote after the landing did not search the changed tree: %v", err)
	}
	if s, _ := reads(); s-snapshots != 2 {
		t.Fatalf("the changed tree was downloaded %d times in all", s-snapshots)
	}
	if record := f.savedAddress(t); record.Phase != "verification_conflict" || len(f.accepted) != 1 {
		t.Fatalf("the landed deposit is not a durable conflict: %+v", record)
	}
	f.repairBindsNote(t, 12, hash)
}

// The quote-time search is advisory: approval searches the tree it signs
// from and fails closed. So an indexer outage does not refuse a retry quote,
// which would end guided setup at its first quote, and approval signs
// nothing until the indexer answers again.
func TestRetryQuoteIsNotRefusedWhileIndexerIsUnavailable(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.setLeaf(12, noteLeaf(12, fieldValue("0x5678"), 7, bucketedExpiry())) // Another deposit takes slot 12.
	f.mu.Unlock()
	f.mine(t, first.TransactionHash, true)
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not recorded: %+v %v", status, err)
	}
	// Retiring signs nothing: a native deposit needs an approved quote.
	_, _ = f.h.FundAddress(context.Background(), 100000)
	if record := f.savedAddress(t); record.Pending != nil || record.Phase != "waiting_funds" || len(record.History) != 1 || !record.History[0].FinalizedRevert {
		t.Fatalf("the revert was not retired: %+v", record)
	}
	f.mu.Lock()
	f.indexerStatus = http.StatusServiceUnavailable
	f.mu.Unlock()
	quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err != nil || quote.ID == "" {
		t.Fatalf("an indexer outage refused the retry quote: %v", err)
	}
	if status, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID); err == nil || !strings.Contains(err.Error(), "no deposit was signed") || len(f.accepted) != 1 {
		t.Fatalf("approval signed without searching the indexer's tree: %+v %v", status, err)
	}
	f.mu.Lock()
	f.indexerStatus = 0
	f.mu.Unlock()
	if quote, err = f.h.QuoteAddressDeposit(context.Background(), 100000); err != nil {
		t.Fatal(err)
	}
	if status, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID); err != nil || status.Phase != "deposit_pending" || len(f.accepted) != 2 {
		t.Fatalf("the retry was not signed once the indexer answered: %+v %v", status, err)
	}
}

// A quote saves phase waiting_funds, so it clears a saved conflict about an
// earlier deposit only after a completed search, as a resume does. An
// indexer outage keeps the conflict.
func TestQuoteKeepsSavedConflictWhileIndexerIsUnavailable(t *testing.T) {
	f, _, commitment := retiredWithheldDeposit(t)
	f.mu.Lock()
	f.registerDeposit(12, commitment, 100000, bucketedExpiry())
	f.mu.Unlock()
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "verification_conflict" {
		t.Fatalf("the landed deposit was not a conflict: %+v %v", status, err)
	}
	f.mu.Lock()
	f.indexerStatus = http.StatusServiceUnavailable
	f.mu.Unlock()
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil {
		t.Fatal("a quote cleared the saved conflict without searching the indexer's tree")
	}
	if record := f.savedAddress(t); record.Phase != "verification_conflict" || record.Quote != nil || len(f.accepted) != 1 {
		t.Fatalf("the saved conflict was not kept: %+v", record)
	}
}

func TestPrepareIgnoresCompanionActivationFields(t *testing.T) {
	f := newAddressFixture(t, true)
	upstream := f.h.client.local.Transport
	f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/funding/api/deposit/prepare" {
			return upstream.RoundTrip(r)
		}
		path := make([]string, 32)
		for i := range path {
			path[i] = "0x0"
		}
		return withdrawalJSONResponse(r, 200, map[string]any{
			"amount": 100000, "secret": "0xabcdef", "commitment": "0x1234", "zero_path": path, "next_note_id": 12, "active_root": "0x1",
			"active": true, "transaction_hash": "0x" + strings.Repeat("d", 64), "deployment_id": "other",
			"binding":      map[string]any{"note_id": 7, "expiry_ts": 1, "block_hash": "0x" + strings.Repeat("e", 64)},
			"rebind":       map[string]any{"from_note_id": 1, "to_note_id": 7, "expiry_ts": 1},
			"slot":         map[string]any{"note_id": 7, "path_sha256": "0x" + strings.Repeat("f", 64), "prepared_at": 1},
			"signed_slots": []map[string]any{{"note_id": 7, "path_sha256": "0x" + strings.Repeat("f", 64), "prepared_at": 1}},
		}), nil
	})
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err != nil {
		t.Fatal(err)
	}
	record := f.savedDeposit(t)
	if record.Active || record.TransactionHash != "" || record.Binding != nil || record.Rebind != nil || record.Slot != nil || record.SignedSlots != nil || record.Secret != "0xabcdef" || record.DeploymentID == "other" {
		t.Fatalf("companion seeded Go-owned deposit fields: %+v", record)
	}
}

func TestConfirmGuidesRebindForMismatchedCompanionNote(t *testing.T) {
	for _, mismatch := range []string{"note", "expiry"} {
		t.Run(mismatch, func(t *testing.T) {
			f, hash := minedNativeDeposit(t)
			if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "active" {
				t.Fatalf("fixture did not activate: %+v %v", status, err)
			}
			f.mu.Lock()
			// A pre-fix release activated this deposit at the RPC's note ID.
			f.walletNote["expiry_ts"] = f.vaultNotes[12].expiry + 86400
			if mismatch == "note" {
				f.walletNote["note_id"] = 0xA4A4
				f.walletNote["expiry_ts"] = f.vaultNotes[12].expiry
			}
			f.mu.Unlock()
			_, err := f.h.confirm(context.Background(), hash)
			if err == nil || !strings.Contains(err.Error(), "choose repair, and replace companion note") {
				t.Fatalf("mismatched companion note was not guided to rebind: %v", err)
			}
			if f.activated != 1 {
				t.Fatal("confirmation reinitialized the companion")
			}
		})
	}
}

func TestFundingAdminRebindRejectsMalformedBodiesBeforeIO(t *testing.T) {
	h := &FundingHandler{}
	for _, body := range []string{`{"note_id":4294967296}`, `{"replace_note_id":4294967296}`, `{"note_id":-1}`, `{"note_id":"12"}`, `{"note_id":1,"secret":"0x1"}`, `{"note_id":1} {}`, `{"note_id":1}` + strings.Repeat(" ", 1025)} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8787/admin/funding/rebind", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeAdminHTTP(w, r)
		if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "0x1") {
			t.Fatalf("malformed rebind body %q: %d %s", body, w.Code, w.Body.String())
		}
	}
}

func TestRebindRefusesWhileDifferentSavedDepositIsUnconfirmed(t *testing.T) {
	f := newAddressFixture(t, true)
	if _, err := f.fundNative(t, 100000); err != nil {
		t.Fatal(err)
	}
	// A note with this commitment exists, but the saved deposit is unmined
	// and could still create a second one.
	f.mu.Lock()
	f.registerDeposit(12, "0x1234", 100000, bucketedExpiry())
	f.mu.Unlock()
	note := uint64(12)
	if _, err := f.h.RebindDeposit(context.Background(), &note, nil); err == nil || !strings.Contains(err.Error(), "second note") {
		t.Fatalf("rebind ignored an unconfirmed saved deposit: %v", err)
	}
	if f.activated != 0 || f.resetCalls != 0 || f.savedDeposit(t).Active {
		t.Fatal("refused rebind changed the companion or deposit")
	}
}

func TestRebindRequiresFinalizedVaultAndIndexerAgreement(t *testing.T) {
	for name, mutate := range map[string]func(f *addressFixture){
		"vault uninitialized": func(f *addressFixture) { delete(f.vaultNotes, 12) },
		"vault other note": func(f *addressFixture) {
			note := f.vaultNotes[12]
			note.commitment = "0x" + addressABIWord("0x5678")
			f.vaultNotes[12] = note
		},
		"vault pending withdrawal": func(f *addressFixture) {
			note := f.vaultNotes[12]
			note.status = notePendingWithdrawal
			f.vaultNotes[12] = note
		},
		"indexer behind finality": func(f *addressFixture) { f.indexerBlock = 0x1f },
		"indexer other leaf":      func(f *addressFixture) { f.setLeaf(12, big.NewInt(77)) },
		"foreign 1 gwei note": func(f *addressFixture) {
			f.registerDeposit(12, "0x1234", 1, f.vaultNotes[12].expiry)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := minedNativeDeposit(t)
			f.finalized = "0x20"
			f.mu.Lock()
			mutate(f)
			f.mu.Unlock()
			note := uint64(12)
			if _, err := f.h.RebindDeposit(context.Background(), &note, nil); err == nil {
				t.Fatal("rebind accepted a note the finalized vault and indexer do not agree on")
			}
			if f.activated != 0 || f.resetCalls != 0 || f.savedDeposit(t).Active || f.savedDeposit(t).Binding != nil {
				t.Fatal("refused rebind changed state")
			}
		})
	}
}

// expiryAt is the expiry the vault assigns to a deposit mined at chain time at.
func expiryAt(at int64) uint64 {
	return (uint64(at) + 2592000 + vaultExpiryBucket - 1) / vaultExpiryBucket * vaultExpiryBucket
}

// Closure regression (unpinned-rpc #1): the search for an earlier deposit
// follows the block time of the indexer view it searches, never the device
// clock. Here the device clock runs days behind the chain while the payment
// RPC fakes its head time to match it (the fixture's "latest" block carries
// the device time), withholds the first deposit and relays it after its
// forged revert was retired. A retry is never signed: approval refuses the
// clock before the deposit lands, and its leaf is found after.
func TestDepositSearchFollowsChainTimeNotTheDeviceClock(t *testing.T) {
	for _, days := range []int64{2, 3, 10} {
		t.Run(fmt.Sprintf("device clock %d days behind", days), func(t *testing.T) {
			f, _, commitment := retiredWithheldDeposit(t)
			chainNow := time.Now().Unix() + days*vaultExpiryBucket
			f.setChainTime(chainNow)
			quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
			if err != nil {
				t.Fatalf("a retry with no landed deposit was not quoted: %v", err)
			}
			status, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID)
			if err == nil || !strings.Contains(err.Error(), "clock") || len(f.accepted) != 1 {
				t.Fatalf("a deposit was signed with the device clock %d days off: %+v %v (accepted %d)", days, status, err, len(f.accepted))
			}
			f.mu.Lock()
			f.registerDeposit(12, commitment, 100000, expiryAt(chainNow))
			f.mu.Unlock()
			if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "at note 12") {
				t.Fatalf("the deposit that landed at chain time was not found: %v", err)
			}
			if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "verification_conflict" {
				t.Fatalf("the landed deposit was not a conflict: %+v %v", status, err)
			}
			if len(f.accepted) != 1 {
				t.Fatal("a second deposit was signed for the same note")
			}
		})
	}
}

// The search is refused rather than run at an unverified time: a header the
// RPC withholds or that does not hash to the indexer view's block signs
// nothing.
func TestDepositSearchRequiresTheIndexerViewsVerifiedBlockTime(t *testing.T) {
	for name, tamper := range map[string]func(f *addressFixture){
		"withheld": func(f *addressFixture) { delete(f.headers, strings.ToLower(f.indexerHash)) },
		"forged time": func(f *addressFixture) {
			forged := *f.headers[strings.ToLower(f.indexerHash)]
			forged.Time -= 3 * vaultExpiryBucket
			f.headers[strings.ToLower(f.indexerHash)] = &forged
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, _, _ := retiredWithheldDeposit(t)
			quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			tamper(f)
			f.mu.Unlock()
			if _, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID); err == nil || !strings.Contains(err.Error(), "block header") || len(f.accepted) != 1 {
				t.Fatalf("a retry was signed without the view's verified block time: %v (accepted %d)", err, len(f.accepted))
			}
		})
	}
}

// A reported revert is not retired, and no retry quoted, while the device
// clock is days off chain time. (retiredWithheldDeposit retires one when
// the clocks agree.)
func TestRevertIsNotRetiredWhileTheDeviceClockIsOff(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.setChainTime(time.Now().Unix() - 2*vaultExpiryBucket)
	f.mine(t, first.TransactionHash, true)
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not recorded: %+v %v", status, err)
	}
	for range 2 {
		if _, err := f.h.FundAddress(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "clock") {
			t.Fatalf("the revert was retired with the device clock off: %v", err)
		}
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("a retry was quoted with the device clock off: %v", err)
	}
	if record := f.savedAddress(t); record.Pending == nil || record.Pending.Hash != first.TransactionHash || len(record.History) != 0 || len(f.accepted) != 1 {
		t.Fatal("the revert was retired with the device clock off")
	}
}

// seam:tests-ci #4: a block mined just before a UTC day boundary has the
// earlier expiry bucket even when the deposit's preparation, by chain or by
// device clock, falls just after it. A slot from an earlier build has only
// the device's preparation time, which can be days off chain time.
func TestDepositLeafSearchToleratesTheDayBoundaryAndOldDeviceTimes(t *testing.T) {
	commitment := fieldValue("0x1234")
	boundary := (time.Now().Unix()/vaultExpiryBucket + 1) * vaultExpiryBucket
	prepared, mined := boundary+30, boundary-30
	leaves := make([]string, 0, 13)
	for i := range 12 {
		leaves = append(leaves, fmt.Sprintf("0x%x", 0x1000+i))
	}
	leaves = append(leaves, fmt.Sprintf("0x%x", noteLeaf(12, commitment, 100000, expiryAt(mined))))
	snapshot := &treeSnapshot{NextNoteID: 13, Leaves: leaves}
	path := "0x" + strings.Repeat("f", 64)
	for name, search := range map[string]struct {
		slot depositSlot
		now  int64
	}{
		"chain time":  {depositSlot{NoteID: 12, PathSHA256: path, PreparedAt: prepared, PreparedChainAt: prepared}, boundary + 120},
		"device time": {depositSlot{NoteID: 12, PathSHA256: path, PreparedAt: prepared}, boundary + 120},
		// Saved by an earlier build on a device clock 6 days fast, and
		// searched 10 days later.
		"device 6 days ahead": {depositSlot{NoteID: 12, PathSHA256: path, PreparedAt: prepared + 6*vaultExpiryBucket}, boundary + 10*vaultExpiryBucket},
	} {
		if id, found := findDepositLeaf(snapshot, &search.slot, commitment, 100000, 2592000, search.now); !found || id != 12 {
			t.Fatalf("%s: a deposit mined just before the day boundary was not found: %d %v", name, id, found)
		}
	}
	if expiryAt(mined) == expiryAt(prepared) {
		t.Fatal("the fixture does not cross a bucket boundary")
	}
}

// seam:tests-ci #3: every signed slot is searched, not only the earliest,
// and two signings for the same note ID from different empty runs are both
// searched.
func TestSignedDepositSearchCoversEverySlotAndEmptyRun(t *testing.T) {
	commitment, now := fieldValue("0x1234"), time.Now().Unix()
	path := "0x" + strings.Repeat("f", 64)
	search := func(leaves []string, slots ...depositSlot) (uint32, bool) {
		return findSignedDepositLeaf(&treeSnapshot{NextNoteID: uint32(len(leaves)), Leaves: leaves}, slots, commitment, 100000, 2592000, now)
	}
	ours := func(id int) string {
		return fmt.Sprintf("0x%x", noteLeaf(uint32(id), commitment, 100000, expiryAt(now)))
	}

	// A later slot's landing, 150 occupied leaves past the earliest slot.
	leaves := make([]string, 200)
	for i := range leaves {
		leaves[i] = fmt.Sprintf("0x%x", 0x5000+i)
	}
	leaves[150] = ours(150)
	for _, slots := range [][]depositSlot{
		{{NoteID: 0, PathSHA256: path, PreparedAt: now, PreparedChainAt: now}, {NoteID: 100, PathSHA256: path, PreparedAt: now, PreparedChainAt: now}},
		{{NoteID: 100, PathSHA256: path, PreparedAt: now, PreparedChainAt: now}, {NoteID: 0, PathSHA256: path, PreparedAt: now - 60, PreparedChainAt: now - 60}},
	} {
		if id, found := search(leaves, slots...); !found || id != 150 {
			t.Fatalf("the later signed slot was not searched: %d %v", id, found)
		}
	}

	// Slot 100 signed twice: once from a view with no empty run, once from a
	// view in which slots [20, 100) were empty. The second lands at 30.
	leaves = make([]string, 0, 100+depositRevertScanSlots)
	for i := range 100 + depositRevertScanSlots {
		leaf := fmt.Sprintf("0x%x", 0x5000+i)
		if i >= 20 && i < 100 {
			leaf = "0x0"
		}
		leaves = append(leaves, leaf)
	}
	leaves[30] = ours(30)
	for _, slots := range [][]depositSlot{
		{{NoteID: 100, PathSHA256: path, PreparedAt: now - 60, PreparedChainAt: now - 60}, {NoteID: 100, PathSHA256: path, PreparedAt: now, PreparedChainAt: now, EmptyBefore: 80}},
		{{NoteID: 100, PathSHA256: path, PreparedAt: now, PreparedChainAt: now, EmptyBefore: 80}, {NoteID: 100, PathSHA256: path, PreparedAt: now - 60, PreparedChainAt: now - 60}},
	} {
		if id, found := search(leaves, slots...); !found || id != 30 {
			t.Fatalf("the same note ID's other empty run was not searched: %d %v", id, found)
		}
	}
}

// seam:tests-ci #3, approval path: after two forged reverts, the second
// deposit is relayed and lands at its own slot, far more than
// depositRevertScanSlots occupied leaves after the first deposit's slot. No
// third deposit of the note is quoted or signed.
func TestRetryAfterTwoForgedRevertsSearchesTheLaterSlot(t *testing.T) {
	f, _, commitment := retiredWithheldDeposit(t)
	f.mu.Lock()
	for id := uint32(addressTestFirstNote); id < addressTestFirstNote+100; id++ {
		f.setLeaf(id, big.NewInt(int64(0x7000+id))) // Other users' deposits.
	}
	f.mu.Unlock()
	second, err := f.fundNative(t, 100000)
	if err != nil || len(f.accepted) != 2 {
		t.Fatalf("the genuine retry was not signed: %+v %v", second, err)
	}
	if slot := f.savedDeposit(t).Slot; slot == nil || slot.NoteID != addressTestFirstNote+100 {
		t.Fatalf("the retry was not built for the next slot: %+v", slot)
	}
	f.mine(t, second.TransactionHash, true) // Forged again; withheld.
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "reverted" {
		t.Fatalf("second revert not recorded: %+v %v", status, err)
	}
	_, _ = f.h.FundAddress(context.Background(), 100000)
	if record := f.savedAddress(t); record.Pending != nil || len(record.History) != 2 {
		t.Fatalf("the second withheld deposit was not retired: %+v", record)
	}
	f.mu.Lock()
	f.registerDeposit(addressTestFirstNote+100, commitment, 100000, bucketedExpiry())
	f.mu.Unlock()
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("at note %d", addressTestFirstNote+100)) {
		t.Fatalf("a third deposit was quoted after the second landed: %v", err)
	}
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "verification_conflict" {
		t.Fatalf("the landed second deposit was not a conflict: %+v %v", status, err)
	}
	if len(f.accepted) != 2 {
		t.Fatal("a third deposit was signed for the same note")
	}
}
