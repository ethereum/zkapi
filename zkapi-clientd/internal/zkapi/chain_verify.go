package zkapi

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// The packaged payment RPC is a third party. Before a note secret leaves this
// process, or a failed deposit is retired or retried, its claims are checked
// against the operator indexer's snapshot, which records every deposited
// note (vault revision 4 records a deposit without inserting it into the
// tree; operator batches activate notes later). The snapshot is the same
// payload for every caller, so the indexer never learns which note is ours;
// Go recomputes the expected recorded leaf with zkAPI Poseidon. Lag or
// missing data is pending; disagreement is a non-terminal conflict. The
// indexer is the operator's: once a deposit is final, the owner's exit RPC,
// when configured, stands in for it, so a withheld note can still be saved
// and escaped (corroborateDepositByExitRPC).

const notesSelector = "0x9f18e4ed" // notes(uint32)

const (
	noteUninitialized uint8 = iota
	noteActive
	notePendingWithdrawal
	noteClosed
)

const (
	maxSafeNoteAmount = 9_007_199_254_740_991
	// About 450,000 notes in a whole snapshot, which carries every note's
	// tree leaf, recorded leaf and note record. The records part this client
	// asks for (snapshotRecordsRoute) leaves out the tree leaves, but an
	// older indexer ignores the request and serves everything.
	indexerSnapshotLimit = 128 << 20
	// No deposit is signed while the device clock is further than this from
	// chain time.
	deviceClockTolerance = 24 * 60 * 60
	// A tree root response is a few hundred bytes.
	indexerRootLimit = 4 << 10
)

var (
	errDepositVerificationPending    = errors.New("the deposit is mined; waiting for the zkAPI indexer to confirm its note record before the private note is saved")
	errDepositVerificationConflict   = errors.New("the payment RPC, the vault state, and the zkAPI indexer disagree about this deposit; its private note was not saved")
	errRevertVerificationPending     = errors.New("waiting for the zkAPI indexer to confirm the revert")
	errWithdrawalVerificationPending = errors.New("the withdrawal is final on Ethereum; waiting for the vault state to show the note closed")
	// errExitRPCCloseCheckUnusable is an exit RPC that cannot check a close
	// at all (corroborateWithdrawalClosed): waiting does not help, its
	// configuration needs fixing.
	errExitRPCCloseCheckUnusable = errors.New("your exit RPC did not answer, is on another network, or refused to read the vault at a block hash")
	// errExitRPCDepositCheckUnusable is an exit RPC that cannot stand in for
	// the indexer at all (corroborateDepositByExitRPC): waiting does not
	// help, its configuration needs fixing.
	errExitRPCDepositCheckUnusable = errors.New("your exit RPC did not answer, is on another network, or refused to read the vault at a block hash")
	// errIndexerDepositConflict is the indexer alone disagreeing with a
	// deposit the payment RPC's vault state holds, which the owner's exit
	// RPC can settle (corroborateDepositByExitRPC).
	errIndexerDepositConflict = errors.New("the zkAPI indexer does not record this deposit")
)

const conflictGuidance = " Checking again re-verifies automatically. If this persists, compare the transaction on a block explorer and run zkapi-clientd config --menu, then choose repair."

type vaultNoteState struct {
	Commitment string // 0x + 64 lowercase hex
	Amount     uint64
	ExpiryTs   uint64
	Status     uint8
}

// blockAtHash is an EIP-1898 block parameter: the read fails, rather than
// silently using another fork, when the RPC's block is not canonical.
func blockAtHash(hash string) map[string]any {
	return map[string]any{"blockHash": strings.ToLower(hash), "requireCanonical": true}
}

func (h *FundingHandler) vaultNote(ctx context.Context, config fundingConfig, id uint32, block any) (vaultNoteState, error) {
	var encoded string
	call := map[string]string{"to": config.Contract, "data": fmt.Sprintf("%s%064x", notesSelector, id)}
	if err := h.addressRPC(ctx, config, "eth_call", []any{call, block}, &encoded); err != nil {
		return vaultNoteState{}, err
	}
	return decodeVaultNote(encoded)
}

// vaultNoteAtReceipt reads notes(id) at the receipt's own canonical block.
// Full nodes keep state only for recent blocks, so once that block is final
// the finalized block, also read by hash and canonical only, is used instead.
func (h *FundingHandler) vaultNoteAtReceipt(ctx context.Context, config fundingConfig, id uint32, receiptBlock uint64, receiptHash string) (vaultNoteState, error) {
	note, err := h.vaultNote(ctx, config, id, blockAtHash(receiptHash))
	if err == nil {
		return note, nil
	}
	finalized, hash, finalErr := h.finalizedBlock(ctx, config)
	if finalErr != nil || finalized < receiptBlock {
		return vaultNoteState{}, err
	}
	return h.vaultNote(ctx, config, id, blockAtHash(hash))
}

func (h *FundingHandler) finalizedBlock(ctx context.Context, config fundingConfig) (uint64, string, error) {
	var header struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if err := h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{"finalized", false}, &header); err != nil {
		return 0, "", err
	}
	number, err := addressHexUint(header.Number)
	if err != nil || !number.IsUint64() || !isHex(header.Hash, 32) {
		return 0, "", errors.New("invalid finalized block from the payment RPC")
	}
	return number.Uint64(), strings.ToLower(header.Hash), nil
}

// decodeVaultNote accepts exactly notes(uint32)'s four static words:
// (bytes32 commitment, uint128 depositAmount, uint64 expiryTs, uint8 status).
func decodeVaultNote(encoded string) (vaultNoteState, error) {
	invalid := errors.New("invalid vault note state")
	if len(encoded) != 2+4*64 || !strings.HasPrefix(encoded, "0x") {
		return vaultNoteState{}, invalid
	}
	raw, err := hex.DecodeString(encoded[2:])
	if err != nil {
		return vaultNoteState{}, invalid
	}
	zero := func(bytes []byte) bool {
		for _, b := range bytes {
			if b != 0 {
				return false
			}
		}
		return true
	}
	amount := binary.BigEndian.Uint64(raw[56:64])
	if !zero(raw[32:56]) || amount > maxSafeNoteAmount || !zero(raw[64:88]) || !zero(raw[96:127]) || raw[127] > noteClosed {
		return vaultNoteState{}, invalid
	}
	return vaultNoteState{Commitment: "0x" + hex.EncodeToString(raw[:32]), Amount: amount, ExpiryTs: binary.BigEndian.Uint64(raw[88:96]), Status: raw[127]}, nil
}

// treeSnapshot is the indexer's view of the vault's notes: every recorded
// note [0, NextNoteID), activated or not. Its tree leaves are not kept: a
// recorded note enters the tree only when an operator batch activates it,
// and nothing here depends on that.
type treeSnapshot struct {
	Root       *big.Int
	NextNoteID uint32
	// NoteLeaves[id] is note id's recorded leaf, the leaf activation inserts.
	NoteLeaves []string
	// Notes[id] is what NoteDeposited recorded for note id.
	Notes       []recordedNote
	BlockNumber uint64
	BlockHash   string
	// Time is the view's block time, set only by snapshotChainTime.
	Time int64
}

// recordedNote is a vault notes(noteId) record without its status.
type recordedNote struct {
	Commitment *big.Int
	Amount     *big.Int
	ExpiryTs   uint64
}

// recordedLeaf returns the indexer's recorded leaf for id. present is false
// only when the snapshot records no such note.
func (s *treeSnapshot) recordedLeaf(id uint32) (value *big.Int, present bool) {
	if uint64(id) >= uint64(len(s.NoteLeaves)) {
		return nil, false
	}
	value, _ = parseFieldElement(s.NoteLeaves[id])
	return value, true
}

// indexerGet reads a fixed public route of the packaged indexer through the
// configured transport, with no credentials and no redirects. Every client
// sends the same request and gets the same response, so the indexer never
// learns which note is ours. Bodies are never reflected.
func (h *FundingHandler) indexerGet(ctx context.Context, config fundingConfig, route string, limit int, timeout time.Duration) ([]byte, bool) {
	if config.Indexer == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(config.Indexer, "/")+route, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	response, err := h.client.inference.Do(req)
	if err != nil {
		return nil, false
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) > limit || response.StatusCode != http.StatusOK {
		return nil, false
	}
	return raw, true
}

// indexerRoot reads the identity of the indexer's current view, its root and
// next_note_id, without the leaves or note records. The root changes with
// every activation and retirement, next_note_id with every deposit.
func (h *FundingHandler) indexerRoot(ctx context.Context, config fundingConfig) (*big.Int, uint32, error) {
	raw, ok := h.indexerGet(ctx, config, "/v1/tree/root", indexerRootLimit, 5*time.Second)
	if !ok {
		return nil, 0, errors.New("the zkAPI indexer root is unavailable")
	}
	var wire struct {
		Root       string  `json:"root"`
		NextNoteID *uint32 `json:"next_note_id"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.NextNoteID == nil {
		return nil, 0, errors.New("invalid zkAPI indexer root")
	}
	root, valid := parseFieldElement(wire.Root)
	if !valid {
		return nil, 0, errors.New("invalid zkAPI indexer root")
	}
	return root, *wire.NextNoteID, nil
}

// snapshotRecordsRoute asks for the snapshot's header and note records
// without the tree leaves, which nothing here reads. The query names no note.
const snapshotRecordsRoute = "/v1/tree/snapshot?parts=records"

// indexerSnapshot reads the packaged indexer's whole-vault snapshot: the
// recorded leaf and the note record of every deposited note. An indexer that
// ignores the parts query serves the whole snapshot, whose tree leaves are
// ignored. A snapshot without block metadata or note records (an older
// indexer) can never be evidence: its applied block, or what it recorded,
// is unknown.
func (h *FundingHandler) indexerSnapshot(ctx context.Context, config fundingConfig) (*treeSnapshot, error) {
	raw, ok := h.indexerGet(ctx, config, snapshotRecordsRoute, indexerSnapshotLimit, 20*time.Second)
	if !ok {
		return nil, errors.New("the zkAPI indexer snapshot is unavailable")
	}
	var wire struct {
		Root       string    `json:"root"`
		NextNoteID *uint32   `json:"next_note_id"`
		NoteLeaves *[]string `json:"note_leaves"`
		Notes      *[]struct {
			NoteID     *uint32     `json:"note_id"`
			Commitment string      `json:"commitment"`
			Amount     json.Number `json:"amount"`
			ExpiryTs   *uint64     `json:"expiry_ts"`
		} `json:"notes"`
		BlockNumber *uint64 `json:"block_number"`
		BlockHash   string  `json:"block_hash"`
	}
	invalid := errors.New("invalid zkAPI indexer snapshot")
	if json.Unmarshal(raw, &wire) != nil || wire.NextNoteID == nil {
		return nil, invalid
	}
	if wire.BlockNumber == nil || !isHex(wire.BlockHash, 32) {
		return nil, errors.New("the zkAPI indexer snapshot has no block identity; the indexer must be upgraded")
	}
	if wire.NoteLeaves == nil || wire.Notes == nil {
		return nil, errors.New("the zkAPI indexer snapshot has no note records; the indexer must be upgraded")
	}
	root, ok := parseFieldElement(wire.Root)
	if !ok || uint64(len(*wire.NoteLeaves)) != uint64(*wire.NextNoteID) || len(*wire.Notes) != len(*wire.NoteLeaves) {
		return nil, invalid
	}
	for _, leaf := range *wire.NoteLeaves {
		if _, ok := parseFieldElement(leaf); !ok {
			return nil, invalid
		}
	}
	notes := make([]recordedNote, len(*wire.Notes))
	for id, note := range *wire.Notes {
		commitment, valid := parseFieldElement(note.Commitment)
		amount, number := new(big.Int).SetString(note.Amount.String(), 10)
		if note.NoteID == nil || uint64(*note.NoteID) != uint64(id) || !valid || !number || amount.Sign() < 0 || amount.BitLen() > 128 || note.ExpiryTs == nil {
			return nil, invalid
		}
		notes[id] = recordedNote{Commitment: commitment, Amount: amount, ExpiryTs: *note.ExpiryTs}
	}
	return &treeSnapshot{Root: root, NextNoteID: *wire.NextNoteID, NoteLeaves: *wire.NoteLeaves, Notes: notes, BlockNumber: *wire.BlockNumber, BlockHash: strings.ToLower(wire.BlockHash)}, nil
}

// snapshotChainTime sets snapshot.Time to the block time of the indexer's
// view. The payment RPC serves the header of the view's block by its hash,
// and the header is accepted only when it hashes to that block hash and
// carries the view's block number. The indexer names the block, so a hostile
// RPC can withhold the header but cannot move its time. A deposit slot
// records it as the chain time of its preparation.
func (h *FundingHandler) snapshotChainTime(ctx context.Context, config fundingConfig, snapshot *treeSnapshot) error {
	var header types.Header
	if err := h.addressRPC(ctx, config, "eth_getBlockByHash", []any{snapshot.BlockHash, false}, &header); err != nil {
		return errors.New("the payment RPC did not serve the block header of the zkAPI indexer's view")
	}
	if !strings.EqualFold(header.Hash().Hex(), snapshot.BlockHash) || header.Number == nil || !header.Number.IsUint64() || header.Number.Uint64() != snapshot.BlockNumber || header.Time == 0 || header.Time > math.MaxInt64 {
		return errors.New("the payment RPC's block header does not match the zkAPI indexer's view")
	}
	snapshot.Time = int64(header.Time)
	return nil
}

// checkDeviceClock refuses a device clock more than deviceClockTolerance
// from chain time: the deposit's note expiry, its quote and its receipt are
// judged by this clock.
func checkDeviceClock(chain int64) error {
	if skew := time.Now().Unix() - chain; skew > deviceClockTolerance || skew < -deviceClockTolerance {
		return errors.New("this device's clock differs from Ethereum's block time by more than a day; correct the system clock and retry")
	}
	return nil
}

// confirmedSnapshot is an indexer view that has applied minBlock, on the
// chain the payment RPC also reports as canonical. A lagging or forked view
// is pending, never a verdict.
func (h *FundingHandler) confirmedSnapshot(ctx context.Context, config fundingConfig, minBlock uint64) (*treeSnapshot, error) {
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return nil, err
	}
	if snapshot.BlockNumber < minBlock {
		return nil, errors.New("the zkAPI indexer has not reached the receipt block")
	}
	var header struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if err := h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{fmt.Sprintf("0x%x", snapshot.BlockNumber), false}, &header); err != nil {
		return nil, err
	}
	number, err := addressHexUint(header.Number)
	if err != nil || !number.IsUint64() || number.Uint64() != snapshot.BlockNumber || !strings.EqualFold(header.Hash, snapshot.BlockHash) {
		return nil, errors.New("the zkAPI indexer view is not on the payment RPC's canonical chain")
	}
	return snapshot, nil
}

// corroborateDeposit binds a validated deposit receipt to a note only when the
// vault, read at the receipt's own canonical block, and the indexer snapshot
// (at or after that block) both record exactly this deposit at the
// receipt's note ID. When the indexer does not, the owner's exit RPC may
// stand in for it (corroborateDepositByExitRPC). A recorded note need not be
// activated: it can exit at once, and requests wait for its activation.
// Called before the companion receives the note secret.
func (h *FundingHandler) corroborateDeposit(ctx context.Context, config fundingConfig, record depositRecord, receipt ethReceipt, noteID uint32, expiry uint64) (*depositBinding, error) {
	pending := func(reason string) error { return fmt.Errorf("%w (%s)", errDepositVerificationPending, reason) }
	conflict := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errDepositVerificationConflict, fmt.Sprintf(format, args...))
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return nil, pending("the payment RPC network check is unavailable")
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() || !isHex(receipt.BlockHash, 32) {
		return nil, pending("the receipt has no block identity")
	}
	commitment, ok := parseFieldElement(record.Commitment)
	if !ok {
		return nil, errors.New("invalid pending commitment")
	}
	note, err := h.vaultNoteAtReceipt(ctx, config, noteID, block.Uint64(), receipt.BlockHash)
	if err != nil {
		return nil, pending("the vault state at the receipt block is unavailable")
	}
	if note.Status == noteUninitialized {
		return nil, pending("the vault does not show the note yet")
	}
	if note.Status != noteActive || !strings.EqualFold(note.Commitment, "0x"+addressABIWord(record.Commitment)) || note.Amount != record.Amount || note.ExpiryTs != expiry {
		return nil, conflict("vault note %d does not hold this deposit", noteID)
	}
	snapshot, err := h.confirmedSnapshot(ctx, config, block.Uint64())
	if err != nil {
		return h.corroborateDepositByExitRPC(ctx, config, record, receipt, noteID, expiry, pending(err.Error()))
	}
	leaf, present := snapshot.recordedLeaf(noteID)
	if !present || leaf.Cmp(noteLeaf(noteID, commitment, record.Amount, expiry)) != 0 {
		return h.corroborateDepositByExitRPC(ctx, config, record, receipt, noteID, expiry, fmt.Errorf("%w: %w at note %d", errDepositVerificationConflict, errIndexerDepositConflict, noteID))
	}
	return &depositBinding{NoteID: noteID, ExpiryTs: expiry, BlockNumber: block.Uint64(), BlockHash: strings.ToLower(receipt.BlockHash), IndexerBlock: snapshot.BlockNumber}, nil
}

// corroborateDepositByExitRPC stands in for the operator's indexer when it
// does not confirm a deposit the payment RPC's vault state already holds
// (indexerErr: lag, unavailability or disagreement). The owner's exit RPC,
// which the operator does not control, is asked about the deposit only once
// its block is final there: until then only its finalized block, which
// names no transaction, is read, so the ordinary indexer lag right after
// mining tells it nothing (its chain ID, also read on every check, names
// none either). It must then serve the same successful receipt, in the same
// block, with this deposit's event at this note, and the vault at that block
// must hold exactly this deposit. The note is then saved, so it can be
// withdrawn through the vault alone (an escape needs no indexer), while
// requests still wait for its activation. Without an exit RPC, or before
// that finality, indexerErr stands. An exit RPC that does not answer or
// serves another network, or that refuses EIP-1898 reads once the deposit is
// final there, is reported as such (errExitRPCDepositCheckUnusable), with
// indexerErr's pending or conflict. A note bound wrongly could still never
// be exited by mistake: withdrawals bind the vault's own record of the note
// (exitNote).
func (h *FundingHandler) corroborateDepositByExitRPC(ctx context.Context, config fundingConfig, record depositRecord, receipt ethReceipt, noteID uint32, expiry uint64, indexerErr error) (*depositBinding, error) {
	if config.ExitRPC == "" {
		return nil, indexerErr
	}
	conflict := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errDepositVerificationConflict, fmt.Sprintf(format, args...))
	}
	unusable := func() error { return fmt.Errorf("%w (%w)", indexerErr, errExitRPCDepositCheckUnusable) }
	exit := config.exitConfig()
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() {
		return nil, indexerErr
	}
	// Another network's block numbers would read as a deposit not final yet.
	if err := h.assertAddressChain(ctx, exit); err != nil {
		return nil, unusable()
	}
	finalized, _, err := h.finalizedBlock(ctx, exit)
	if errors.Is(err, errExitRPCUnavailable) {
		return nil, unusable()
	}
	if err != nil || finalized < block.Uint64() {
		return nil, indexerErr
	}
	final, isFinal, err := h.addressFinalReceipt(ctx, exit, receipt.TransactionHash, true)
	if errors.Is(err, errExitRPCUnavailable) {
		return nil, unusable()
	}
	if err != nil || !isFinal {
		return nil, indexerErr
	}
	// Another block is a reorganization the payment RPC has not followed yet.
	if number, err := addressHexUint(final.BlockNumber); err != nil || number.Cmp(block) != 0 || !strings.EqualFold(final.BlockHash, receipt.BlockHash) {
		return nil, indexerErr
	}
	id, finalExpiry, err := matchDepositEvent(ethReceipt{Status: final.Status, To: final.To, TransactionHash: final.TransactionHash, Logs: final.Logs}, record, 0)
	if err != nil || id != noteID || finalExpiry != expiry {
		return nil, conflict("your exit RPC's receipt of this deposit does not record it at note %d", noteID)
	}
	// The deposit is final there, so a vault read failing both at its block
	// and at the finalized block is the RPC, not the chain.
	note, err := h.vaultNoteAtReceipt(ctx, exit, noteID, block.Uint64(), receipt.BlockHash)
	if err != nil {
		return nil, unusable()
	}
	if note.Status != noteActive || !strings.EqualFold(note.Commitment, "0x"+addressABIWord(record.Commitment)) || note.Amount != record.Amount || note.ExpiryTs != expiry {
		return nil, conflict("your exit RPC's vault state does not hold this deposit at note %d", noteID)
	}
	return &depositBinding{NoteID: noteID, ExpiryTs: expiry, BlockNumber: block.Uint64(), BlockHash: strings.ToLower(receipt.BlockHash), ExitRPC: true}, nil
}

// exitRPCFinalizedNote reads notes(id) through the owner's exit RPC at its own
// finalized block, by hash and canonical only.
func (h *FundingHandler) exitRPCFinalizedNote(ctx context.Context, config fundingConfig, id uint32) (vaultNoteState, error) {
	exit := config.exitConfig()
	if err := h.assertAddressChain(ctx, exit); err != nil {
		return vaultNoteState{}, err
	}
	_, hash, err := h.finalizedBlock(ctx, exit)
	if err != nil {
		return vaultNoteState{}, err
	}
	return h.vaultNote(ctx, exit, id, blockAtHash(hash))
}

// bindDepositSlot records, immediately before signing, the slot a deposit is
// prepared for: the snapshot's next_note_id. The deposit carries no path
// and lands at that slot or a later one, so the slot is saved with the note
// record before the transaction exists, and a later reported revert can be
// checked against what actually happened.
//
// A deposit reported as reverted may have been withheld and still land, and
// a second deposit of this note would share its nullifier. So the same
// snapshot is searched for any recorded note holding this deposit
// (findDepositNote) once a deposit of this note was signed before, and
// nothing is signed when it is found. Retirement only zeroes tree leaves,
// never note records, so a landed earlier deposit stays in every later
// snapshot.
func (h *FundingHandler) bindDepositSlot(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) (string, error) {
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return "", fmt.Errorf("%v; no deposit was signed", err)
	}
	if err := h.snapshotChainTime(ctx, config, snapshot); err != nil {
		return "", fmt.Errorf("%v; no deposit was signed, retry", err)
	}
	signed := signedDepositSlots(deposit, record)
	if err := priorDepositConflict(snapshot, deposit, signed); err != nil {
		return "", err
	}
	if err := checkDeviceClock(snapshot.Time); err != nil {
		return "", fmt.Errorf("%v; no deposit was signed", err)
	}
	data := depositCalldata(deposit.Commitment, deposit.Amount)
	calldata, err := hex.DecodeString(data[2:])
	if err != nil || len(calldata) != depositCalldataLength {
		return "", errors.New("invalid deposit call data")
	}
	deposit.SignedSlots = signed
	deposit.Slot = &depositSlot{NoteID: snapshot.NextNoteID, PathSHA256: depositPathDigest(calldata), PreparedAt: time.Now().Unix(), PreparedChainAt: snapshot.Time}
	if err := h.save(*deposit); err != nil {
		return "", err
	}
	return data, nil
}

// depositSelector is deposit(bytes32 commitment, uint128 amount) of vault revisions 3 and 4: the
// calldata carries no siblings, so a signed deposit lands at the prepared slot or any later one,
// never below it. Revision 4 only records the note; an operator batch inserts its leaf later.
const depositSelector = "56d2e1ea"

// depositCalldataLength is the selector and the two argument words.
const depositCalldataLength = 4 + 2*32

func depositCalldata(commitment string, amount uint64) string {
	return "0x" + depositSelector + addressABIWord(commitment) + fmt.Sprintf("%064x", amount)
}

// isDepositCalldata reports whether data is a deposit call of the vault.
func isDepositCalldata(data []byte) bool {
	return len(data) == depositCalldataLength && hex.EncodeToString(data[:4]) == depositSelector
}

// depositPathDigest identifies a signed deposit's arguments (commitment and amount).
func depositPathDigest(calldata []byte) string {
	digest := sha256.Sum256(calldata[4:])
	return "0x" + hex.EncodeToString(digest[:])
}

// legacyDepositSelector is deposit(bytes32,uint128,uint256[32]) of vault revision 2, whose
// calldata carried the slot's 32 sibling words; saved records may still hold such transactions.
const legacyDepositSelector = "c588341c"

const legacyDepositCalldataLength = 4 + 34*32

// signedDepositSlot returns the recorded slot only when this saved deposit
// transaction was signed for it: a revision-3 deposit of this note at the
// slot's signed nonce, or a revision-2 deposit carrying exactly the sibling
// words the slot's digest names.
func signedDepositSlot(deposit *depositRecord, saved *addressTransaction) (*depositSlot, bool) {
	if deposit == nil || deposit.Slot == nil || saved == nil || saved.Kind != "deposit" {
		return nil, false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(saved.Raw, "0x"))
	var tx types.Transaction
	if err != nil || tx.UnmarshalBinary(raw) != nil {
		return nil, false
	}
	data := tx.Data()
	if isDepositCalldata(data) {
		if !deposit.Slot.Signed || tx.Nonce() != deposit.Slot.SignedNonce {
			return nil, false
		}
		if !strings.EqualFold(depositPathDigest(data), deposit.Slot.PathSHA256) {
			return nil, false
		}
		return deposit.Slot, true
	}
	if len(data) == legacyDepositCalldataLength && hex.EncodeToString(data[:4]) == legacyDepositSelector {
		digest := sha256.Sum256(data[68:])
		if strings.EqualFold("0x"+hex.EncodeToString(digest[:]), deposit.Slot.PathSHA256) {
			return deposit.Slot, true
		}
	}
	return nil, false
}

// recordSignedDepositSlot ties the slot the pending deposit was prepared for
// (bindDepositSlot) to the transaction just signed for it, by its nonce.
func (h *FundingHandler) recordSignedDepositSlot(record *addressFundingRecord, deposit *depositRecord) error {
	if deposit == nil || deposit.Slot == nil || record == nil || record.Pending == nil || record.Pending.Kind != "deposit" {
		return nil
	}
	deposit.Slot.Signed = true
	deposit.Slot.SignedNonce = record.Pending.Nonce
	return h.save(*deposit)
}

// checkDepositRevert decides whether a finalized failed deposit may be retired.
// A hostile RPC can report a revert for a deposit that actually created our
// note; retiring it would reuse the note secret in a second deposit. The
// indexer's snapshot, at or after the receipt block, must record no note
// holding this deposit (findDepositNote). Foreign deposits reusing the
// public commitment with another amount never match, so they cannot block a
// genuine retry. Deposits signed before slots were recorded keep the
// previous behaviour.
func (h *FundingHandler) checkDepositRevert(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord, receipt *addressReceipt) error {
	if _, ok := signedDepositSlot(deposit, record.Pending); !ok {
		return nil
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() {
		return errRevertVerificationPending
	}
	snapshot, err := h.confirmedSnapshot(ctx, config, block.Uint64())
	if err != nil {
		return fmt.Errorf("%w (%v)", errRevertVerificationPending, err)
	}
	// The deposit may still land later, so a retry is searched for it again,
	// in the snapshot the retry is signed from.
	return priorDepositConflict(snapshot, deposit, signedDepositSlots(deposit, record))
}

// landedDepositConflict reports this note's deposit found in the indexer's
// note records. Another deposit of the note would share its nullifier, so
// nothing more is signed; repair binds the note that landed.
func landedDepositConflict(id uint32) error {
	return fmt.Errorf("%w: the zkAPI indexer records this private note's deposit at note %d; no replacement will be signed; run zkapi-clientd config --menu, then choose repair", errDepositVerificationConflict, id)
}

// priorDepositConflict searches snapshot for this note's deposit once a
// deposit of it was signed (slots lists those deposits).
func priorDepositConflict(snapshot *treeSnapshot, deposit *depositRecord, slots []depositSlot) error {
	if len(slots) == 0 {
		return nil
	}
	commitment, ok := parseFieldElement(deposit.Commitment)
	if !ok {
		return errors.New("invalid pending commitment")
	}
	if id, found := findDepositNote(snapshot, commitment, deposit.Amount); found {
		return landedDepositConflict(id)
	}
	return nil
}

// checkPriorDeposits searches the indexer's current snapshot the same way and
// fails closed: an unavailable indexer is an error. It decides whether a
// saved conflict about an earlier deposit is cleared. With no deposit of this
// note signed yet, it makes no request.
func (h *FundingHandler) checkPriorDeposits(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) error {
	slots := signedDepositSlots(deposit, record)
	if len(slots) == 0 {
		return nil
	}
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return err
	}
	return priorDepositConflict(snapshot, deposit, slots)
}

// priorDepositAdvice is the indexer view that the last quote-time search ran
// on without finding this note's deposit.
type priorDepositAdvice struct {
	key  string
	root *big.Int
	next uint32
}

// advisePriorDeposits is the quote-time search, so that a user is not asked
// to fund a retry that approval would refuse. Approval searches the snapshot
// it signs from again and fails closed. So here only a deposit that is found
// refuses the quote, and an unavailable or older indexer does not. A view
// that was already searched is not downloaded again: while a client polls
// quotes and waits for funds, each quote costs one small root read until
// a note is recorded (next_note_id) or the tree changes (root).
func (h *FundingHandler) advisePriorDeposits(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) error {
	slots := signedDepositSlots(deposit, record)
	if len(slots) == 0 {
		return nil
	}
	key := priorDepositKey(config, deposit)
	if advice := h.priorAdvice; advice != nil && advice.key == key {
		root, next, err := h.indexerRoot(ctx, config)
		if err != nil || (root.Cmp(advice.root) == 0 && next == advice.next) {
			return nil
		}
	}
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return nil
	}
	if err := priorDepositConflict(snapshot, deposit, slots); err != nil {
		h.priorAdvice = nil
		return err
	}
	h.priorAdvice = &priorDepositAdvice{key: key, root: snapshot.Root, next: snapshot.NextNoteID}
	return nil
}

// priorDepositKey names what a search verdict depends on besides the view:
// the indexer and the deposit searched for. Note records are never removed,
// so a verdict that found nothing still holds while next_note_id is the same.
func priorDepositKey(config fundingConfig, deposit *depositRecord) string {
	return fmt.Sprintf("%s|%s|%d", config.Indexer, strings.ToLower(deposit.Commitment), deposit.Amount)
}

// signedDepositSlots lists the slot of every deposit of this note that was
// signed: those kept from earlier attempts and, when a saved deposit
// transaction of this note was signed for it, the current one. A slot
// already kept is not added again, so its earliest preparation stays.
func signedDepositSlots(deposit *depositRecord, record *addressFundingRecord) []depositSlot {
	if deposit == nil {
		return nil
	}
	slots := append([]depositSlot{}, deposit.SignedSlots...)
	current := deposit.Slot
	if current == nil || slices.ContainsFunc(slots, func(slot depositSlot) bool {
		return slot.NoteID == current.NoteID && strings.EqualFold(slot.PathSHA256, current.PathSHA256)
	}) {
		return slots
	}
	transactions := noteDepositTransactions(record, deposit)
	for _, entry := range transactions {
		if _, ok := signedDepositSlot(deposit, &entry); ok {
			return append(slots, *current)
		}
	}
	// A revision-3 deposit transaction no kept slot accounts for (a record
	// whose signed slots were lost) is searched from the current slot: a
	// slot searched in vain only costs comparisons, one missed hides a
	// landed deposit.
	if !current.Signed {
		for _, entry := range transactions {
			raw, err := hex.DecodeString(strings.TrimPrefix(entry.Raw, "0x"))
			var tx types.Transaction
			if err != nil || tx.UnmarshalBinary(raw) != nil || !isDepositCalldata(tx.Data()) {
				continue
			}
			if !slices.ContainsFunc(slots, func(slot depositSlot) bool { return slot.Signed && slot.SignedNonce == tx.Nonce() }) {
				return append(slots, *current)
			}
		}
	}
	return slots
}

// noteDepositTransactions returns the saved deposit transactions whose signed
// calldata deposits exactly this note's commitment and amount.
func noteDepositTransactions(record *addressFundingRecord, deposit *depositRecord) []addressTransaction {
	if record == nil || deposit == nil {
		return nil
	}
	var deposits []addressTransaction
	for _, entry := range append(append([]addressTransaction{}, record.History...), pendingAddressTransaction(record.Pending)...) {
		if entry.Kind != "deposit" {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(entry.Raw, "0x"))
		var tx types.Transaction
		if err != nil || tx.UnmarshalBinary(raw) != nil {
			continue
		}
		data := tx.Data()
		if !isDepositCalldata(data) || !strings.EqualFold(hex.EncodeToString(data[4:36]), addressABIWord(deposit.Commitment)) || hex.EncodeToString(data[36:68]) != fmt.Sprintf("%064x", deposit.Amount) {
			continue
		}
		deposits = append(deposits, entry)
	}
	return deposits
}

// findDepositNote returns the first note the snapshot records with this
// deposit's commitment and amount. The commitment derives from the note
// secret, so any such note is a deposit of this note, whoever relayed it,
// and another deposit would share its nullifier. Every recorded note is
// compared: a withheld deposit can land any number of notes after the slot
// it was prepared for, and a deposit prepared from a short-lived fork's
// view below it.
func findDepositNote(snapshot *treeSnapshot, commitment *big.Int, amount uint64) (uint32, bool) {
	want := new(big.Int).SetUint64(amount)
	for id, note := range snapshot.Notes {
		if note.Commitment.Cmp(commitment) == 0 && note.Amount.Cmp(want) == 0 {
			return uint32(id), true
		}
	}
	return 0, false
}

// corroborateWithdrawalClosed requires the vault, read at the payout receipt's
// canonical block, to show the reserved note closed before the companion
// deletes its note state. A forged payout receipt therefore never retires a
// live note; disagreement waits. A close changes no tree leaf (a note closed
// before its activation is still inserted by its batch), so the indexer's
// tree is not consulted. When the receipt and the vault state came from the
// payment RPC and the owner configured an exit RPC, the exit RPC must agree
// as well: the same successful, final receipt with the same logs, and the
// note closed at that block. Without an exit RPC, the payment RPC's vault
// state alone decides. An exit RPC that does not answer, serves another
// network or refuses EIP-1898 reads is reported as such
// (errExitRPCCloseCheckUnusable), still pending. So is the exit RPC as the
// only source (exitOnly, a gasless close), once the payout is final there.
func (h *FundingHandler) corroborateWithdrawalClosed(ctx context.Context, config fundingConfig, noteID uint64, receipt *addressReceipt) error {
	pending := func(reason string) error { return fmt.Errorf("%w (%s)", errWithdrawalVerificationPending, reason) }
	unusable := func() error {
		return fmt.Errorf("%w (%w)", errWithdrawalVerificationPending, errExitRPCCloseCheckUnusable)
	}
	if noteID > 0xffffffff {
		return errors.New("invalid withdrawal note")
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		if config.exitOnly {
			return unusable()
		}
		return pending("the payment RPC network check is unavailable")
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() || !isHex(receipt.BlockHash, 32) {
		return pending("the receipt has no block identity")
	}
	note, err := h.vaultNoteAtReceipt(ctx, config, uint32(noteID), block.Uint64(), receipt.BlockHash)
	if err != nil && config.exitOnly {
		// The exit RPC is the only source here: once the payout is final
		// there, a vault read failing both at its block and at the
		// finalized block is the RPC, not the chain.
		if errors.Is(err, errExitRPCUnavailable) {
			return unusable()
		}
		if finalized, _, finalErr := h.finalizedBlock(ctx, config); errors.Is(finalErr, errExitRPCUnavailable) || (finalErr == nil && finalized >= block.Uint64()) {
			return unusable()
		}
	}
	if err != nil || note.Status != noteClosed {
		return pending("the vault does not show the note closed at the payout block")
	}
	if config.ExitRPC == "" || config.exitOnly {
		return nil
	}
	exit := config.exitConfig()
	if err := h.assertAddressChain(ctx, exit); err != nil {
		return unusable()
	}
	final, isFinal, err := h.addressFinalReceipt(ctx, exit, receipt.TransactionHash, true)
	if errors.Is(err, errExitRPCUnavailable) {
		return unusable()
	}
	if err != nil || !isFinal {
		return pending("your exit RPC does not show the payout final")
	}
	if number, err := addressHexUint(final.BlockNumber); err != nil || number.Cmp(block) != 0 || !strings.EqualFold(final.BlockHash, receipt.BlockHash) || final.Status != receipt.Status || !sameReceiptLogs(final, receipt) {
		return pending("your exit RPC does not show the same payout receipt")
	}
	// The payout is final there, so a vault read failing both at its block
	// and at the finalized block is the RPC, not the chain.
	note, err = h.vaultNoteAtReceipt(ctx, exit, uint32(noteID), block.Uint64(), receipt.BlockHash)
	if err != nil {
		return unusable()
	}
	if note.Status != noteClosed {
		return pending("your exit RPC's vault state does not show the note closed at the payout block")
	}
	return nil
}

// sameReceiptLogs reports whether two receipts of one transaction carry the
// same logs. Hex case may differ between RPCs.
func sameReceiptLogs(a, b *addressReceipt) bool {
	if len(a.Logs) != len(b.Logs) {
		return false
	}
	for i, log := range a.Logs {
		other := b.Logs[i]
		if log.Removed != other.Removed || !strings.EqualFold(log.Address, other.Address) || !strings.EqualFold(log.Data, other.Data) || !slices.EqualFunc(log.Topics, other.Topics, strings.EqualFold) {
			return false
		}
	}
	return true
}
