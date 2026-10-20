package zkapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// The packaged payment RPC is a third party. Before a note secret leaves this
// process, a failed deposit is retired or retried, or a withdrawal closes
// local state, its claims are checked against vault state read by block hash
// and, where it still adds evidence, the operator indexer's tree snapshot.
// A vault of revision 4 stores one word per note, its leaf and status
// (noteRecord); the leaf binds the commitment, the note ID, the amount and
// the expiry, so Go recomputes the expected leaf with zkAPI Poseidon and
// compares it with the vault's. The snapshot is the same payload for every
// caller, so the indexer never learns which note is ours. Lag or missing data
// is pending; disagreement is a non-terminal conflict.

// Vault revision 4 note reads.
const (
	noteRecordSelector = "0xd154f5bf" // noteRecord(uint32) -> (uint256 leaf, uint8 status)
	nextNoteIDSelector = "0x7a2043a3" // nextNoteId()
	noteLeavesSelector = "0x31749c58" // noteLeaves(uint32 start, uint32 count) -> uint256[]
	minDepositSelector = "0x41b3d185" // minDeposit()
	// noteLeavesPage is the most leaves one noteLeaves call reads (about
	// 5.2M gas of eth_call at 2,048).
	noteLeavesPage = 2048
)

const (
	noteUninitialized uint8 = iota
	noteActive
	notePendingWithdrawal
	noteClosed
)

const (
	maxSafeNoteAmount = 9_007_199_254_740_991
	// About 450,000 leaves; a snapshot is the whole leaf vector.
	indexerSnapshotLimit = 32 << 20
	// The vault rounds expiry up to whole days: ceil((t + noteTtl) / 1 day).
	vaultExpiryBucket = 24 * 60 * 60
	// The search for our leaf is bounded (see findDepositLeaf): it compares
	// this many occupied slots from a signed slot, over this many expiry days.
	depositRevertScanSlots  = 64
	depositRevertMaxBuckets = 64
	// The search's expiry window is anchored to chain time (see
	// snapshotChainTime), with one day of tolerance on each side for bucket
	// rounding and fork timing.
	chainTimeTolerance = vaultExpiryBucket
	// A slot saved before chain times were recorded has only the device
	// clock's preparation time. Its window starts this much earlier.
	devicePreparedTolerance = 7 * vaultExpiryBucket
	// No deposit is signed and no reported revert retired while the device
	// clock is further than this from chain time.
	deviceClockTolerance = vaultExpiryBucket
	// A tree root response is a few hundred bytes.
	indexerRootLimit = 4 << 10
)

var (
	errDepositVerificationPending    = errors.New("the deposit is mined; waiting for the vault state to confirm it before activation")
	errDepositVerificationConflict   = errors.New("the payment RPC, the vault state, and the zkAPI indexer disagree about this deposit; its private note was not activated")
	errRevertVerificationPending     = errors.New("waiting for the zkAPI indexer to confirm the revert")
	errWithdrawalVerificationPending = errors.New("the withdrawal is final on Ethereum; waiting for the vault state to confirm the note is closed")
)

const conflictGuidance = " Checking again re-verifies automatically. If this persists, compare the transaction on a block explorer and run zkapi-clientd config --menu, then choose repair."

// vaultNoteState is noteRecord(id): the stored leaf (zero for an unused ID
// and for a retired, Closed note) and the status.
type vaultNoteState struct {
	Leaf   *big.Int
	Status uint8
}

// holds reports whether the stored leaf is exactly this note's: the leaf
// commits to the note ID, the commitment, the amount and the expiry.
func (n vaultNoteState) holds(id uint32, commitment *big.Int, amount, expiry uint64) bool {
	return n.Leaf != nil && n.Leaf.Sign() != 0 && n.Leaf.Cmp(noteLeaf(id, commitment, amount, expiry)) == 0
}

// blockAtHash is an EIP-1898 block parameter: the read fails, rather than
// silently using another fork, when the RPC's block is not canonical.
func blockAtHash(hash string) map[string]any {
	return map[string]any{"blockHash": strings.ToLower(hash), "requireCanonical": true}
}

func (h *FundingHandler) vaultNote(ctx context.Context, config fundingConfig, id uint32, block any) (vaultNoteState, error) {
	var encoded string
	call := map[string]string{"to": config.Contract, "data": fmt.Sprintf("%s%064x", noteRecordSelector, id)}
	if err := h.addressRPC(ctx, config, "eth_call", []any{call, block}, &encoded); err != nil {
		return vaultNoteState{}, err
	}
	return decodeVaultNote(encoded)
}

// vaultNoteAtReceipt reads noteRecord(id) at the receipt's own canonical block.
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

// decodeVaultNote accepts exactly noteRecord(uint32)'s two static words,
// (uint256 leaf, uint8 status), as a revision-4 vault stores them: a
// canonical field element as the leaf, a status up to Closed, no leaf for an
// unused ID and a leaf for an Active or PendingWithdrawal note.
func decodeVaultNote(encoded string) (vaultNoteState, error) {
	invalid := errors.New("invalid vault note state")
	if len(encoded) != 2+2*64 || !strings.HasPrefix(encoded, "0x") {
		return vaultNoteState{}, invalid
	}
	raw, err := hex.DecodeString(encoded[2:])
	if err != nil {
		return vaultNoteState{}, invalid
	}
	leaf := new(big.Int).SetBytes(raw[:32])
	for _, b := range raw[32:63] {
		if b != 0 {
			return vaultNoteState{}, invalid
		}
	}
	status := raw[63]
	if leaf.Cmp(bn254ScalarModulus) >= 0 || status > noteClosed || (status == noteUninitialized && leaf.Sign() != 0) || ((status == noteActive || status == notePendingWithdrawal) && leaf.Sign() == 0) {
		return vaultNoteState{}, invalid
	}
	return vaultNoteState{Leaf: leaf, Status: status}, nil
}

type treeSnapshot struct {
	Root        *big.Int
	NextNoteID  uint32
	Leaves      []string
	BlockNumber uint64
	BlockHash   string
	// Time is the view's block time, set only by snapshotChainTime.
	Time int64
}

// leaf returns the indexer's current leaf for id. present is false only when
// the snapshot has no such note; a malformed leaf is an error.
func (s *treeSnapshot) leaf(id uint32) (value *big.Int, present bool, err error) {
	if uint64(id) >= uint64(len(s.Leaves)) {
		return nil, false, nil
	}
	value, ok := parseFieldElement(s.Leaves[id])
	if !ok {
		return nil, true, errors.New("invalid zkAPI indexer leaf")
	}
	return value, true, nil
}

// emptyBeforeNext counts the empty leaves right below next_note_id: notes
// deposited last and closed or escaping since.
func (s *treeSnapshot) emptyBeforeNext() uint32 {
	start := s.NextNoteID
	for start > 0 {
		leaf, present, err := s.leaf(start - 1)
		if err != nil || !present || leaf.Sign() != 0 {
			break
		}
		start--
	}
	return s.NextNoteID - start
}

// indexerGet reads a public, parameterless route of the packaged indexer
// through the configured transport, with no credentials and no redirects.
// Every caller gets the same response, so the indexer never learns which
// note is ours. Bodies are never reflected.
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

// indexerRoot reads the identity of the indexer's current tree, its root and
// next_note_id, without the leaves. The root commits to every leaf.
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

// indexerSnapshot reads the packaged indexer's whole-tree snapshot. A
// snapshot without block metadata (an older indexer) can never be evidence:
// its applied block is unknown.
func (h *FundingHandler) indexerSnapshot(ctx context.Context, config fundingConfig) (*treeSnapshot, error) {
	raw, ok := h.indexerGet(ctx, config, "/v1/tree/snapshot", indexerSnapshotLimit, 20*time.Second)
	if !ok {
		return nil, errors.New("the zkAPI indexer snapshot is unavailable")
	}
	var wire struct {
		Root        string   `json:"root"`
		NextNoteID  *uint32  `json:"next_note_id"`
		Leaves      []string `json:"leaves"`
		BlockNumber *uint64  `json:"block_number"`
		BlockHash   string   `json:"block_hash"`
	}
	invalid := errors.New("invalid zkAPI indexer snapshot")
	if json.Unmarshal(raw, &wire) != nil || wire.NextNoteID == nil || uint64(len(wire.Leaves)) != uint64(*wire.NextNoteID) {
		return nil, invalid
	}
	root, ok := parseFieldElement(wire.Root)
	if !ok {
		return nil, invalid
	}
	for _, leaf := range wire.Leaves {
		if _, ok := parseFieldElement(leaf); !ok {
			return nil, invalid
		}
	}
	if wire.BlockNumber == nil || !isHex(wire.BlockHash, 32) {
		return nil, errors.New("the zkAPI indexer snapshot has no block identity; the indexer must be upgraded")
	}
	return &treeSnapshot{Root: root, NextNoteID: *wire.NextNoteID, Leaves: wire.Leaves, BlockNumber: *wire.BlockNumber, BlockHash: strings.ToLower(wire.BlockHash)}, nil
}

// snapshotChainTime sets snapshot.Time to the block time of the indexer's
// view. The payment RPC serves the header of the view's block by its hash,
// and the header is accepted only when it hashes to that block hash and
// carries the view's block number. The indexer names the block, so a hostile
// RPC can withhold the header but cannot move its time. A deposit search is
// anchored to this time, never to the device clock: every leaf in the view
// was mined at or before it.
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
// from chain time. The search does not use the device clock, but slots
// saved by earlier builds and the user's own expectations do.
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

// blockTime is the time of the block number/hash, from a header the payment
// RPC serves by hash that hashes to hash and carries number.
func (h *FundingHandler) blockTime(ctx context.Context, config fundingConfig, number uint64, hash string) (int64, error) {
	var header types.Header
	if err := h.addressRPC(ctx, config, "eth_getBlockByHash", []any{hash, false}, &header); err != nil {
		return 0, errors.New("the payment RPC did not serve the block header")
	}
	if !strings.EqualFold(header.Hash().Hex(), hash) || header.Number == nil || !header.Number.IsUint64() || header.Number.Uint64() != number || header.Time == 0 || header.Time > math.MaxInt64 {
		return 0, errors.New("the payment RPC's block header does not match the block it names")
	}
	return int64(header.Time), nil
}

// vaultLeafSnapshot is a tree view read from the vault itself at one block,
// by hash (EIP-1898): nextNoteId() and noteLeaves(start, count) in pages of
// noteLeavesPage, every page pinned to that block. Only the leaves from..to
// are read; the view ends at min(nextNoteId, to), and leaves below from read
// as empty. It serves the deposit search (findSignedDepositLeaf) without the
// indexer.
func (h *FundingHandler) vaultLeafSnapshot(ctx context.Context, config fundingConfig, number uint64, hash string, from, to uint32) (*treeSnapshot, error) {
	invalid := errors.New("invalid vault note leaves")
	next, err := h.addressQuantity(ctx, config, "eth_call", []any{map[string]string{"to": config.Contract, "data": nextNoteIDSelector}, blockAtHash(hash)})
	if err != nil {
		return nil, err
	}
	if !next.IsUint64() || next.Uint64() > math.MaxUint32 {
		return nil, invalid
	}
	end := min(uint32(next.Uint64()), to)
	start := min(from, end)
	leaves := make([]string, end)
	for i := range start {
		leaves[i] = "0x0"
	}
	for page := start; page < end; {
		count := min(end-page, noteLeavesPage)
		var encoded string
		call := map[string]string{"to": config.Contract, "data": fmt.Sprintf("%s%064x%064x", noteLeavesSelector, page, count)}
		if err := h.addressRPC(ctx, config, "eth_call", []any{call, blockAtHash(hash)}, &encoded); err != nil {
			return nil, err
		}
		words, err := decodeUint256Array(encoded, int(count))
		if err != nil {
			return nil, err
		}
		for i, word := range words {
			leaves[page+uint32(i)] = word
		}
		page += count
	}
	return &treeSnapshot{NextNoteID: end, Leaves: leaves, BlockNumber: number, BlockHash: strings.ToLower(hash)}, nil
}

// decodeUint256Array accepts exactly an ABI-encoded uint256[] of count
// canonical field elements, returned as 0x-prefixed words.
func decodeUint256Array(encoded string, count int) ([]string, error) {
	invalid := errors.New("invalid vault note leaves")
	if len(encoded) != 2+(2+count)*64 || !strings.HasPrefix(encoded, "0x") {
		return nil, invalid
	}
	body := strings.ToLower(encoded[2:])
	if body[:64] != fmt.Sprintf("%064x", 32) || body[64:128] != fmt.Sprintf("%064x", count) {
		return nil, invalid
	}
	words := make([]string, count)
	for i := range words {
		word := "0x" + body[128+i*64:128+(i+1)*64]
		if _, ok := parseFieldElement(word); !ok {
			return nil, invalid
		}
		words[i] = word
	}
	return words, nil
}

// corroborateDeposit binds a validated deposit receipt to a note only when the
// vault, read at the receipt's own canonical block, holds exactly this
// deposit at the receipt's note ID: an Active note whose stored leaf is
// noteLeaf(noteID, commitment, amount, expiry), with the expiry the receipt's
// NoteDeposited names. The leaf commits to every value of the note, so the
// indexer is not needed for this check. It only corroborates: an indexer
// view that has applied the receipt block on the canonical chain must show
// the same leaf there, and a lagging or unavailable indexer is skipped.
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
	if note.Status != noteActive || !note.holds(noteID, commitment, record.Amount, expiry) {
		return nil, conflict("vault note %d does not hold this deposit", noteID)
	}
	binding := &depositBinding{NoteID: noteID, ExpiryTs: expiry, BlockNumber: block.Uint64(), BlockHash: strings.ToLower(receipt.BlockHash)}
	if snapshot, err := h.confirmedSnapshot(ctx, config, block.Uint64()); err == nil {
		leaf, present, err := snapshot.leaf(noteID)
		if err != nil || !present || leaf.Cmp(note.Leaf) != 0 {
			return nil, conflict("the zkAPI indexer does not show this deposit at note %d", noteID)
		}
		binding.IndexerBlock = snapshot.BlockNumber
	}
	return binding, nil
}

// bindDepositPath binds the deposit about to be signed to the slot it is
// prepared for, the indexer view's next_note_id, immediately before signing.
// A deposit of vault revision 3 or 4 carries no Merkle path: the vault
// appends the leaf itself, at the prepared slot or a later one. The slot is
// saved with the note record before the transaction exists, so a later
// reported revert can be checked against what actually happened there.
//
// The slot also records the run of empty leaves right below it, for a
// revision-2 deposit, whose calldata carried the slot's siblings and could
// land in that run when the view it was built from was orphaned.
//
// A deposit reported as reverted may have been withheld and still land, and
// a second deposit of this note would share its nullifier. So the indexer
// view is searched for our leaf from the slot of every deposit of this note
// signed before, and nothing is signed when it is found. An earlier deposit
// in that view is found unless it lies outside findDepositLeaf's bounds:
// about 63 or more days ago, or behind 64 or more occupied slots after the
// slot it was prepared for.
func (h *FundingHandler) bindDepositPath(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) (string, error) {
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return "", fmt.Errorf("%v; no deposit was signed", err)
	}
	if err := h.snapshotChainTime(ctx, config, snapshot); err != nil {
		return "", fmt.Errorf("%v; no deposit was signed, retry", err)
	}
	signed := signedDepositSlots(deposit, record)
	if err := h.priorDepositConflict(snapshot, deposit, signed); err != nil {
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
	deposit.Slot = &depositSlot{NoteID: snapshot.NextNoteID, PathSHA256: depositPathDigest(calldata), PreparedAt: time.Now().Unix(), PreparedChainAt: snapshot.Time, EmptyBefore: snapshot.emptyBeforeNext()}
	if err := h.save(*deposit); err != nil {
		return "", err
	}
	return data, nil
}

// depositSelector is deposit(bytes32 commitment, uint128 amount) of vault revisions 3 and 4: the
// vault appends the leaf to its tree itself, so the calldata carries no siblings and a signed
// deposit lands at the prepared slot or any later one, never below it.
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
// (bindDepositPath) to the transaction just signed for it, by its nonce.
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
// indexer's tree must show no deposit of this note where findDepositLeaf
// searches, from the slots of this and every earlier signed deposit of it;
// the search is bounded (see bindDepositPath). Foreign deposits reusing the
// public commitment with another amount never match our leaf, so they cannot
// block a genuine retry. Deposits signed before slots were recorded keep the
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
	if err := h.snapshotChainTime(ctx, config, snapshot); err != nil {
		return fmt.Errorf("%w (%v)", errRevertVerificationPending, err)
	}
	// Otherwise another leaf holds the slot, it was emptied, or it is still
	// free. The deposit may still land later, so a retry is searched for it
	// again, in the tree the retry is built from, before it is signed.
	if err := h.priorDepositConflict(snapshot, deposit, signedDepositSlots(deposit, record)); err != nil {
		return err
	}
	return checkDeviceClock(snapshot.Time)
}

// landedDepositConflict reports this note's deposit found in the indexer's
// tree. Another deposit of the note would share its nullifier, so nothing
// more is signed; repair binds the note that landed.
func landedDepositConflict(id uint32) error {
	return fmt.Errorf("%w: the zkAPI indexer records this private note's deposit at note %d; no replacement will be signed; run zkapi-clientd config --menu, then choose repair", errDepositVerificationConflict, id)
}

// priorDepositConflict searches snapshot for our leaf from every slot a
// deposit of this note was signed for, at the snapshot's chain time.
func (h *FundingHandler) priorDepositConflict(snapshot *treeSnapshot, deposit *depositRecord, slots []depositSlot) error {
	if len(slots) == 0 {
		return nil
	}
	if snapshot.Time <= 0 {
		return errors.New("the zkAPI indexer view has no verified block time")
	}
	commitment, ok := parseFieldElement(deposit.Commitment)
	if !ok {
		return errors.New("invalid pending commitment")
	}
	ttl, err := h.noteTTL()
	if err != nil {
		return err
	}
	if id, found := findSignedDepositLeaf(snapshot, slots, commitment, deposit.Amount, ttl, snapshot.Time); found {
		return landedDepositConflict(id)
	}
	return nil
}

// checkPriorDeposits searches the indexer's current tree the same way and
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
	if err := h.snapshotChainTime(ctx, config, snapshot); err != nil {
		return err
	}
	return h.priorDepositConflict(snapshot, deposit, slots)
}

// priorDepositAdvice is the indexer tree that the last quote-time search ran
// on without finding any of the searched deposits.
type priorDepositAdvice struct {
	key  string
	root *big.Int
	next uint32
}

// advisePriorDeposits is the quote-time search, so that a user is not asked
// to fund a retry that approval would refuse. Approval searches the tree it
// signs from again and fails closed. So here only a deposit that is found
// refuses the quote, and an unavailable or older indexer does not. A tree
// that was already searched is not downloaded again: while a client polls
// quotes and waits for funds, each quote costs one small root read until
// the tree changes.
func (h *FundingHandler) advisePriorDeposits(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) error {
	slots := signedDepositSlots(deposit, record)
	if len(slots) == 0 {
		return nil
	}
	ttl, err := h.noteTTL()
	if err != nil {
		return err
	}
	key := priorDepositKey(config, deposit, slots, ttl)
	if advice := h.priorAdvice; advice != nil && advice.key == key {
		root, next, err := h.indexerRoot(ctx, config)
		if err != nil || (root.Cmp(advice.root) == 0 && next == advice.next) {
			return nil
		}
	}
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil || h.snapshotChainTime(ctx, config, snapshot) != nil {
		return nil
	}
	if err := h.priorDepositConflict(snapshot, deposit, slots); err != nil {
		h.priorAdvice = nil
		return err
	}
	h.priorAdvice = &priorDepositAdvice{key: key, root: snapshot.Root, next: snapshot.NextNoteID}
	return nil
}

// priorDepositKey names what a search verdict depends on besides the tree and
// the time. Over time the expiry window only gains days after the search,
// when no leaf of an unchanged tree can have landed, and drops older ones.
// So a verdict that found nothing still holds while the root is the same.
func priorDepositKey(config fundingConfig, deposit *depositRecord, slots []depositSlot, ttl uint64) string {
	ordered := append([]depositSlot{}, slots...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].NoteID != ordered[j].NoteID {
			return ordered[i].NoteID < ordered[j].NoteID
		}
		if ordered[i].EmptyBefore != ordered[j].EmptyBefore {
			return ordered[i].EmptyBefore < ordered[j].EmptyBefore
		}
		if ordered[i].PreparedAt != ordered[j].PreparedAt {
			return ordered[i].PreparedAt < ordered[j].PreparedAt
		}
		if ordered[i].PreparedChainAt != ordered[j].PreparedChainAt {
			return ordered[i].PreparedChainAt < ordered[j].PreparedChainAt
		}
		return strings.ToLower(ordered[i].PathSHA256) < strings.ToLower(ordered[j].PathSHA256)
	})
	var key strings.Builder
	fmt.Fprintf(&key, "%s|%s|%d|%d", config.Indexer, strings.ToLower(deposit.Commitment), deposit.Amount, ttl)
	for _, slot := range ordered {
		fmt.Fprintf(&key, "|%d-%d:%d:%d:%s", slot.NoteID, slot.EmptyBefore, slot.PreparedAt, slot.PreparedChainAt, strings.ToLower(slot.PathSHA256))
	}
	return key.String()
}

// signedDepositSlots lists the slot of every deposit of this note that was
// signed: those kept from earlier attempts and, when a saved deposit
// transaction of this note was signed for it (signedDepositSlot), the current
// one. A slot already kept is not added again, so its earliest preparation
// stays.
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

// findSignedDepositLeaf searches from each signed slot, earliest first, at
// chain time now. Slots with the same note ID and empty run are searched
// once, with the earliest window start.
func findSignedDepositLeaf(snapshot *treeSnapshot, slots []depositSlot, commitment *big.Int, amount, ttl uint64, now int64) (uint32, bool) {
	ordered := append([]depositSlot{}, slots...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].NoteID != ordered[j].NoteID {
			return ordered[i].NoteID < ordered[j].NoteID
		}
		if ordered[i].EmptyBefore != ordered[j].EmptyBefore {
			return ordered[i].EmptyBefore < ordered[j].EmptyBefore
		}
		return ordered[i].searchFrom() < ordered[j].searchFrom()
	})
	for i := range ordered {
		if i > 0 && ordered[i].NoteID == ordered[i-1].NoteID && ordered[i].EmptyBefore == ordered[i-1].EmptyBefore {
			continue
		}
		if id, found := findDepositLeaf(snapshot, &ordered[i], commitment, amount, ttl, now); found {
			return id, true
		}
	}
	return 0, false
}

// findDepositLeaf looks for exactly our leaf (commitment, amount and a
// day-bucketed expiry from plausibleExpiries) at the prepared slot and the
// occupied slots after it, then in the run of slots that were empty right
// below it (slot.EmptyBefore). Every comparison costs a Poseidon hash per
// expiry day, so each of the two ranges compares at most
// depositRevertScanSlots occupied slots. Empty (retired) slots are skipped
// without counting. A deposit of vault revision 3 or 4 lands at the vault's
// next note ID when it is mined, so at the prepared slot or after the
// deposits that landed first; a landing behind depositRevertScanSlots of
// them is not found. A revision-2 deposit, whose calldata carried the slot's
// siblings, lands at an earlier slot only inside the empty run: its siblings
// fix every leaf below the slot it was built for, and a leaf commits to its
// note ID, so they fit a lower slot only where every slot in between was
// empty.
func findDepositLeaf(snapshot *treeSnapshot, slot *depositSlot, commitment *big.Int, amount, ttl uint64, now int64) (uint32, bool) {
	expiries := plausibleExpiries(slot.searchFrom(), now, ttl)
	search := func(from, to uint64) (uint32, bool) {
		compared := 0
		for id := from; id < to && id < uint64(snapshot.NextNoteID) && compared < depositRevertScanSlots; id++ {
			leaf, ok := parseFieldElement(snapshot.Leaves[id])
			if !ok || leaf.Sign() == 0 {
				continue
			}
			compared++
			for _, expiry := range expiries {
				if leaf.Cmp(noteLeaf(uint32(id), commitment, amount, expiry)) == 0 {
					return uint32(id), true
				}
			}
		}
		return 0, false
	}
	if id, found := search(uint64(slot.NoteID), uint64(snapshot.NextNoteID)); found {
		return id, true
	}
	return search(uint64(slot.NoteID)-uint64(min(slot.EmptyBefore, slot.NoteID)), uint64(slot.NoteID))
}

// searchFrom is the earliest time this slot's deposit can have been mined:
// the chain time of the indexer view it was built from, one day earlier, or
// for a slot saved before chain times were recorded, the device clock's
// preparation time devicePreparedTolerance earlier.
func (slot depositSlot) searchFrom() int64 {
	if slot.PreparedChainAt > 0 {
		return slot.PreparedChainAt - chainTimeTolerance
	}
	return slot.PreparedAt - devicePreparedTolerance
}

// plausibleExpiries lists every bucketed expiry for a deposit mined between
// from and chain time now, plus one day of tolerance, limited to the
// depositRevertMaxBuckets days that end one day after now. now is the block
// time of the searched indexer view, never the device clock, so a device
// clock that is days off cannot move the window past the landing. A deposit
// mined about 63 or more days before the search is not covered. The 30-day
// note TTL of the pinned deployments has passed by then, unless vault pauses
// extended it by more than 33 days.
func plausibleExpiries(from, now int64, ttl uint64) []uint64 {
	to := now + chainTimeTolerance
	if oldest := to - depositRevertMaxBuckets*vaultExpiryBucket; from < oldest {
		from = oldest
	}
	if from > to {
		from = now - chainTimeTolerance // A view older than the slot's own.
	}
	if from < 0 {
		from = 0
	}
	bucket := func(t int64) uint64 {
		return (uint64(t) + ttl + vaultExpiryBucket - 1) / vaultExpiryBucket * vaultExpiryBucket
	}
	var expiries []uint64
	for expiry := bucket(from); expiry <= bucket(to); expiry += vaultExpiryBucket {
		expiries = append(expiries, expiry)
	}
	return expiries
}

func (h *FundingHandler) noteTTL() (uint64, error) {
	deployment, _, err := deployedDeployment(h.client.config.Network)
	if err != nil {
		return 0, err
	}
	return deployment.NoteTTL, nil
}

// corroborateWithdrawalClosed requires the vault, read at the payout receipt's
// canonical block, to show the reserved note Closed before the companion
// deletes its note state: noteRecord's status, whose leaf stays in the tree
// (an exit never removes it; only retireClosedLeaf zeroes it, and a retired
// note is Closed as well). The indexer cannot corroborate a close, because
// the tree does not change. When the owner configured an exit RPC, the note
// must read Closed through it too, so the pinned RPC alone, which served the
// receipt, never decides that the note closed. Disagreement waits.
func (h *FundingHandler) corroborateWithdrawalClosed(ctx context.Context, config fundingConfig, noteID uint64, receipt *addressReceipt) error {
	pending := func(reason string) error { return fmt.Errorf("%w (%s)", errWithdrawalVerificationPending, reason) }
	if noteID > 0xffffffff {
		return errors.New("invalid withdrawal note")
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return pending("the payment RPC network check is unavailable")
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() || !isHex(receipt.BlockHash, 32) {
		return pending("the receipt has no block identity")
	}
	note, err := h.vaultNoteAtReceipt(ctx, config, uint32(noteID), block.Uint64(), receipt.BlockHash)
	if err != nil || note.Status != noteClosed {
		return pending("the vault does not show the note closed at the payout block")
	}
	if config.ExitRPC != "" && !config.exitOnly {
		exit := config.exitConfig()
		if err := h.assertAddressChain(ctx, exit); err != nil {
			return pending("the exit RPC network check is unavailable")
		}
		note, err := h.vaultNoteAtReceipt(ctx, exit, uint32(noteID), block.Uint64(), receipt.BlockHash)
		if err != nil || note.Status != noteClosed {
			return pending("the vault does not show the note closed at the payout block through the exit RPC")
		}
	}
	return nil
}
