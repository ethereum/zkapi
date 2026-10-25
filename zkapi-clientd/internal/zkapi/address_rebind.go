package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
)

// RebindDeposit repairs a saved deposit's note binding from finalized vault
// state, for example after an RPC reported the wrong note ID, or a revert for
// a deposit that landed. Only the note ID and expiry can change: the secret,
// commitment and amount come from this daemon's own journal. A vault of
// revision 4 stores only each note's leaf, which commits to the note ID, the
// commitment, the amount and the expiry, so the expiry is the bucketed day
// whose leaf is the stored one (rebindExpiry). A companion note is replaced only when the caller names it and it
// is an unspent genesis note of exactly this amount, with no pending request.
// A withdrawal reservation of that note is first released through the
// companion, which refuses while the withdrawal has a plan or the server
// knows its nullifier.
func (h *FundingHandler) RebindDeposit(ctx context.Context, noteID, replaceNoteID *uint64) (AddressFundingStatus, error) {
	if (noteID != nil && *noteID > 0xffffffff) || (replaceNoteID != nil && *replaceNoteID > 0xffffffff) {
		return AddressFundingStatus{}, errors.New("note IDs must be 32-bit vault note IDs")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	config, err := h.config(ctx)
	if err != nil {
		return AddressFundingStatus{}, err
	}
	if err := h.checkWithdrawalFunding(config); err != nil {
		return AddressFundingStatus{}, err
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return AddressFundingStatus{}, err
	}
	deposit, err := h.readAddressDeposit(config)
	if err != nil {
		return AddressFundingStatus{}, err
	}
	if deposit == nil || !isField(deposit.Secret) || deposit.Amount == 0 {
		return AddressFundingStatus{}, errors.New("there is no saved private deposit to rebind")
	}
	commitment, ok := parseFieldElement(deposit.Commitment)
	if !ok {
		return AddressFundingStatus{}, errors.New("the saved private deposit is invalid; preserve its recovery file")
	}
	var record *addressFundingRecord
	if _, statErr := os.Lstat(h.addressStatePath()); statErr == nil {
		if record, err = h.loadAddress(config); err != nil {
			return AddressFundingStatus{}, err
		}
		if record.Pending != nil && record.Pending.Kind != "deposit" {
			return AddressFundingStatus{}, errors.New("a different public transaction is saved; finish it before rebinding the deposit")
		}
		if record.Withdrawal != nil && record.Withdrawal.Phase != "complete" {
			return AddressFundingStatus{}, errors.New("finish the saved withdrawal before rebinding the deposit")
		}
		if (record.Commitment != "" && !strings.EqualFold(record.Commitment, deposit.Commitment)) || (record.Amount != 0 && record.Amount != deposit.Amount) {
			return AddressFundingStatus{}, errors.New("the saved payment journal belongs to another deposit; preserve the funding files")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return AddressFundingStatus{}, errors.New("cannot read the local payment address; preserve its recovery file")
	}

	// Every saved deposit transaction must be final: an unmined one could
	// still create a second note with this secret after the rebind. That
	// includes earlier deposits of this note retired after a reported revert,
	// which a withholding RPC can still relay.
	type savedDeposit struct {
		hash    string
		receipt *addressReceipt
	}
	var saved []savedDeposit
	hashes := []string{pendingDepositHash(record), deposit.TransactionHash}
	for _, entry := range noteDepositTransactions(record, deposit) {
		if entry.FinalizedRevert {
			hashes = append(hashes, entry.Hash)
		}
	}
	for _, hash := range hashes {
		if hash == "" || slices.ContainsFunc(saved, func(entry savedDeposit) bool { return strings.EqualFold(entry.hash, hash) }) {
			continue
		}
		receipt, final, err := h.addressFinalReceipt(ctx, config, hash, true)
		if err != nil {
			return AddressFundingStatus{}, err
		}
		if !final {
			return AddressFundingStatus{}, errors.New("the saved deposit transaction is still unconfirmed and could create a second note; wait for Ethereum finality before rebinding")
		}
		saved = append(saved, savedDeposit{hash, receipt})
	}
	receiptNote := func(entry savedDeposit) (uint32, uint64, bool) {
		if entry.receipt.Status != "0x1" {
			return 0, 0, false
		}
		receipt := ethReceipt{Status: entry.receipt.Status, To: entry.receipt.To, TransactionHash: entry.receipt.TransactionHash, Logs: entry.receipt.Logs}
		id, expiry, err := matchDepositEvent(receipt, *deposit, 0)
		return id, expiry, err == nil
	}

	var candidate uint32
	automatic := false
	switch {
	case deposit.Rebind != nil:
		if noteID != nil && *noteID != uint64(deposit.Rebind.ToNoteID) {
			return AddressFundingStatus{}, fmt.Errorf("a rebind to note %d is already in progress; resume it without a different --note-id", deposit.Rebind.ToNoteID)
		}
		candidate = deposit.Rebind.ToNoteID
	case noteID != nil:
		candidate = uint32(*noteID)
	default:
		automatic = true
		found := false
		for _, entry := range saved {
			if id, _, ok := receiptNote(entry); ok {
				candidate, found = id, true
				break
			}
		}
		if !found && deposit.Slot != nil {
			// Without a usable receipt, only our exact leaf from a slot this
			// note's deposits were built for, earliest first, identifies it.
			// The search reads the vault's leaves at the finalized block; the
			// indexer is not needed.
			ttl, err := h.noteTTL()
			if err != nil {
				return AddressFundingStatus{}, err
			}
			slots := append(signedDepositSlots(deposit, record), *deposit.Slot)
			if snapshot, err := h.finalizedLeafSnapshot(ctx, config, slots); err == nil {
				candidate, found = findSignedDepositLeaf(snapshot, slots, commitment, deposit.Amount, ttl, snapshot.Time)
			}
		}
		if !found {
			return AddressFundingStatus{}, errors.New("cannot identify this deposit's note automatically; compare the deposit on a block explorer and rerun with --note-id")
		}
	}

	// Finalized vault state must hold exactly this deposit at the candidate
	// note: an Active note whose stored leaf is ours for one expiry. An
	// active note remains closable after its expiry, so it is not required
	// to be in the future.
	finalizedNumber, finalizedHash, err := h.finalizedBlock(ctx, config)
	if err != nil {
		return AddressFundingStatus{}, err
	}
	note, err := h.vaultNote(ctx, config, candidate, blockAtHash(finalizedHash))
	if err != nil {
		return AddressFundingStatus{}, err
	}
	guidance := "nothing was changed"
	if automatic {
		guidance = "compare the deposit on a block explorer and rerun with --note-id"
	}
	if note.Status != noteActive {
		return AddressFundingStatus{}, fmt.Errorf("finalized vault note %d does not hold this active deposit; %s", candidate, guidance)
	}
	var receiptExpiries []uint64
	for _, entry := range saved {
		if id, receiptExpiry, ok := receiptNote(entry); ok && id == candidate {
			receiptExpiries = append(receiptExpiries, receiptExpiry)
		}
	}
	expiry, found, err := h.rebindExpiry(ctx, config, note, candidate, commitment, deposit, record, receiptExpiries, finalizedNumber, finalizedHash)
	if err != nil {
		return AddressFundingStatus{}, err
	}
	if !found {
		if deposit.Rebind != nil {
			return AddressFundingStatus{}, errors.New("the saved rebind no longer matches finalized vault state; preserve recovery files")
		}
		// The slot holds another deposit (another commitment or amount), or
		// ours from outside the searched days.
		return AddressFundingStatus{}, fmt.Errorf("finalized vault note %d does not hold this active deposit; %s", candidate, guidance)
	}
	// The indexer only corroborates: a view that has applied the finalized
	// block must show the same leaf, and a lagging or unavailable one is
	// skipped.
	indexerBlock := uint64(0)
	if snapshot, err := h.confirmedSnapshot(ctx, config, finalizedNumber); err == nil {
		leaf, present, err := snapshot.leaf(candidate)
		if err != nil || !present || leaf.Cmp(note.Leaf) != 0 {
			return AddressFundingStatus{}, fmt.Errorf("the zkAPI indexer does not show this deposit at note %d; nothing was changed", candidate)
		}
		indexerBlock = snapshot.BlockNumber
	}
	// A saved transaction is the target only when its own receipt names the
	// verified note; any other final saved deposit is retired below.
	targetHash := ""
	for _, entry := range saved {
		if id, receiptExpiry, ok := receiptNote(entry); ok && id == candidate && receiptExpiry == expiry {
			targetHash = entry.hash
			break
		}
	}

	if err := h.rebindCompanion(ctx, deposit, candidate, expiry, replaceNoteID); err != nil {
		return AddressFundingStatus{}, err
	}

	deposit.Binding = &depositBinding{NoteID: candidate, ExpiryTs: expiry, BlockNumber: finalizedNumber, BlockHash: finalizedHash, IndexerBlock: indexerBlock}
	deposit.Active, deposit.Rebind = true, nil
	if deposit.TransactionHash == "" {
		deposit.TransactionHash = targetHash
	}
	if err := h.save(*deposit); err != nil {
		return AddressFundingStatus{}, err
	}
	if record == nil {
		if record, err = h.loadAddress(config); err != nil {
			return AddressFundingStatus{}, err
		}
	}
	if record.Pending != nil && !strings.EqualFold(record.Pending.Hash, targetHash) {
		retired := *record.Pending
		for _, entry := range saved {
			if strings.EqualFold(entry.hash, retired.Hash) {
				retired.FinalizedRevert = entry.receipt.Status == "0x0"
			}
		}
		record.History = append(record.History, retired)
		record.Pending = nil
	}
	if record.Withdrawal != nil && record.Withdrawal.Phase == "complete" && record.Withdrawal.NoteID != uint64(candidate) {
		retireWithdrawal(record)
	}
	if record.Quote != nil && record.Quote.Kind == "deposit" {
		record.Quote = nil
	}
	record.Phase, record.Amount, record.Commitment = "active", deposit.Amount, deposit.Commitment
	if err := h.saveAddress(record); err != nil {
		return AddressFundingStatus{}, err
	}
	_, _, status, err := h.addressSnapshot(ctx)
	return status, err
}

// rebindExpiry finds the expiry of our deposit at the candidate note: the e
// for which noteLeaf(candidate, commitment, amount, e) is the vault's stored
// leaf. A resumed rebind tries only its journaled expiry. Otherwise the
// expiries of saved receipts that name the candidate are tried first, then
// every day bucket ceil((t + noteTtl) / 1 day) · 1 day for a deposit mined t
// between the earliest preparation of this note's deposits (less a day; the
// last 64 days without one) and the finalized block's time (plausibleExpiries:
// normally one or two days, at most 66 Poseidon permutations). found is false
// when none matches: the slot holds another deposit.
func (h *FundingHandler) rebindExpiry(ctx context.Context, config fundingConfig, note vaultNoteState, candidate uint32, commitment *big.Int, deposit *depositRecord, record *addressFundingRecord, receiptExpiries []uint64, finalizedNumber uint64, finalizedHash string) (uint64, bool, error) {
	if deposit.Rebind != nil {
		expiry := deposit.Rebind.ExpiryTs
		return expiry, note.holds(candidate, commitment, deposit.Amount, expiry), nil
	}
	for _, expiry := range receiptExpiries {
		if note.holds(candidate, commitment, deposit.Amount, expiry) {
			return expiry, true, nil
		}
	}
	ttl, err := h.noteTTL()
	if err != nil {
		return 0, false, err
	}
	now, err := h.blockTime(ctx, config, finalizedNumber, finalizedHash)
	if err != nil {
		return 0, false, err
	}
	from := int64(0)
	if deposit.Slot != nil {
		slots := append(signedDepositSlots(deposit, record), *deposit.Slot)
		from = slots[0].searchFrom()
		for _, slot := range slots[1:] {
			from = min(from, slot.searchFrom())
		}
	}
	for _, expiry := range plausibleExpiries(from, now, ttl) {
		if note.holds(candidate, commitment, deposit.Amount, expiry) {
			return expiry, true, nil
		}
	}
	return 0, false, nil
}

// finalizedLeafSnapshot reads the vault's leaves at the finalized block, by
// hash, for the slot search from slots (findSignedDepositLeaf): from the
// lowest slot's run of empty slots to two pages of leaves beyond the highest
// slot, with the finalized block's time.
func (h *FundingHandler) finalizedLeafSnapshot(ctx context.Context, config fundingConfig, slots []depositSlot) (*treeSnapshot, error) {
	number, hash, err := h.finalizedBlock(ctx, config)
	if err != nil {
		return nil, err
	}
	from, to := uint32(math.MaxUint32), uint32(0)
	for _, slot := range slots {
		from = min(from, slot.NoteID-min(slot.EmptyBefore, slot.NoteID))
		to = max(to, slot.NoteID)
	}
	to = uint32(min(uint64(to)+2*noteLeavesPage, math.MaxUint32))
	snapshot, err := h.vaultLeafSnapshot(ctx, config, number, hash, from, to)
	if err != nil {
		return nil, err
	}
	if snapshot.Time, err = h.blockTime(ctx, config, number, hash); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func pendingDepositHash(record *addressFundingRecord) string {
	if record == nil || record.Pending == nil || record.Pending.Kind != "deposit" {
		return ""
	}
	return record.Pending.Hash
}

// rebindCompanion makes the companion hold exactly (candidate, expiry) for
// this note secret. The replacement is journaled before /wallet/reset, so an
// interrupted rebind resumes to the same verified note.
func (h *FundingHandler) rebindCompanion(ctx context.Context, deposit *depositRecord, candidate uint32, expiry uint64, replaceNoteID *uint64) error {
	raw, err := h.client.WalletStatus(ctx)
	if err != nil {
		return err
	}
	var wallet struct {
		HasNote *bool `json:"has_note"`
		Pending *bool `json:"pending_request"`
		Note    *struct {
			NoteID         uint32  `json:"note_id"`
			DepositAmount  *uint64 `json:"deposit_amount"`
			CurrentBalance *uint64 `json:"current_balance"`
			ExpiryTs       *uint64 `json:"expiry_ts"`
			IsGenesis      *bool   `json:"is_genesis"`
		} `json:"note"`
	}
	if json.Unmarshal(raw, &wallet) != nil || wallet.HasNote == nil || wallet.Pending == nil || (*wallet.HasNote && (wallet.Note == nil || wallet.Note.DepositAmount == nil || wallet.Note.CurrentBalance == nil || wallet.Note.ExpiryTs == nil || wallet.Note.IsGenesis == nil)) {
		return errors.New("invalid companion wallet status")
	}
	if *wallet.Pending {
		return errors.New("the companion has an unsettled inference request; wait for it to settle before rebinding")
	}
	raw, err = h.client.request(ctx, http.MethodGet, "/oa/v1/withdraw/status", nil)
	if err != nil {
		return err
	}
	var reservation withdrawalBridgeStatus
	if json.Unmarshal(raw, &reservation) != nil {
		return errors.New("invalid companion withdrawal status")
	}
	reserved := fmt.Errorf("the companion holds a withdrawal reservation for note %d; finish or release it before rebinding", reservation.NoteID)
	switch reservation.Phase {
	case "none":
	case "complete":
		if reservation.NoteID == uint64(candidate) || (*wallet.HasNote && reservation.NoteID == uint64(wallet.Note.NoteID)) {
			return fmt.Errorf("the companion has a withdrawal record for note %d; finish it before rebinding", reservation.NoteID)
		}
	case "reserved":
		// Only a reservation of the note being replaced is released, below.
		if !*wallet.HasNote || reservation.NoteID != uint64(wallet.Note.NoteID) || reservation.Nullifier == "" {
			return reserved
		}
	default:
		return reserved
	}
	if *wallet.HasNote {
		note := wallet.Note
		if note.NoteID == candidate && *note.ExpiryTs == expiry && *note.DepositAmount == deposit.Amount {
			if reservation.Phase == "reserved" {
				return reserved
			}
			return nil
		}
		named := replaceNoteID != nil && *replaceNoteID == uint64(note.NoteID)
		resuming := deposit.Rebind != nil && deposit.Rebind.FromNoteID == note.NoteID && deposit.Rebind.ToNoteID == candidate
		if !named && !resuming {
			return fmt.Errorf("the companion holds note %d; rerun with --replace-note-id %d to replace it with verified note %d", note.NoteID, note.NoteID, candidate)
		}
		if !*note.IsGenesis || *note.CurrentBalance != *note.DepositAmount || *note.DepositAmount != deposit.Amount {
			return fmt.Errorf("the companion's note %d has been used or holds a different amount; it cannot be replaced", note.NoteID)
		}
		if reservation.Phase == "reserved" {
			if err := h.releaseWithdrawalReservation(ctx, reservation); err != nil {
				return err
			}
		}
		deposit.Rebind = &depositRebind{FromNoteID: note.NoteID, ToNoteID: candidate, ExpiryTs: expiry}
		if err := h.save(*deposit); err != nil {
			return err
		}
		raw, err := h.client.request(ctx, http.MethodPost, "/wallet/reset", nil)
		if err != nil {
			return err
		}
		var reset struct {
			HasNote *bool `json:"has_note"`
		}
		if json.Unmarshal(raw, &reset) != nil || reset.HasNote == nil || *reset.HasNote {
			return errors.New("the companion did not clear the replaced note; preserve recovery files and retry the rebind")
		}
	}
	body, _ := json.Marshal(map[string]any{"secret": deposit.Secret, "note_id": candidate, "amount": deposit.Amount, "expiry_ts": expiry})
	_, err = h.client.request(ctx, http.MethodPost, "/funding/api/deposit/confirm", body)
	return err
}

// releaseWithdrawalReservation releases the companion's withdrawal
// reservation of the note being replaced. The companion releases only a
// reservation that never obtained a withdrawal plan, that on a vault below
// revision 2 never sent an ownership proof, and whose nullifier the zkAPI
// server does not know; otherwise that withdrawal must finish first.
func (h *FundingHandler) releaseWithdrawalReservation(ctx context.Context, reservation withdrawalBridgeStatus) error {
	body, _ := json.Marshal(map[string]any{"note_id": reservation.NoteID, "withdrawal_nullifier": reservation.Nullifier})
	raw, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/release", body)
	var refused *Error
	if errors.As(err, &refused) {
		switch refused.Code {
		case "withdrawal_pending":
			return fmt.Errorf("the zkAPI server already holds a clearance or request for the withdrawal reserved on note %d, so the note cannot be replaced; finish that withdrawal (run zkapi-clientd config --menu and choose withdraw) instead of rebinding; nothing was changed", reservation.NoteID)
		case "withdrawal_conflict":
			return fmt.Errorf("the withdrawal reserved on note %d has a prepared plan or no longer matches the companion's note, so the note cannot be replaced; finish that withdrawal (run zkapi-clientd config --menu and choose withdraw) instead of rebinding; nothing was changed", reservation.NoteID)
		case "ownership_proof_sent":
			// Whoever saw that clearance request may hold the proof, an
			// escape at this state; on a vault below revision 2 the
			// reservation never lifts. The code crosses the management
			// boundary with this explanation.
			return &codedError{code: refused, message: fmt.Sprintf("the withdrawal reserved on note %d sent, or may have sent, its ownership proof towards the zkAPI server, so on this vault the note must stay reserved for that withdrawal and cannot be replaced; finish that withdrawal (run zkapi-clientd config --menu and choose withdraw) instead of rebinding; nothing was changed", reservation.NoteID)}
		}
	}
	if err != nil {
		return err
	}
	var released withdrawalBridgeStatus
	if json.Unmarshal(raw, &released) != nil || released.Phase != "none" {
		return errors.New("the companion did not release the withdrawal reservation; nothing was changed")
	}
	return nil
}

// codedError explains a companion refusal in its own words while keeping the
// refusal's code: errors.As finds the *Error, so the management API forwards
// the code beside this message.
type codedError struct {
	code    *Error
	message string
}

func (e *codedError) Error() string { return e.message }

func (e *codedError) Unwrap() error { return e.code }
