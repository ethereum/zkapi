package zkapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// This file is local custody material, separate from both the inference API
// credential and the companion's private-note recovery file. Back up both.
type addressFundingRecord struct {
	DepositMicroUSD uint64                   `json:"deposit_micro_usd,omitempty"`
	DepositUSDUnits uint64                   `json:"deposit_usd_units,omitempty"`
	DeploymentID    string                   `json:"deployment_id,omitempty"`
	BillingAsset    string                   `json:"billing_asset,omitempty"`
	BillingUnit     string                   `json:"billing_unit,omitempty"`
	WeiPerUnit      string                   `json:"native_asset_wei_per_unit,omitempty"`
	Version         int                      `json:"version"`
	ChainID         uint64                   `json:"chain_id"`
	Contract        string                   `json:"contract_address"`
	Token           string                   `json:"token_address"`
	Address         string                   `json:"address"`
	PrivateKey      string                   `json:"private_key"`
	Amount          uint64                   `json:"amount,omitempty"`
	Commitment      string                   `json:"commitment,omitempty"`
	Phase           string                   `json:"phase"`
	Pending         *addressTransaction      `json:"pending,omitempty"`
	History         []addressTransaction     `json:"history,omitempty"`
	Withdrawal      *addressWithdrawalRecord `json:"withdrawal,omitempty"`
	Quote           *AddressPaymentQuote     `json:"quote,omitempty"`
	Return          *addressReturnRecord     `json:"return,omitempty"`
	// CreditedPayouts keeps every credited escape payout (a complete
	// withdrawal with PayoutCredited) after a later deposit replaced its
	// withdrawal record, so status keeps reporting its claim until the
	// vault no longer holds a credit for the destination.
	CreditedPayouts []addressCreditedPayout `json:"credited_payouts,omitempty"`
}

// addressCreditedPayout is a finalized escape that closed a note without
// paying its destination: the vault credited the balance to
// escapePayoutCredits(Destination) instead.
type addressCreditedPayout struct {
	NoteID         uint64 `json:"note_id"`
	Destination    string `json:"destination"`
	Amount         uint64 `json:"amount"`
	SettlementHash string `json:"settlement_hash"`
}

type addressTransaction struct {
	ActualFeeWei      string `json:"actual_fee_wei,omitempty"`
	ReturnDestination string `json:"return_destination,omitempty"`
	ReturnValueWei    string `json:"return_value_wei,omitempty"`
	Kind              string `json:"kind"`
	Raw               string `json:"raw"`
	Hash              string `json:"hash"`
	Nonce             uint64 `json:"nonce"`
	FinalizedRevert   bool   `json:"finalized_revert,omitempty"`
	ApprovedFeeWei    string `json:"approved_fee_wei,omitempty"`
	// SignedAt is when the transaction was signed (Unix seconds; 0 in
	// records of earlier builds).
	SignedAt int64 `json:"signed_at,omitempty"`
	// Unmined marks an escape transaction retired without a receipt once
	// it could no longer be included (deadEscapeTransaction).
	Unmined bool `json:"unmined,omitempty"`
}

func (h *FundingHandler) addressStatePath() string {
	return filepath.Join(filepath.Dir(h.statePath), "address-funding.json")
}

func (h *FundingHandler) loadAddress(config fundingConfig) (*addressFundingRecord, error) {
	path := h.addressStatePath()
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot read the local payment address; preserve its recovery file")
	}
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
		return nil, errors.New("payment address recovery file must be a regular private mode-0600 file")
	}
	if errors.Is(err, os.ErrNotExist) {
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, errors.New("cannot generate the local payment address")
		}
		record := &addressFundingRecord{
			Version: 1, ChainID: config.ChainID, Contract: config.Contract, Token: config.Token,
			Address: crypto.PubkeyToAddress(key.PublicKey).Hex(), PrivateKey: hex.EncodeToString(crypto.FromECDSA(key)), Phase: "ready",
		}
		if config.nativeETH() {
			record.Version = 2
			record.DeploymentID, record.BillingAsset, record.BillingUnit, record.WeiPerUnit = config.DeploymentID, config.BillingAsset, config.BillingUnit, config.WeiPerUnit
		}
		// Never expose an address that has not survived fsync plus atomic rename.
		if err := h.saveAddress(record); err != nil {
			return nil, err
		}
		return record, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8<<20 {
		return nil, errors.New("cannot read the local payment address; preserve its recovery file")
	}
	var record addressFundingRecord
	if json.Unmarshal(raw, &record) != nil || (record.Version != 1 && record.Version != 2) {
		return nil, errors.New("payment address recovery data is invalid; preserve the file")
	}
	key, err := crypto.HexToECDSA(record.PrivateKey)
	if err != nil || !strings.EqualFold(crypto.PubkeyToAddress(key.PublicKey).Hex(), record.Address) {
		return nil, errors.New("payment address recovery key is invalid; preserve the file")
	}
	if record.ChainID != config.ChainID || !strings.EqualFold(record.Contract, config.Contract) || !strings.EqualFold(record.Token, config.Token) {
		return nil, errors.New("payment address belongs to another deployment; preserve its recovery file")
	}
	if config.nativeETH() {
		if record.Version != 2 || record.DeploymentID != config.DeploymentID || record.BillingAsset != config.BillingAsset || record.BillingUnit != config.BillingUnit || record.WeiPerUnit != config.WeiPerUnit {
			return nil, errors.New("payment recovery deployment or native units mismatch; preserve the recovery file")
		}
	} else if record.Version != 1 || record.BillingAsset == "native_eth" {
		return nil, errors.New("native payment recovery cannot be used for token funding; preserve the recovery file")
	}
	if record.Pending != nil && (record.Pending.FinalizedRevert || record.Pending.Unmined) {
		return nil, errors.New("pending payment is incorrectly marked as retired; preserve the recovery file")
	}
	for _, entry := range record.History {
		if entry.Unmined && (entry.FinalizedRevert || entry.ActualFeeWei != "" || !escapeKinds[entry.Kind]) {
			return nil, errors.New("an unmined payment record is invalid; preserve the recovery file")
		}
	}
	for _, entry := range append(append([]addressTransaction{}, record.History...), pendingAddressTransaction(record.Pending)...) {
		encoded, decodeErr := hex.DecodeString(strings.TrimPrefix(entry.Raw, "0x"))
		var tx types.Transaction
		if decodeErr != nil || tx.UnmarshalBinary(encoded) != nil || !strings.EqualFold(tx.Hash().Hex(), entry.Hash) || tx.Nonce() != entry.Nonce || !tx.ChainId().IsUint64() || tx.ChainId().Uint64() != config.ChainID {
			return nil, errors.New("payment transaction recovery data is invalid; preserve the file")
		}
		if tx.Type() != types.LegacyTxType && tx.Type() != types.DynamicFeeTxType {
			return nil, errors.New("unsupported saved transaction type; preserve recovery files")
		}
		if entry.ActualFeeWei != "" {
			actual, ok := new(big.Int).SetString(entry.ActualFeeWei, 10)
			if !ok || actual.Sign() < 0 || actual.BitLen() > 256 || actual.Cmp(new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap())) > 0 {
				return nil, errors.New("saved actual transaction fee is invalid; preserve recovery files")
			}
		}
		if entry.ApprovedFeeWei != "" {
			approved, ok := new(big.Int).SetString(entry.ApprovedFeeWei, 10)
			if !ok || approved.Sign() <= 0 || approved.BitLen() > 256 || new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap()).Cmp(approved) > 0 {
				return nil, errors.New("saved payment exceeds its approved network fee; preserve recovery files")
			}
		}
		from, senderErr := types.Sender(types.LatestSignerForChainID(tx.ChainId()), &tx)
		if senderErr != nil || !strings.EqualFold(from.Hex(), record.Address) || tx.To() == nil || (entry.Kind != "deposit" && entry.Kind != "approval" && entry.Kind != "approval_reset" && entry.Kind != "withdrawal" && entry.Kind != "return" && !escapeKinds[entry.Kind] && !transitKinds[entry.Kind]) {
			return nil, errors.New("payment transaction recovery signature is invalid; preserve the file")
		}
		if config.nativeETH() {
			if entry.Kind == "approval" || entry.Kind == "approval_reset" {
				return nil, errors.New("native payment recovery contains an unexpected token approval; preserve the file")
			}
			if entry.Kind == "deposit" {
				data := tx.Data()
				if !isDepositCalldata(data) {
					return nil, errors.New("native deposit recovery call is invalid; preserve the file")
				}
				amount := new(big.Int).SetBytes(data[36:68])
				if !amount.IsUint64() || amount.Sign() == 0 || tx.Value().Cmp(new(big.Int).Mul(new(big.Int).Set(amount), big.NewInt(1_000_000_000))) != 0 {
					return nil, errors.New("native deposit recovery value does not match its amount; preserve the file")
				}
				if record.Pending != nil && strings.EqualFold(record.Pending.Hash, entry.Hash) && (amount.Uint64() != record.Amount || !strings.EqualFold(hex.EncodeToString(data[4:36]), addressABIWord(record.Commitment))) {
					return nil, errors.New("native deposit recovery does not match its saved authorization; preserve the file")
				}
			} else if entry.Kind != "return" && tx.Value().Sign() != 0 {
				return nil, errors.New("withdrawal recovery value must be zero; preserve the file")
			}
		} else if tx.Value().Sign() != 0 {
			return nil, errors.New("token payment recovery value must be zero; preserve the file")
		}
		expected := config.Token
		if entry.Kind == "return" {
			expected = entry.ReturnDestination
			value, ok := new(big.Int).SetString(entry.ReturnValueWei, 10)
			if !ok || value.Sign() <= 0 || value.Cmp(tx.Value()) != 0 || len(tx.Data()) != 0 || entry.ApprovedFeeWei == "" {
				return nil, errors.New("return recovery authorization is invalid; preserve the file")
			}
		}
		if entry.Kind == "deposit" || entry.Kind == "withdrawal" || escapeKinds[entry.Kind] {
			expected = config.Contract
		}
		if transitKinds[entry.Kind] && record.Pending != nil && strings.EqualFold(record.Pending.Hash, entry.Hash) {
			// A pending transit transaction of the gasless path calls the
			// factory, the transit account or the paymaster of the saved
			// withdrawal with exactly its intent.
			w := record.Withdrawal
			if w == nil || w.Transit == nil {
				return nil, errors.New("transit transaction recovery data is missing its withdrawal; preserve the file")
			}
			var data string
			expected, data = transitTransactionData(entry.Kind, w)
			if !strings.EqualFold("0x"+hex.EncodeToString(tx.Data()), data) || tx.Value().Sign() != 0 {
				return nil, errors.New("transit transaction recovery call is invalid; preserve the file")
			}
		} else if transitKinds[entry.Kind] {
			// A finished one stays in the history after its withdrawal was
			// retired for the next note (whose transit account, if any, is
			// another): it was checked against its withdrawal when signed,
			// and carries no value.
			if tx.Value().Sign() != 0 {
				return nil, errors.New("transit transaction recovery call is invalid; preserve the file")
			}
			expected = tx.To().Hex()
		}
		if !strings.EqualFold(tx.To().Hex(), expected) {
			return nil, errors.New("payment transaction recovery destination is invalid; preserve the file")
		}
		if entry.Kind == "withdrawal" && (len(tx.Data()) != withdrawalCalldataLength || hex.EncodeToString(tx.Data()[:4]) != withdrawalSelector) {
			return nil, errors.New("withdrawal transaction recovery call is invalid; preserve the file")
		}
		if escapeKinds[entry.Kind] {
			pending := record.Pending != nil && strings.EqualFold(entry.Hash, record.Pending.Hash)
			w := record.Withdrawal
			if pending && (w == nil || w.Mode != "escape") {
				return nil, errors.New("pending escape authorization is invalid; preserve the file")
			}
			if pending {
				var err error
				switch entry.Kind {
				case "escape":
					err = validateSignedEscape(tx.Data(), config, w, time.Time{})
				case "escape_finalize":
					if "0x"+hex.EncodeToString(tx.Data()) != finalizeEscapeCalldata(w.NoteID) {
						err = errors.New("escape finalization recovery call is invalid; preserve the file")
					}
				case "escape_claim":
					if !strings.EqualFold("0x"+hex.EncodeToString(tx.Data()), claimEscapeCalldata(w.Destination)) {
						err = errors.New("escape payout claim recovery call is invalid; preserve the file")
					}
				}
				if err != nil {
					return nil, err
				}
			}
		}
		if entry.Kind == "withdrawal" {
			pending := record.Pending != nil && strings.EqualFold(entry.Hash, record.Pending.Hash)
			if pending && (record.Withdrawal == nil || !strings.EqualFold(entry.Hash, record.Withdrawal.TransactionHash) || record.Withdrawal.Phase == "complete") {
				return nil, errors.New("pending withdrawal authorization is invalid; preserve the file")
			}
			if pending || (record.Withdrawal != nil && strings.EqualFold(entry.Hash, record.Withdrawal.TransactionHash)) {
				if err := validateSignedWithdrawal(tx.Data(), config, record.Withdrawal, time.Time{}); err != nil {
					return nil, err
				}
			}
		}
	}
	if r := record.Return; r != nil {
		amount, ok := new(big.Int).SetString(r.AmountWei, 10)
		if _, err := NormalizeWithdrawalDestination(r.Destination); err != nil || !ok || amount.Sign() < 0 || amount.BitLen() > 256 {
			return nil, errors.New("public return recovery is invalid; preserve the file")
		}
		switch r.Phase {
		case "quoted", "return_pending", "complete", "reverted":
		default:
			return nil, errors.New("public return phase is invalid; preserve the file")
		}
		if r.Phase == "return_pending" && (record.Pending == nil || record.Pending.Kind != "return" || !strings.EqualFold(record.Pending.Hash, r.TransactionHash) || !strings.EqualFold(record.Pending.ReturnDestination, r.Destination) || record.Pending.ReturnValueWei != r.AmountWei) {
			return nil, errors.New("pending public return is missing its authorization; preserve the file")
		}
	}
	for _, credit := range record.CreditedPayouts {
		if _, err := NormalizeWithdrawalDestination(credit.Destination); err != nil || credit.NoteID > 0xffffffff || !isHex(credit.SettlementHash, 32) {
			return nil, errors.New("credited escape payout recovery data is invalid; preserve the file")
		}
	}
	if w := record.Withdrawal; w != nil {
		if _, err := NormalizeWithdrawalDestination(w.Destination); err != nil || w.NoteID > 0xffffffff || (w.Binding != "" && (!isHex(w.Binding, 32) || !isHex(w.Nullifier, 32))) {
			return nil, errors.New("withdrawal recovery data is invalid; preserve the file")
		}
		if w.Mode == "escape" {
			if err := validateEscapeRecord(record, w); err != nil {
				return nil, err
			}
			return &record, nil
		}
		if w.Mode != "" {
			return nil, errors.New("withdrawal recovery mode is invalid; preserve the file")
		}
		if err := validateGaslessRecord(config, w); err != nil {
			return nil, err
		}
		// A record with a transit account follows the gasless journal
		// whatever pays its fee now: after the --fees wallet fallback the
		// transit account's balance is still forwarded by a sponsored
		// operation, journaled under the same phases.
		gasless := w.Transit != nil
		switch w.Phase {
		case "quoted", "withdrawal_pending", "waiting_settlement", "waiting_funds", "confirming", "reverted", "complete":
		case "op_built", "op_submitted", "op_reverted", "forward_op_built", "forward_op_submitted":
			if !gasless || w.UserOp == nil {
				return nil, errors.New("withdrawal recovery phase is invalid; preserve the file")
			}
		case "gasless_refused":
			if !gasless {
				return nil, errors.New("withdrawal recovery phase is invalid; preserve the file")
			}
		default:
			return nil, errors.New("withdrawal recovery phase is invalid; preserve the file")
		}
		if (w.Phase == "complete" || w.Phase == "forward_op_built" || w.Phase == "forward_op_submitted") && ((!isHex(w.TransactionHash, 32) && !(gasless && isHex(w.SettlementHash, 32))) || w.Binding == "") {
			return nil, errors.New("completed withdrawal recovery data is invalid; preserve the file")
		}
		// Only an independently relayed escape, or the paymaster, can leave
		// a credited payout.
		if w.PayoutCredited && !w.PaymasterCredited && (w.SettlementHash == "" || (w.Phase != "confirming" && w.Phase != "complete")) {
			return nil, errors.New("credited escape payout recovery data is invalid; preserve the file")
		}
		if w.SettlementHash != "" {
			if !isHex(w.SettlementHash, 32) || (!gasless && !isHex(w.TransactionHash, 32)) || strings.EqualFold(w.SettlementHash, w.TransactionHash) || w.Binding == "" || (w.Phase != "confirming" && w.Phase != "complete" && w.Phase != "forward_op_built" && w.Phase != "forward_op_submitted" && w.Phase != "gasless_refused") {
				return nil, errors.New("alternate withdrawal settlement is invalid; preserve the file")
			}
			if w.Phase == "confirming" && !gasless && (record.Pending == nil || record.Pending.Kind != "withdrawal" || !strings.EqualFold(record.Pending.Hash, w.TransactionHash)) {
				return nil, errors.New("alternate withdrawal settlement lost its signed intent; preserve the file")
			}
		}
		if w.Phase == "complete" && w.FeePayer != "payout" && (!gasless || isHex(w.TransactionHash, 32)) {
			// A wallet-paid close (the plain path, or the fallback of a
			// gasless record) retired its signed transaction to the history.
			found := false
			for _, entry := range record.History {
				// A relayer's finalized payout permits retiring the original
				// signed nonce only after its own canonical finalized failure.
				if entry.Kind == "withdrawal" && entry.FinalizedRevert == (w.SettlementHash != "") && strings.EqualFold(entry.Hash, w.TransactionHash) {
					found = true
				}
			}
			if !found {
				return nil, errors.New("completed withdrawal transaction is missing; preserve the file")
			}
		}
	}
	return &record, nil
}

// validateEscapeRecord checks a saved escape: its phase, amounts and the
// transactions its phase names.
func validateEscapeRecord(record addressFundingRecord, w *addressWithdrawalRecord) error {
	invalid := errors.New("escape recovery data is invalid; preserve the file")
	if err := validateGaslessRecord(fundingConfig{ChainID: record.ChainID, Contract: record.Contract}, w); err != nil {
		return err
	}
	gasless := w.Transit != nil
	switch w.Phase {
	case "escape_decision", "escape_wait", "quoted", "waiting_funds", "reverted", "escape_expired":
	case "escape_pending", "escape_initiated", "finalize_pending", "defeated":
		if w.Binding == "" || !isHex(w.NextNullifier, 32) {
			return invalid
		}
	case "op_built", "op_submitted", "op_reverted", "finalize_op_built", "finalize_op_submitted", "forward_op_built", "forward_op_submitted":
		if !gasless || w.UserOp == nil || w.Binding == "" || !isHex(w.NextNullifier, 32) {
			return invalid
		}
	case "gasless_refused":
		if !gasless {
			return invalid
		}
	case "complete":
		if w.Binding == "" || !isHex(w.FinalizeHash, 32) || !strings.EqualFold(w.SettlementHash, w.FinalizeHash) {
			return invalid
		}
	default:
		return invalid
	}
	if w.Conceded > w.StateBalance || (w.Conceded != 0 && w.Conceded > w.Bound) {
		return invalid
	}
	if w.InitiateHash != "" && !isHex(w.InitiateHash, 32) {
		return invalid
	}
	if record.Pending != nil && escapeKinds[record.Pending.Kind] {
		want := map[string]string{"escape": "escape_pending", "escape_finalize": "finalize_pending", "escape_claim": "complete"}[record.Pending.Kind]
		if w.Phase != want {
			return invalid
		}
	}
	return nil
}

func pendingAddressTransaction(entry *addressTransaction) []addressTransaction {
	if entry == nil {
		return nil
	}
	return []addressTransaction{*entry}
}

func (h *FundingHandler) saveAddress(record *addressFundingRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return errors.New("cannot encode payment address recovery data")
	}
	file, err := os.CreateTemp(filepath.Dir(h.statePath), ".address-funding-*")
	if err != nil {
		return errors.New("cannot persist payment address recovery data; no new transaction was sent")
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(file.Name(), h.addressStatePath())
	}
	if err == nil {
		directory, openErr := os.Open(filepath.Dir(h.statePath))
		if openErr == nil {
			err = directory.Sync()
			_ = directory.Close()
		} else {
			err = openErr
		}
	}
	if err != nil {
		return errors.New("cannot persist payment address recovery data; no new transaction was sent")
	}
	return nil
}

// validateGaslessRecord checks a withdrawal's transit account and user
// operation: the transit account is the CREATE2 of its owner key and payout
// address under the pinned gasless contracts (when this release pins them),
// the proof destination is that account, and a saved operation hashes to
// its saved hash, is signed by the owner and carries exactly the exit the
// record authorizes (the close or escape words, the finalization of the
// note, or nothing for a forward).
func validateGaslessRecord(config fundingConfig, w *addressWithdrawalRecord) error {
	invalid := errors.New("gasless withdrawal recovery data is invalid; preserve the file")
	if w.Transit == nil {
		if w.FeePayer == "payout" || w.ProofDestination != "" || w.UserOp != nil {
			return invalid
		}
		return nil
	}
	t := w.Transit
	for _, address := range []string{t.Factory, t.Paymaster, t.EntryPoint, t.Account, t.Owner} {
		if !isHex(address, 20) {
			return invalid
		}
	}
	key, err := crypto.HexToECDSA(t.OwnerKey)
	if err != nil || !strings.EqualFold(crypto.PubkeyToAddress(key.PublicKey).Hex(), t.Owner) || !isHex(t.CreationCodeKeccak, 32) || !strings.EqualFold(w.ProofDestination, t.Account) {
		return invalid
	}
	if w.FeePayer != "payout" && w.FeePayer != "wallet" {
		return invalid
	}
	// A funding key never owns a transit account.
	if w.UserOp == nil {
		return nil
	}
	u := w.UserOp
	var encoded gaslessUserOpJSON
	if json.Unmarshal(u.JSON, &encoded) != nil || !isHex(u.Hash, 32) {
		return invalid
	}
	op, err := gaslessUserOpFromJSON(encoded)
	if err != nil || !strings.EqualFold(op.Sender.Hex(), t.Account) || !strings.EqualFold(op.Paymaster.Hex(), t.Paymaster) {
		return invalid
	}
	hash := op.hash(common.HexToAddress(t.EntryPoint), config.ChainID)
	if !strings.EqualFold(hash.Hex(), u.Hash) {
		return invalid
	}
	if signer, err := recoverUserOpSigner(hash, op.Signature); err != nil || !strings.EqualFold(signer.Hex(), t.Owner) {
		return invalid
	}
	vaultCall, err := vaultCallOfTransitCallData(op.CallData)
	if err != nil {
		return invalid
	}
	nullifier := new(big.Int)
	if isHex(w.Nullifier, 32) {
		nullifier.SetBytes(common.FromHex(w.Nullifier))
	}
	switch gaslessKindOf(u.Kind) {
	case gaslessKindClose:
		if w.Mode != "" || validateSignedWithdrawal(vaultCall, config, w, time.Time{}) != nil {
			return invalid
		}
	case gaslessKindEscape:
		if w.Mode != "escape" || validateSignedEscape(vaultCall, config, w, time.Time{}) != nil {
			return invalid
		}
	case gaslessKindFinalize:
		if w.Mode != "escape" || "0x"+hex.EncodeToString(vaultCall) != finalizeEscapeCalldata(w.NoteID) {
			return invalid
		}
	case gaslessKindForward:
		if len(vaultCall) != 0 {
			return invalid
		}
	default:
		return invalid
	}
	if new(big.Int).Rsh(op.Nonce, 64).Cmp(gaslessNonceKey(gaslessKindOf(u.Kind), nullifier)) != 0 {
		return invalid
	}
	for _, listed := range u.Hashes {
		if !isHex(listed, 32) {
			return invalid
		}
	}
	if u.TransactionHash != "" && !isHex(u.TransactionHash, 32) {
		return invalid
	}
	// The included copy is one of the journaled hashes (the signed one, or
	// an earlier copy a bundler included after a re-sign).
	if u.IncludedHash != "" {
		if !isHex(u.IncludedHash, 32) {
			return invalid
		}
		listed := strings.EqualFold(u.IncludedHash, u.Hash)
		for _, hash := range u.Hashes {
			listed = listed || strings.EqualFold(hash, u.IncludedHash)
		}
		if !listed {
			return invalid
		}
	}
	return nil
}
