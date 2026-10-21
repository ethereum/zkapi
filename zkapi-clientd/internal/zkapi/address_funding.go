package zkapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// AddressFundingStatus exposes only public funding data, never signing keys,
// signed bytes, private-note secrets, or inference credentials.
type AddressFundingStatus struct {
	ActualFeeWei    string `json:"actual_fee_wei,omitempty"`
	DeploymentID    string `json:"deployment_id,omitempty"`
	BillingAsset    string `json:"billing_asset,omitempty"`
	BillingUnit     string `json:"billing_unit,omitempty"`
	WeiPerUnit      string `json:"native_asset_wei_per_unit,omitempty"`
	Address         string `json:"address"`
	ChainID         uint64 `json:"chain_id"`
	TokenAddress    string `json:"token_address"`
	TokenDecimals   int    `json:"token_decimals"`
	TokenBalance    string `json:"token_balance"`
	ETHBalance      string `json:"eth_balance"`
	Amount          uint64 `json:"amount,omitempty"`
	Phase           string `json:"phase"`
	DepositStage    string `json:"deposit_stage,omitempty"`
	TransactionHash string `json:"transaction_hash,omitempty"`
	Message         string `json:"message"`
	// EscapePayoutCredits lists credited escape payouts of earlier notes
	// that the vault still holds (see EscapePayoutCredit).
	EscapePayoutCredits []EscapePayoutCredit `json:"escape_payout_credits,omitempty"`
}

var errAddressNeedsETH = errors.New("send more ETH to the payment address for Ethereum network fees")

func (h *FundingHandler) Address(ctx context.Context) (AddressFundingStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addressLocked(ctx)
}

func (h *FundingHandler) FundAddress(ctx context.Context, amount uint64) (AddressFundingStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fundAddressLocked(ctx, amount)
}

func (h *FundingHandler) addressLocked(ctx context.Context) (AddressFundingStatus, error) {
	_, _, status, err := h.addressSnapshot(ctx)
	return status, err
}

func (h *FundingHandler) addressSnapshot(ctx context.Context) (fundingConfig, *addressFundingRecord, AddressFundingStatus, error) {
	return h.addressSnapshotFor(ctx, false)
}

// addressSnapshotFor is addressSnapshot, read only through the owner's exit
// RPC when one is configured (exitConfig) for an escape: when exit is set,
// or when the saved withdrawal is an escape.
func (h *FundingHandler) addressSnapshotFor(ctx context.Context, exit bool) (fundingConfig, *addressFundingRecord, AddressFundingStatus, error) {
	config, err := h.config(ctx)
	if err != nil {
		return config, nil, AddressFundingStatus{}, err
	}
	if exit || h.escapeSaved(config) {
		config = config.exitConfig()
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return config, nil, AddressFundingStatus{}, err
	}
	if !config.nativeETH() {
		decimals, err := h.addressUintCall(ctx, config, config.Token, "0x313ce567", "latest")
		if err != nil || decimals.Cmp(big.NewInt(6)) != 0 {
			return config, nil, AddressFundingStatus{}, errors.New("the payment token must use exactly six decimals")
		}
	}
	record, err := h.loadAddress(config)
	if err != nil {
		return config, nil, AddressFundingStatus{}, err
	}
	status := addressPublicStatus(record)
	token := new(big.Int)
	if !config.nativeETH() {
		token, err = h.addressUintCall(ctx, config, config.Token, "0x70a08231"+addressABIWord(record.Address), "latest")
		if err != nil {
			return config, record, status, err
		}
	}
	eth, err := h.addressQuantity(ctx, config, "eth_getBalance", []any{record.Address, "pending"})
	if err != nil {
		return config, record, status, err
	}
	if config.nativeETH() {
		token.Quo(eth, big.NewInt(1_000_000_000))
	}
	status.TokenBalance, status.ETHBalance = token.String(), eth.String()
	if status.EscapePayoutCredits, err = h.escapePayoutCredits(ctx, config, record); err != nil {
		return config, record, status, err
	}
	if record.Phase == "active" {
		hasNote, err := h.addressHasNote(ctx)
		if err != nil {
			return config, record, status, err
		}
		if !hasNote {
			status.Phase = "recovery_required"
			status.DepositStage = ""
			status.Message = "The saved private note is missing from the companion. Restore its state before further funding; no new deposit will be sent."
		}
	}
	return config, record, status, nil
}

// escapeSaved reports whether the saved withdrawal is an escape, or a
// gasless withdrawal (whose reads prefer the exit RPC too, design 3.1). It
// reads the payment record only when one exists, and creates nothing.
func (h *FundingHandler) escapeSaved(config fundingConfig) bool {
	if _, err := os.Lstat(h.addressStatePath()); err != nil {
		return false
	}
	record, err := h.loadAddress(config)
	return err == nil && record.Withdrawal != nil && (record.Withdrawal.Mode == "escape" || record.Withdrawal.Transit != nil)
}

func (h *FundingHandler) addressHasNote(ctx context.Context) (bool, error) {
	raw, err := h.client.WalletStatus(ctx)
	if err != nil {
		return false, err
	}
	var wallet struct {
		HasNote *bool `json:"has_note"`
	}
	if json.Unmarshal(raw, &wallet) != nil || wallet.HasNote == nil {
		return false, errors.New("invalid companion note status")
	}
	return *wallet.HasNote, nil
}

func addressPublicStatus(record *addressFundingRecord) AddressFundingStatus {
	status := AddressFundingStatus{Address: record.Address, ChainID: record.ChainID, TokenAddress: record.Token, TokenDecimals: 6, TokenBalance: "0", ETHBalance: "0", Amount: record.Amount, Phase: record.Phase}
	status.DeploymentID, status.BillingAsset, status.BillingUnit, status.WeiPerUnit = record.DeploymentID, record.BillingAsset, record.BillingUnit, record.WeiPerUnit
	if record.BillingAsset == "native_eth" {
		status.TokenDecimals = 9
	}
	if record.Pending != nil {
		status.TransactionHash = record.Pending.Hash
		status.ActualFeeWei = record.Pending.ActualFeeWei
	}
	switch record.Phase {
	case "ready":
		status.Message = "Send the configured token and ETH for network fees to this address, then choose a deposit amount."
	case "waiting_funds":
		status.Message = "Waiting for the selected token amount and enough ETH for network fees."
	case "approval_pending":
		status.Message = "The token approval is pending Ethereum confirmation. Checking again reuses the same transaction."
	case "deposit_pending":
		// The durable phase spans both unmined and included deposits. Only a
		// current receipt check can distinguish their progress.
		status.Message = "The deposit is awaiting confirmation. Checking again reuses the same transaction."
	case "confirming":
		status.DepositStage = "activating"
		status.Message = "The deposit is mined. Checking again verifies it and activates the saved private note."
	case "verification_conflict":
		status.Message = errDepositVerificationConflict.Error() + "." + conflictGuidance
	case "active":
		status.DepositStage = "active"
		status.Message = "Your private balance is ready."
	case "reverted":
		status.Message = "The saved transaction reverted. Retry explicitly to reuse the private note with a fresh transaction after finality."
	case "legacy_recovery":
		status.Message = "A saved deposit needs recovery. Resume its transaction before starting another deposit."
	case "withdrawal_pending":
		status.Message = "A withdrawal is saved. Run zkapi-clientd withdraw and resume its destination before funding again."
	default:
		status.Message = "Payment recovery is required. Preserve the local funding files."
	}
	if record.BillingAsset == "native_eth" {
		if record.Phase == "ready" {
			status.Message = "Send ETH on the displayed network to this address, then choose a private deposit amount in ETH."
		} else if record.Phase == "waiting_funds" {
			status.Message = "Waiting for the selected ETH principal plus enough ETH for network fees."
		}
	}
	return status
}

func (h *FundingHandler) fundAddressLocked(ctx context.Context, amount uint64) (AddressFundingStatus, error) {
	if amount == 0 || amount > 1_000_000_000_000 {
		return AddressFundingStatus{}, errors.New("invalid deposit amount")
	}
	config, record, status, err := h.addressSnapshot(ctx)
	if err != nil {
		return status, err
	}
	// Live progress is diagnostic only; never persist it or let it change
	// transaction identity, signing, replay, or the finality requirement.
	depositStage := ""
	update := func() AddressFundingStatus {
		next := addressPublicStatus(record)
		next.TokenBalance, next.ETHBalance, next.EscapePayoutCredits = status.TokenBalance, status.ETHBalance, status.EscapePayoutCredits
		if depositStage != "" {
			next.DepositStage = depositStage
		}
		if depositStage == "verifying" {
			next.Message = "The deposit is mined; waiting for the zkAPI indexer to confirm it before activating the private note."
		}
		return next
	}
	// A verification conflict is never terminal: report it, keep the saved
	// transaction, and re-verify on every later resume.
	conflicted := func(err error) AddressFundingStatus {
		next := update()
		next.Phase, next.DepositStage = "verification_conflict", ""
		next.Message = err.Error() + "." + conflictGuidance
		return next
	}
	// The indexer showing this note's deposit is a durable conflict.
	landed := func(err error) (AddressFundingStatus, error) {
		if record.Phase != "verification_conflict" {
			record.Phase = "verification_conflict"
			if saveErr := h.saveAddress(record); saveErr != nil {
				return update(), saveErr
			}
		}
		return conflicted(err), nil
	}
	// A finalized deposit revert is retired, or reported as retryable, only
	// after the indexer's tree shows no deposit of the note within
	// findDepositLeaf's bounds from every slot a deposit of it was signed for.
	revertUnconfirmed := func(receipt *addressReceipt) (AddressFundingStatus, bool, error) {
		deposit, err := h.readAddressDeposit(config)
		if err != nil {
			return update(), true, err
		}
		err = h.checkDepositRevert(ctx, config, record, deposit, receipt)
		switch {
		case err == nil:
			return AddressFundingStatus{}, false, nil
		case errors.Is(err, errDepositVerificationConflict):
			next, saveErr := landed(err)
			return next, true, saveErr
		case errors.Is(err, errRevertVerificationPending):
			next := update()
			next.Message = "The saved deposit reported a revert; " + errRevertVerificationPending.Error() + " before any retry is allowed."
			return next, true, nil
		}
		return update(), true, err
	}
	if record.Pending != nil && record.Pending.Kind != "deposit" && record.Pending.Kind != "approval" && record.Pending.Kind != "approval_reset" {
		return update(), errors.New("a different public transaction is saved; resume its withdrawal or return command before funding")
	}
	if record.Withdrawal != nil && record.Withdrawal.Phase != "complete" {
		return update(), errors.New("a withdrawal is saved; finish it with the same destination before funding again")
	}
	if record.Withdrawal.waitingPayout() {
		return update(), errWithdrawalPayoutWaiting
	}
	if record.Phase == "active" {
		hasNote, err := h.addressHasNote(ctx)
		if err != nil {
			return update(), err
		}
		if hasNote {
			if record.Amount != amount {
				return update(), errors.New("a private note is already active; close it before funding a new amount")
			}
			return update(), nil
		}
		return status, nil
	}
	if record.Amount != 0 && record.Amount != amount {
		return update(), errors.New("a different deposit amount is already saved; resume the saved amount")
	}
	if record.Pending == nil && record.Phase == "verification_conflict" {
		// An earlier, retired deposit of this note showed in the indexer's
		// tree. Re-check it on every resume, whatever the balance. Once it is
		// gone this call signs nothing; a fresh quote or resume continues.
		deposit, err := h.readAddressDeposit(config)
		if err != nil {
			return update(), err
		}
		if err := h.checkPriorDeposits(ctx, config, record, deposit); err != nil {
			if errors.Is(err, errDepositVerificationConflict) {
				return landed(err)
			}
			return update(), err
		}
		record.Phase = "waiting_funds"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return update(), nil
	}
	if record.Phase == "reverted" {
		if record.Pending == nil {
			return update(), errors.New("reverted transaction journal is missing; preserve the funding files")
		}
		receipt, final, err := h.addressFinalReceipt(ctx, config, record.Pending.Hash, true)
		if err != nil {
			return update(), err
		}
		if !final {
			return update(), nil
		}
		if receipt.Status != "0x0" {
			return update(), errors.New("the saved transaction no longer has a reverted receipt; check its status")
		}
		if record.Pending.Kind == "deposit" {
			if next, stop, err := revertUnconfirmed(receipt); stop {
				return next, err
			}
		}
		deposit, err := h.readAddressDeposit(config)
		if err != nil {
			return update(), err
		}
		if deposit != nil && strings.EqualFold(deposit.TransactionHash, record.Pending.Hash) {
			if deposit.Active {
				return update(), errors.New("an active private note cannot be replaced")
			}
			deposit.TransactionHash = ""
			if err := h.save(*deposit); err != nil {
				return update(), err
			}
		}
		failed := *record.Pending
		failed.FinalizedRevert = true
		record.History = append(record.History, failed)
		record.Pending, record.Phase = nil, "waiting_funds"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
	}

	if record.Amount == 0 {
		// Old wallet dialogs may have broadcast a deposit without returning its
		// hash. Never adopt their note and send another deposit from this key.
		previous, readErr := h.readAddressDeposit(config)
		if readErr != nil {
			return status, readErr
		}
		if previous != nil {
			record.Phase, record.Amount = "legacy_recovery", previous.Amount
			if previous.Active {
				record.Phase = "active"
			}
			if err := h.saveAddress(record); err != nil {
				return status, err
			}
			return update(), nil
		}
		record.Amount, record.Phase = amount, "waiting_funds"
		credited := len(record.CreditedPayouts)
		retireWithdrawal(record)
		if err := h.saveAddress(record); err != nil {
			return status, err
		}
		if len(record.CreditedPayouts) != credited {
			// The replaced withdrawal's credited payout is reported from now on.
			if status.EscapePayoutCredits, err = h.escapePayoutCredits(ctx, config, record); err != nil {
				return update(), err
			}
		}
	}
	if record.Phase == "legacy_recovery" {
		return update(), nil
	}
	if record.Pending == nil && len(record.History) != 0 {
		previous := record.History[len(record.History)-1]
		if !previous.FinalizedRevert && (previous.Kind == "approval" || previous.Kind == "approval_reset") {
			// The approval may have been archived just before an interruption
			// or a failed deposit simulation. No successor was then signed to
			// drive normal pending recovery. Restore that exact approval if
			// its provisional receipt disappeared or changed after a reorg.
			receipt, _, err := h.addressFinalReceipt(ctx, config, previous.Hash, false)
			if err != nil {
				return update(), err
			}
			if receipt == nil || receipt.Status == "0x0" {
				record.History = record.History[:len(record.History)-1]
				record.Pending, record.Phase = &previous, "approval_pending"
				if err := h.saveAddress(record); err != nil {
					return update(), err
				}
			}
		}
	}
	if record.Pending != nil {
		// Native deposits match the web wallet: a canonical successful mined
		// receipt can activate immediately. Reverts still require finality in
		// addressFinalReceipt before a later explicit retry may use a new nonce.
		receipt, confirmed, receiptErr := h.addressFinalReceipt(ctx, config, record.Pending.Hash, record.Pending.Kind == "deposit" && !config.nativeETH())
		if receiptErr != nil {
			if record.Pending.Kind == "deposit" && (record.Phase == "confirming" || record.Phase == "verification_conflict") {
				record.Phase = "deposit_pending"
				if err := h.saveAddress(record); err != nil {
					return update(), err
				}
			}
			return update(), receiptErr
		}
		if !confirmed {
			if record.Pending.Kind == "deposit" {
				if record.Phase == "confirming" || record.Phase == "verification_conflict" {
					record.Phase = "deposit_pending"
					if err := h.saveAddress(record); err != nil {
						return update(), err
					}
				}
				depositStage = "finalizing"
				if receipt != nil && receipt.Status == "0x0" {
					depositStage = "failed_finalizing"
				}
				if receipt == nil {
					depositStage = h.pendingDepositStage(ctx, config, record.Pending)
				}
			}
			// A missing receipt is uncertainty, not permission to choose a new
			// nonce. Replaying identical EIP-155 bytes is safe after any restart.
			if receipt == nil {
				// Approval confirmation does not wait for finality. If it is
				// reorganized away, the dependent deposit cannot use its nonce
				// until that exact prior approval is replayed. Never sign a
				// replacement, nor replay an older deposit under this policy.
				for i := range record.History {
					previous := &record.History[i]
					if !previous.FinalizedRevert && (previous.Kind == "approval" || previous.Kind == "approval_reset") {
						h.broadcastAddress(ctx, config, previous)
					}
				}
				h.broadcastAddress(ctx, config, record.Pending)
			}
			return update(), nil
		}
		if err := recordAddressActualFee(record.Pending, receipt); err != nil {
			return update(), err
		}
		if receipt.Status == "0x0" {
			if record.Pending.Kind == "deposit" && record.Phase == "verification_conflict" {
				// A conflicting revert never silently becomes retryable.
				if next, stop, err := revertUnconfirmed(receipt); stop {
					return next, err
				}
			}
			record.Phase = "reverted"
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
			return update(), nil
		}
		if record.Pending.Kind == "deposit" {
			record.Phase = "confirming"
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
			if _, err := h.confirm(ctx, record.Pending.Hash); err != nil {
				switch {
				case errors.Is(err, errUnconfirmedDepositReceipt):
					// Inclusion can change between the first check and
					// activation. Keep the transaction journal, but do not
					// leave durable status claiming the receipt is ready.
					record.Phase = "deposit_pending"
					if saveErr := h.saveAddress(record); saveErr != nil {
						return update(), saveErr
					}
				case errors.Is(err, errDepositVerificationPending):
					// Mined, but the vault and indexer have not both
					// confirmed it; keep polling without activating.
					depositStage = "verifying"
					return update(), nil
				case errors.Is(err, errDepositVerificationConflict):
					record.Phase = "verification_conflict"
					if saveErr := h.saveAddress(record); saveErr != nil {
						return update(), saveErr
					}
					return conflicted(err), nil
				}
				return update(), err
			}
			record.Phase = "active"
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
			return update(), nil
		}
		expected := new(big.Int).SetUint64(amount)
		if record.Pending.Kind == "approval_reset" {
			expected.SetUint64(0)
		}
		allowance, err := h.addressAllowance(ctx, config, record.Address, receipt.BlockNumber)
		if err != nil || allowance.Cmp(expected) != 0 {
			return update(), errors.New("the confirmed token approval has not been verified; retry without sending a replacement")
		}
		record.History = append(record.History, *record.Pending)
		record.Pending = nil
		record.Phase = "waiting_funds"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
	}
	tokenBalance, _ := new(big.Int).SetString(status.TokenBalance, 10)
	ethBalance, _ := new(big.Int).SetString(status.ETHBalance, 10)
	if tokenBalance.Cmp(new(big.Int).SetUint64(amount)) < 0 || ethBalance.Sign() == 0 {
		return update(), nil
	}
	if _, err := h.prepare(ctx, amount); err != nil {
		return update(), err
	}
	deposit, err := h.readAddressDeposit(config)
	if err != nil || deposit == nil {
		return update(), errors.New("the private deposit recovery record is unavailable")
	}
	if deposit.Amount != amount || (record.Commitment != "" && record.Commitment != deposit.Commitment) {
		return update(), errors.New("the saved private deposit does not match this funding attempt")
	}
	if deposit.Active {
		record.Phase = "active"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return update(), nil
	}
	if deposit.TransactionHash != "" {
		return update(), errors.New("a submitted deposit is missing its local transaction journal; recover its saved hash before continuing")
	}
	record.Commitment = deposit.Commitment
	if err := h.saveAddress(record); err != nil {
		return update(), err
	}
	allowance := new(big.Int).SetUint64(amount)
	if !config.nativeETH() {
		allowance, err = h.addressAllowance(ctx, config, record.Address, "latest")
		if err != nil {
			return update(), err
		}
	}
	kind, to, data := "approval", config.Token, "0x095ea7b3"+addressABIWord(config.Contract)+fmt.Sprintf("%064x", amount)
	if allowance.Cmp(new(big.Int).SetUint64(amount)) < 0 {
		if allowance.Sign() != 0 {
			kind, data = "approval_reset", "0x095ea7b3"+addressABIWord(config.Contract)+strings.Repeat("0", 64)
		}
	} else {
		// Approval may take minutes. Obtain the current empty-leaf witness,
		// bound to its indexer slot, immediately before simulating/signing.
		bound, bindErr := h.bindDepositPath(ctx, config, record, deposit)
		if errors.Is(bindErr, errDepositVerificationConflict) {
			return landed(bindErr)
		}
		if bindErr != nil {
			return update(), bindErr
		}
		kind, to, data = "deposit", config.Contract, bound
	}
	if err := h.signAddressTransaction(ctx, config, record, kind, to, data); err != nil {
		if errors.Is(err, errAddressNeedsETH) {
			next := update()
			next.Message = err.Error()
			return next, nil
		}
		return update(), err
	}
	if kind == "deposit" {
		if err := h.recordSignedDepositSlot(record, deposit); err != nil {
			return update(), err
		}
		depositStage = "pending"
	}
	return update(), nil
}

// A signed deposit below the latest base fee cannot currently be included.
// This optional read only refines progress; unavailable/malformed data leaves
// the transaction pending, and never changes its approved fee or signed bytes.
func (h *FundingHandler) pendingDepositStage(ctx context.Context, config fundingConfig, saved *addressTransaction) string {
	if saved == nil || saved.Kind != "deposit" {
		return "pending"
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(saved.Raw, "0x"))
	var tx types.Transaction
	if err != nil || tx.UnmarshalBinary(raw) != nil || !strings.EqualFold(tx.Hash().Hex(), saved.Hash) {
		return "pending"
	}
	var latest struct {
		BaseFeePerGas string `json:"baseFeePerGas"`
		Timestamp     string `json:"timestamp"`
	}
	if h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{"latest", false}, &latest) != nil {
		return "pending"
	}
	timestamp, err := feeQuantity(latest.Timestamp)
	if err != nil || !timestamp.IsInt64() || timestamp.BitLen() > 53 {
		return "pending"
	}
	now := time.Now().Unix()
	if timestamp.Int64() < now-120 || timestamp.Int64() > now+30 {
		return "pending"
	}
	baseFee, err := feeQuantity(latest.BaseFeePerGas)
	if err == nil && baseFee.Cmp(tx.GasFeeCap()) > 0 {
		return "fee_wait"
	}
	return "pending"
}

func (h *FundingHandler) readAddressDeposit(config fundingConfig) (*depositRecord, error) {
	raw, err := os.ReadFile(h.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot read the pending private deposit")
	}
	var record depositRecord
	if json.Unmarshal(raw, &record) != nil || !depositDeploymentMatches(record, config) || !validDepositRecovery(record) {
		return nil, errors.New("pending private deposit belongs to another deployment or is invalid; preserve it for recovery")
	}
	return &record, nil
}

// The additive recovery fields are written only by this daemon. A malformed
// one means the file was damaged or edited; preserve it rather than act on it.
func validDepositRecovery(record depositRecord) bool {
	if b := record.Binding; b != nil && (b.ExpiryTs == 0 || !isHex(b.BlockHash, 32)) {
		return false
	}
	if r := record.Rebind; r != nil && r.ExpiryTs == 0 {
		return false
	}
	if s := record.Slot; s != nil && (!isHex(s.PathSHA256, 32) || s.PreparedAt <= 0 || s.PreparedChainAt < 0 || s.EmptyBefore > s.NoteID) {
		return false
	}
	for _, s := range record.SignedSlots {
		if !isHex(s.PathSHA256, 32) || s.PreparedAt <= 0 || s.PreparedChainAt < 0 || s.EmptyBefore > s.NoteID {
			return false
		}
	}
	return true
}

func addressABIWord(value string) string {
	value = strings.TrimPrefix(value, "0x")
	if len(value) > 64 {
		return ""
	}
	return strings.Repeat("0", 64-len(value)) + value
}

// errAddressRPCUnavailable is a payment RPC that did not answer: a transport
// failure, or an HTTP status other than 200 (a 429 rate limit, a 5xx).
var errAddressRPCUnavailable = errors.New("payment RPC unavailable; retry the saved funding attempt")

// errExitRPCUnavailable is the owner's exit RPC failing after its retries.
var errExitRPCUnavailable = errors.New("the exit RPC (--exit-rpc-url) did not answer; nothing was read from or sent through another RPC in its place. Retry, or configure another exit RPC")

// exitRPCRetryDelays are the waits before each retry of an exit RPC call
// that did not answer (exitConfig).
var exitRPCRetryDelays = []time.Duration{time.Second, 3 * time.Second}

var errAddressRPCResponse = errors.New("invalid payment RPC response; retry the saved funding attempt")

func (h *FundingHandler) addressRPC(ctx context.Context, config fundingConfig, method string, params []any, result any) error {
	raw, refused, err := h.addressRPCRaw(ctx, config, method, params)
	if err != nil {
		return err
	}
	// An RPC's refusal (a JSON-RPC error) is never reflected to callers: it
	// may carry request bodies or signed bytes. The gasless dry run reads
	// it through addressRPCRaw.
	if refused != nil || len(raw) == 0 || json.Unmarshal(raw, result) != nil {
		return errAddressRPCResponse
	}
	return nil
}

// addressRPCRaw is addressRPC with the answer unparsed: the result, or the
// JSON-RPC error the node answered (which is final, never retried).
func (h *FundingHandler) addressRPCRaw(ctx context.Context, config fundingConfig, method string, params []any) (json.RawMessage, *rpcError, error) {
	if !config.exitOnly {
		return h.addressRPCAt(ctx, config.RPC, method, params)
	}
	// An escape through the owner's exit RPC: a call it did not answer is
	// retried there, never asked of the pinned RPC (exitConfig). An answer
	// it refused (a JSON-RPC error) is final, as for any RPC.
	for attempt := 0; ; attempt++ {
		raw, refused, err := h.addressRPCAt(ctx, config.RPC, method, params)
		if !errors.Is(err, errAddressRPCUnavailable) {
			return raw, refused, err
		}
		if attempt == len(exitRPCRetryDelays) {
			return nil, nil, errExitRPCUnavailable
		}
		select {
		case <-ctx.Done():
			return nil, nil, errExitRPCUnavailable
		case <-time.After(exitRPCRetryDelays[attempt]):
		}
	}
}

func (h *FundingHandler) addressRPCAt(ctx context.Context, url, method string, params []any) (json.RawMessage, *rpcError, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, errors.New("invalid payment RPC request")
	}
	req.Header.Set("Content-Type", "application/json")
	// This uses the configured direct/Wisp client. Never use http.DefaultClient
	// and never reflect RPC errors, request bodies, or signed bytes to callers.
	response, err := h.client.inference.Do(req)
	if err != nil {
		return nil, nil, errAddressRPCUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != http.StatusOK {
		return nil, nil, errAddressRPCUnavailable
	}
	var envelope struct {
		Version string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *rpcError       `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != "2.0" || envelope.ID != 1 {
		return nil, nil, errAddressRPCResponse
	}
	if envelope.Error != nil {
		return nil, envelope.Error, nil
	}
	return envelope.Result, nil, nil
}

func (h *FundingHandler) addressQuantity(ctx context.Context, config fundingConfig, method string, params []any) (*big.Int, error) {
	var encoded string
	if err := h.addressRPC(ctx, config, method, params, &encoded); err != nil {
		return nil, err
	}
	return addressHexUint(encoded)
}

func addressHexUint(encoded string) (*big.Int, error) {
	if !isField(encoded) {
		return nil, errors.New("invalid Ethereum quantity")
	}
	value, ok := new(big.Int).SetString(encoded[2:], 16)
	if !ok || value.Sign() < 0 || value.BitLen() > 256 {
		return nil, errors.New("invalid Ethereum quantity")
	}
	return value, nil
}

func (h *FundingHandler) assertAddressChain(ctx context.Context, config fundingConfig) error {
	chain, err := h.addressQuantity(ctx, config, "eth_chainId", []any{})
	if err != nil {
		return err
	}
	if !chain.IsUint64() || chain.Uint64() != config.ChainID {
		return errors.New("payment RPC is on the wrong Ethereum network; no transaction was sent")
	}
	return nil
}

func (h *FundingHandler) addressUintCall(ctx context.Context, config fundingConfig, contract, data, block string) (*big.Int, error) {
	return h.addressQuantity(ctx, config, "eth_call", []any{map[string]string{"to": contract, "data": data}, block})
}

func (h *FundingHandler) addressAllowance(ctx context.Context, config fundingConfig, owner, block string) (*big.Int, error) {
	return h.addressUintCall(ctx, config, config.Token, "0xdd62ed3e"+addressABIWord(owner)+addressABIWord(config.Contract), block)
}

func (h *FundingHandler) signAddressTransaction(ctx context.Context, config fundingConfig, record *addressFundingRecord, kind, to, data string) error {
	if record.Pending != nil && !(quoteMode(ctx) != nil && quoteMode(ctx).Capture != nil && ((record.Pending.Kind == "withdrawal" && record.Withdrawal != nil && record.Withdrawal.Phase == "reverted") || (record.Pending.Kind == "deposit" && record.Phase == "reverted")) && strings.EqualFold(quoteMode(ctx).RetryHash, record.Pending.Hash)) {
		return errors.New("a signed payment is still pending; no replacement was sent")
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return err
	}
	// Design §6.7: before every deposit, the deployment on chain must be the
	// pinned one (codehashes, adapter, getters), through the pinned RPC and
	// the owner's exit RPC. Exits are never refused this way.
	if kind == "deposit" {
		if err := h.client.CheckDeployment(ctx); err != nil {
			return err
		}
	}
	nonce, err := h.addressQuantity(ctx, config, "eth_getTransactionCount", []any{record.Address, "pending"})
	if err != nil {
		return err
	}
	if !nonce.IsUint64() || nonce.BitLen() > 53 {
		return errors.New("invalid payment nonce")
	}
	confirmedNonce, err := h.addressQuantity(ctx, config, "eth_getTransactionCount", []any{record.Address, "latest"})
	if err != nil {
		return err
	}
	if confirmedNonce.Cmp(nonce) != 0 {
		// The one unsettled transaction may be an escape this client
		// retired unmined (its proof expired before inclusion, design §6.4
		// E4 step 7): the next escape transaction replaces it at its nonce.
		if !escapeKinds[kind] || !confirmedNonce.IsUint64() || nonce.Uint64() != confirmedNonce.Uint64()+1 || unminedEscapeFees(record, confirmedNonce.Uint64()) == nil {
			return errors.New("an unsettled public transaction exists; recover it before signing another")
		}
		nonce = confirmedNonce
	}
	for _, previous := range record.History {
		// An escape retired unmined never took its nonce.
		if previous.Nonce >= nonce.Uint64() && !previous.Unmined {
			return errors.New("the payment RPC has not caught up with saved transactions; no new transaction was sent")
		}
	}
	value := new(big.Int)
	if config.nativeETH() && kind == "deposit" {
		value.Mul(new(big.Int).SetUint64(record.Amount), big.NewInt(1_000_000_000))
	}
	if kind == "return" {
		if record.Return == nil || !strings.EqualFold(record.Return.Destination, to) || data != "0x" {
			return errors.New("public return intent is missing")
		}
		var ok bool
		value, ok = new(big.Int).SetString(record.Return.AmountWei, 10)
		if !ok || value.Sign() < 0 || value.BitLen() > 256 {
			return errors.New("invalid public return value")
		}
		if record.Return.Sweep {
			if mode := quoteMode(ctx); mode != nil && mode.Capture != nil {
				// Start with a nonzero transfer; smart/delegated wallets may have
				// a payable receive path different from a zero-value call.
				value.SetInt64(1)
			}
		}
	}
	mode := quoteMode(ctx)
	if config.nativeETH() && mode == nil {
		return errors.New("review and approve a current payment quote before signing")
	}
	input := map[string]string{"from": record.Address, "to": to, "data": data, "value": "0x" + value.Text(16)}
	params := []any{input, "pending"}
	if mode != nil && mode.Capture != nil {
		// Override only this signer's balance; contract state and exact payable
		// calldata stay real. Unsupported state overrides must fail closed.
		simulationBalance := new(big.Int).Set(addressUint256Max)
		if config.nativeETH() && (kind == "withdrawal" || kind == "escape_finalize" || kind == "escape_claim") {
			if record.Withdrawal == nil {
				return errors.New("withdrawal intent is missing; no transaction was sent")
			}
			// The authorized payout may go back to this same funding account.
			// Leave room for that exact credit instead of making an otherwise
			// valid self-withdrawal overflow a synthetic maximum balance.
			payout := new(big.Int).Mul(new(big.Int).SetUint64(record.Withdrawal.Amount), big.NewInt(1_000_000_000))
			simulationBalance.Sub(simulationBalance, payout)
		}
		params = append(params, map[string]any{record.Address: map[string]string{"balance": "0x" + simulationBalance.Text(16)}})
	}
	var simulated string
	var warnings []string
	simulationErr := h.addressRPC(ctx, config, "eth_call", params, &simulated)
	gas, estimateErr := h.addressQuantity(ctx, config, "eth_estimateGas", params)
	var gasLimit uint64
	if simulationErr == nil && estimateErr == nil {
		gasLimit, err = paddedAddressGas(gas)
		if err != nil {
			return err
		}
		// An escape transaction is never signed below its entry point's
		// measured cost, whatever the estimate: one that runs out of gas
		// reverts, and a reverted escape costs another proof release.
		if escapeKinds[kind] && gasLimit < escapeGasLimits[kind] {
			gasLimit = escapeGasLimits[kind]
		}
	} else if escapeKinds[kind] {
		// Design §6.4 E4 step 5: for an exit the simulation is advisory. A
		// failed or refused simulation is shown, and the owner may sign at
		// a fixed gas limit anyway: a genuinely flagged nullifier or an
		// expired proof reverts cheaply, while an RPC that refuses to
		// simulate must not block the exit.
		gasLimit = escapeGasLimits[kind]
		gas = new(big.Int).SetUint64(gasLimit)
		warnings = append(warnings, "the escape's simulation failed or was refused; it may revert, and is signed at a fixed gas limit")
	} else {
		return errors.New("payment simulation failed; no transaction was sent")
	}
	if kind == "return" && record.Return.Sweep && gas.Uint64() == 21000 {
		gasLimit = 21000
	}
	fees, err := h.addressLowFees(ctx, config, gasLimit)
	if err != nil {
		return err
	}
	// Replacing an escape retired unmined at this nonce, which a mempool
	// may still hold: its fee cap and tip are raised by more than the 10%
	// a node requires to accept the replacement.
	if floor := unminedEscapeFees(record, nonce.Uint64()); floor != nil {
		for _, fee := range []*big.Int{fees.Max, fees.Minimum} {
			if fee.Cmp(floor.Max) < 0 {
				fee.Set(floor.Max)
			}
		}
		if fees.Tip.Cmp(floor.Tip) < 0 {
			fees.Tip.Set(floor.Tip)
		}
	}
	balance, err := h.addressQuantity(ctx, config, "eth_getBalance", []any{record.Address, "pending"})
	if err != nil {
		return err
	}
	if mode != nil && mode.Capture != nil && kind == "return" && record.Return.Sweep {
		reserve := new(big.Int).Mul(fees.Max, new(big.Int).SetUint64(gasLimit))
		if balance.Cmp(reserve) <= 0 {
			return errAddressNeedsETH
		}
		value.Sub(balance, reserve)
		// Check the exact swept amount as well, including value-dependent
		// recipient code. Never sign a sweep simulated only with a probe value.
		input["value"] = "0x" + value.Text(16)
		if err := h.addressRPC(ctx, config, "eth_call", params, &simulated); err != nil {
			return errors.New("public return simulation failed; no transaction was sent")
		}
		exactGas, err := h.addressQuantity(ctx, config, "eth_estimateGas", params)
		if err != nil || !exactGas.IsUint64() || exactGas.Uint64() > gasLimit {
			return errors.New("public return gas changed with its value; choose an exact amount; no transaction was sent")
		}
		record.Return.AmountWei = value.String()
	}
	if mode != nil && mode.Capture != nil {
		quote, err := h.savePaymentQuote(record, kind, to, value, balance, gas, gasLimit, nonce.Uint64(), fees, mode.RetryHash, warnings...)
		if err == nil {
			*mode.Capture = quote
		}
		return err
	}
	var approved *AddressPaymentQuote
	if mode != nil {
		approved = mode.Approval
	}
	if config.nativeETH() {
		if err := validatePaymentApproval(record, approved, kind, to, value, nonce.Uint64()); err != nil {
			return err
		}
		ceiling, ok := new(big.Int).SetString(approved.FeeReserveWei, 10)
		if !ok || ceiling.Sign() <= 0 || ceiling.BitLen() > 256 {
			return errAddressQuoteChanged
		}
		cap := new(big.Int).Quo(ceiling, new(big.Int).SetUint64(gasLimit))
		if cap.Cmp(fees.Minimum) < 0 {
			return errAddressQuoteChanged
		}
		if fees.Max.Cmp(cap) > 0 {
			fees.Max.Set(cap)
		}
	}
	minimumFee := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), fees.Minimum)
	minimumRequired := new(big.Int).Add(value, minimumFee)
	if minimumRequired.BitLen() > 256 {
		return errAddressFeeData
	}
	if balance.Cmp(minimumRequired) < 0 {
		return fmt.Errorf("%w (send at least %s ETH more to %s on chain %d; no transaction was sent)", errAddressNeedsETH, new(big.Rat).SetFrac(new(big.Int).Sub(minimumRequired, balance), big.NewInt(1_000_000_000_000_000_000)).FloatString(18), record.Address, config.ChainID)
	}
	// The recommended buffer is optional: clamp the signed fee cap to the
	// current balance without changing principal or approved total liability.
	affordablePrice := new(big.Int).Quo(new(big.Int).Sub(balance, value), new(big.Int).SetUint64(gasLimit))
	if fees.Max.Cmp(affordablePrice) > 0 {
		fees.Max.Set(affordablePrice)
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), fees.Max)
	if new(big.Int).Add(value, fee).BitLen() > 256 {
		return errAddressFeeData
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return err
	}
	key, err := crypto.HexToECDSA(record.PrivateKey)
	if err != nil {
		return errors.New("invalid saved payment key; preserve its recovery file")
	}
	calldata, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return errors.New("invalid payment call data")
	}
	if approved != nil && approved.ExpiresAt <= time.Now().UnixMilli() {
		return errAddressQuoteChanged
	}
	destination := common.HexToAddress(to)
	unsigned := types.NewTx(&types.DynamicFeeTx{ChainID: new(big.Int).SetUint64(config.ChainID), Nonce: nonce.Uint64(), To: &destination, Value: value, Gas: gasLimit, GasFeeCap: fees.Max, GasTipCap: fees.Tip, Data: calldata})
	signed, err := types.SignTx(unsigned, types.LatestSignerForChainID(new(big.Int).SetUint64(config.ChainID)), key)
	if err != nil {
		return errors.New("cannot sign payment transaction")
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return errors.New("cannot encode payment transaction")
	}
	record.Pending = &addressTransaction{Kind: kind, Raw: "0x" + hex.EncodeToString(raw), Hash: signed.Hash().Hex(), Nonce: nonce.Uint64(), SignedAt: time.Now().Unix()}
	if kind == "return" {
		record.Pending.ReturnDestination = to
		record.Pending.ReturnValueWei = value.String()
	}
	if approved != nil {
		record.Pending.ApprovedFeeWei = approved.FeeReserveWei
	}
	record.Quote = nil
	record.Phase = "approval_pending"
	if kind == "deposit" {
		record.Phase = "deposit_pending"
	}
	if kind == "withdrawal" {
		record.Phase = "withdrawal_pending"
		if record.Withdrawal == nil {
			return errors.New("withdrawal intent is missing; no transaction was sent")
		}
		record.Withdrawal.Phase, record.Withdrawal.TransactionHash = "withdrawal_pending", signed.Hash().Hex()
	}
	if escapeKinds[kind] {
		if record.Withdrawal == nil || record.Withdrawal.Mode != "escape" {
			return errors.New("escape intent is missing; no transaction was sent")
		}
		switch kind {
		case "escape":
			record.Phase = "withdrawal_pending"
			record.Withdrawal.Phase, record.Withdrawal.TransactionHash = "escape_pending", signed.Hash().Hex()
		case "escape_finalize":
			record.Phase = "withdrawal_pending"
			record.Withdrawal.Phase = "finalize_pending"
		case "escape_claim":
			// The note is closed already; a claim only delivers its credit.
			record.Phase = "ready"
		}
	}
	if kind == "return" {
		record.Phase = "return_pending"
		record.Return.Phase = "return_pending"
		record.Return.TransactionHash = signed.Hash().Hex()
	}
	if transitKinds[kind] {
		// The note is closed already; the transaction only moves the
		// payout out of the transit account or the paymaster.
		if record.Withdrawal == nil || record.Withdrawal.Transit == nil {
			return errors.New("transit intent is missing; no transaction was sent")
		}
		record.Phase = "ready"
	}
	// From this point every retry uses these exact bytes, even if a broadcast
	// fails or the daemon crashes before the RPC responds.
	if err := h.saveAddress(record); err != nil {
		return err
	}
	h.broadcastAddress(ctx, config, record.Pending)
	return nil
}

func (h *FundingHandler) broadcastAddress(ctx context.Context, config fundingConfig, tx *addressTransaction) {
	// Design §6.7: exits are sent through the owner's exit RPC when set.
	if escapeKinds[tx.Kind] || transitKinds[tx.Kind] {
		config = config.exitConfig()
	}
	if h.assertAddressChain(ctx, config) != nil {
		return
	}
	var hash string
	// A missing or wrong hash is ambiguous: the locally derived hash is the
	// only transaction identity. Never recover by choosing another nonce.
	_ = h.addressRPC(ctx, config, "eth_sendRawTransaction", []any{tx.Raw}, &hash)
}

type addressReceipt struct {
	GasUsed           string `json:"gasUsed"`
	EffectiveGasPrice string `json:"effectiveGasPrice"`
	Status            string `json:"status"`
	TransactionHash   string `json:"transactionHash"`
	BlockHash         string `json:"blockHash"`
	BlockNumber       string `json:"blockNumber"`
	To                string `json:"to"`
	Logs              []struct {
		Address string   `json:"address"`
		Topics  []string `json:"topics"`
		Data    string   `json:"data"`
		Removed bool     `json:"removed"`
	} `json:"logs"`
}

func (h *FundingHandler) addressFinalReceipt(ctx context.Context, config fundingConfig, hash string, requireFinality bool) (*addressReceipt, bool, error) {
	var receipt *addressReceipt
	if err := h.addressRPC(ctx, config, "eth_getTransactionReceipt", []any{hash}, &receipt); err != nil {
		return nil, false, err
	}
	if receipt == nil {
		return nil, false, nil
	}
	if !strings.EqualFold(receipt.TransactionHash, hash) || !isHex(receipt.BlockHash, 32) || (receipt.Status != "0x0" && receipt.Status != "0x1") {
		return nil, false, errors.New("invalid payment receipt; preserve its saved transaction")
	}
	number, err := addressHexUint(receipt.BlockNumber)
	if err != nil {
		return nil, false, err
	}
	var finalized struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	blockTag := "latest"
	// A provisional failure can disappear or become successful in a reorg.
	// Persisting "reverted" grants a later explicit retry a fresh nonce, so
	// failure always needs finality even when successful transactions do not.
	if requireFinality || receipt.Status == "0x0" {
		blockTag = "finalized"
	}
	if err := h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{blockTag, false}, &finalized); err != nil {
		return receipt, false, err
	}
	finalizedNumber, err := addressHexUint(finalized.Number)
	if err != nil {
		return receipt, false, err
	}
	if finalizedNumber.Cmp(number) < 0 {
		return receipt, false, nil
	}
	var canonical struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if err := h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{receipt.BlockNumber, false}, &canonical); err != nil {
		return receipt, false, err
	}
	if canonical.Number != receipt.BlockNumber || !strings.EqualFold(canonical.Hash, receipt.BlockHash) {
		return receipt, false, errors.New("payment receipt is not canonical; retry its saved transaction")
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return receipt, false, err
	}
	return receipt, true, nil
}

// Manual confirmation and saved-transaction recovery use the same native
// activation policy. Return the exact receipt whose block was checked so event
// validation cannot accidentally use a second, unchecked RPC response.
func (h *FundingHandler) confirmedDepositReceipt(ctx context.Context, config fundingConfig, hash string) (ethReceipt, error) {
	if config.nativeETH() {
		receipt, confirmed, err := h.addressFinalReceipt(ctx, config, hash, false)
		if err != nil {
			return ethReceipt{}, err
		}
		if !confirmed {
			if receipt != nil && receipt.Status == "0x0" {
				return ethReceipt{}, errors.New("the failed deposit is awaiting Ethereum finality; retry confirmation later")
			}
			return ethReceipt{}, errors.New("the saved deposit is awaiting a canonical mined receipt; retry confirmation later")
		}
		return ethReceipt{Status: receipt.Status, To: receipt.To, TransactionHash: receipt.TransactionHash, BlockNumber: receipt.BlockNumber, BlockHash: receipt.BlockHash, Logs: receipt.Logs}, nil
	}
	// Keep the historical token-wallet confirmation policy for recovery.
	if _, err := os.Lstat(h.addressStatePath()); errors.Is(err, os.ErrNotExist) {
		return h.receipt(ctx, config.RPC, hash)
	} else if err != nil {
		return ethReceipt{}, errors.New("cannot read payment address recovery data")
	}
	record, err := h.loadAddress(config)
	if err != nil {
		return ethReceipt{}, err
	}
	for _, entry := range append(append([]addressTransaction{}, record.History...), pendingAddressTransaction(record.Pending)...) {
		if entry.Kind != "deposit" || !strings.EqualFold(entry.Hash, hash) {
			continue
		}
		_, final, err := h.addressFinalReceipt(ctx, config, hash, true)
		if err != nil {
			return ethReceipt{}, err
		}
		if !final {
			return ethReceipt{}, errors.New("the saved deposit is awaiting Ethereum finality; retry confirmation later")
		}
	}
	return h.receipt(ctx, config.RPC, hash)
}

// Receipt fee metadata is useful only after canonicality/finality and exact
// transaction identity have been established by addressFinalReceipt. Older
// records without both fields stay unknown, never a fabricated zero fee.
func recordAddressActualFee(saved *addressTransaction, receipt *addressReceipt) error {
	if receipt.GasUsed == "" && receipt.EffectiveGasPrice == "" {
		return nil
	}
	invalid := errors.New("invalid canonical transaction fee metadata; preserve the saved transaction")
	if saved == nil || !strings.EqualFold(saved.Hash, receipt.TransactionHash) {
		return invalid
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(saved.Raw, "0x"))
	if err != nil {
		return invalid
	}
	var tx types.Transaction
	if tx.UnmarshalBinary(raw) != nil {
		return invalid
	}
	gas, e1 := feeQuantity(receipt.GasUsed)
	price, e2 := feeQuantity(receipt.EffectiveGasPrice)
	if e1 != nil || e2 != nil || !gas.IsUint64() || gas.Uint64() < 21000 || gas.Uint64() > tx.Gas() || price.Cmp(tx.GasFeeCap()) > 0 {
		return invalid
	}
	actual := new(big.Int).Mul(gas, price)
	if actual.BitLen() > 256 {
		return invalid
	}
	if saved.ApprovedFeeWei != "" {
		approved, ok := new(big.Int).SetString(saved.ApprovedFeeWei, 10)
		if !ok || actual.Cmp(approved) > 0 {
			return invalid
		}
	}
	saved.ActualFeeWei = actual.String()
	return nil
}
