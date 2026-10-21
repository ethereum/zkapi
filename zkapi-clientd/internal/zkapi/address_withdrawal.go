package zkapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// AddressWithdrawalStatus contains public progress only. Proofs, raw signed
// transactions, note recovery secrets, and the signing key stay on disk.
type AddressWithdrawalStatus struct {
	ActualFeeWei    string `json:"actual_fee_wei,omitempty"`
	DeploymentID    string `json:"deployment_id,omitempty"`
	BillingAsset    string `json:"billing_asset,omitempty"`
	BillingUnit     string `json:"billing_unit,omitempty"`
	WeiPerUnit      string `json:"native_asset_wei_per_unit,omitempty"`
	Address         string `json:"address"`
	ChainID         uint64 `json:"chain_id"`
	TokenAddress    string `json:"token_address"`
	TokenDecimals   int    `json:"token_decimals"`
	ETHBalance      string `json:"eth_balance"`
	PrivateBalance  uint64 `json:"private_balance"`
	Amount          uint64 `json:"amount"`
	Destination     string `json:"destination,omitempty"`
	NoteID          uint64 `json:"note_id,omitempty"`
	Phase           string `json:"phase"`
	TransactionHash string `json:"transaction_hash,omitempty"`
	Message         string `json:"message"`
	// NoteExpiry is the active note's expiry (Unix seconds). After it no
	// chat request can move the note to a new state.
	NoteExpiry uint64 `json:"note_expiry,omitempty"`
	// PayoutCredited marks a complete withdrawal whose note an escape closed
	// without paying the destination: the vault holds the balance in
	// escapePayoutCredits(destination). Nothing has reached the destination
	// until someone sends ClaimCalldata to VaultAddress.
	PayoutCredited bool   `json:"payout_credited,omitempty"`
	VaultAddress   string `json:"vault_address,omitempty"`
	ClaimCalldata  string `json:"claim_calldata,omitempty"`
	// EscapePayoutCredits lists credited escape payouts of earlier notes
	// that the vault still holds (see EscapePayoutCredit).
	EscapePayoutCredits []EscapePayoutCredit `json:"escape_payout_credits,omitempty"`
	// Mode is "escape" for an escape withdrawal (design §6.4 E4); its
	// decision and progress follow. Amount is then the payout, which a raise
	// may lower until finalization.
	Mode                    string `json:"mode,omitempty"`
	StateBalance            uint64 `json:"state_balance,omitempty"`
	Conceded                uint64 `json:"conceded,omitempty"`
	BoundAtState            uint64 `json:"bound_at_state,omitempty"`
	Reason                  string `json:"reason,omitempty"`
	WaitUntil               uint64 `json:"wait_until,omitempty"`
	ChallengeDeadline       uint64 `json:"challenge_deadline,omitempty"`
	ValidUntil              uint64 `json:"valid_until,omitempty"`
	ConcessionExceededBound bool   `json:"concession_exceeded_bound,omitempty"`
	// A gasless withdrawal (design 3.3): the fee is paid from the payout by a
	// sponsored user operation from the transit account. UserOpHash is the
	// operation in flight; TransactionHash its bundle transaction once
	// known. The wei figures are the paymaster's Settled figures; a
	// PaymasterCredited payout waits in the paymaster for
	// withdraw --claim-credit; FundsWaitingInTransit marks a payout that
	// reached the transit account and waits for --collect or --sweep.
	FeePayer              string `json:"fee_payer,omitempty"`
	TransitAccount        string `json:"transit_account,omitempty"`
	UserOpHash            string `json:"user_op_hash,omitempty"`
	ChargedWei            string `json:"charged_wei,omitempty"`
	OwedPaidWei           string `json:"owed_paid_wei,omitempty"`
	ReceivedWei           string `json:"received_wei,omitempty"`
	InitiationDebtWei     string `json:"initiation_debt_wei,omitempty"`
	FundsWaitingInTransit bool   `json:"funds_waiting_in_transit,omitempty"`
	PaymasterCredited     bool   `json:"paymaster_credited,omitempty"`
	PaymasterAddress      string `json:"paymaster_address,omitempty"`
	GaslessRefusal        string `json:"gasless_refusal,omitempty"`
	// PayeeHasCode: the payout address is a contract, and GaslessAdvisory
	// design 3.1's advisory about it (shown before proving: the push may
	// fail and the payout be credited).
	PayeeHasCode    bool   `json:"payee_has_code,omitempty"`
	GaslessAdvisory string `json:"gasless_advisory,omitempty"`
}

type addressWithdrawalRecord struct {
	NoteID          uint64 `json:"note_id"`
	Destination     string `json:"destination"`
	Amount          uint64 `json:"amount"`
	Nullifier       string `json:"nullifier,omitempty"`
	Binding         string `json:"binding,omitempty"`
	Phase           string `json:"phase"`
	TransactionHash string `json:"transaction_hash,omitempty"`
	// SettlementHash records an independently relayed payout. TransactionHash
	// remains the locally signed intent whose nonce was consumed by a revert.
	SettlementHash string `json:"settlement_hash,omitempty"`
	// PayoutCredited records that the relayed payout is a finalized escape
	// whose push to Destination failed (EscapePayoutDeferred in the same
	// receipt): the note is closed, and the vault holds its balance for
	// Destination until claimEscapePayout(Destination) delivers it.
	PayoutCredited bool `json:"payout_credited,omitempty"`
	// Mode "escape" (design §6.4 E4): the fields below. Amount is the
	// payout B − c at initiation, and the finalized payout once complete.
	Mode          string `json:"mode,omitempty"`
	StateBalance  uint64 `json:"state_balance,omitempty"`
	Conceded      uint64 `json:"conceded,omitempty"`
	Bound         uint64 `json:"bound_at_state,omitempty"`
	NextNullifier string `json:"next_nullifier,omitempty"`
	Reason        string `json:"reason,omitempty"`
	StartBlock    uint64 `json:"start_block,omitempty"`
	ValidUntil    uint64 `json:"valid_until,omitempty"`
	WaitUntil     uint64 `json:"wait_until,omitempty"`
	Deadline      uint64 `json:"challenge_deadline,omitempty"`
	Payout        uint64 `json:"payout,omitempty"`
	InitiateHash  string `json:"initiate_hash,omitempty"`
	FinalizeHash  string `json:"finalize_hash,omitempty"`
	ClaimHash     string `json:"claim_hash,omitempty"`
	// ConcessionExceededBound is E5's alert: the escape paid less than the
	// state balance less the state's bound.
	ConcessionExceededBound bool `json:"concession_exceeded_bound,omitempty"`
	// CompletedOnPinnedRPC records an escape completed while no exit RPC was
	// set: the pinned RPC, which the operator may run, reported its
	// finalization and payout, so the owner is told to check the payout
	// through an independent source.
	CompletedOnPinnedRPC bool `json:"completed_on_pinned_rpc,omitempty"`
	// A gasless withdrawal (design 3.3). The proof binds the transit account
	// S (ProofDestination), the vault log's destination word, while
	// Destination stays the payout address Y for display and the command
	// line. FeePayer is "payout" while the sponsored path carries the exit
	// and "wallet" once the owner fell back to a wallet-paid call to S.
	ProofDestination string          `json:"proof_destination,omitempty"`
	FeePayer         string          `json:"fee_payer,omitempty"`
	Transit          *addressTransit `json:"transit,omitempty"`
	UserOp           *addressUserOp  `json:"user_op,omitempty"`
	// The paymaster's Settled figures (wei) and an escape initiation's debt.
	ChargedWei        string `json:"charged_wei,omitempty"`
	OwedPaidWei       string `json:"owed_paid_wei,omitempty"`
	ReceivedWei       string `json:"received_wei,omitempty"`
	InitiationDebtWei string `json:"initiation_debt_wei,omitempty"`
	// FundsWaitingInTransit marks a payout that sits in S (a replayed close,
	// a third-party finalization, a wallet-paid call to S) until a sponsored
	// FORWARD (--collect, CollectHashes) or a wallet-paid sweep (SweepHash).
	FundsWaitingInTransit bool     `json:"funds_waiting_in_transit,omitempty"`
	SweepHash             string   `json:"sweep_hash,omitempty"`
	CollectHashes         []string `json:"collect_hashes,omitempty"`
	// PaymasterCredited marks a PayoutCredited payout the paymaster holds
	// (its push to Y failed), delivered by withdraw --claim-credit.
	PaymasterCredited bool `json:"paymaster_credited,omitempty"`
	// GaslessRefusal is why the gasless path stopped (phase gasless_refused).
	GaslessRefusal string `json:"gasless_refusal,omitempty"`
	// PayeeHasCode records that the payout address had code when the
	// withdrawal was prepared (design 3.1's advisory).
	PayeeHasCode bool `json:"payee_has_code,omitempty"`
}

// proofDestination is the address the proof and the vault's logs name: the
// transit account of a gasless withdrawal, else the payout address.
func (w *addressWithdrawalRecord) proofDestination() string {
	if w.ProofDestination != "" {
		return w.ProofDestination
	}
	return w.Destination
}

// transitClaimCalldata is paymaster.claimCredit(Y).
func (w *addressWithdrawalRecord) transitClaimCalldata() string {
	return "0x" + selectorClaimCredit + addressABIWord(strings.ToLower(w.Destination))
}

// setGaslessStatus copies a gasless withdrawal's public progress into the
// status.
func setGaslessStatus(status *AddressWithdrawalStatus, w *addressWithdrawalRecord) {
	if w == nil || w.Transit == nil {
		return
	}
	status.FeePayer, status.TransitAccount = w.FeePayer, w.Transit.Account
	if w.FeePayer == "" {
		status.FeePayer = "wallet"
	}
	if w.PayeeHasCode {
		status.PayeeHasCode, status.GaslessAdvisory = true, gaslessPayeeAdvisory
	}
	if w.UserOp != nil {
		status.UserOpHash = w.UserOp.shownHash()
		// While an operation is in flight the transaction shown is its
		// own bundle transaction (none until it is found), not the exit's.
		if status.TransactionHash == "" || GaslessPendingPhase(w.Phase) {
			status.TransactionHash = w.UserOp.TransactionHash
		}
	}
	status.ChargedWei, status.OwedPaidWei, status.ReceivedWei, status.InitiationDebtWei = w.ChargedWei, w.OwedPaidWei, w.ReceivedWei, w.InitiationDebtWei
	status.FundsWaitingInTransit, status.GaslessRefusal = w.FundsWaitingInTransit, w.GaslessRefusal
	if w.Phase == "op_reverted" && w.UserOp != nil && status.GaslessRefusal == "" {
		status.GaslessRefusal = w.UserOp.Revert
	}
	// Read from the record as this run left it (a claim may have just
	// delivered the credit), never kept from an earlier snapshot.
	status.PaymasterCredited, status.PaymasterAddress = false, ""
	if w.PaymasterCredited {
		status.PaymasterCredited, status.PaymasterAddress = true, w.Transit.Paymaster
	}
}

type withdrawalWallet struct {
	HasNote *bool `json:"has_note"`
	Pending bool  `json:"pending_request"`
	Note    *struct {
		NoteID  uint64 `json:"note_id"`
		Balance uint64 `json:"current_balance"`
		Expiry  uint64 `json:"expiry_ts"`
	} `json:"note"`
}

type withdrawalBridgeStatus struct {
	Phase           string `json:"phase"`
	NoteID          uint64 `json:"note_id"`
	Destination     string `json:"destination"`
	FinalBalance    string `json:"final_balance"`
	Nullifier       string `json:"withdrawal_nullifier"`
	TransactionHash string `json:"transaction_hash"`
	// EscapePayoutCredited is the companion's own reading of the confirmed
	// receipt: a finalized escape whose payout the vault credited.
	EscapePayoutCredited bool `json:"escape_payout_credited"`
}

// withdrawalInputs is the 16-field statement of circuit
// zkapi-v2-concession-v1 (WithdrawalPublicInputsV2C), in public-input order.
type withdrawalInputs struct {
	ProtocolVersion uint64  `json:"protocol_version"`
	ChainID         uint64  `json:"chain_id"`
	Contract        string  `json:"contract_address"`
	ActiveRoot      string  `json:"active_root"`
	StateKeyX       string  `json:"state_signing_key_x"`
	StateKeyY       string  `json:"state_signing_key_y"`
	ClearanceKeyX   string  `json:"clearance_signing_key_x"`
	ClearanceKeyY   string  `json:"clearance_signing_key_y"`
	NoteID          uint64  `json:"note_id"`
	FinalBalance    uint64  `json:"final_balance"`
	Destination     []uint8 `json:"destination"`
	Nullifier       string  `json:"withdrawal_nullifier"`
	Kind            uint64  `json:"kind"`
	NextNullifier   string  `json:"next_nullifier"`
	Conceded        uint64  `json:"conceded"`
	ValidUntil      uint64  `json:"valid_until"`
}

// withdrawalTuple is the vault's WithdrawalPublicInputs tuple.
const withdrawalTuple = "(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)"

// exitProofValidity is how long the vault accepts an escape or close proof;
// a proof is signed only while its valid_until is within this (plus a small
// clock allowance) of now.
const exitProofValidity = 10_800
const exitProofClockAllowance = 300

// withdrawalCalldataLength is selector | 16 tuple words | offset | length |
// 8 proof words: 836 bytes.
const withdrawalCalldataLength = 4 + 26*32

type withdrawalPlan struct {
	Mode         string           `json:"mode"`
	PublicInputs withdrawalInputs `json:"public_inputs"`
	Siblings     []string         `json:"siblings"`
	Proof        struct {
		Backend string `json:"backend"`
		Proof   string `json:"proof"`
	} `json:"proof"`
}

var withdrawalSelector = hex.EncodeToString(crypto.Keccak256([]byte("mutualClose(" + withdrawalTuple + ",bytes)"))[:4])
var withdrawalEventTopic = crypto.Keccak256Hash([]byte("MutualClose(uint32,uint256,uint128,address)")).Hex()

// A finalized escape of the same reservation pays the same nullifier, final
// balance and destination. An ownership proof sent for clearance is a valid
// escape proof, so anyone holding it can close the note this way instead.
var escapeFinalizedEventTopic = crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()

// A vault with vault_revision 2 pushes an escape payout with at most 100,000
// gas. When the destination rejects it or needs more, the escape still
// finalizes, but the balance is credited to escapePayoutCredits(destination)
// and EscapePayoutDeferred(noteId, destination, amount) precedes
// EscapeWithdrawalFinalized in the same receipt. Anyone can then deliver the
// credit with claimEscapePayout(destination).
var escapePayoutDeferredEventTopic = crypto.Keccak256Hash([]byte("EscapePayoutDeferred(uint32,address,uint128)")).Hex()

const claimEscapePayoutSelector = "88c10aee"

// escapePayoutCredits(address) on a vault with vault_revision 2.
const escapePayoutCreditsSelector = "91f6e93a"

// EscapePayoutCredit is a destination for which the vault still holds an
// escape payout credit left by this wallet's finalized escapes, whose
// withdrawal records a later deposit replaced. Nothing has arrived at
// Destination until someone sends ClaimCalldata to VaultAddress.
type EscapePayoutCredit struct {
	Destination string `json:"destination"`
	// CreditedAmount is escapePayoutCredits(Destination) as the vault reads
	// now, in the deployment's billing units.
	CreditedAmount    string   `json:"credited_amount"`
	NoteIDs           []uint64 `json:"note_ids"`
	TransactionHashes []string `json:"transaction_hashes"`
	VaultAddress      string   `json:"vault_address"`
	ClaimCalldata     string   `json:"claim_calldata"`
	Message           string   `json:"message"`
}

// retireWithdrawal drops a complete withdrawal's record for the next note. A
// credited escape payout stays in CreditedPayouts: the vault holds it for
// the destination until claimEscapePayout(destination) delivers it.
func retireWithdrawal(record *addressFundingRecord) {
	if w := record.Withdrawal; w != nil && w.Phase == "complete" && w.PayoutCredited && !w.PaymasterCredited {
		listed := false
		for _, credit := range record.CreditedPayouts {
			listed = listed || strings.EqualFold(credit.SettlementHash, w.SettlementHash)
		}
		if !listed {
			amount := w.Amount
			if w.Payout != 0 {
				amount = w.Payout
			}
			record.CreditedPayouts = append(record.CreditedPayouts, addressCreditedPayout{NoteID: w.NoteID, Destination: w.Destination, Amount: amount, SettlementHash: strings.ToLower(w.SettlementHash)})
		}
	}
	record.Withdrawal = nil
}

// escapePayoutCredits reports the saved credited escape payouts whose
// destination the vault still credits. A destination whose credit reads zero
// was claimed since; its entries stay saved but are not reported.
func (h *FundingHandler) escapePayoutCredits(ctx context.Context, config fundingConfig, record *addressFundingRecord) ([]EscapePayoutCredit, error) {
	var credits []EscapePayoutCredit
	index := map[string]int{}
	for _, saved := range record.CreditedPayouts {
		destination := common.HexToAddress(saved.Destination).Hex()
		i, seen := index[destination]
		if !seen {
			amount, err := h.addressUintCall(ctx, config, config.Contract, "0x"+escapePayoutCreditsSelector+addressABIWord(strings.ToLower(destination)), "latest")
			if err != nil {
				return nil, err
			}
			i = -1
			if amount.Sign() > 0 {
				credits = append(credits, EscapePayoutCredit{Destination: destination, CreditedAmount: amount.String(), VaultAddress: common.HexToAddress(config.Contract).Hex(), ClaimCalldata: "0x" + claimEscapePayoutSelector + addressABIWord(strings.ToLower(destination))})
				i = len(credits) - 1
			}
			index[destination] = i
		}
		if i >= 0 {
			credits[i].NoteIDs = append(credits[i].NoteIDs, saved.NoteID)
			credits[i].TransactionHashes = append(credits[i].TransactionHashes, saved.SettlementHash)
		}
	}
	unit := config.BillingUnit
	if unit == "" {
		unit = "token units"
	}
	for i := range credits {
		c := &credits[i]
		notes := make([]string, len(c.NoteIDs))
		for j, id := range c.NoteIDs {
			notes[j] = fmt.Sprint(id)
		}
		c.Message = fmt.Sprintf("An earlier escape (note %[5]s) closed its note, but the vault could not deliver the payout to %[1]s, and it still holds a credit of %[2]s %[7]s for that address, so nothing has arrived there yet. Once %[1]s accepts a plain ETH transfer, anyone can deliver the credit, even while the vault is paused, by calling claimEscapePayout(%[1]s) (selector 0x%[6]s) on the vault %[3]s; the transaction's data is %[4]s.", c.Destination, c.CreditedAmount, c.VaultAddress, c.ClaimCalldata, strings.Join(notes, ", "), claimEscapePayoutSelector, unit)
	}
	return credits, nil
}

const withdrawalVerifyingMessage = "The withdrawal is final on Ethereum; waiting for the vault state and the zkAPI indexer to confirm the note is closed before finishing local bookkeeping."

// requireClearanceOwnershipCapability runs only before a companion reserves a
// note for a new withdrawal. Where the pinned deployment's server may require
// clearance ownership proofs, an older companion would reserve the note, fail
// clearance and leave inference paused, so refuse before any reservation.
func (h *FundingHandler) requireClearanceOwnershipCapability(ctx context.Context) error {
	required, err := h.client.clearanceOwnershipRequired()
	if err != nil {
		return err
	}
	if !required {
		return nil
	}
	raw, err := h.client.request(ctx, http.MethodGet, "/oa/v1/status", nil)
	if err != nil {
		return err
	}
	var capability struct {
		Version *int `json:"clearance_ownership_proof_version"`
	}
	if json.Unmarshal(raw, &capability) != nil || capability.Version == nil || *capability.Version < 1 {
		return errors.New("this deployment requires withdrawal clearance ownership proofs; update the zkAPI native bundle before withdrawing (nothing was reserved)")
	}
	return nil
}

// requireUnsettledRequestOverride refuses to forward the owner's
// acknowledgement to a companion that does not understand it.
func (h *FundingHandler) requireUnsettledRequestOverride(ctx context.Context) error {
	raw, err := h.client.request(ctx, http.MethodGet, "/oa/v1/status", nil)
	if err != nil {
		return err
	}
	var capability struct {
		Version *int `json:"unsettled_request_override_version"`
	}
	if json.Unmarshal(raw, &capability) != nil || capability.Version == nil || *capability.Version < 1 {
		return errors.New("this zkAPI native bundle cannot send an acknowledged ownership proof; update the native bundle (no ownership proof was sent)")
	}
	return nil
}

// errWithdrawalToVault refuses the deployment's own vault as a withdrawal
// destination. The vault cannot pay itself: a vault with vault_revision 2
// reverts InvalidDestination, and a legacy vault cannot receive the payout,
// so every close reverts. The companion's clearance is permanent and its
// reservation pins the destination, so the note could then only expire.
var errWithdrawalToVault = errors.New("withdrawal destination cannot be the zkAPI vault contract, which cannot receive its own payout")

// CheckWithdrawalDestination refuses the vault of this release's packaged
// deployment on chainID as a withdrawal destination, before any note is
// reserved for it.
func CheckWithdrawalDestination(chainID uint64, destination string) error {
	for _, network := range []string{"mainnet", "sepolia"} {
		if chain, _ := ChainID(network); chain != chainID {
			continue
		}
		deployment, _, err := deployedDeployment(network)
		if err == nil && isHex(destination, 20) && common.HexToAddress(destination) == common.HexToAddress(deployment.Contract) {
			return errWithdrawalToVault
		}
	}
	return nil
}

// NormalizeWithdrawalDestination rejects zero and bad mixed-case checksums.
// Lower/upper-case addresses remain accepted, as with standard Ethereum tools.
func NormalizeWithdrawalDestination(value string) (string, error) {
	if !isHex(value, 20) || common.HexToAddress(value) == (common.Address{}) {
		return "", errors.New("withdrawal destination must be a nonzero Ethereum address")
	}
	address := common.HexToAddress(value).Hex()
	body := value[2:]
	if body != strings.ToLower(body) && body != strings.ToUpper(body) && value != address {
		return "", errors.New("withdrawal destination has an invalid Ethereum checksum")
	}
	return address, nil
}

func (h *FundingHandler) AddressWithdrawal(ctx context.Context) (AddressWithdrawalStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, _, _, status, err := h.withdrawalSnapshot(ctx)
	return status, err
}

func (h *FundingHandler) withdrawalSnapshot(ctx context.Context) (fundingConfig, *addressFundingRecord, withdrawalWallet, AddressWithdrawalStatus, error) {
	return h.withdrawalSnapshotFor(ctx, false)
}

// withdrawalSnapshotFor is withdrawalSnapshot; with exit set (an escape), the
// chain is read only through the owner's exit RPC when one is configured
// (exitConfig).
func (h *FundingHandler) withdrawalSnapshotFor(ctx context.Context, exit bool) (fundingConfig, *addressFundingRecord, withdrawalWallet, AddressWithdrawalStatus, error) {
	config, record, payment, err := h.addressSnapshotFor(ctx, exit)
	status := AddressWithdrawalStatus{Address: payment.Address, ChainID: payment.ChainID, TokenAddress: payment.TokenAddress, TokenDecimals: payment.TokenDecimals, DeploymentID: payment.DeploymentID, BillingAsset: payment.BillingAsset, BillingUnit: payment.BillingUnit, WeiPerUnit: payment.WeiPerUnit, ETHBalance: payment.ETHBalance, EscapePayoutCredits: payment.EscapePayoutCredits}
	var wallet withdrawalWallet
	if err != nil {
		return config, record, wallet, status, err
	}
	raw, err := h.client.request(ctx, http.MethodGet, "/oa/v1/status", nil)
	var capability struct {
		Version int `json:"withdrawal_bridge_version"`
	}
	if err != nil {
		return config, record, wallet, status, err
	}
	if json.Unmarshal(raw, &capability) != nil || capability.Version != 1 {
		return config, record, wallet, status, errors.New("the companion needs the wallet-independent withdrawal bridge; update the native bundle")
	}
	raw, err = h.client.WalletStatus(ctx)
	if err != nil {
		return config, record, wallet, status, err
	}
	if json.Unmarshal(raw, &wallet) != nil || wallet.HasNote == nil || (*wallet.HasNote && (wallet.Note == nil || wallet.Note.NoteID > 0xffffffff)) {
		return config, record, wallet, status, errors.New("invalid companion withdrawal status")
	}
	status.Phase = "no_note"
	if *wallet.HasNote {
		status.NoteID, status.PrivateBalance, status.Amount = wallet.Note.NoteID, wallet.Note.Balance, wallet.Note.Balance
		status.NoteExpiry = wallet.Note.Expiry
		status.Phase = "ready"
		if wallet.Pending {
			status.Phase = "waiting_settlement"
		}
	}
	if withdrawal := record.Withdrawal; withdrawal != nil {
		status.NoteID, status.Amount, status.Destination = withdrawal.NoteID, withdrawal.Amount, withdrawal.Destination
		status.Phase, status.TransactionHash = withdrawal.Phase, withdrawal.TransactionHash
		if record.Pending != nil && record.Pending.Kind == "withdrawal" {
			status.TransactionHash = record.Pending.Hash
			status.ActualFeeWei = record.Pending.ActualFeeWei
		}
		if withdrawal.SettlementHash != "" {
			status.TransactionHash = withdrawal.SettlementHash
		}
		setEscapePayoutCredit(&status, withdrawal, config)
		setGaslessStatus(&status, withdrawal)
		if *wallet.HasNote && wallet.Note.NoteID != withdrawal.NoteID {
			status.Phase = "recovery_required"
		}
	} else if !*wallet.HasNote && payment.Phase == "recovery_required" {
		status.Phase = "recovery_required"
	}
	if status.ActualFeeWei == "" && record.Withdrawal != nil {
		for _, entry := range record.History {
			if strings.EqualFold(entry.Hash, record.Withdrawal.TransactionHash) {
				status.ActualFeeWei = entry.ActualFeeWei
			}
		}
	}
	if record.Withdrawal != nil && record.Withdrawal.Mode == "escape" && status.Phase != "recovery_required" {
		return config, record, wallet, escapeStatus(status, record, config), nil
	}
	setWithdrawalMessage(&status)
	return config, record, wallet, status, nil
}

func setEscapeMessage(status *AddressWithdrawalStatus) {
	if setGaslessMessage(status) {
		return
	}
	if status.Phase == "complete" && status.PayoutCredited {
		status.Message = fmt.Sprintf("The escape finalized and closed the note, but the vault could not deliver the payout to %[1]s and holds it as an escape payout credit. Once %[1]s accepts a plain ETH transfer, deliver it with zkapi-clientd withdraw --claim --to %[1]s (claimEscapePayout, selector 0x%[2]s, on the vault %[3]s; data %[4]s).", status.Destination, claimEscapePayoutSelector, status.VaultAddress, status.ClaimCalldata)
		return
	}
	payout := fmt.Sprintf("%d", status.Amount)
	switch status.Phase {
	case "escape_decision":
		status.Message = fmt.Sprintf("Escape decision (%s): the escape pays %s of the %d private balance and concedes %d (at most the state's bound %d). Review it, then confirm the concession: zkapi-clientd withdraw --escape --to %s --conceded %d.", status.Reason, payout, status.StateBalance, status.Conceded, status.BoundAtState, status.Destination, status.Conceded)
	case "escape_wait":
		status.Message = fmt.Sprintf("A request sent from the note's current state may still settle; the escape waits until %s (Unix %d). Rerun then, or exit early with --early-exit concede_nothing (the operator can raise the concession to the request's actual charge) or --early-exit concede_bound.", time.Unix(int64(status.WaitUntil), 0).UTC().Format(time.RFC3339), status.WaitUntil)
	case "quoted":
		status.Message = "The escape is proved and checked; review the fee quote and approve it to sign initiateEscapeWithdrawal."
	case "waiting_funds":
		status.Message = "The escape is proved. Send ETH for network fees to the local payment address, then rerun the same command."
	case "escape_pending":
		status.Message = "initiateEscapeWithdrawal is signed and awaiting Ethereum finality; new inference is paused."
	case "escape_initiated":
		if status.ChallengeDeadline != 0 && time.Now().Unix() > int64(status.ChallengeDeadline) {
			status.Message = fmt.Sprintf("The challenge period is over: request a fee quote for finalizeEscapeWithdrawal with zkapi-clientd withdraw --escape --to %s, then approve it. The payout is %s.", status.Destination, payout)
			break
		}
		status.Message = fmt.Sprintf("The escape is on chain. After the challenge deadline (Unix %d) rerun the same command to finalize it; the payout is %s unless the operator raises the concession, never by more than the state's bound.", status.ChallengeDeadline, payout)
	case "finalize_pending":
		status.Message = "finalizeEscapeWithdrawal is signed and awaiting Ethereum finality."
	case "reverted":
		status.Message = "The escape transaction reverted (for example its proof expired before inclusion). Rerun the same command to review a fresh escape."
	case "escape_expired":
		status.Message = "The signed escape transaction never reached a block and can no longer be included (its proof expired, or its nonce was taken or skipped); nothing was paid. Rerun the same command to review a fresh escape: it is proved and signed again."
	case "defeated":
		status.Message = "device_not_newest: the chain shows this escape defeated with a request from a newer state of this note; another device or backup holds that state. Exit from the newest state: restore the newest backup, or run zkapi-walletd exit-kit escape with the newest exit kit. Every rerun of zkapi-clientd withdraw --escape reads the chain again, and zkapi-clientd withdraw --escape --cancel clears this record once the chain shows the escape neither pending nor closed."
	case "complete":
		status.Message = fmt.Sprintf("The escape finalized and paid %s; the private note is closed.", payout)
		if status.ConcessionExceededBound {
			status.Message += " concession_exceeded_bound: the payout is below the state balance less the state's bound."
		}
	default:
		status.Message = "Escape recovery is required. Preserve the local payment and private-note files."
	}
}

// setEscapePayoutCredit reports a complete withdrawal whose escape payout the
// vault credited instead of paying, with the call that delivers it.
func setEscapePayoutCredit(status *AddressWithdrawalStatus, w *addressWithdrawalRecord, config fundingConfig) {
	status.PayoutCredited, status.VaultAddress, status.ClaimCalldata = false, "", ""
	if w == nil || !w.PayoutCredited || w.Phase != "complete" {
		return
	}
	status.PayoutCredited = true
	if w.PaymasterCredited && w.Transit != nil {
		status.PaymasterCredited, status.PaymasterAddress = true, w.Transit.Paymaster
		status.ClaimCalldata = w.transitClaimCalldata()
		return
	}
	status.VaultAddress = common.HexToAddress(config.Contract).Hex()
	status.ClaimCalldata = "0x" + claimEscapePayoutSelector + addressABIWord(strings.ToLower(w.Destination))
}

func setWithdrawalMessage(status *AddressWithdrawalStatus) {
	if status.Mode == "escape" {
		setEscapeMessage(status)
		return
	}
	if setGaslessMessage(status) {
		return
	}
	if status.Phase == "complete" && status.PayoutCredited {
		status.Message = fmt.Sprintf("An escape of this note finalized and closed it, but the vault could not deliver the payout to %[1]s: that address rejected the ETH or needed more than 100,000 gas to receive it. The vault holds the balance for that address as an escape payout credit, so nothing has arrived there yet. Once %[1]s accepts a plain ETH transfer, anyone can deliver the credit, even while the vault is paused, by calling claimEscapePayout(%[1]s) (selector 0x%[2]s) on the vault %[3]s; the transaction's data is %[4]s.", status.Destination, claimEscapePayoutSelector, status.VaultAddress, status.ClaimCalldata)
		return
	}
	switch status.Phase {
	case "ready":
		status.Message = "Withdraw the entire remaining private balance to an explicit Ethereum address. The local payment address pays network fees."
	case "no_note":
		status.Message = "There is no active private balance to withdraw."
	case "waiting_settlement":
		status.Message = "Wait for the outstanding inference to settle, then rerun the same withdrawal command."
	case "waiting_funds":
		status.Message = "Withdrawal is reserved. Send ETH for network fees to the local payment address, then rerun the same command."
	case "quoted":
		status.Message = "Withdrawal destination and full private balance are reserved; review a current fee quote and explicitly approve before signing."
	case "withdrawal_pending":
		status.Message = "Withdrawal is reserved or awaiting Ethereum finality. Resume with the same destination; new inference is paused."
	case "confirming":
		status.Message = "Withdrawal is finalized on Ethereum; resume to finish local recovery bookkeeping."
	case "complete":
		status.Message = "The remaining private balance was withdrawn and the private note is closed."
	case "reverted":
		status.Message = "The withdrawal transaction reverted and is finalized. Rerun explicitly to refresh its proof, or use --confirm with the transaction hash if the same payout was already relayed; inference remains paused."
	default:
		status.Message = "Withdrawal recovery is required. Preserve the local payment and private-note files."
	}
}

// setGaslessMessage writes the status message of a gasless withdrawal's
// phases (for a mutual close and an escape alike) and of a complete one
// whose payout waits in the transit account or in the paymaster; false when
// the phase is not a gasless one.
func setGaslessMessage(status *AddressWithdrawalStatus) bool {
	if status.TransitAccount == "" {
		return false
	}
	escape := status.Mode == "escape"
	command := "zkapi-clientd withdraw --to " + status.Destination
	if escape {
		command = "zkapi-clientd withdraw --escape --to " + status.Destination
	}
	switch status.Phase {
	case "op_built", "finalize_op_built", "forward_op_built":
		status.Message = fmt.Sprintf("The sponsored operation (%s) is signed and saved and is being sent to the bundler; the network fee is paid from the payout, not by the local signing address. Resume with %s.", status.UserOpHash, command)
	case "op_submitted", "finalize_op_submitted", "forward_op_submitted":
		status.Message = fmt.Sprintf("The sponsored operation (%s) was sent to the bundler and awaits inclusion and Ethereum finality; new inference is paused. Resume with %s.", status.UserOpHash, command)
		if status.TransactionHash != "" {
			status.Message = fmt.Sprintf("The sponsored operation (%s) is in transaction %s and awaits Ethereum finality. Resume with %s.", status.UserOpHash, status.TransactionHash, command)
		}
	case "op_reverted":
		status.Message = fmt.Sprintf("The sponsored operation (%s) was included in %s but reverted (%s). If another transaction closed the note first, the payout sits in the transit account %s: deliver it with zkapi-clientd withdraw --collect --to %s (sponsored) or --sweep --to %s (paid by the local signing address). Otherwise rerun %s to prove again.", status.UserOpHash, status.TransactionHash, status.GaslessRefusal, status.TransitAccount, status.Destination, status.Destination, command)
	case "gasless_refused":
		status.Message = fmt.Sprintf("The gasless path stopped: %s. Rerun %s to try again, or add --fees wallet to pay the fee from the local signing address; the payout then reaches the transit account %s and zkapi-clientd withdraw --sweep --to %s delivers it.", status.GaslessRefusal, command, status.TransitAccount, status.Destination)
		if status.FundsWaitingInTransit {
			status.Message = fmt.Sprintf("The gasless path stopped: %s. The payout waits in the transit account %s: deliver it with zkapi-clientd withdraw --collect --to %s (sponsored) or --sweep --to %s (paid by the local signing address).", status.GaslessRefusal, status.TransitAccount, status.Destination, status.Destination)
		}
	case "complete":
		switch {
		case status.PaymasterCredited:
			status.Message = fmt.Sprintf("The sponsored withdrawal closed the note, but the payout could not be pushed to %[1]s (it rejected the ETH or needed more than 100,000 gas), so the paymaster %[2]s holds it as a credit; nothing has arrived at %[1]s yet. Once %[1]s accepts a plain ETH transfer, anyone can deliver it with zkapi-clientd withdraw --claim-credit --to %[1]s (claimCredit(%[1]s) on the paymaster; data %[3]s).", status.Destination, status.PaymasterAddress, status.ClaimCalldata)
		case status.FundsWaitingInTransit:
			status.Message = fmt.Sprintf("The private note is closed, and the payout waits in the transit account %s. Deliver it to %s with zkapi-clientd withdraw --sweep --to %s (paid by the local signing address), or with zkapi-clientd withdraw --collect --to %s (a sponsored operation; the fee is taken from the payout) when the paymaster holds evidence for a sponsored forward (a sponsored operation of this withdrawal was included and reverted, or another transaction finalized its sponsored escape).", status.TransitAccount, status.Destination, status.Destination, status.Destination)
			if status.GaslessRefusal != "" {
				status.Message = fmt.Sprintf("The sponsored forward stopped: %s. ", status.GaslessRefusal) + status.Message
			}
		case status.ReceivedWei != "":
			status.Message = fmt.Sprintf("The private note is closed; %s received %s wei after a sponsored network fee of %s wei (and %s wei of earlier debt).", status.Destination, status.ReceivedWei, status.ChargedWei, status.OwedPaidWei)
			if escape {
				status.Message = fmt.Sprintf("The escape finalized and closed the note; %s received %s wei after a sponsored network fee of %s wei (and %s wei of earlier debt).", status.Destination, status.ReceivedWei, status.ChargedWei, status.OwedPaidWei)
			}
			if status.ConcessionExceededBound {
				status.Message += " concession_exceeded_bound: the payout is below the state balance less the state's bound."
			}
		default:
			return false
		}
	default:
		return false
	}
	return true
}

func (h *FundingHandler) WithdrawAddress(ctx context.Context, destination string, noteID uint64, retryHashes ...string) (AddressWithdrawalStatus, error) {
	destination, err := NormalizeWithdrawalDestination(destination)
	if err != nil {
		return AddressWithdrawalStatus{}, err
	}
	retryHash, confirmationHash := "", ""
	if len(retryHashes) > 2 {
		return AddressWithdrawalStatus{}, errors.New("invalid withdrawal retry authorization")
	}
	if len(retryHashes) >= 1 {
		retryHash = retryHashes[0]
	}
	if len(retryHashes) == 2 {
		confirmationHash = retryHashes[1]
	}
	if retryHash != "" && !isHex(retryHash, 32) {
		return AddressWithdrawalStatus{}, errors.New("invalid withdrawal retry transaction hash")
	}
	if confirmationHash != "" && (!isHex(confirmationHash, 32) || retryHash != "") {
		return AddressWithdrawalStatus{}, errors.New("withdrawal confirmation requires a valid transaction hash and cannot also retry a transaction")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	config, record, wallet, status, err := h.withdrawalSnapshot(ctx)
	if err != nil {
		return status, err
	}
	if status.NoteID != noteID {
		return status, errors.New("the selected private note has changed; run a new withdrawal command to authorize the current balance")
	}
	update := func() AddressWithdrawalStatus {
		if w := record.Withdrawal; w != nil && w.Mode == "escape" {
			return escapeStatus(status, record, config)
		}
		if w := record.Withdrawal; w != nil {
			status.NoteID, status.Amount, status.Destination = w.NoteID, w.Amount, w.Destination
			status.Phase, status.TransactionHash = w.Phase, w.TransactionHash
			if record.Pending != nil && record.Pending.Kind == "withdrawal" {
				status.TransactionHash = record.Pending.Hash
				status.ActualFeeWei = record.Pending.ActualFeeWei
			}
			if w.SettlementHash != "" {
				status.TransactionHash = w.SettlementHash
			}
		}
		setEscapePayoutCredit(&status, record.Withdrawal, config)
		setGaslessStatus(&status, record.Withdrawal)
		if record.Withdrawal != nil && record.Pending == nil {
			for _, entry := range record.History {
				if strings.EqualFold(entry.Hash, record.Withdrawal.TransactionHash) {
					status.ActualFeeWei = entry.ActualFeeWei
				}
			}
		}
		setWithdrawalMessage(&status)
		return status
	}
	if status.Phase == "recovery_required" {
		return status, errors.New("the saved withdrawal does not match the active note; preserve recovery files")
	}
	options := withdrawalOptions(ctx)
	transitAction := options.Collect || options.Sweep || options.ClaimCredit
	capabilityChecked := false
	if record.Withdrawal != nil {
		if !strings.EqualFold(record.Withdrawal.Destination, destination) {
			return status, errors.New("a withdrawal destination is already saved; resume with that same destination")
		}
		if record.Withdrawal.Phase == "complete" && !transitAction && (record.Pending == nil || !transitKinds[record.Pending.Kind]) {
			return status, nil
		}
		forwardInFlight := record.Withdrawal.UserOp != nil && record.Withdrawal.UserOp.Kind == "forward" && (record.Withdrawal.Phase == "forward_op_built" || record.Withdrawal.Phase == "forward_op_submitted")
		if record.Withdrawal.Mode == "escape" && !transitAction && !forwardInFlight && (record.Pending == nil || !transitKinds[record.Pending.Kind]) {
			return status, errors.New("an escape of this note is under way; follow it with zkapi-clientd withdraw --escape --to " + record.Withdrawal.Destination)
		}
	} else {
		if retryHash != "" || confirmationHash != "" {
			return status, errors.New("there is no saved withdrawal attempt to retry or confirm")
		}
		if common.HexToAddress(destination) == common.HexToAddress(config.Contract) {
			return status, errWithdrawalToVault
		}
		if !*wallet.HasNote {
			return status, nil
		}
		if record.Pending != nil && (record.Pending.Kind != "deposit" || record.Phase != "active") {
			return status, errors.New("finish the saved deposit before withdrawing")
		}
		if transitAction {
			return status, errors.New("there is no saved gasless withdrawal with a transit account to collect, sweep or claim from")
		}
		if err := h.requireClearanceOwnershipCapability(ctx); err != nil {
			return status, err
		}
		capabilityChecked = true
		// Design 3.3: with --fees payout the proof will bind a transit
		// account, so the gasless pre-flight (the pins, the bundler, the
		// paymaster's policy and the fee against the current balance) runs
		// before anything is reserved; a refusal leaves nothing saved.
		var transit *addressTransit
		proofDestination := ""
		payeeHasCode := false
		if options.Fees == "payout" {
			if payeeHasCode, err = h.gaslessPrepareCheck(ctx, config, options, gaslessKindClose, wallet.Note.Balance, destination); err != nil {
				return status, err
			}
			profile, _, err := h.gaslessProfile()
			if err != nil {
				return status, err
			}
			if transit, err = h.newTransit(ctx, config, profile, destination); err != nil {
				return status, err
			}
			proofDestination = transit.Account
		}
		// One atomic save transfers the finalized deposit into nonce history
		// and records intent, before asking the companion to reserve clearance.
		if record.Pending != nil {
			record.History = append(record.History, *record.Pending)
			record.Pending = nil
		}
		record.Withdrawal = &addressWithdrawalRecord{NoteID: wallet.Note.NoteID, Destination: destination, Phase: "quoted"}
		if transit != nil {
			record.Withdrawal.FeePayer, record.Withdrawal.ProofDestination, record.Withdrawal.Transit = "payout", proofDestination, transit
			record.Withdrawal.PayeeHasCode = payeeHasCode
			record.Withdrawal.StartBlock = h.latestBlock(ctx, config.exitConfig())
		}
		record.Phase = "withdrawal_pending"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
	}
	w := record.Withdrawal
	// The fee mode of a saved gasless withdrawal: --fees wallet falls back to
	// a wallet-paid call bound to the transit account (then --sweep delivers
	// the payout) while no operation is in flight; --fees payout cannot be
	// added to a reservation made for the payout address.
	if w.Transit != nil && options.Fees == "wallet" && w.FeePayer == "payout" {
		switch w.Phase {
		case "quoted", "waiting_settlement", "gasless_refused", "op_reverted":
			// A dropped operation the bundler included after all closed the
			// note: it is followed, never replaced by a wallet-paid close
			// (which would revert and pay gas) nor forgotten.
			if late, err := h.lateGaslessOperation(ctx, config, record); err != nil {
				return update(), err
			} else if late {
				return h.resumeGaslessClose(ctx, config, record, update)
			}
			// The bundle transaction of a reverted operation is not this
			// wallet-paid close's: the record starts clean, as a retry does.
			w.FeePayer, w.UserOp, w.GaslessRefusal, w.TransactionHash = "wallet", nil, "", ""
			w.Phase = "quoted"
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
		default:
			return update(), errors.New("a sponsored operation is in flight; resume it before changing how the fee is paid")
		}
	}
	// The reverse: --fees payout on a close the owner fell back to paying
	// from the wallet, while nothing is signed. The sponsored path takes the
	// close over again after its pre-flight.
	if w.Transit != nil && options.Fees == "payout" && w.FeePayer == "wallet" && w.Phase != "complete" && !transitAction {
		if record.Pending != nil {
			return update(), errors.New("a wallet-paid transaction is pending; follow it before changing how the fee is paid")
		}
		switch w.Phase {
		case "quoted", "waiting_funds", "waiting_settlement":
			if _, _, err := h.recordProfile(w); err != nil {
				return update(), err
			}
			if _, _, err := h.gaslessPreflight(ctx, config, options, gaslessKindClose); err != nil {
				return update(), err
			}
			w.FeePayer, w.Phase = "payout", "quoted"
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
		default:
			return update(), errors.New("the wallet-paid close is under way; follow it with --fees wallet")
		}
	}
	if w.Transit == nil && options.Fees == "payout" && w.Phase != "complete" {
		return update(), errors.New("this withdrawal is reserved for the payout address with a wallet-paid fee; finish it with --fees wallet (a gasless withdrawal needs a fresh reservation)")
	}
	if transitAction {
		return h.transitAction(ctx, config, record, options, update)
	}
	if record.Pending != nil && transitKinds[record.Pending.Kind] {
		if err := h.followTransitTransaction(ctx, config, record); err != nil {
			return update(), err
		}
		return update(), nil
	}
	if w.Phase == "complete" {
		return update(), nil
	}
	// An operation in flight is followed whatever pays the fee now: a
	// forward of the transit account's balance is sponsored after a
	// wallet-paid close bound to it as well.
	if w.UserOp != nil {
		switch w.Phase {
		case "op_built", "op_submitted", "withdrawal_pending", "confirming":
			if mode := quoteMode(ctx); mode != nil && mode.Capture != nil {
				return update(), errors.New("recover the sponsored operation before requesting a new quote")
			}
			return h.resumeGaslessClose(ctx, config, record, update)
		case "forward_op_built", "forward_op_submitted":
			return h.resumeForward(ctx, config, record, update)
		case "op_reverted":
			// Like a reverted transaction, a reverted operation is proved
			// again only when the command names its hash.
			if retryHash == "" || (!strings.EqualFold(retryHash, w.UserOp.Hash) && !strings.EqualFold(retryHash, w.UserOp.IncludedHash)) {
				return update(), nil
			}
			retryHash = ""
			w.UserOp, w.Phase, w.TransactionHash, w.GaslessRefusal = nil, "quoted", "", ""
		case "gasless_refused":
			// A dropped operation the bundler included after all is
			// followed; otherwise the close is proved again.
			if late, err := h.lateUserOperation(ctx, config, record); err != nil {
				return update(), err
			} else if late {
				return h.resumeGaslessClose(ctx, config, record, update)
			}
			w.UserOp, w.Phase, w.TransactionHash, w.GaslessRefusal = nil, "quoted", "", ""
		}
	} else if w.Transit != nil && w.Phase == "gasless_refused" {
		w.Phase, w.GaslessRefusal = "quoted", ""
	}
	// Payout evidence comes from the pinned RPC. The vault and indexer must
	// also show the note closed before the companion deletes its state; while
	// they do not, a saved withdrawal keeps polling and an explicit alternate
	// confirmation reports why nothing changed.
	closeUnconfirmed := func(err error) (AddressWithdrawalStatus, error) {
		if errors.Is(err, errWithdrawalVerificationPending) && (w.Phase == "withdrawal_pending" || w.Phase == "confirming") {
			next := update()
			next.Message = withdrawalVerifyingMessage
			return next, nil
		}
		return update(), err
	}
	var retrying *addressTransaction
	if w.SettlementHash != "" {
		if retryHash != "" || (confirmationHash != "" && !strings.EqualFold(confirmationHash, w.SettlementHash)) {
			return update(), errors.New("a relayed payout is already saved; resume the same withdrawal without changing its transaction")
		}
		confirmationHash = w.SettlementHash
	} else if confirmationHash != "" && w.Phase != "reverted" {
		return update(), errors.New("alternate payout confirmation requires a finalized reverted local withdrawal; check its status first")
	}
	if retryHash != "" && (w.Phase != "reverted" || record.Pending == nil || !strings.EqualFold(retryHash, record.Pending.Hash)) {
		return update(), errors.New("the failed withdrawal attempt has changed; check status before retrying")
	}
	if confirmationHash != "" && (record.Pending == nil || record.Pending.Kind != "withdrawal" || strings.EqualFold(confirmationHash, record.Pending.Hash)) {
		return update(), errors.New("alternate payout confirmation must name a distinct transaction for the saved withdrawal")
	}
	if mode := quoteMode(ctx); mode != nil && mode.Capture != nil && record.Pending != nil && retryHash == "" {
		return update(), errors.New("recover the signed withdrawal before requesting a new quote")
	}
	if record.Pending != nil {
		if record.Pending.Kind != "withdrawal" {
			return update(), errors.New("unexpected pending payment during withdrawal; preserve recovery files")
		}
		receipt, final, err := h.addressFinalReceipt(ctx, config, record.Pending.Hash, true)
		if err != nil {
			return update(), err
		}
		if !final {
			if mode := quoteMode(ctx); mode != nil && mode.Capture != nil {
				return update(), errors.New("recover the signed withdrawal before requesting a new quote")
			}
			if confirmationHash != "" {
				return update(), errors.New("the local withdrawal must have a canonical finalized revert before an alternate payout can be confirmed")
			}
			if receipt == nil {
				h.broadcastAddress(ctx, config, record.Pending)
			}
			return update(), nil
		}
		if err := recordAddressActualFee(record.Pending, receipt); err != nil {
			return update(), err
		}
		if confirmationHash != "" {
			// Only a finalized local failure consumes this signer's nonce. An
			// unrelated relayer's success alone cannot retire our signed bytes.
			if receipt.Status != "0x0" {
				return update(), errors.New("the local withdrawal has no finalized revert; an alternate payout cannot replace it")
			}
			alternate, alternateFinal, err := h.addressFinalReceipt(ctx, config, confirmationHash, true)
			if err != nil {
				return update(), err
			}
			if !alternateFinal {
				return update(), errors.New("the alternate payout is missing or not finalized; the saved withdrawal has not changed")
			}
			payout, err := validateWithdrawalReceipt(alternate, config, w, true)
			if err != nil {
				return update(), err
			}
			if payout.EscapePaid != nil {
				if err := h.checkRelayedEscapePayout(ctx, config, w, *payout.EscapePaid, alternate); err != nil {
					return update(), err
				}
				w.Payout = *payout.EscapePaid
			}
			if err := h.corroborateWithdrawalClosed(ctx, config, w.NoteID, alternate); err != nil {
				return closeUnconfirmed(err)
			}
			if err := h.completeAddressWithdrawal(ctx, config, record, confirmationHash, true, payout.Credited); err != nil {
				return update(), err
			}
			status.PrivateBalance = 0
			return update(), nil
		}
		if receipt.Status == "0x0" {
			if w.Phase != "reverted" || retryHash == "" {
				w.Phase = "reverted"
				if err := h.saveAddress(record); err != nil {
					return update(), err
				}
				return update(), nil
			}
			// Continuation polls never carry retry authorization. A fresh CLI
			// invocation must name this exact failed hash, so a second polling
			// client cannot silently turn another client's revert into a retry.
			// Keep the failed attempt eligible for independently relayed
			// payout confirmation until a replacement is durably signed.
			// Proof generation or simulation can fail because it already paid.
			retrying = record.Pending
		} else {
			payout, err := validateWithdrawalReceipt(receipt, config, w, false)
			if err != nil {
				return update(), err
			}
			if err := h.corroborateWithdrawalClosed(ctx, config, w.NoteID, receipt); err != nil {
				return closeUnconfirmed(err)
			}
			if err := h.completeAddressWithdrawal(ctx, config, record, record.Pending.Hash, false, payout.Credited); err != nil {
				return update(), err
			}
			status.PrivateBalance = 0
			return update(), nil
		}
	}
	if !*wallet.HasNote {
		return update(), errors.New("the reserved private note is missing; restore its recovery state")
	}
	// Until a proof plan has been bound, this prepare call is what creates the
	// companion's reservation and requests clearance.
	if w.Binding == "" && !capabilityChecked {
		if err := h.requireClearanceOwnershipCapability(ctx); err != nil {
			return update(), err
		}
	}
	prepare := map[string]any{"destination": w.proofDestination()}
	if mode := quoteMode(ctx); mode != nil && mode.AcceptUnsettledRequestRisk {
		if err := h.requireUnsettledRequestOverride(ctx); err != nil {
			return update(), err
		}
		prepare["accept_unsettled_request_risk"] = true
	}
	body, _ := json.Marshal(prepare)
	raw, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/prepare", body)
	if err != nil {
		var bridge *Error
		if errors.As(err, &bridge) && bridge.Code == "pending_settlement" {
			if retrying != nil {
				return update(), err
			}
			w.Phase = "waiting_settlement"
			if saveErr := h.saveAddress(record); saveErr != nil {
				return update(), saveErr
			}
			return update(), nil
		}
		return update(), err
	}
	var plan withdrawalPlan
	if json.Unmarshal(raw, &plan) != nil {
		return update(), errors.New("invalid withdrawal proof response")
	}
	data, binding, err := withdrawalCalldata(plan, config, w, wallet.Note.Balance, time.Now())
	if err != nil {
		return update(), err
	}
	// Independently bind the proof to the companion's durable reservation,
	// rather than trusting a pre-prepare balance that may just have settled.
	raw, err = h.client.request(ctx, http.MethodGet, "/oa/v1/withdraw/status", nil)
	if err != nil {
		return update(), err
	}
	var reserved withdrawalBridgeStatus
	expected := *w
	expected.Amount, expected.Nullifier = plan.PublicInputs.FinalBalance, "0x"+addressABIWord(plan.PublicInputs.Nullifier)
	if json.Unmarshal(raw, &reserved) != nil || reserved.Phase != "reserved" || !withdrawalStatusMatches(reserved, &expected) {
		return update(), errors.New("withdrawal proof does not match its saved reservation")
	}
	w.Amount, w.Nullifier, w.Binding, w.Phase = expected.Amount, expected.Nullifier, binding, "quoted"
	if retrying != nil {
		w.Phase = "reverted"
	}
	if err := h.saveAddress(record); err != nil {
		return update(), err
	}
	if w.FeePayer == "payout" {
		// Design 3.3: the sponsored operation replaces the wallet-paid
		// transaction; a refusal of the gasless path is journaled with its
		// reason, and the wallet path stays available.
		vaultCall, _ := hex.DecodeString(data[2:])
		if err := h.submitUserOperation(ctx, config, record, gaslessKindClose, vaultCall); err != nil {
			if code := GaslessRefusalCode(err); code != "" {
				w.Phase, w.GaslessRefusal = "gasless_refused", err.Error()
				if saveErr := h.saveAddress(record); saveErr != nil {
					return update(), saveErr
				}
			}
			return update(), err
		}
		return update(), nil
	}
	if mode := quoteMode(ctx); mode != nil && mode.Capture != nil && retrying != nil {
		// Keep the finalized failed transaction in the durable journal while
		// quoting its explicitly requested replacement. No nonce is released.
		err := h.signAddressTransaction(ctx, config, record, "withdrawal", config.Contract, data)
		return update(), err
	}

	if retrying != nil {
		failed := *retrying
		failed.FinalizedRevert = true
		record.History = append(record.History, failed)
		record.Pending = nil
		// This in-memory transition is committed only with the replacement
		// signed transaction by signAddressTransaction's atomic save.
	}
	if err := h.signAddressTransaction(ctx, config, record, "withdrawal", config.Contract, data); err != nil {
		if retrying != nil && record.Pending == nil {
			record.History = record.History[:len(record.History)-1]
			record.Pending = retrying
			w.Phase = "reverted"
			// No replacement was created. The durable journal still contains
			// this exact reverted attempt, including when gas is insufficient.
			return update(), err
		}
		if errors.Is(err, errAddressNeedsETH) {
			w.Phase = "waiting_funds"
			if saveErr := h.saveAddress(record); saveErr != nil {
				return update(), saveErr
			}
			next := update()
			next.Message = err.Error()
			return next, nil
		}
		return update(), err
	}
	return update(), nil
}

// Call only after checking exact, canonical, finalized payout evidence. Save
// its identity before companion confirmation so an uncertain response resumes
// confirmation rather than signing another withdrawal or releasing the nonce.
// credited marks a relayed escape whose payout the vault credited instead of
// paying; the companion's own reading of the same receipt can only add that
// mark. Our own signed mutual close pays in full or reverts.
func (h *FundingHandler) completeAddressWithdrawal(ctx context.Context, config fundingConfig, record *addressFundingRecord, settlementHash string, localReverted, credited bool) error {
	w := record.Withdrawal
	w.Phase, w.TransactionHash = "confirming", record.Pending.Hash
	if localReverted {
		w.SettlementHash = strings.ToLower(settlementHash)
	}
	w.PayoutCredited = localReverted && credited
	if err := h.saveAddress(record); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"transaction_hash": settlementHash})
	raw, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/confirm", body)
	if err != nil {
		return err
	}
	var confirmed withdrawalBridgeStatus
	if json.Unmarshal(raw, &confirmed) != nil || !withdrawalStatusMatches(confirmed, w) || confirmed.Phase != "complete" || !strings.EqualFold(confirmed.TransactionHash, settlementHash) {
		return errors.New("invalid withdrawal confirmation; preserve the saved transaction")
	}
	w.PayoutCredited = localReverted && (w.PayoutCredited || confirmed.EscapePayoutCredited)
	// A payout to the transit account (a wallet-paid call bound to S after a
	// gasless prepare) waits there for --collect or --sweep.
	w.FundsWaitingInTransit = w.ProofDestination != "" && !w.PayoutCredited
	if err := h.archiveWithdrawnDeposit(config, record); err != nil {
		return err
	}
	retired := *record.Pending
	retired.FinalizedRevert = localReverted
	record.History = append(record.History, retired)
	record.Pending, record.Amount, record.Commitment, record.Phase = nil, 0, "", "ready"
	w.Phase = "complete"
	return h.saveAddress(record)
}

func withdrawalStatusMatches(status withdrawalBridgeStatus, record *addressWithdrawalRecord) bool {
	amount, ok := new(big.Int).SetString(status.FinalBalance, 10)
	return ok && amount.IsUint64() && amount.Uint64() == record.Amount && status.NoteID == record.NoteID && strings.EqualFold(status.Destination, record.proofDestination()) && isField(status.Nullifier) && strings.EqualFold(addressABIWord(status.Nullifier), addressABIWord(record.Nullifier))
}

// withdrawalCalldata builds mutualClose calldata from the companion's plan
// and checks it against the authorized note, destination and balance, with
// valid_until in the signing window at now.
func withdrawalCalldata(plan withdrawalPlan, config fundingConfig, saved *addressWithdrawalRecord, previousBalance uint64, now time.Time) (string, string, error) {
	p := plan.PublicInputs
	invalid := errors.New("withdrawal proof does not match the authorized note, destination, balance, or deployment")
	if plan.Mode != "mutual" || p.Kind != 1 || p.Conceded != 0 || !isField(p.NextNullifier) || addressABIWord(p.NextNullifier) != strings.Repeat("0", 64) || p.ProtocolVersion != 2 || p.ChainID != config.ChainID || !isField(p.Contract) || !strings.EqualFold(addressABIWord(p.Contract), addressABIWord(config.Contract)) || p.NoteID != saved.NoteID || p.NoteID > 0xffffffff || len(p.Destination) != 20 || !strings.EqualFold(common.BytesToAddress(p.Destination).Hex(), saved.proofDestination()) || p.FinalBalance > previousBalance || plan.Proof.Backend != "groth16_bn254" {
		return "", "", invalid
	}
	words, proof, err := withdrawalWords(p, plan.Proof.Proof, saved.proofDestination())
	if err != nil {
		return "", "", invalid
	}
	binding := withdrawalBinding(words)
	if saved.Binding != "" && (saved.Binding != binding || saved.Amount != p.FinalBalance || !strings.EqualFold(addressABIWord(saved.Nullifier), addressABIWord(p.Nullifier))) {
		return "", "", invalid
	}
	data := "0x" + withdrawalSelector + strings.Join(words, "") + fmt.Sprintf("%064x%064x", 17*32, len(proof)) + hex.EncodeToString(proof)
	raw, _ := hex.DecodeString(data[2:])
	expected := *saved
	expected.Amount, expected.Nullifier, expected.Binding = p.FinalBalance, "0x"+addressABIWord(p.Nullifier), binding
	if err := validateSignedWithdrawal(raw, config, &expected, now); err != nil {
		return "", "", invalid
	}
	return data, binding, nil
}

// withdrawalWords is the 16 tuple words of p, with destination as the
// payout address, and the 256 proof bytes.
func withdrawalWords(p withdrawalInputs, encodedProof, destination string) ([]string, []byte, error) {
	proof, err := base64.StdEncoding.DecodeString(encodedProof)
	if err != nil || len(proof) != 256 {
		return nil, nil, errors.New("invalid proof")
	}
	for _, field := range []string{p.ActiveRoot, p.StateKeyX, p.StateKeyY, p.ClearanceKeyX, p.ClearanceKeyY, p.Nullifier, p.NextNullifier} {
		if !isField(field) {
			return nil, nil, errors.New("invalid field")
		}
	}
	words := []string{fmt.Sprintf("%064x", p.ProtocolVersion), fmt.Sprintf("%064x", p.ChainID), addressABIWord(p.Contract), addressABIWord(p.ActiveRoot), addressABIWord(p.StateKeyX), addressABIWord(p.StateKeyY), addressABIWord(p.ClearanceKeyX), addressABIWord(p.ClearanceKeyY), fmt.Sprintf("%064x", p.NoteID), fmt.Sprintf("%064x", p.FinalBalance), addressABIWord(destination), addressABIWord(p.Nullifier), fmt.Sprintf("%064x", p.Kind), addressABIWord(p.NextNullifier), fmt.Sprintf("%064x", p.Conceded), fmt.Sprintf("%064x", p.ValidUntil)}
	for i := range words {
		words[i] = strings.ToLower(words[i])
	}
	return words, proof, nil
}

// withdrawalBinding is the keccak of the 16 tuple words with the root (word
// 3) and valid_until (word 15) blanked: a re-proof at another root or with a
// fresh lifetime keeps every other public input of the authorized exit.
func withdrawalBinding(words []string) string {
	bound := append([]string{}, words[:16]...)
	bound[3], bound[15] = "", ""
	return crypto.Keccak256Hash([]byte(strings.Join(bound, ""))).Hex()
}

// withdrawalPayout is what a matching payout receipt shows.
type withdrawalPayout struct {
	// Credited: the receipt's escape closed the note, but the vault could
	// not push the balance to the destination and credited it to
	// escapePayoutCredits(destination) instead (EscapePayoutDeferred for
	// this note and destination). Nothing reached the destination yet.
	Credited bool
	// EscapePaid is the amount a relayed escape paid, which the caller
	// matches (checkRelayedEscapePayout).
	EscapePaid *uint64
}

func validateWithdrawalReceipt(receipt *addressReceipt, config fundingConfig, saved *addressWithdrawalRecord, relayed bool) (withdrawalPayout, error) {
	// An independently relayed payout can call the vault through a wrapper.
	// Its exact authenticated vault event is the payout evidence; the outer
	// recipient remains bound to the vault for our own signed transaction.
	// Only a relayed payout may be a finalized escape of the same reserved
	// state, which pays the reserved balance less its concession, possibly
	// raised (design §6.4 E5): its amount is returned for the caller to match.
	if receipt.Status == "0x1" && (relayed || strings.EqualFold(receipt.To, config.Contract)) {
		matches, credited := 0, false
		var escapePaid *uint64
		noteTopic := fmt.Sprintf("0x%064x", saved.NoteID)
		for _, log := range receipt.Logs {
			if log.Removed || !strings.EqualFold(log.Address, config.Contract) {
				continue
			}
			// Whatever amount it names, a deferral for this note and
			// destination means the destination was not paid. Only an
			// escape, and so only a relayed payout, can be credited.
			if len(log.Topics) == 3 && strings.EqualFold(log.Topics[0], escapePayoutDeferredEventTopic) && strings.EqualFold(log.Topics[1], noteTopic) && strings.EqualFold(log.Topics[2], "0x"+addressABIWord(saved.proofDestination())) {
				credited = relayed
				continue
			}
			mutual := len(log.Topics) == 2 && strings.EqualFold(log.Topics[0], withdrawalEventTopic)
			escape := len(log.Topics) == 2 && relayed && strings.EqualFold(log.Topics[0], escapeFinalizedEventTopic)
			if !(mutual || escape) || !strings.EqualFold(log.Topics[1], noteTopic) || !isHex(log.Data, 96) {
				continue
			}
			data := strings.TrimPrefix(log.Data, "0x")
			if !strings.EqualFold(data[:64], addressABIWord(saved.Nullifier)) || !strings.EqualFold(data[128:], addressABIWord(saved.proofDestination())) {
				continue
			}
			amount, ok := new(big.Int).SetString(data[64:128], 16)
			if !ok || !amount.IsUint64() {
				continue
			}
			if mutual && amount.Uint64() == saved.Amount {
				matches++
			} else if escape && amount.Uint64() <= saved.Amount {
				paid := amount.Uint64()
				escapePaid = &paid
				matches++
			}
		}
		if matches == 1 {
			return withdrawalPayout{Credited: credited, EscapePaid: escapePaid}, nil
		}
	}
	return withdrawalPayout{}, errors.New("finalized receipt does not match the saved withdrawal; preserve recovery files")
}

var escapeConcessionRecordedTopic = crypto.Keccak256Hash([]byte("EscapeConcessionRecorded(uint32,uint256,uint128,uint128)")).Hex()

// checkRelayedEscapePayout matches a relayed escape's payout of the reserved
// state (E5): the latest EscapeConcessionRecorded of the note gives its state
// balance, which must be the reserved balance, and its initial concession;
// EscapeConcessionRaised logs give every raise.
func (h *FundingHandler) checkRelayedEscapePayout(ctx context.Context, config fundingConfig, w *addressWithdrawalRecord, paid uint64, receipt *addressReceipt) error {
	if paid == w.Amount {
		return nil
	}
	mismatch := errors.New("the relayed escape payout matches neither the reserved balance nor its recorded concession and raises; preserve recovery files")
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() {
		return mismatch
	}
	deployment, _, err := deployedDeployment(h.client.config.Network)
	if err != nil {
		return err
	}
	var logs []struct {
		Address string   `json:"address"`
		Topics  []string `json:"topics"`
		Data    string   `json:"data"`
		Removed bool     `json:"removed"`
	}
	filter := map[string]any{"address": config.Contract, "fromBlock": fmt.Sprintf("0x%x", deployment.DeployBlock), "toBlock": receipt.BlockNumber, "topics": []string{escapeConcessionRecordedTopic, fmt.Sprintf("0x%064x", w.NoteID)}}
	if err := h.addressRPC(ctx, config, "eth_getLogs", []any{filter}, &logs); err != nil {
		return err
	}
	var stateBalance, concededAtInit *big.Int
	for _, log := range logs {
		if log.Removed || !strings.EqualFold(log.Address, config.Contract) || !isHex(log.Data, 96) {
			continue
		}
		data := strings.TrimPrefix(log.Data, "0x")
		stateBalance, _ = new(big.Int).SetString(data[64:128], 16)
		concededAtInit, _ = new(big.Int).SetString(data[128:192], 16)
	}
	if stateBalance == nil || concededAtInit == nil || !stateBalance.IsUint64() || !concededAtInit.IsUint64() || stateBalance.Uint64() != w.Amount {
		return mismatch
	}
	raises, err := h.escapeRaises(ctx, config, w.NoteID, w.Nullifier, deployment.DeployBlock, block.Uint64())
	if err != nil {
		return err
	}
	if !matchEscapePayout(paid, stateBalance.Uint64(), concededAtInit.Uint64(), raises, nil).Matches {
		return mismatch
	}
	return nil
}

// validateSignedWithdrawal checks signed mutualClose calldata against the
// saved authorization: 836 bytes; the fixed words 0, 1, 2, 8, 9, 10 and 11;
// kind 1 with no successor nullifier and no concession; the bytes offset and
// length; and the binding over the 16 tuple words with words 3 and 15
// blanked. With a nonzero now (before signing), valid_until (word 15) must
// also lie in [now, now + 10,800 + 300].
func validateSignedWithdrawal(data []byte, config fundingConfig, saved *addressWithdrawalRecord, now time.Time) error {
	invalid := errors.New("signed withdrawal does not match its saved authorization; preserve recovery files")
	if saved == nil || len(data) != withdrawalCalldataLength || hex.EncodeToString(data[:4]) != withdrawalSelector || saved.Binding == "" || !isHex(saved.Nullifier, 32) {
		return invalid
	}
	words := make([]string, 18)
	for i := range words {
		words[i] = hex.EncodeToString(data[4+i*32 : 4+(i+1)*32])
	}
	zero := strings.Repeat("0", 64)
	expected := map[int]string{0: fmt.Sprintf("%064x", 2), 1: fmt.Sprintf("%064x", config.ChainID), 2: addressABIWord(config.Contract), 8: fmt.Sprintf("%064x", saved.NoteID), 9: fmt.Sprintf("%064x", saved.Amount), 10: addressABIWord(saved.proofDestination()), 11: addressABIWord(saved.Nullifier), 12: fmt.Sprintf("%064x", 1), 13: zero, 14: zero, 16: fmt.Sprintf("%064x", 17*32), 17: fmt.Sprintf("%064x", 256)}
	for index, value := range expected {
		if !strings.EqualFold(words[index], value) {
			return invalid
		}
	}
	if !now.IsZero() && !validUntilInWindow(words[15], now) {
		return invalid
	}
	if withdrawalBinding(words) != saved.Binding {
		return invalid
	}
	return nil
}

// validUntilInWindow reports whether the valid_until word lies in
// [now, now + 10,800 + 300].
func validUntilInWindow(word string, now time.Time) bool {
	validUntil, ok := new(big.Int).SetString(word, 16)
	current := now.Unix()
	return ok && validUntil.IsInt64() && validUntil.Int64() >= current && validUntil.Int64() <= current+exitProofValidity+exitProofClockAllowance
}

func (h *FundingHandler) archiveWithdrawnDeposit(config fundingConfig, record *addressFundingRecord) error {
	deposit, err := h.readAddressDeposit(config)
	if err != nil {
		return err
	}
	if deposit == nil {
		return nil
	} // A prior confirmation may have archived it.
	if !deposit.Active || (record.Commitment != "" && !strings.EqualFold(record.Commitment, deposit.Commitment)) || (record.Amount != 0 && record.Amount != deposit.Amount) {
		return errors.New("withdrawal cannot archive unrelated deposit recovery data")
	}
	info, err := os.Lstat(h.statePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("deposit recovery file is not private; preserve it")
	}
	archive := h.statePath + ".withdrawn-" + strings.TrimPrefix(record.Pending.Hash, "0x")
	if _, err := os.Lstat(archive); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("withdrawn deposit archive already exists; preserve recovery files")
	}
	if err := os.Rename(h.statePath, archive); err != nil {
		return errors.New("cannot archive withdrawn deposit recovery data")
	}
	directory, err := os.Open(filepath.Dir(h.statePath))
	if err != nil {
		return errors.New("cannot sync withdrawn deposit archive")
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return errors.New("cannot sync withdrawn deposit archive")
	}
	return nil
}

// Legacy capability endpoints share the same lifecycle: a companion that has
// already closed its note must not accept a new deposit until Go finishes the
// old withdrawal's bookkeeping, even if that last local write was interrupted.
func (h *FundingHandler) checkWithdrawalFunding(config fundingConfig) error {
	if _, err := os.Lstat(h.addressStatePath()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("cannot read withdrawal recovery data")
	}
	record, err := h.loadAddress(config)
	if err != nil {
		return err
	}
	if record.Withdrawal != nil && record.Withdrawal.Phase != "complete" {
		return errors.New("finish the saved withdrawal before funding a new private balance")
	}
	if record.Withdrawal != nil && record.Withdrawal.waitingPayout() {
		return errWithdrawalPayoutWaiting
	}
	return nil
}

// errWithdrawalPayoutWaiting refuses a new deposit while a gasless
// withdrawal's payout waits in the transit account or the paymaster: a new
// deposit retires the record, with the transit account and its key.
var errWithdrawalPayoutWaiting = errors.New("deliver the completed withdrawal's payout first (zkapi-clientd withdraw --collect, --sweep or --claim-credit with its destination) before funding a new private balance")

// waitingPayout reports a complete gasless withdrawal whose payout has not
// reached the payout address yet.
func (w *addressWithdrawalRecord) waitingPayout() bool {
	return w != nil && w.Phase == "complete" && w.Transit != nil && (w.FundsWaitingInTransit || w.PaymasterCredited)
}

// Called only by deposit confirmation after the exact new note's receipt and
// companion activation have been checked. This also covers legacy deposits.
func (h *FundingHandler) adoptPostWithdrawalDeposit(config fundingConfig, deposit depositRecord, noteID uint32) error {
	if _, err := os.Lstat(h.addressStatePath()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("cannot read withdrawal recovery data")
	}
	record, err := h.loadAddress(config)
	if err != nil {
		return err
	}
	if record.Withdrawal == nil {
		return nil
	}
	if record.Withdrawal.Phase != "complete" || record.Withdrawal.NoteID == uint64(noteID) {
		return errors.New("a closed note cannot be activated again")
	}
	if record.Pending != nil {
		return errors.New("a saved transaction must be recovered before adopting a new note")
	}
	retireWithdrawal(record)
	record.Phase, record.Amount, record.Commitment = "active", deposit.Amount, deposit.Commitment
	return h.saveAddress(record)
}
