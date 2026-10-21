package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// The escape withdrawal (design §6.4 E4–E6, §6.7): an exit that needs no
// operator. The companion decides what the escape concedes under the exit
// rules and proves it; the owner confirms that concession; Go checks the
// calldata word by word and signs initiateEscapeWithdrawal, then, after the
// challenge period, finalizeEscapeWithdrawal, and claimEscapePayout when the
// vault credited the payout. Every transaction goes through the same
// quote-and-approve signing path as the mutual close, and through the
// owner's exit RPC when one is configured.

var escapeSelector = hex.EncodeToString(crypto.Keccak256([]byte("initiateEscapeWithdrawal(" + withdrawalTuple + ",bytes)"))[:4])

const finalizeEscapeSelector = "ff8f5585"

// escapeKinds are the signed transaction kinds of an escape.
var escapeKinds = map[string]bool{"escape": true, "escape_finalize": true, "escape_claim": true}

// escapeGasLimits sign an escape transaction whose simulation failed (E4
// step 5: advisory): above each entry point's measured cost (initiation
// about 0.6M gas, finalization at most about 0.2M, a credit claim far less).
var escapeGasLimits = map[string]uint64{"escape": 900_000, "escape_finalize": 350_000, "escape_claim": 150_000}

// escapePlan is the companion's /oa/v1/withdraw/escape/prepare answer.
type escapePlan struct {
	Status       string           `json:"status"`
	Action       string           `json:"action"`
	NoteID       uint64           `json:"note_id"`
	StateBalance string           `json:"state_balance"`
	Conceded     string           `json:"conceded"`
	BoundAtState string           `json:"bound_at_state"`
	Payout       string           `json:"payout"`
	Reason       string           `json:"reason"`
	WaitUntil    uint64           `json:"wait_until"`
	ValidUntil   uint64           `json:"valid_until"`
	PublicInputs withdrawalInputs `json:"public_inputs"`
	Proof        struct {
		Backend string `json:"backend"`
		Proof   string `json:"proof"`
	} `json:"proof"`
	Warnings []string `json:"warnings"`
}

// escapeChainStatus is the companion's /oa/v1/withdraw/escape/status answer.
// Trusted marks a reading through the owner's exit RPC; without one every
// reading is the pinned RPC's, which the operator may run (design §2.1).
// DefeatChecked marks a reading that read the escape's defeat logs at a
// finalized block: one whose logs did not load reports the phase
// "unknown", untrusted, and decides nothing.
type escapeChainStatus struct {
	Phase             string `json:"phase"`
	Payout            string `json:"payout"`
	Conceded          string `json:"conceded"`
	ChallengeDeadline uint64 `json:"challenge_deadline"`
	Error             string `json:"error"`
	Trusted           bool   `json:"trusted"`
	DefeatChecked     bool   `json:"defeat_checked"`
	Record            *struct {
		StartBlock uint64 `json:"start_block"`
	} `json:"record"`
}

// escapeChain reads the companion's view of the saved escape on chain.
func (h *FundingHandler) escapeChain(ctx context.Context) (escapeChainStatus, error) {
	var chain escapeChainStatus
	raw, err := h.client.request(ctx, http.MethodGet, "/oa/v1/withdraw/escape/status", nil)
	if err != nil {
		return chain, err
	}
	if json.Unmarshal(raw, &chain) != nil {
		return chain, errors.New("invalid escape status from the companion")
	}
	return chain, nil
}

func parseUnits(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("invalid amount in the escape plan")
	}
	return parsed, nil
}

// escapeCalldata builds initiateEscapeWithdrawal calldata from the
// companion's plan and checks it against the owner's confirmation in saved.
func escapeCalldata(plan escapePlan, config fundingConfig, saved *addressWithdrawalRecord, now time.Time) (string, *addressWithdrawalRecord, error) {
	p := plan.PublicInputs
	invalid := errors.New("escape proof does not match the confirmed note, destination, balance, concession or deployment")
	if plan.Status != "prepared" || p.Kind != 0 || p.ProtocolVersion != 2 || p.ChainID != config.ChainID || !isField(p.Contract) || !strings.EqualFold(addressABIWord(p.Contract), addressABIWord(config.Contract)) || p.NoteID != saved.NoteID || p.NoteID > 0xffffffff || len(p.Destination) != 20 || !strings.EqualFold(common.BytesToAddress(p.Destination).Hex(), saved.proofDestination()) || plan.Proof.Backend != "groth16_bn254" {
		return "", nil, invalid
	}
	stateBalance, err := parseUnits(plan.StateBalance)
	if err != nil || stateBalance != saved.StateBalance || p.Conceded != saved.Conceded || p.FinalBalance+p.Conceded != stateBalance || p.FinalBalance > stateBalance {
		return "", nil, invalid
	}
	words, proof, err := withdrawalWords(p, plan.Proof.Proof, saved.proofDestination())
	if err != nil {
		return "", nil, invalid
	}
	binding := withdrawalBinding(words)
	if saved.Binding != "" && (saved.Binding != binding || !strings.EqualFold(addressABIWord(saved.Nullifier), addressABIWord(p.Nullifier))) {
		return "", nil, invalid
	}
	data := "0x" + escapeSelector + strings.Join(words, "") + fmt.Sprintf("%064x%064x", 17*32, len(proof)) + hex.EncodeToString(proof)
	raw, _ := hex.DecodeString(data[2:])
	expected := *saved
	expected.Amount, expected.Nullifier, expected.NextNullifier, expected.Binding = p.FinalBalance, "0x"+addressABIWord(p.Nullifier), "0x"+addressABIWord(p.NextNullifier), binding
	expected.ValidUntil = p.ValidUntil
	if err := validateSignedEscape(raw, config, &expected, now); err != nil {
		return "", nil, invalid
	}
	return data, &expected, nil
}

// validateSignedEscape checks signed initiateEscapeWithdrawal calldata
// against the saved, owner-confirmed escape: 836 bytes; the fixed words 0,
// 1, 2, 8, 9, 10 and 11; kind 0 (word 12); a successor nullifier (word 13)
// that is set, differs from the nullifier and is the saved one; the
// confirmed concession (word 14), at most the bound unless zero; payout plus
// concession equal to the state balance; the bytes offset and length; and
// the binding over the 16 tuple words with the root and valid_until blanked.
// With a nonzero now (before signing), valid_until must lie in
// [now, now + 10,800 + 300].
func validateSignedEscape(data []byte, config fundingConfig, saved *addressWithdrawalRecord, now time.Time) error {
	invalid := errors.New("signed escape does not match its confirmed authorization; preserve recovery files")
	if saved == nil || saved.Mode != "escape" || len(data) != withdrawalCalldataLength || hex.EncodeToString(data[:4]) != escapeSelector || saved.Binding == "" || !isHex(saved.Nullifier, 32) || !isHex(saved.NextNullifier, 32) {
		return invalid
	}
	words := make([]string, 18)
	for i := range words {
		words[i] = hex.EncodeToString(data[4+i*32 : 4+(i+1)*32])
	}
	expected := map[int]string{0: fmt.Sprintf("%064x", 2), 1: fmt.Sprintf("%064x", config.ChainID), 2: addressABIWord(config.Contract), 8: fmt.Sprintf("%064x", saved.NoteID), 9: fmt.Sprintf("%064x", saved.Amount), 10: addressABIWord(saved.proofDestination()), 11: addressABIWord(saved.Nullifier), 12: strings.Repeat("0", 64), 13: addressABIWord(saved.NextNullifier), 14: fmt.Sprintf("%064x", saved.Conceded), 16: fmt.Sprintf("%064x", 17*32), 17: fmt.Sprintf("%064x", 256)}
	for index, value := range expected {
		if !strings.EqualFold(words[index], value) {
			return invalid
		}
	}
	if words[13] == strings.Repeat("0", 64) || strings.EqualFold(words[13], words[11]) {
		return invalid
	}
	if saved.Amount+saved.Conceded != saved.StateBalance || saved.Amount > saved.StateBalance {
		return invalid
	}
	if saved.Conceded != 0 && saved.Conceded > saved.Bound {
		return invalid
	}
	if !now.IsZero() && !validUntilInWindow(words[15], now) {
		return invalid
	}
	// The signed bytes carry exactly the proved lifetime.
	if saved.ValidUntil != 0 && words[15] != fmt.Sprintf("%064x", saved.ValidUntil) {
		return invalid
	}
	if withdrawalBinding(words) != saved.Binding {
		return invalid
	}
	return nil
}

func finalizeEscapeCalldata(noteID uint64) string {
	return fmt.Sprintf("0x%s%064x", finalizeEscapeSelector, noteID)
}

func claimEscapeCalldata(destination string) string {
	return "0x" + claimEscapePayoutSelector + addressABIWord(strings.ToLower(destination))
}

// EscapeAddress advances the escape of the note noteID to destination. With
// conceded nil it only asks the companion for the exit decision and saves it
// for the owner's review (phase escape_decision, or escape_wait while E3
// waits for a released request). With the concession the owner confirmed, it
// has the escape proved, checks it and signs initiateEscapeWithdrawal (under
// a quote approval); later calls follow it on chain, sign
// finalizeEscapeWithdrawal after the challenge period and close the record.
// earlyExit is "", "concede_nothing" or "concede_bound" (E3 forced exit).
func (h *FundingHandler) EscapeAddress(ctx context.Context, destination string, noteID uint64, conceded *uint64, earlyExit string) (AddressWithdrawalStatus, error) {
	destination, err := NormalizeWithdrawalDestination(destination)
	if err != nil {
		return AddressWithdrawalStatus{}, err
	}
	if earlyExit != "" && earlyExit != "concede_nothing" && earlyExit != "concede_bound" {
		return AddressWithdrawalStatus{}, errors.New("early exit must be concede_nothing or concede_bound")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	config, record, wallet, status, err := h.withdrawalSnapshotFor(ctx, true)
	if err != nil {
		return status, err
	}
	update := func() AddressWithdrawalStatus {
		return escapeStatus(status, record, config)
	}
	if status.Phase == "recovery_required" {
		return update(), errors.New("the saved withdrawal does not match the active note; preserve recovery files")
	}
	w := record.Withdrawal
	options := withdrawalOptions(ctx)
	if w != nil && w.Phase == "complete" {
		if !strings.EqualFold(w.Destination, destination) {
			return update(), errors.New("the completed withdrawal went to its saved destination")
		}
		// A finalized escape whose payout sits in the transit account (a
		// third party finalized it): the sponsored forward is quoted now.
		if w.Transit != nil && w.FundsWaitingInTransit && quoteMode(ctx) != nil {
			return h.transitAction(ctx, config, record, addressWithdrawalOptions{Collect: true, BundlerURL: options.BundlerURL, FeeCapGwei: options.FeeCapGwei, AllowExpensiveGas: options.AllowExpensiveGas}, update)
		}
		return update(), nil
	}
	if status.NoteID != noteID {
		return update(), errors.New("the selected private note has changed; review the escape again")
	}
	if common.HexToAddress(destination) == common.HexToAddress(config.Contract) {
		return update(), errWithdrawalToVault
	}
	switch {
	case w == nil:
		if !*wallet.HasNote {
			return update(), errors.New("there is no private balance to withdraw")
		}
		if record.Pending != nil && (record.Pending.Kind != "deposit" || record.Phase != "active") {
			return update(), errors.New("finish the saved deposit before withdrawing")
		}
		w = &addressWithdrawalRecord{NoteID: noteID, Destination: destination, Mode: "escape", Phase: "escape_decision"}
		// initiationRefused is a paymaster that sponsors no escape
		// initiation (escapes disabled, the published default) while a
		// sponsored finalization passes its pre-flight: the escape is still
		// reserved for the transit account, so --fees wallet initiates it
		// bound to that account and --fees payout, once it is on chain,
		// finalizes it sponsored and forwards the payout.
		var initiationRefused error
		if options.Fees == "payout" {
			// Design 3.3: the gasless pre-flight runs before the companion
			// reserves the exit for the transit account.
			payeeHasCode, err := h.gaslessPrepareCheck(ctx, config, options, gaslessKindEscape, wallet.Note.Balance, destination)
			if GaslessRefusalCode(err) == "escapes_disabled" {
				initiationRefused = err
				if payeeHasCode, err = h.gaslessPrepareCheck(ctx, config, options, gaslessKindFinalize, wallet.Note.Balance, destination); err != nil {
					// Nothing is reserved: the escape is wallet-paid
					// throughout, bound to the payout address.
					return update(), refuse("escapes_disabled", "the paymaster does not sponsor escape initiations, and a sponsored finalization is not available either (%v); use --fees wallet, which pays both the initiation and the finalization from the local signing address", err)
				}
			}
			if err != nil {
				return update(), err
			}
			profile, _, err := h.gaslessProfile()
			if err != nil {
				return update(), err
			}
			transit, err := h.newTransit(ctx, config, profile, destination)
			if err != nil {
				return update(), err
			}
			w.FeePayer, w.ProofDestination, w.Transit, w.PayeeHasCode = "payout", transit.Account, transit, payeeHasCode
		}
		if record.Pending != nil {
			record.History = append(record.History, *record.Pending)
			record.Pending = nil
		}
		record.Withdrawal, record.Phase = w, "withdrawal_pending"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		if initiationRefused != nil {
			return update(), initiationRefused
		}
	case w.Mode != "escape":
		// A mutual close the companion could not complete turns into an
		// escape to the same destination, unless its signed close may still
		// land. A close whose revert is final (for example one mined after
		// its valid_until, ProofExpired, or behind an owner's pause) can
		// no longer pay: it moves to the history and the escape proceeds.
		if record.Pending != nil && record.Pending.Kind == "withdrawal" {
			receipt, final, err := h.addressFinalReceipt(ctx, config, record.Pending.Hash, true)
			if err != nil {
				return update(), err
			}
			if !final || receipt == nil || receipt.Status != "0x0" {
				return update(), errors.New("a signed mutual close is pending; finish it with zkapi-clientd withdraw --resume")
			}
			if err := recordAddressActualFee(record.Pending, receipt); err != nil {
				return update(), err
			}
			retired := *record.Pending
			retired.FinalizedRevert = true
			record.History = append(record.History, retired)
			record.Pending = nil
		}
		if !strings.EqualFold(w.Destination, destination) {
			return update(), errors.New("a withdrawal destination is already saved; escape to that same destination")
		}
		if w.UserOp != nil && w.Phase != "op_reverted" && w.Phase != "gasless_refused" {
			return update(), errors.New("a sponsored close operation is in flight; finish it with zkapi-clientd withdraw --to " + w.Destination)
		}
		// A close operation the bundler dropped (gasless_refused) may still
		// be included until its valid_until: looked for first, as before
		// every other fallback that discards it. Found, the note is closed
		// and paid by that close, which is followed (under a quote request,
		// refused with the resume command) instead of becoming an escape.
		if late, err := h.lateGaslessOperation(ctx, config, record); err != nil {
			return update(), err
		} else if late {
			return h.resumeGaslessClose(ctx, config, record, update)
		}
		// The reservation (and so a transit account the proof binds) stays.
		*w = addressWithdrawalRecord{NoteID: w.NoteID, Destination: w.Destination, Mode: "escape", Phase: "escape_decision", FeePayer: w.FeePayer, ProofDestination: w.ProofDestination, Transit: w.Transit, StartBlock: w.StartBlock}
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
	default:
		if !strings.EqualFold(w.Destination, destination) {
			return update(), errors.New("an escape destination is already saved; resume with that same destination")
		}
	}
	// The fee mode of a saved gasless escape: --fees wallet falls back to
	// wallet-paid transactions bound to the transit account while no
	// operation is in flight.
	if w.Transit != nil && options.Fees == "wallet" && w.FeePayer == "payout" {
		switch w.Phase {
		case "escape_decision", "escape_wait", "quoted", "reverted", "escape_expired", "gasless_refused", "op_reverted", "escape_initiated", "defeated":
			// A dropped operation the bundler included after all is
			// followed, never replaced by a wallet-paid transaction nor
			// forgotten.
			if late, err := h.lateGaslessOperation(ctx, config, record); err != nil {
				return update(), err
			} else if late && w.InitiateHash != "" {
				return h.resumeGaslessFinalize(ctx, config, record, update)
			} else if late {
				return h.resumeGaslessEscapeInitiation(ctx, config, record, update)
			}
			w.FeePayer, w.UserOp, w.GaslessRefusal = "wallet", nil, ""
			// The bundle transaction of a reverted operation is not the
			// escape's: the record shows the initiation on chain, or none.
			w.TransactionHash = w.InitiateHash
			if w.Phase == "gasless_refused" || w.Phase == "op_reverted" {
				w.Phase = "escape_decision"
				if w.InitiateHash != "" {
					w.Phase = "escape_initiated"
				}
			}
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
		default:
			return update(), errors.New("a sponsored operation is in flight; resume it before changing how the fee is paid")
		}
	}
	// The reverse: --fees payout on an escape the owner pays from the wallet
	// (an initiation the paymaster does not sponsor, say, bound to the
	// transit account). While no transaction is pending the sponsored path
	// takes over the next step after its pre-flight: the finalization of an
	// escape on chain, else the initiation.
	if w.Transit != nil && options.Fees == "payout" && w.FeePayer == "wallet" {
		if record.Pending != nil {
			return update(), errors.New("a wallet-paid escape transaction is pending; follow it before changing how the fee is paid")
		}
		switch w.Phase {
		case "escape_decision", "escape_wait", "quoted", "waiting_funds", "reverted", "escape_expired", "escape_initiated", "defeated":
			kind := gaslessKindEscape
			if w.InitiateHash != "" {
				kind = gaslessKindFinalize
			}
			if _, _, err := h.recordProfile(w); err != nil {
				return update(), err
			}
			if _, _, err := h.gaslessPreflight(ctx, config, options, kind); err != nil {
				return update(), err
			}
			w.FeePayer = "payout"
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
		default:
			return update(), errors.New("the wallet-paid escape step is under way; follow it with --fees wallet")
		}
	}
	if w.Transit == nil && options.Fees == "payout" {
		return update(), errors.New("this escape is reserved for the payout address with a wallet-paid fee; finish it with --fees wallet (a gasless escape needs a fresh reservation)")
	}
	if record.Pending != nil && escapeKinds[record.Pending.Kind] {
		return h.followEscapeTransaction(ctx, config, record, update)
	}
	if record.Pending != nil && transitKinds[record.Pending.Kind] {
		if err := h.followTransitTransaction(ctx, config, record); err != nil {
			return update(), err
		}
		return update(), nil
	}
	if record.Pending != nil {
		return update(), errors.New("unexpected pending payment during an escape; preserve recovery files")
	}
	// An operation in flight is followed whatever pays the fee now (a
	// forward after the wallet fallback included).
	if w.UserOp != nil {
		switch w.Phase {
		case "op_built", "op_submitted", "escape_pending":
			if mode := quoteMode(ctx); mode != nil && mode.Capture != nil {
				return update(), errors.New("recover the sponsored operation before requesting a new quote")
			}
			return h.resumeGaslessEscapeInitiation(ctx, config, record, update)
		case "finalize_op_built", "finalize_op_submitted", "finalize_pending":
			if mode := quoteMode(ctx); mode != nil && mode.Capture != nil {
				return update(), errors.New("recover the sponsored operation before requesting a new quote")
			}
			return h.resumeGaslessFinalize(ctx, config, record, update)
		case "forward_op_built", "forward_op_submitted":
			return h.resumeForward(ctx, config, record, update)
		}
	}
	switch w.Phase {
	case "escape_initiated", "defeated":
		// A defeat is never final on one reading: it is asked again on
		// every run, through the exit RPC once one is configured.
		return h.finalizeEscape(ctx, config, record, update)
	case "op_reverted", "gasless_refused":
		if w.Phase == "gasless_refused" {
			// A dropped operation the bundler included after all is
			// followed.
			if late, err := h.lateUserOperation(ctx, config, record); err != nil {
				return update(), err
			} else if late && w.InitiateHash != "" {
				return h.resumeGaslessFinalize(ctx, config, record, update)
			} else if late {
				return h.resumeGaslessEscapeInitiation(ctx, config, record, update)
			}
		}
		if w.InitiateHash != "" {
			// The finalization's operation failed or was refused: the escape
			// is still on chain and is looked at again.
			w.UserOp, w.Phase, w.GaslessRefusal, w.TransactionHash = nil, "escape_initiated", "", w.InitiateHash
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
			return h.finalizeEscape(ctx, config, record, update)
		}
		// The initiation's operation failed or was refused: the decision is
		// reviewed and proved again (like a reverted initiation).
		w.UserOp, w.GaslessRefusal, w.TransactionHash = nil, "", ""
		w.Phase = "reverted"
		w.Binding = ""
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
	}
	// No escape transaction is live: decide, or prove and sign. The companion
	// reserves the exit for the proof's destination (the transit account of
	// a gasless escape).
	body := map[string]any{"destination": w.proofDestination()}
	if earlyExit != "" {
		body["early_exit"] = earlyExit
	}
	if conceded != nil {
		if w.Phase != "escape_decision" && w.Phase != "quoted" && w.Phase != "waiting_funds" && w.Phase != "reverted" && w.Phase != "escape_expired" && w.Phase != "gasless_refused" {
			return update(), errors.New("review the escape decision before confirming a concession")
		}
		if *conceded != w.Conceded || w.StateBalance == 0 {
			return update(), errors.New("the confirmed concession is not the one the escape decision showed; review it again")
		}
		// No proof is released unless it is signed under a fee quote.
		if quoteMode(ctx) == nil {
			return update(), errors.New("the escape is signed under an approved fee quote; request one with the confirmed concession")
		}
		body["conceded"] = strconv.FormatUint(*conceded, 10)
	}
	encoded, _ := json.Marshal(body)
	raw, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/escape/prepare", encoded)
	if err != nil {
		return update(), err
	}
	var plan escapePlan
	if json.Unmarshal(raw, &plan) != nil {
		return update(), errors.New("invalid escape decision from the companion")
	}
	switch plan.Status {
	case "wait":
		w.Phase, w.WaitUntil = "escape_wait", plan.WaitUntil
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return update(), nil
	case "decision":
		stateBalance, e1 := parseUnits(plan.StateBalance)
		proposed, e2 := parseUnits(plan.Conceded)
		bound, e3 := parseUnits(plan.BoundAtState)
		if e1 != nil || e2 != nil || e3 != nil || proposed > stateBalance || (proposed != 0 && proposed > bound) || plan.NoteID != noteID {
			return update(), errors.New("invalid escape decision from the companion")
		}
		w.Phase, w.StateBalance, w.Conceded, w.Bound, w.Reason, w.Amount, w.WaitUntil = "escape_decision", stateBalance, proposed, bound, plan.Reason, stateBalance-proposed, 0
		w.Binding, w.Nullifier, w.NextNullifier = "", "", ""
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return update(), nil
	case "prepared":
	default:
		return update(), errors.New("invalid escape answer from the companion")
	}
	if conceded == nil {
		// A plan the companion already made for this state is handed out
		// again; the owner still confirms its concession first.
		stateBalance, e1 := parseUnits(plan.StateBalance)
		bound, e2 := parseUnits(plan.BoundAtState)
		if e1 != nil || e2 != nil || plan.PublicInputs.Conceded > stateBalance {
			return update(), errors.New("invalid escape plan from the companion")
		}
		w.Phase, w.StateBalance, w.Conceded, w.Bound, w.Reason, w.Amount = "escape_decision", stateBalance, plan.PublicInputs.Conceded, bound, plan.Reason, stateBalance-plan.PublicInputs.Conceded
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return update(), nil
	}
	data, expected, err := escapeCalldata(plan, config, w, time.Now())
	if err != nil {
		return update(), err
	}
	w.Amount, w.Nullifier, w.NextNullifier, w.Binding, w.ValidUntil = expected.Amount, expected.Nullifier, expected.NextNullifier, expected.Binding, expected.ValidUntil
	w.Phase = "quoted"
	if mode := quoteMode(ctx); mode == nil || mode.Capture == nil {
		w.StartBlock = h.latestBlock(ctx, config)
	}
	if err := h.saveAddress(record); err != nil {
		return update(), err
	}
	if w.FeePayer == "payout" {
		vaultCall, _ := hex.DecodeString(data[2:])
		if err := h.submitUserOperation(ctx, config, record, gaslessKindEscape, vaultCall); err != nil {
			if GaslessRefusalCode(err) != "" {
				w.Phase, w.GaslessRefusal = "gasless_refused", err.Error()
				if saveErr := h.saveAddress(record); saveErr != nil {
					return update(), saveErr
				}
			}
			return update(), err
		}
		return update(), nil
	}
	if err := h.signAddressTransaction(ctx, config, record, "escape", config.Contract, data); err != nil {
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
	if record.Pending != nil && record.Pending.Kind == "escape" {
		h.reportEscapeSubmission(ctx, record.Pending.Hash)
	}
	return update(), nil
}

// resumeGaslessEscapeInitiation follows the sponsored initiation: once its
// bundle transaction is final and successful the escape is on chain, the
// companion is told the transaction and the initiation's charge is recorded
// as the transit account's debt.
func (h *FundingHandler) resumeGaslessEscapeInitiation(ctx context.Context, config fundingConfig, record *addressFundingRecord, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	outcome, err := h.followUserOperation(ctx, config, record)
	if err != nil {
		return update(), err
	}
	if outcome.Hash != "" {
		h.reportEscapeSubmission(ctx, outcome.Hash)
	}
	if !outcome.Included || !outcome.Success {
		return update(), nil
	}
	env, err := h.followEnvironment(ctx, config, record)
	if err != nil {
		return update(), err
	}
	if settlement := parsePaymasterSettlement(outcome.Receipt, env.paymaster, env.account, env.payee); settlement.Found {
		w.InitiationDebtWei = settlement.Charged.String()
	}
	w.Phase, w.InitiateHash, w.TransactionHash = "escape_initiated", strings.ToLower(outcome.Hash), strings.ToLower(outcome.Hash)
	if err := h.saveAddress(record); err != nil {
		return update(), err
	}
	return h.finalizeEscape(ctx, config, record, update)
}

// resumeGaslessFinalize follows the sponsored finalization; one that
// reverted (someone else may have finalized first) is looked at again.
func (h *FundingHandler) resumeGaslessFinalize(ctx context.Context, config fundingConfig, record *addressFundingRecord, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	outcome, err := h.followUserOperation(ctx, config, record)
	if err != nil {
		return update(), err
	}
	if !outcome.Included {
		return update(), nil
	}
	if !outcome.Success {
		w.UserOp, w.Phase, w.GaslessRefusal, w.TransactionHash = nil, "escape_initiated", "", w.InitiateHash
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return h.finalizeEscape(ctx, config, record, update)
	}
	return h.completeEscape(ctx, config, record, outcome.Hash, outcome.Receipt, update)
}

// CancelAddressEscape cancels an escape that released no exit proof (design
// §6.4 E6, "no kind-0 or kind-1 proof was released and the user cancels"):
// the companion removes its exit lock, so chats resume (except from a state
// whose ownership proof was sent), and the saved escape decision is
// cleared. It is refused once an escape transaction is signed, and by the
// companion while a released proof may still land; that lock is released
// only when the proof is dead or the note closes. A defeated escape is
// cleared too, once the chain (read again now) shows it neither pending
// nor closed: it can pay nothing, and its record would otherwise block
// every later exit of the note.
func (h *FundingHandler) CancelAddressEscape(ctx context.Context) (AddressWithdrawalStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, record, _, status, err := h.withdrawalSnapshotFor(ctx, true)
	if err != nil {
		return status, err
	}
	w := record.Withdrawal
	if record.Pending != nil && escapeKinds[record.Pending.Kind] {
		return status, errors.New("an escape transaction is signed; it cannot be cancelled, only followed with zkapi-clientd withdraw --escape")
	}
	if w != nil && w.Mode == "escape" {
		switch w.Phase {
		case "escape_pending", "escape_initiated", "finalize_pending", "complete":
			return status, errors.New("this escape is on chain; it cannot be cancelled")
		case "defeated":
			chain, err := h.escapeChain(ctx)
			if err != nil {
				return status, err
			}
			if chain.Phase == "pending" || chain.Phase == "closed" {
				return status, errors.New("this escape is on chain; it cannot be cancelled")
			}
		}
	}
	if _, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/escape/cancel", []byte("{}")); err != nil {
		return status, err
	}
	if w != nil && w.Mode == "escape" {
		record.Withdrawal = nil
		if record.Phase == "withdrawal_pending" {
			record.Phase = "active"
		}
		if err := h.saveAddress(record); err != nil {
			return status, err
		}
	}
	status.Phase, status.Mode, status.Message = "cancelled", "", "The escape was cancelled; no exit proof was released. Chats can resume from this note."
	return status, nil
}

// latestBlock is the latest block number, 0 when it cannot be read; raises
// are scanned from it.
func (h *FundingHandler) latestBlock(ctx context.Context, config fundingConfig) uint64 {
	number, err := h.addressQuantity(ctx, config, "eth_blockNumber", []any{})
	if err != nil || !number.IsUint64() {
		return 0
	}
	return number.Uint64()
}

// reportEscapeSubmission tells the companion which transaction carries its
// escape proof; a failure is retried on the next poll.
func (h *FundingHandler) reportEscapeSubmission(ctx context.Context, hash string) {
	body, _ := json.Marshal(map[string]string{"transaction_hash": hash})
	_, _ = h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/escape/submit", body)
}

// stuckEscapeGrace is how long a signed escape transaction whose nonce lies
// beyond the account's pending nonce may wait for that gap to fill.
var stuckEscapeGrace = 15 * time.Minute

// deadEscapeTransaction reports why the pending escape transaction, which
// has no receipt, can no longer be included, or "" while it still may be
// (design §6.4 E4 step 7: "If valid_until passes before inclusion,
// re-prove"). It reads the escape's RPC (the exit RPC when one is set):
//   - nonce_consumed: another transaction took its nonce in a finalized
//     block;
//   - nonce_gap: its nonce lies beyond the account's pending nonce (nothing
//     this client signed fills the gap; for example an RPC answered a wrong
//     nonce when it was signed) for stuckEscapeGrace;
//   - expired: an initiation whose valid_until is behind the latest block.
//
// The receipt is read again after the nonces, so a transaction mined in
// between is followed, never retired. A read that fails decides nothing.
func (h *FundingHandler) deadEscapeTransaction(ctx context.Context, config fundingConfig, record *addressFundingRecord) string {
	pending, w := record.Pending, record.Withdrawal
	finalized, e1 := h.addressQuantity(ctx, config, "eth_getTransactionCount", []any{record.Address, "finalized"})
	next, e2 := h.addressQuantity(ctx, config, "eth_getTransactionCount", []any{record.Address, "pending"})
	var latest struct {
		Timestamp string `json:"timestamp"`
	}
	e3 := h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{"latest", false}, &latest)
	reason := ""
	switch {
	case e1 == nil && finalized.IsUint64() && finalized.Uint64() > pending.Nonce:
		reason = "nonce_consumed"
	case e2 == nil && next.IsUint64() && next.Uint64() < pending.Nonce && time.Since(time.Unix(pending.SignedAt, 0)) >= stuckEscapeGrace:
		reason = "nonce_gap"
	case e3 == nil && pending.Kind == "escape" && w != nil && w.ValidUntil != 0:
		if timestamp, err := addressHexUint(latest.Timestamp); err == nil && timestamp.IsUint64() && timestamp.Uint64() > w.ValidUntil {
			reason = "expired"
		}
	}
	if reason == "" {
		return ""
	}
	if receipt, _, err := h.addressFinalReceipt(ctx, config, pending.Hash, true); err != nil || receipt != nil {
		return ""
	}
	return reason
}

// retireUnminedEscape moves a pending escape transaction that can no longer
// be included to the history, marked unmined, so the next one is signed: an
// initiation is decided and proved again (phase escape_expired), a
// finalization or a claim is quoted again.
func (h *FundingHandler) retireUnminedEscape(record *addressFundingRecord, reason string, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w, pending := record.Withdrawal, record.Pending
	retired := *pending
	retired.Unmined = true
	record.History = append(record.History, retired)
	record.Pending = nil
	switch pending.Kind {
	case "escape":
		w.Phase, w.Binding = "escape_expired", ""
	case "escape_finalize":
		w.Phase = "escape_initiated"
	}
	if err := h.saveAddress(record); err != nil {
		return update(), err
	}
	status := update()
	status.Message = fmt.Sprintf("The signed %s transaction %s can no longer be included (%s); it was retired unmined and nothing was paid by it. %s", strings.ReplaceAll(pending.Kind, "_", " "), pending.Hash, strings.ReplaceAll(reason, "_", " "), status.Message)
	return status, nil
}

// unminedEscapeFees is the fee cap and tip a transaction at nonce must
// exceed to replace an escape transaction retired unmined at that nonce:
// each raised by an eighth, plus one wei. Nil when there is none.
func unminedEscapeFees(record *addressFundingRecord, nonce uint64) *addressFees {
	var floor *addressFees
	for _, entry := range record.History {
		if !entry.Unmined || entry.Nonce != nonce {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(entry.Raw, "0x"))
		var tx types.Transaction
		if err != nil || tx.UnmarshalBinary(raw) != nil {
			continue
		}
		raise := func(fee *big.Int) *big.Int {
			return new(big.Int).Add(new(big.Int).Add(fee, new(big.Int).Quo(fee, big.NewInt(8))), big.NewInt(1))
		}
		if floor == nil {
			floor = &addressFees{Max: new(big.Int), Tip: new(big.Int)}
		}
		if raised := raise(tx.GasFeeCap()); raised.Cmp(floor.Max) > 0 {
			floor.Max = raised
		}
		if raised := raise(tx.GasTipCap()); raised.Cmp(floor.Tip) > 0 {
			floor.Tip = raised
		}
	}
	return floor
}

// followEscapeTransaction follows the pending escape transaction to
// finality, and retires one that can no longer be included.
func (h *FundingHandler) followEscapeTransaction(ctx context.Context, config fundingConfig, record *addressFundingRecord, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w, pending := record.Withdrawal, record.Pending
	receipt, final, err := h.addressFinalReceipt(ctx, config, pending.Hash, true)
	if err != nil {
		return update(), err
	}
	if !final {
		if receipt == nil {
			if reason := h.deadEscapeTransaction(ctx, config, record); reason != "" {
				return h.retireUnminedEscape(record, reason, update)
			}
			h.broadcastAddress(ctx, config, pending)
		}
		if pending.Kind == "escape" {
			h.reportEscapeSubmission(ctx, pending.Hash)
		}
		return update(), nil
	}
	if err := recordAddressActualFee(pending, receipt); err != nil {
		return update(), err
	}
	retired := *pending
	retired.FinalizedRevert = receipt.Status == "0x0"
	record.History = append(record.History, retired)
	record.Pending = nil
	switch pending.Kind {
	case "escape":
		if receipt.Status == "0x0" {
			// Reverted (for example the proof expired before inclusion): a
			// fresh proof needs the owner's confirmation again.
			w.Phase, w.Binding = "reverted", ""
		} else {
			w.Phase, w.InitiateHash = "escape_initiated", strings.ToLower(pending.Hash)
		}
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		if w.Phase == "escape_initiated" {
			return h.finalizeEscape(ctx, config, record, update)
		}
		return update(), nil
	case "escape_finalize":
		if receipt.Status == "0x1" {
			return h.completeEscape(ctx, config, record, pending.Hash, receipt, update)
		}
		// Someone else may have finalized first; look again.
		w.Phase = "escape_initiated"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return h.finalizeEscape(ctx, config, record, update)
	case "escape_claim":
		w.ClaimHash = strings.ToLower(pending.Hash)
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return update(), nil
	}
	return update(), errors.New("unexpected escape transaction")
}

// finalizeEscape signs finalizeEscapeWithdrawal once the challenge period
// passed, or adopts the finalization someone else made. It also follows a
// saved defeat: one reading (through the pinned RPC, say) never makes it
// final, so a defeat the chain no longer shows gives way to what it shows.
func (h *FundingHandler) finalizeEscape(ctx context.Context, config fundingConfig, record *addressFundingRecord, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	chain, err := h.escapeChain(ctx)
	if err != nil {
		return update(), err
	}
	switch chain.Phase {
	case "pending":
		w.Phase = "escape_initiated"
		w.Deadline = chain.ChallengeDeadline
		if payout, err := parseUnits(chain.Payout); err == nil {
			w.Payout = payout
		}
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		if uint64(time.Now().Unix()) <= chain.ChallengeDeadline || quoteMode(ctx) == nil {
			// Finalization is signed under an approved fee quote.
			return update(), nil
		}
		if w.FeePayer == "payout" {
			vaultCall, _ := hex.DecodeString(finalizeEscapeCalldata(w.NoteID)[2:])
			if err := h.submitUserOperation(ctx, config, record, gaslessKindFinalize, vaultCall); err != nil {
				if GaslessRefusalCode(err) != "" {
					w.Phase, w.GaslessRefusal = "gasless_refused", err.Error()
					if saveErr := h.saveAddress(record); saveErr != nil {
						return update(), saveErr
					}
				}
				return update(), err
			}
			return update(), nil
		}
		if err := h.signAddressTransaction(ctx, config, record, "escape_finalize", config.Contract, finalizeEscapeCalldata(w.NoteID)); err != nil {
			if errors.Is(err, errAddressNeedsETH) {
				next := update()
				next.Message = err.Error()
				return next, nil
			}
			return update(), err
		}
		return update(), nil
	case "closed":
		hash, err := h.findEscapeFinalization(ctx, config, w)
		if err != nil {
			return update(), err
		}
		receipt, final, err := h.addressFinalReceipt(ctx, config, hash, true)
		if err != nil || !final {
			return update(), err
		}
		status, err := h.completeEscape(ctx, config, record, hash, receipt, update)
		if err == nil && w.Transit != nil && w.FundsWaitingInTransit && quoteMode(ctx) != nil {
			// Design 3.3: finalized by someone else, the payout sits in the
			// transit account; the sponsored forward is quoted right away.
			// The forward is quoted under the command's own choices: like
			// every operation it is refused as gasless_uneconomic unless
			// --allow-expensive-gas was passed (--sweep is the way out).
			options := withdrawalOptions(ctx)
			return h.transitAction(ctx, config, record, addressWithdrawalOptions{Collect: true, BundlerURL: options.BundlerURL, FeeCapGwei: options.FeeCapGwei, AllowExpensiveGas: options.AllowExpensiveGas}, update)
		}
		return status, err
	case "defeated":
		w.Phase = "defeated"
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		next := update()
		if !chain.Trusted {
			next.Message += " This reading came through the pinned RPC, which the operator may run: it is asked again on every run, and with your own RPC set (zkapi-clientd config --exit-rpc-url URL) the escape's state is read from that RPC instead."
		}
		return next, &Error{http.StatusConflict, "device_not_newest"}
	case "expired":
		// The companion released the escape's lock: through the owner's exit
		// RPC, the note is Active at a finalized block with no pending exit
		// and no defeat in the logs it read there, and the proof is dead.
		// The escape a receipt (or a defeat) once showed is not on chain; it
		// is decided and proved again. A pinned-RPC reading, or one that did
		// not read the defeat logs, leaves the record as it is.
		if chain.Trusted && chain.DefeatChecked {
			w.Phase, w.Binding = "escape_expired", ""
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
		}
	case "unknown":
		// The companion could not read whether the escape was defeated (its
		// defeat logs did not load): nothing is decided from this reading.
		next := update()
		next.Message += " " + escapeUnreadNote
		return next, nil
	}
	return update(), nil
}

// escapeUnreadNote is added to an escape's status when the chain reading
// could not tell whether the escape was defeated.
const escapeUnreadNote = "The escape's defeat logs could not be read just now, so this run decided nothing about the escape; rerun later."

// findEscapeFinalization finds the transaction that finalized the note's
// escape through the pinned RPC's logs.
func (h *FundingHandler) findEscapeFinalization(ctx context.Context, config fundingConfig, w *addressWithdrawalRecord) (string, error) {
	var logs []struct {
		TransactionHash string `json:"transactionHash"`
		Removed         bool   `json:"removed"`
	}
	filter := map[string]any{"address": config.Contract, "fromBlock": fmt.Sprintf("0x%x", w.StartBlock), "toBlock": "finalized", "topics": []string{escapeFinalizedEventTopic, fmt.Sprintf("0x%064x", w.NoteID)}}
	if err := h.addressRPC(ctx, config, "eth_getLogs", []any{filter}, &logs); err != nil {
		return "", err
	}
	for _, log := range logs {
		if !log.Removed && isHex(log.TransactionHash, 32) {
			return log.TransactionHash, nil
		}
	}
	return "", errors.New("the note closed, but its escape finalization is not yet in a finalized block")
}

// completeEscape checks the finalized payout (E5) and closes the record.
func (h *FundingHandler) completeEscape(ctx context.Context, config fundingConfig, record *addressFundingRecord, hash string, receipt *addressReceipt, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	paid, credited, err := escapeReceiptPayout(receipt, config, w)
	if err != nil {
		return update(), err
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() {
		return update(), errors.New("invalid escape receipt block")
	}
	raises, err := h.escapeRaises(ctx, config, w.NoteID, w.Nullifier, w.StartBlock, block.Uint64())
	if err != nil {
		return update(), err
	}
	bound := w.Bound
	matched := matchEscapePayout(paid, w.StateBalance, w.Conceded, raises, &bound)
	if !matched.Matches {
		return update(), errors.New("the escape payout matches neither the state balance less its concession nor any recorded raise; preserve recovery files")
	}
	body, _ := json.Marshal(map[string]string{"transaction_hash": hash})
	if _, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/escape/finalize", body); err != nil {
		return update(), err
	}
	w.FinalizeHash, w.Payout, w.Amount, w.PayoutCredited, w.ConcessionExceededBound = strings.ToLower(hash), paid, paid, credited, matched.ExceededBound
	if w.UserOp != nil && gaslessKindOf(w.UserOp.Kind) == gaslessKindEscape {
		// A finalization another transaction made: the operation still
		// journaled is the sponsored initiation, on chain since (its
		// InitiateHash and debt are recorded). It authorized the proof's
		// B − c at initiation, which a raise lowered: kept, it would no
		// longer match the record's Amount (the payout just read).
		w.UserOp = nil
	}
	w.CompletedOnPinnedRPC = config.ExitRPC == ""
	w.SettlementHash = strings.ToLower(hash)
	if w.Transit != nil {
		// The vault paid the transit account: a sponsored finalization's
		// Settled figures say what reached Y; without them the payout waits
		// in the transit account.
		recordSettlement(w, parsePaymasterSettlement(receipt, common.HexToAddress(w.Transit.Paymaster), common.HexToAddress(w.Transit.Account), common.HexToAddress(w.Destination)))
		if w.PayoutCredited && !w.PaymasterCredited {
			w.FundsWaitingInTransit = false
		}
	}
	if err := h.archiveWithdrawnDepositForEscape(config, record, hash); err != nil {
		return update(), err
	}
	record.Amount, record.Commitment, record.Phase = 0, "", "ready"
	w.Phase = "complete"
	if err := h.saveAddress(record); err != nil {
		return update(), err
	}
	return update(), nil
}

// escapeReceiptPayout reads the EscapeWithdrawalFinalized of the saved
// escape in receipt: the amount paid (or credited), and whether
// EscapePayoutDeferred credited it instead of paying.
func escapeReceiptPayout(receipt *addressReceipt, config fundingConfig, w *addressWithdrawalRecord) (uint64, bool, error) {
	invalid := errors.New("the finalize receipt does not finalize the saved escape; preserve recovery files")
	if receipt == nil || receipt.Status != "0x1" {
		return 0, false, invalid
	}
	noteTopic := fmt.Sprintf("0x%064x", w.NoteID)
	var paid *big.Int
	credited := false
	for _, log := range receipt.Logs {
		if log.Removed || !strings.EqualFold(log.Address, config.Contract) {
			continue
		}
		if len(log.Topics) == 3 && strings.EqualFold(log.Topics[0], escapePayoutDeferredEventTopic) && strings.EqualFold(log.Topics[1], noteTopic) && strings.EqualFold(log.Topics[2], "0x"+addressABIWord(w.proofDestination())) {
			credited = true
			continue
		}
		if len(log.Topics) != 2 || !strings.EqualFold(log.Topics[0], escapeFinalizedEventTopic) || !strings.EqualFold(log.Topics[1], noteTopic) || !isHex(log.Data, 96) {
			continue
		}
		data := strings.TrimPrefix(log.Data, "0x")
		if !strings.EqualFold(data[:64], addressABIWord(w.Nullifier)) || !strings.EqualFold(data[128:], addressABIWord(w.proofDestination())) {
			continue
		}
		if paid != nil {
			return 0, false, invalid
		}
		paid, _ = new(big.Int).SetString(data[64:128], 16)
	}
	if paid == nil || !paid.IsUint64() {
		return 0, false, invalid
	}
	return paid.Uint64(), credited, nil
}

// archiveWithdrawnDepositForEscape archives the deposit recovery data of a
// note an escape closed.
func (h *FundingHandler) archiveWithdrawnDepositForEscape(config fundingConfig, record *addressFundingRecord, hash string) error {
	saved := record.Pending
	record.Pending = &addressTransaction{Hash: hash}
	err := h.archiveWithdrawnDeposit(config, record)
	record.Pending = saved
	return err
}

// QuoteAddressEscape prepares the next escape transaction (the initiation
// with the confirmed concession, or the finalization) and returns its fee
// quote without signing.
func (h *FundingHandler) QuoteAddressEscape(ctx context.Context, destination string, noteID uint64, conceded *uint64, earlyExit string) (AddressPaymentQuote, error) {
	var quote AddressPaymentQuote
	mode := &addressQuoteMode{Capture: &quote}
	status, err := h.EscapeAddress(context.WithValue(ctx, addressQuoteContextKey{}, mode), destination, noteID, conceded, earlyExit)
	if err == nil && quote.ID == "" {
		err = fmt.Errorf("the escape cannot be quoted while its status is %s; follow its saved status", status.Phase)
	}
	return quote, err
}

// ApproveAddressEscape signs the escape transaction of a saved quote.
func (h *FundingHandler) ApproveAddressEscape(ctx context.Context, id string) (AddressWithdrawalStatus, error) {
	h.mu.Lock()
	config, err := h.config(ctx)
	if err != nil {
		h.mu.Unlock()
		return AddressWithdrawalStatus{}, err
	}
	record, err := h.loadAddress(config)
	if err != nil {
		h.mu.Unlock()
		return AddressWithdrawalStatus{}, err
	}
	q := record.Quote
	if q == nil || q.ID != id || !escapeKinds[q.Kind] {
		h.mu.Unlock()
		return AddressWithdrawalStatus{}, errAddressQuoteChanged
	}
	quote, err := checkedAddressQuote(record, id, q.Kind)
	w := record.Withdrawal
	h.mu.Unlock()
	if err != nil || w == nil || w.Mode != "escape" {
		return AddressWithdrawalStatus{}, errAddressQuoteChanged
	}
	ctx = context.WithValue(ctx, addressQuoteContextKey{}, &addressQuoteMode{Approval: quote})
	if quote.Kind == "escape_claim" {
		return h.ClaimEscapePayout(ctx, quote.Destination)
	}
	conceded := w.Conceded
	return h.EscapeAddress(ctx, quote.Destination, quote.NoteID, &conceded, "")
}

// QuoteEscapeClaim returns the fee quote of claimEscapePayout(destination)
// without signing.
func (h *FundingHandler) QuoteEscapeClaim(ctx context.Context, destination string) (AddressPaymentQuote, error) {
	var quote AddressPaymentQuote
	status, err := h.ClaimEscapePayout(context.WithValue(ctx, addressQuoteContextKey{}, &addressQuoteMode{Capture: &quote}), destination)
	if err == nil && quote.ID == "" {
		err = fmt.Errorf("the escape payout claim cannot be quoted while its status is %s", status.Phase)
	}
	return quote, err
}

// ClaimEscapePayout signs claimEscapePayout(destination) for a credited
// escape payout (EscapePayoutDeferred); under a quote it only quotes.
func (h *FundingHandler) ClaimEscapePayout(ctx context.Context, destination string) (AddressWithdrawalStatus, error) {
	destination, err := NormalizeWithdrawalDestination(destination)
	if err != nil {
		return AddressWithdrawalStatus{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	config, record, _, status, err := h.withdrawalSnapshotFor(ctx, true)
	if err != nil {
		return status, err
	}
	update := func() AddressWithdrawalStatus { return escapeStatus(status, record, config) }
	w := record.Withdrawal
	if w == nil || w.Mode != "escape" || w.Phase != "complete" || !w.PayoutCredited || !strings.EqualFold(w.Destination, destination) {
		return update(), errors.New("there is no credited escape payout for this destination")
	}
	if record.Pending != nil {
		return h.followEscapeTransaction(ctx, config, record, update)
	}
	credit, err := h.addressUintCall(ctx, config, config.Contract, "0x"+escapePayoutCreditsSelector+addressABIWord(strings.ToLower(destination)), "latest")
	if err != nil {
		return update(), err
	}
	if credit.Sign() == 0 {
		return update(), errors.New("the vault holds no escape payout credit for this destination; it was claimed already")
	}
	if err := h.signAddressTransaction(ctx, config, record, "escape_claim", config.Contract, claimEscapeCalldata(destination)); err != nil {
		return update(), err
	}
	return update(), nil
}

// escapeStatus adds the escape's fields to a withdrawal status.
func escapeStatus(status AddressWithdrawalStatus, record *addressFundingRecord, config fundingConfig) AddressWithdrawalStatus {
	w := record.Withdrawal
	if w == nil {
		setWithdrawalMessage(&status)
		return status
	}
	status.NoteID, status.Destination, status.Amount, status.Phase = w.NoteID, w.Destination, w.Amount, w.Phase
	status.TransactionHash = w.TransactionHash
	if record.Pending != nil {
		status.TransactionHash = record.Pending.Hash
		status.ActualFeeWei = record.Pending.ActualFeeWei
	}
	if w.Mode == "escape" {
		status.Mode = "escape"
		status.StateBalance, status.Conceded, status.BoundAtState = w.StateBalance, w.Conceded, w.Bound
		status.Reason, status.WaitUntil, status.ChallengeDeadline, status.ValidUntil = w.Reason, w.WaitUntil, w.Deadline, w.ValidUntil
		status.ConcessionExceededBound = w.ConcessionExceededBound
		if w.Payout != 0 {
			status.Amount = w.Payout
		}
		if w.FinalizeHash != "" && record.Pending == nil {
			status.TransactionHash = w.FinalizeHash
		}
	}
	setEscapePayoutCredit(&status, w, config)
	setGaslessStatus(&status, w)
	setWithdrawalMessage(&status)
	if w.Mode == "escape" && config.ExitRPC == "" && status.Phase != "complete" {
		status.Message += " " + noExitRPCWarning
	}
	if w.Mode == "escape" && status.Phase == "complete" && w.CompletedOnPinnedRPC {
		status.Message += " " + fmt.Sprintf(pinnedPayoutAdvice, w.Destination)
	}
	return status
}

// noExitRPCWarning is added to every open escape's status while no exit RPC
// is configured (design §6.4 E6, §6.7): the pinned RPC then answers every
// chain reading the escape depends on.
const noExitRPCWarning = "No exit RPC is set: the pinned RPC, which the operator may run or influence, then sends this escape and reports its state (when its lock is released, whether it landed, whether it was defeated, what it paid). Set your own Ethereum RPC first with zkapi-clientd config --exit-rpc-url URL."

// pinnedPayoutAdvice is added to the status of an escape completed while no
// exit RPC was set: a pinned RPC that fakes the receipts and logs makes an
// escape look paid while the note stays open on chain, where the operator
// can sweep it at expiry (design §6.4 E6).
const pinnedPayoutAdvice = "No exit RPC was set when this escape completed: the pinned RPC, which the operator may run, reported its finalization and payout. Check through a source the operator does not control (your own node or a block explorer) that the payout reached %s, or for a credited payout that the vault holds it for that address. If it did not, the note may still be open on chain, where the operator can sweep it at expiry: preserve the local payment and private-note files and any exit kit, and exit the note through your own RPC before it expires (zkapi-walletd exit-kit escape --rpc URL)."
