package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// Quoting reserves the selected note and destination, but cannot sign. Resume
// is used only after the journal has an identified signed transaction.
type guidedWithdrawalService interface {
	Status(context.Context) (zkapi.AddressWithdrawalStatus, error)
	// The boolean is the owner's acknowledgement for an expired note at a
	// state with an unsettled request (see confirmUnsettledWithdrawal); the
	// last argument is how the fee is paid ("payout" for a sponsored
	// operation paid from the payout, else from the wallet).
	Quote(context.Context, string, uint64, string, bool, string) (zkapi.AddressPaymentQuote, error)
	Approve(context.Context, string) (zkapi.AddressWithdrawalStatus, error)
	Resume(context.Context, string, uint64) (zkapi.AddressWithdrawalStatus, error)
	Confirm(context.Context, string, uint64, string) (zkapi.AddressWithdrawalStatus, error)
	// GaslessAvailability is the pre-flight of design 3.1: whether the fee
	// can be paid from the payout for the next withdrawal.
	GaslessAvailability(context.Context) (zkapi.GaslessAvailability, error)
}

type localGuidedWithdrawal struct{ config config.Config }

func (s localGuidedWithdrawal) Status(ctx context.Context) (zkapi.AddressWithdrawalStatus, error) {
	return requestWithdrawal(ctx, s.config, http.MethodGet, nil)
}
func (s localGuidedWithdrawal) Quote(ctx context.Context, destination string, note uint64, retry string, acceptUnsettledRequestRisk bool, fees string) (zkapi.AddressPaymentQuote, error) {
	body := map[string]any{"destination": destination, "note_id": note}
	if retry != "" {
		body["retry_transaction_hash"] = retry
	}
	if acceptUnsettledRequestRisk {
		body["accept_unsettled_request_risk"] = true
	}
	// A chosen fee mode is sent as such: "payout" asks for the sponsored
	// path, "wallet" (chosen when it was offered) falls a saved sponsored
	// withdrawal back to the wallet-paid path; "" keeps the daemon's
	// default and a saved withdrawal's mode.
	if fees != "" {
		body["fees"] = fees
	}
	if fees == "payout" && s.config.ZKAPI.BundlerURL != "" {
		body["bundler_url"] = s.config.ZKAPI.BundlerURL
	}
	return requestPaymentQuote(ctx, s.config, http.MethodPost, "/admin/withdrawal/quote", "withdrawal", body)
}
func (s localGuidedWithdrawal) GaslessAvailability(ctx context.Context) (zkapi.GaslessAvailability, error) {
	var availability zkapi.GaslessAvailability
	body := map[string]any{}
	if s.config.ZKAPI.BundlerURL != "" {
		body["bundler_url"] = s.config.ZKAPI.BundlerURL
	}
	err := requestManagementJSON(ctx, s.config, http.MethodPost, "/admin/withdrawal/gasless", body, &availability)
	return availability, err
}
func (s localGuidedWithdrawal) Approve(ctx context.Context, id string) (zkapi.AddressWithdrawalStatus, error) {
	return requestWithdrawalPath(ctx, s.config, http.MethodPost, "/admin/withdrawal/approve", map[string]string{"quote_id": id})
}
func (s localGuidedWithdrawal) Resume(ctx context.Context, destination string, note uint64) (zkapi.AddressWithdrawalStatus, error) {
	return requestWithdrawal(ctx, s.config, http.MethodPost, map[string]any{"destination": destination, "note_id": note})
}
func (s localGuidedWithdrawal) Confirm(ctx context.Context, destination string, note uint64, hash string) (zkapi.AddressWithdrawalStatus, error) {
	return requestWithdrawal(ctx, s.config, http.MethodPost, map[string]any{"destination": destination, "note_id": note, "confirmation_transaction_hash": hash})
}

func runGuidedWithdrawal(ctx context.Context, c config.Config, ui setupPrompter) error {
	return guidedWithdrawal(ctx, localGuidedWithdrawal{c}, ui, waitFundingPoll, c.ZKAPI.WithdrawalFees)
}

// guidedWithdrawal runs the guided withdrawal; defaultFees is the
// configured fee mode ("payout" or "", wallet) the fee question defaults to.
func guidedWithdrawal(ctx context.Context, service guidedWithdrawalService, ui setupPrompter, wait func(context.Context) error, defaultFees string) error {
	defer clearSetupProgress(ui)
	setupProgress(ui, "Checking withdrawal status...")
	initial, err := service.Status(ctx)
	if err != nil {
		return err
	}
	if initial.BillingAsset != "native_eth" {
		return errors.New("guided withdrawal requires the native ETH deployment")
	}
	for _, credit := range initial.EscapePayoutCredits {
		clearSetupProgress(ui)
		ui.Printf("Unclaimed escape payout: %s\n", credit.Message)
	}
	if initial.Mode == "escape" {
		// An escape is under way: it is reviewed, confirmed and approved
		// with the escape command, never by the mutual close.
		clearSetupProgress(ui)
		ui.Printf("%s\nFollow the escape with: zkapi-clientd withdraw --escape --to %s\n", initial.Message, initial.Destination)
		return nil
	}
	switch initial.Phase {
	case "no_note":
		ui.Printf("There is no open private balance to withdraw.\n")
		return nil
	case "complete", "withdrawal_pending", "confirming", "op_built", "op_submitted", "forward_op_built", "forward_op_submitted":
		return finishGuidedWithdrawal(ctx, service, initial, ui, wait)
	case "ready", "quoted", "waiting_funds", "waiting_settlement", "reverted", "gasless_refused":
	case "op_reverted":
		clearSetupProgress(ui)
		return errors.New(initial.Message)
	default:
		return errors.New("withdrawal needs recovery; preserve the wallet files and run zkapi-clientd config --menu")
	}
	destination := initial.Destination
	if destination == "" {
		clearSetupProgress(ui)
		for {
			answer, err := ui.Ask(ctx, "Withdraw the full private balance to Ethereum address", "")
			if err != nil {
				return err
			}
			destination, err = zkapi.NormalizeWithdrawalDestination(strings.TrimSpace(answer))
			if err == nil {
				err = zkapi.CheckWithdrawalDestination(initial.ChainID, destination)
			}
			if err == nil {
				break
			}
			ui.Printf("%s. Please enter the destination address.\n", err)
		}
	} else if _, err := zkapi.NormalizeWithdrawalDestination(destination); err != nil {
		return errors.New("the saved withdrawal destination is invalid; preserve recovery files")
	}

	retryHash := ""
	if initial.Phase == "reverted" {
		if !validWithdrawalTransactionHash(initial.TransactionHash) {
			return errors.New("the reverted withdrawal has no valid saved transaction; preserve recovery files")
		}
		clearSetupProgress(ui)
		choice, err := ui.Ask(ctx, "The previous withdrawal reverted. Choose retry, or confirm a payout submitted separately", "retry")
		if err != nil {
			return err
		}
		switch choice {
		case "retry":
			retryHash = initial.TransactionHash
		case "confirm":
			hash, err := ui.Ask(ctx, "Matching withdrawal transaction hash", "")
			if err != nil {
				return err
			}
			if !validWithdrawalTransactionHash(hash) || strings.EqualFold(hash, initial.TransactionHash) {
				return errors.New("enter a valid, separately submitted withdrawal transaction hash")
			}
			state, err := service.Confirm(ctx, destination, initial.NoteID, hash)
			if err != nil {
				return errors.New("payout confirmation did not complete; run zkapi-clientd config --menu to recover saved progress")
			}
			if !sameGuidedWithdrawalWallet(initial, state) || initial.Amount != state.Amount || !strings.EqualFold(destination, state.Destination) || !strings.EqualFold(hash, state.TransactionHash) {
				return errors.New("payout confirmation changed the saved withdrawal; preserve recovery files")
			}
			return finishGuidedWithdrawal(ctx, service, state, ui, wait)
		default:
			return errors.New("choose retry or confirm; no transaction was authorized")
		}
	} else if initial.TransactionHash != "" {
		return errors.New("saved withdrawal transaction needs recovery before preparing another quote")
	}
	// Design 3.3: when the deployment's paymaster can sponsor the exit, the
	// fee may be paid from the payout, so no ETH (and no fee QR) is needed.
	// The choice is made before the note is reserved (the proof binds the
	// transit account), or again after the sponsored path refused.
	fees := ""
	switch {
	case initial.FeePayer == "payout" && initial.Phase != "gasless_refused":
		fees = "payout"
	case initial.Destination == "" || initial.Phase == "gasless_refused":
		fees = chooseGuidedFees(ctx, service, ui, defaultFees, initial.Phase == "gasless_refused" && initial.FeePayer == "payout")
	}
	setupProgress(ui, "Preparing withdrawal; this can take a few minutes.")
	return waitAndWithdraw(ctx, service, initial, destination, retryHash, fees, ui, wait)
}

// chooseGuidedFees asks how the fee is paid when the payout can pay it:
// "payout" or "wallet" as chosen (a chosen wallet is named to the daemon,
// which falls a refused sponsored withdrawal back to the wallet-paid
// path); "" (the daemon's default) when the choice is not offered. A
// refused sponsored withdrawal (refused) whose sponsored path is
// unavailable has only the wallet-paid way out, so "wallet" is named
// without asking (the quote is still reviewed before anything is signed).
func chooseGuidedFees(ctx context.Context, service guidedWithdrawalService, ui setupPrompter, defaultFees string, refused bool) string {
	availability, err := service.GaslessAvailability(ctx)
	if err != nil || !availability.Available {
		if refused {
			clearSetupProgress(ui)
			reason := availability.Message
			if err != nil || reason == "" {
				reason = "the sponsored path is unavailable"
			}
			ui.Printf("The network fee cannot be paid from the payout now (%s). The saved withdrawal falls back to this wallet's public ETH (a fee QR appears when needed); its payout then waits in the transit account for zkapi-clientd withdraw --to DESTINATION --sweep.\n", reason)
			return "wallet"
		}
		return ""
	}
	clearSetupProgress(ui)
	fallback := "wallet"
	if defaultFees == "payout" {
		fallback = "payout"
	}
	choice, err := selectSetupChoice(ctx, ui, "How is the network fee paid? wallet (this wallet's public ETH; a fee QR appears when needed) or payout (taken from the payout; no ETH needed)", fallback, []setupChoice{
		{value: "wallet", label: "Pay the network fee from this wallet's public ETH (fee QR when needed)"},
		{value: "payout", label: "Pay the network fee from the payout (no ETH needed)"},
	})
	if err != nil {
		return ""
	}
	if strings.ToLower(strings.TrimSpace(choice)) == "payout" {
		return "payout"
	}
	return "wallet"
}

// sameGuidedWithdrawalOperation compares the saved transaction of two
// readings: a sponsored withdrawal is identified by its transit account (its
// operation's hash changes with a fee bump and its bundle transaction
// appears later), a wallet-paid one by its transaction.
func sameGuidedWithdrawalOperation(a, b zkapi.AddressWithdrawalStatus) bool {
	if a.TransitAccount != "" || b.TransitAccount != "" {
		return strings.EqualFold(a.TransitAccount, b.TransitAccount)
	}
	return strings.EqualFold(a.TransactionHash, b.TransactionHash)
}

func sameGuidedWithdrawalWallet(a, b zkapi.AddressWithdrawalStatus) bool {
	return a.BillingAsset == "native_eth" && b.BillingAsset == a.BillingAsset && a.ChainID == b.ChainID && a.DeploymentID == b.DeploymentID && strings.EqualFold(a.Address, b.Address) && a.NoteID == b.NoteID
}

func sameGuidedWithdrawalQuote(a, b zkapi.AddressPaymentQuote) bool {
	return a.Kind == "withdrawal" && b.Kind == a.Kind && a.ChainID == b.ChainID && a.DeploymentID == b.DeploymentID && strings.EqualFold(a.Contract, b.Contract) && strings.EqualFold(a.Address, b.Address) && a.NoteID == b.NoteID && strings.EqualFold(a.Destination, b.Destination) && a.Amount == b.Amount && a.PrincipalWei == "0" && b.PrincipalWei == a.PrincipalWei && a.Binding != "" && a.Binding == b.Binding && a.Commitment == "" && b.Commitment == "" && a.Nonce == b.Nonce && a.RetryHash == b.RetryHash
}

func withdrawalStateMatchesQuote(state zkapi.AddressWithdrawalStatus, quote zkapi.AddressPaymentQuote) bool {
	return state.BillingAsset == "native_eth" && state.ChainID == quote.ChainID && state.DeploymentID == quote.DeploymentID && strings.EqualFold(state.Address, quote.Address) && state.NoteID == quote.NoteID && state.Amount == quote.Amount && strings.EqualFold(state.Destination, quote.Destination)
}

func waitAndWithdraw(ctx context.Context, service guidedWithdrawalService, initial zkapi.AddressWithdrawalStatus, destination, retryHash, fees string, ui setupPrompter, wait func(context.Context) error) error {
	defer clearSetupProgress(ui)
	var frozen *zkapi.AddressPaymentQuote
	var displayedPayment *zkapi.AddressPaymentQuote
	approved, retrying, settling, acceptedUnsettled := false, false, false, false
	ceiling, lastProgress := "", ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		quote, err := service.Quote(ctx, destination, initial.NoteID, retryHash, acceptedUnsettled, fees)
		if managementErrorCode(err) == "receipt_journal_missing" {
			// Waiting cannot help; the message names the nullifier the
			// operator needs.
			return err
		}
		if code := managementErrorCode(err); code == "escape_required" || code == "device_not_newest" {
			// Design §6.4 E2: the operator refused or could not be reached
			// for a mutual close (or a released request makes one
			// impossible); the escape needs no operator. Its decision and
			// concession are reviewed before anything is signed.
			if code == "escape_required" {
				ui.Printf("A mutual close is not possible from this note's current state. The private balance can still be withdrawn without the operator by an escape: review its decision with\n  zkapi-clientd withdraw --escape --to %s\nNothing was signed.\n", destination)
			}
			return err
		}
		if code := managementErrorCode(err); err != nil && (code == "unsettled_request_state" || code == "unsettled_clearance_reserved") {
			// Waiting cannot settle this state by itself: stop with the
			// remedy, or, for an expired note, ask for the acknowledgement.
			if acceptedUnsettled {
				return err
			}
			if err := confirmUnsettledWithdrawal(ctx, service, ui, err, time.Now()); err != nil {
				return err
			}
			acceptedUnsettled, retrying, settling, lastProgress = true, false, false, ""
			setupProgress(ui, "Preparing withdrawal with the ownership proof; this can take a few minutes.")
			continue
		}
		if fees == "payout" && managementErrorCode(err) != "" {
			// A gasless refusal does not clear by waiting: the wallet-paid
			// path is the way out.
			clearSetupProgress(ui)
			return fmt.Errorf("%w. The fee cannot be paid from the payout now; run zkapi-clientd config --menu, choose withdraw and the wallet-paid fee, or zkapi-clientd withdraw --to %s --fees wallet", err, destination)
		}
		if err != nil {
			state, statusErr := service.Status(ctx)
			if statusErr == nil {
				if !sameGuidedWithdrawalWallet(initial, state) || (state.Destination != "" && !strings.EqualFold(destination, state.Destination)) || (frozen != nil && !withdrawalStateMatchesQuote(state, *frozen)) {
					return errors.New("saved withdrawal changed while waiting; stopped without authorizing another transaction")
				}
				switch state.Phase {
				case "withdrawal_pending", "confirming", "complete", "op_built", "op_submitted":
					return finishGuidedWithdrawal(ctx, service, state, ui, wait)
				case "waiting_settlement":
					if !settling {
						setupProgress(ui, "Waiting for your previous inference to settle; checking automatically.")
						settling = true
					}
					retrying = false
				case "ready", "quoted", "waiting_funds":
					if state.TransactionHash != "" {
						return errors.New("saved withdrawal transaction needs recovery; no replacement was authorized")
					}
				case "reverted":
					if retryHash == "" || !strings.EqualFold(state.TransactionHash, retryHash) {
						return errors.New("withdrawal reverted; run zkapi-clientd config --menu to review recovery; no retry was authorized")
					}
				case "gasless_refused":
					// The sponsored path stopped; waiting does not clear it,
					// and the wallet-paid fee is the way out.
					clearSetupProgress(ui)
					reason := state.GaslessRefusal
					if reason == "" {
						reason = err.Error()
					}
					return fmt.Errorf("the sponsored withdrawal stopped: %s. Pay the network fee from this wallet instead: run zkapi-clientd config --menu and choose withdraw (the wallet-paid fee is offered), or zkapi-clientd withdraw --to %s --fees wallet", reason, destination)
				default:
					return errors.New("saved withdrawal needs recovery; run zkapi-clientd config --menu")
				}
			}
			if !retrying && (statusErr != nil || state.Phase != "waiting_settlement") {
				setupProgress(ui, "Could not refresh withdrawal fees; checking again.")
				retrying = true
				settling = false
			}
			lastProgress = ""
			if err := wait(ctx); err != nil {
				return err
			}
			continue
		}
		retrying, settling = false, false
		if quote.ChainID != initial.ChainID || quote.DeploymentID != initial.DeploymentID || !strings.EqualFold(quote.Address, initial.Address) || quote.NoteID != initial.NoteID || !strings.EqualFold(quote.Destination, destination) || quote.RetryHash != retryHash || !sameGuidedWithdrawalQuote(quote, quote) || (frozen != nil && !sameGuidedWithdrawalQuote(*frozen, quote)) || (initial.Phase == "reverted" && quote.Amount != initial.Amount) {
			return errors.New("withdrawal quote changed the selected wallet, note, destination, amount, or transaction; stopped without approving")
		}
		if quote.FeePolicy != "payout" {
			// A payout quote never shows a payment request.
			if _, err := paymentRequestURI(quote); err != nil {
				return err
			}
		}
		if frozen == nil {
			copy := quote
			frozen = &copy
			ui.Printf("\nWithdraw %s ETH on %s\nDestination: %s\n", fundingUnits(strconv.FormatUint(quote.Amount, 10), 9), fundingNetwork(quote.ChainID), quote.Destination)
			if quote.FeePolicy == "payout" {
				ui.Printf("The network fee is paid from the payout by a sponsored operation; no ETH is needed from this wallet. Transit account: %s\n", quote.TransitAccount)
			}
		}
		if quote.ShortfallWei != "0" {
			if approved {
				ui.Printf("The receiving balance no longer covers fees. Waiting for ETH again.\n")
				approved, ceiling = false, ""
			}
			if displayedPayment == nil || withdrawalPaymentNeedsRefresh(quote, *displayedPayment) {
				var payment strings.Builder
				payment.WriteString("Add ETH for network fees to the receiving account below.\n")
				if err := printSetupPaymentQR(&payment, quote); err != nil {
					return err
				}
				setupPayment(ui, payment.String())
				copy := quote
				displayedPayment = &copy
			}
			progress := setupFundingProgressKey(quote)
			if progress != lastProgress {
				showSetupFundingProgress(ui, quote)
				lastProgress = progress
			}
			if err := wait(ctx); err != nil {
				return err
			}
			continue
		}
		displayedPayment = nil
		if !approved || !setupFeeWithin(quote, ceiling) {
			clearSetupProgress(ui)
			if approved {
				ui.Printf("Network fees increased; review the updated maximum.\n")
			}
			if quote.FeePolicy == "payout" {
				ui.Printf("Fee taken from the payout: at most %s ETH (expected charge at today's base fee: about %s ETH, an estimate); %s receives at least %s ETH.\n", fundingUnits(quote.FeeCapWei, 18), fundingUnits(quote.ExpectedFeeWei, 18), quote.Destination, fundingUnits(quote.MinimumReceivedWei, 18))
				if quote.PayeeHasCode {
					ui.Printf("%s has code: it must accept the ETH within 100,000 gas, or the payout is credited in the paymaster for zkapi-clientd withdraw --claim-credit (the floor above already deducts that case's surcharge).\n", quote.Destination)
				}
			} else {
				ui.Printf("Fees funded. Maximum network fee: %s ETH.\n", fundingUnits(quote.FeeReserveWei, 18))
			}
			proceed, err := ui.Continue(ctx, "Press Enter to withdraw, or type cancel")
			if err != nil {
				return err
			}
			if !proceed {
				return errors.New("withdrawal declined; no transaction was authorized")
			}
			approved, ceiling = true, quote.FeeReserveWei
			continue // The terminal pause must not authorize stale fees or balance.
		}
		setupProgress(ui, "Submitting withdrawal...")
		state, err := service.Approve(ctx, quote.ID)
		if err != nil {
			// A lost response may follow a durable signature. Do not approve a
			// different quote: only inspect and resume that saved transaction.
			setupProgress(ui, "Checking saved withdrawal progress after an interrupted response.")
			state, err = readGuidedWithdrawal(ctx, service, ui, wait)
			if err != nil {
				return err
			}
			if state.Phase != "withdrawal_pending" && state.Phase != "confirming" && state.Phase != "complete" && !zkapi.GaslessPendingPhase(state.Phase) {
				return errors.New("withdrawal was not confirmed; run zkapi-clientd config --menu to inspect saved progress before approving again")
			}
		}
		if !withdrawalStateMatchesQuote(state, quote) {
			return errors.New("saved withdrawal no longer matches the approved operation; preserve recovery files")
		}
		// A balance change during approval can leave an unsigned reservation.
		// Return to funding and require a new Enter; never call Resume on it.
		if state.Phase == "waiting_funds" && state.TransactionHash == "" {
			approved, ceiling = false, ""
			lastProgress = ""
			continue
		}
		return finishGuidedWithdrawal(ctx, service, state, ui, wait)
	}
}

// confirmUnsettledWithdrawal handles the companion's refusal at a note state
// with an unsettled request. Before the note expires, one chat request settles
// that state (unsettled_request_state), so it stops with that remedy and the
// expiry time. After expiry no chat request can, and the vault's owner may
// claim the note at any time; nor can one when the server already holds a
// clearance for the state (unsettled_clearance_reserved). Then it asks for the
// owner's explicit acknowledgement before the ownership proof is sent; nil
// means the owner gave it.
func confirmUnsettledWithdrawal(ctx context.Context, service guidedWithdrawalService, ui setupPrompter, refusal error, now time.Time) error {
	clearSetupProgress(ui)
	if managementErrorCode(refusal) == "unsettled_clearance_reserved" {
		ui.Printf("A chat request sent from this note's current state never settled, and the server already holds a withdrawal clearance for that state, for example because the zkAPI operator released it for you. No chat request can settle it, and the server grants the clearance only with an ownership proof. If you did not ask the operator to release this note and did not start this withdrawal earlier, stop here.\n")
	} else {
		state, err := service.Status(ctx)
		if err != nil || state.NoteExpiry == 0 {
			return refusal
		}
		expiry := time.Unix(int64(state.NoteExpiry), 0).UTC()
		if !now.After(expiry) {
			return fmt.Errorf("%w. This note expires at %s; after that no chat request can settle its state", refusal, expiry.Format(time.RFC3339))
		}
		ui.Printf("This note expired at %s, and a chat request sent from its current state never settled. No chat request can settle that state now, and the server grants no withdrawal clearance without an ownership proof.\n", expiry.Format(time.RFC3339))
	}
	ui.Printf("On this vault an ownership proof is also a valid escape. Whoever kept the unsettled request (the zkAPI operator, or anyone who intercepted it) could start that escape and challenge it with the request, which burns the note's nullifier: the balance could then never be withdrawn. Without the proof, the vault owner can claim the expired balance at any time.\n")
	answer, err := ui.Ask(ctx, "Type send to send the ownership proof anyway, or press Enter to stop", "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != "send" {
		return errors.New("withdrawal stopped; no ownership proof was sent and no transaction was authorized")
	}
	return nil
}

func withdrawalPaymentNeedsRefresh(current, displayed zkapi.AddressPaymentQuote) bool {
	if current.BalanceWei != displayed.BalanceWei {
		return true
	}
	required, _ := new(big.Int).SetString(current.RequiredTotalWei, 10)
	buffered, _ := new(big.Int).SetString(displayed.RecommendedTotalWei, 10)
	return required.Cmp(buffered) > 0
}

func readGuidedWithdrawal(ctx context.Context, service guidedWithdrawalService, ui setupPrompter, wait func(context.Context) error) (zkapi.AddressWithdrawalStatus, error) {
	defer clearSetupProgress(ui)
	warned := false
	for {
		state, err := service.Status(ctx)
		if err == nil {
			return state, nil
		}
		if !warned {
			setupProgress(ui, "Withdrawal status is temporarily unavailable; checking saved progress again.")
			warned = true
		}
		if err := wait(ctx); err != nil {
			return state, err
		}
	}
}

func finishGuidedWithdrawal(ctx context.Context, service guidedWithdrawalService, initial zkapi.AddressWithdrawalStatus, ui setupPrompter, wait func(context.Context) error) error {
	defer clearSetupProgress(ui)
	if (!validWithdrawalTransactionHash(initial.TransactionHash) && !validWithdrawalTransactionHash(initial.UserOpHash)) || initial.Destination == "" {
		return errors.New("saved withdrawal transaction is missing; preserve recovery files")
	}
	state, announced := initial, false
	for {
		if !sameGuidedWithdrawalWallet(initial, state) || state.Amount != initial.Amount || !strings.EqualFold(state.Destination, initial.Destination) || !sameGuidedWithdrawalOperation(initial, state) {
			return errors.New("saved withdrawal changed during recovery; preserve recovery files")
		}
		switch state.Phase {
		case "complete":
			clearSetupProgress(ui)
			if state.PayoutCredited || state.FundsWaitingInTransit {
				// The escape closed the note, but the vault holds the
				// payout for the destination; or a sponsored withdrawal's
				// payout waits in the transit account or the paymaster:
				// nothing was sent yet.
				ui.Printf("The private note is closed, but its %s ETH payout was not delivered to %s.\n%s\n", fundingUnits(strconv.FormatUint(state.Amount, 10), 9), state.Destination, state.Message)
				return nil
			}
			if state.FeePayer == "payout" && state.ReceivedWei != "" {
				ui.Printf("Withdrawal complete: %s ETH reached %s after a sponsored network fee of %s ETH taken from the payout.\n", fundingUnits(state.ReceivedWei, 18), state.Destination, fundingUnits(zeroIfEmpty(state.ChargedWei), 18))
				return nil
			}
			ui.Printf("Withdrawal complete: %s ETH sent to %s.\n", fundingUnits(strconv.FormatUint(state.Amount, 10), 9), state.Destination)
			if state.ActualFeeWei != "" {
				ui.Printf("Network fee: %s ETH.\n", fundingUnits(state.ActualFeeWei, 18))
			}
			return nil
		case "withdrawal_pending", "confirming":
			if !announced {
				setupProgress(ui, "Withdrawal submitted; waiting for Ethereum finality (usually about 15 minutes). Ctrl+C preserves progress.")
				announced = true
			}
		case "op_built", "op_submitted", "forward_op_built", "forward_op_submitted":
			if !announced {
				setupProgress(ui, "Sponsored operation sent to the bundler; waiting for inclusion and Ethereum finality (usually about 15 minutes). Ctrl+C preserves progress.")
				announced = true
			}
		default:
			return errors.New("withdrawal needs attention; run zkapi-clientd config --menu to recover it; a reverted transaction is never retried automatically")
		}
		if err := wait(ctx); err != nil {
			return err
		}
		next, err := service.Resume(ctx, initial.Destination, initial.NoteID)
		if err != nil {
			next, err = readGuidedWithdrawal(ctx, service, ui, wait)
			if err != nil {
				return err
			}
			announced = false // Restore the stage after a temporary status message.
		}
		state = next
	}
}
