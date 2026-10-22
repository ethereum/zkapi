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
// is used only after the journal has an identified signed transaction, or
// for a payout withdrawal approved within its maximum fee.
type guidedWithdrawalService interface {
	Status(context.Context) (zkapi.AddressWithdrawalStatus, error)
	Quote(context.Context, string, uint64, string, guidedQuoteOptions) (zkapi.AddressPaymentQuote, error)
	Approve(context.Context, string) (zkapi.AddressWithdrawalStatus, error)
	Resume(context.Context, string, uint64) (zkapi.AddressWithdrawalStatus, error)
	Confirm(context.Context, string, uint64, string) (zkapi.AddressWithdrawalStatus, error)
	// GaslessAvailability is the pre-flight of design 3.1: whether the fee
	// can be paid from the payout for the next withdrawal.
	GaslessAvailability(context.Context) (zkapi.GaslessAvailability, error)
}

// guidedQuoteOptions are a guided quote's choices. acceptUnsettledRequestRisk
// is the owner's acknowledgement for an expired note at a state with an
// unsettled request (see confirmUnsettledWithdrawal). payout asks for the
// fee to be paid from the payout; otherwise no fee mode is named (the
// daemon's policy, and a saved withdrawal keeps its mode): the guided flow
// never asks for a wallet-paid fee. allowExpensiveGas is the owner's
// acceptance of a fee above the deployment's uneconomic fraction.
type guidedQuoteOptions struct {
	acceptUnsettledRequestRisk bool
	payout                     bool
	allowExpensiveGas          bool
}

type localGuidedWithdrawal struct{ config config.Config }

func (s localGuidedWithdrawal) Status(ctx context.Context) (zkapi.AddressWithdrawalStatus, error) {
	return requestWithdrawal(ctx, s.config, http.MethodGet, nil)
}
func (s localGuidedWithdrawal) Quote(ctx context.Context, destination string, note uint64, retry string, o guidedQuoteOptions) (zkapi.AddressPaymentQuote, error) {
	body := map[string]any{"destination": destination, "note_id": note}
	if retry != "" {
		body["retry_transaction_hash"] = retry
	}
	if o.acceptUnsettledRequestRisk {
		body["accept_unsettled_request_risk"] = true
	}
	if o.payout {
		body["fees"] = "payout"
		if s.config.ZKAPI.BundlerURL != "" {
			body["bundler_url"] = s.config.ZKAPI.BundlerURL
		}
	}
	if o.allowExpensiveGas {
		body["allow_expensive_gas"] = true
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
	return guidedWithdrawal(ctx, localGuidedWithdrawal{c}, ui, waitFundingPoll)
}

// guidedWithdrawal runs the guided withdrawal. Where the deployment sponsors
// withdrawals (and for a saved sponsored withdrawal) the fee is paid from the
// payout, the only option: no fee question, no QR, no wallet fallback. A
// saved wallet-paid withdrawal keeps its funding, QR and approval flow.
func guidedWithdrawal(ctx context.Context, service guidedWithdrawalService, ui setupPrompter, wait func(context.Context) error) error {
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
	// A daemon an older build started offers no payout-only withdrawal and
	// keeps no authorization: only a withdrawal it already signed is
	// followed through it.
	if err := checkWithdrawalDaemon(initial); err != nil {
		clearSetupProgress(ui)
		return err
	}
	switch initial.Phase {
	case "no_note":
		ui.Printf("There is no open private balance to withdraw.\n")
		return nil
	case "complete", "withdrawal_pending", "confirming", "op_built", "op_submitted", "forward_op_built", "forward_op_submitted":
		return finishGuidedWithdrawal(ctx, service, initial, ui, wait)
	case "quoted", "gasless_refused":
		if usableAuthorization(initial) {
			// Approved within its maximum fee (a restart before signing, or a
			// retry the daemon makes within it): continue without asking.
			return finishGuidedWithdrawal(ctx, service, initial, ui, wait)
		}
	case "ready", "waiting_funds", "waiting_settlement", "reverted":
	case "op_reverted":
		clearSetupProgress(ui)
		return errors.New(initial.Message)
	default:
		return errors.New("withdrawal needs recovery; preserve the wallet files and run zkapi-clientd config --menu")
	}
	// Design 3.3: where the deployment sponsors withdrawals the fee is paid
	// from the payout, the only option (the proof binds the transit account,
	// so it is settled before the note is reserved). A saved wallet-paid
	// withdrawal finishes as it was reserved.
	payout := false
	if walletBoundWithdrawal(initial) {
		if initial.NewWithdrawalFees == "payout" {
			clearSetupProgress(ui)
			if initial.TransitAccount == "" {
				ui.Printf("This withdrawal was reserved with a wallet-paid network fee before sponsorship; it finishes that way (a fee QR appears when ETH is needed).\n")
			} else {
				ui.Printf("This withdrawal was moved to a wallet-paid network fee as recovery; it finishes that way (a fee QR appears when ETH is needed).\n")
			}
		}
	} else if initial.NewWithdrawalFees == "payout" || (savedWithdrawal(initial) && initial.TransitAccount != "") {
		payout = true
		availability, err := service.GaslessAvailability(ctx)
		if err != nil || !availability.Available {
			clearSetupProgress(ui)
			reason := availability.Message
			if reason == "" {
				reason = availability.Reason
			}
			if err != nil {
				reason = err.Error()
			}
			if reason == "" {
				reason = "the sponsored path is unavailable"
			}
			return fmt.Errorf("the network fee cannot be paid from the payout now (%s). Nothing was reserved or signed. Try again later, or use your own ERC-4337 bundler with zkapi-clientd config --bundler-url URL", withoutWalletFeeAdvice(reason))
		}
	}
	destination := initial.Destination
	if destination == "" {
		clearSetupProgress(ui)
		var err error
		if destination, err = askGuidedDestination(ctx, ui, initial.ChainID); err != nil {
			return err
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
	setupProgress(ui, "Preparing withdrawal; this can take a few minutes.")
	return waitAndWithdraw(ctx, service, initial, destination, retryHash, payout, ui, wait)
}

// askGuidedDestination asks for the withdrawal's destination until it is a
// valid address that can receive the payout on this chain.
func askGuidedDestination(ctx context.Context, ui setupPrompter, chain uint64) (string, error) {
	for {
		answer, err := ui.Ask(ctx, "Withdraw the full private balance to Ethereum address", "")
		if err != nil {
			return "", err
		}
		destination, err := zkapi.NormalizeWithdrawalDestination(strings.TrimSpace(answer))
		if err == nil {
			err = zkapi.CheckWithdrawalDestination(chain, destination)
		}
		if err == nil {
			return destination, nil
		}
		ui.Printf("%s. Please enter the destination address.\n", err)
	}
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

// sameGuidedWithdrawalQuote compares the identity two quotes of one
// withdrawal must share: the wallet, vault, note, destination, amount,
// binding, transit account (which a payout approval covers) and retry.
func sameGuidedWithdrawalQuote(a, b zkapi.AddressPaymentQuote) bool {
	return a.Kind == "withdrawal" && b.Kind == a.Kind && a.ChainID == b.ChainID && a.DeploymentID == b.DeploymentID && strings.EqualFold(a.Contract, b.Contract) && strings.EqualFold(a.Address, b.Address) && a.NoteID == b.NoteID && strings.EqualFold(a.Destination, b.Destination) && a.Amount == b.Amount && a.PrincipalWei == "0" && b.PrincipalWei == a.PrincipalWei && a.Binding != "" && a.Binding == b.Binding && a.Commitment == "" && b.Commitment == "" && a.Nonce == b.Nonce && a.RetryHash == b.RetryHash && strings.EqualFold(a.TransitAccount, b.TransitAccount)
}

func withdrawalStateMatchesQuote(state zkapi.AddressWithdrawalStatus, quote zkapi.AddressPaymentQuote) bool {
	return state.BillingAsset == "native_eth" && state.ChainID == quote.ChainID && state.DeploymentID == quote.DeploymentID && strings.EqualFold(state.Address, quote.Address) && state.NoteID == quote.NoteID && state.Amount == quote.Amount && strings.EqualFold(state.Destination, quote.Destination) && (quote.TransitAccount == "" || strings.EqualFold(state.TransitAccount, quote.TransitAccount))
}

// waitAndWithdraw quotes, shows and approves the withdrawal. A wallet-paid
// one waits for fee funds (QR) and approves a fresh quote within the fee the
// owner accepted. A payout one shows its bounded terms once and approves the
// displayed quote: the daemon builds the operation at the fees of the moment
// within that maximum. A quote that expired or was replaced before the
// approval was saved is quoted again, and approved without asking when its
// identity is the same and its bound no looser than the accepted one.
func waitAndWithdraw(ctx context.Context, service guidedWithdrawalService, initial zkapi.AddressWithdrawalStatus, destination, retryHash string, payout bool, ui setupPrompter, wait func(context.Context) error) error {
	defer clearSetupProgress(ui)
	var frozen, displayedPayment, accepted *zkapi.AddressPaymentQuote
	approved, retrying, settling, acceptedUnsettled, allowExpensiveGas := false, false, false, false, false
	ceiling, lastProgress, changes := "", "", 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		quote, err := service.Quote(ctx, destination, initial.NoteID, retryHash, guidedQuoteOptions{acceptUnsettledRequestRisk: acceptedUnsettled, payout: payout, allowExpensiveGas: allowExpensiveGas})
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
		if code := managementErrorCode(err); payout && code != "" {
			// A refusal of the payout path does not clear by waiting, and
			// there is no wallet-paid fallback: explain it and stop, except
			// for the two the owner can answer here.
			switch {
			case code == "gasless_uneconomic" && !allowExpensiveGas:
				clearSetupProgress(ui)
				ui.Printf("The network fee is unusually high for this payout right now (%s). You can stop and try again later, or accept the higher fee; its maximum is shown before you approve.\n", payoutRefusal(err))
				accept, err := ui.Confirm(ctx, "Accept a network fee above the usual share of the payout")
				if err != nil {
					return err
				}
				if !accept {
					return errors.New("withdrawal stopped; nothing was approved or signed; try again later from zkapi-clientd config --menu")
				}
				allowExpensiveGas, lastProgress = true, ""
				setupProgress(ui, "Preparing withdrawal; this can take a few minutes.")
				continue
			case code == zkapi.CodeInvalidPayee && initial.Destination == "" && frozen == nil:
				// Refused before anything was reserved for it: another
				// destination may be chosen.
				clearSetupProgress(ui)
				ui.Printf("%s cannot receive this payout (%s).\n", destination, payoutRefusal(err))
				if destination, err = askGuidedDestination(ctx, ui, initial.ChainID); err != nil {
					return err
				}
				lastProgress = ""
				setupProgress(ui, "Preparing withdrawal; this can take a few minutes.")
				continue
			}
			return guidedPayoutStopped(ui, err)
		}
		if err != nil {
			state, statusErr := service.Status(ctx)
			if statusErr == nil {
				if !sameGuidedWithdrawalWallet(initial, state) || (state.Destination != "" && !strings.EqualFold(destination, state.Destination)) || (frozen != nil && !withdrawalStateMatchesQuote(state, *frozen)) {
					return errors.New("saved withdrawal changed while waiting; stopped without authorizing another transaction")
				}
				if payout && usableAuthorization(state) {
					// Approved within its maximum fee meanwhile: follow it.
					return finishGuidedWithdrawal(ctx, service, state, ui, wait)
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
					// The sponsored path stopped; waiting does not clear it.
					clearSetupProgress(ui)
					if state.GaslessRefusal == "" {
						state.GaslessRefusal = err.Error()
					}
					return sponsoredWithdrawalStopped(state)
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
			return errors.New("withdrawal quote changed the selected wallet, note, destination, transit account, amount, or transaction; stopped without approving")
		}
		if payout != (quote.FeePolicy == "payout") {
			// How the fee is paid never changes silently: a payout
			// withdrawal is never quoted wallet-paid, nor the reverse.
			return errors.New("withdrawal quote changed how the network fee is paid; stopped without approving")
		}
		if !payout {
			// A payout quote never shows a payment request.
			if _, err := paymentRequestURI(quote); err != nil {
				return err
			}
		}
		if frozen == nil {
			copy := quote
			frozen = &copy
			ui.Printf("\nWithdraw %s ETH on %s\nDestination: %s\n", fundingUnits(strconv.FormatUint(quote.Amount, 10), 9), fundingNetwork(quote.ChainID), quote.Destination)
			if payout {
				ui.Printf("The network fee is paid from the payout by a sponsored operation; no ETH is needed from this wallet. Transit account: %s\n", quote.TransitAccount)
			}
		}
		if payout {
			if accepted == nil || !payoutWithinBound(quote, *accepted) {
				clearSetupProgress(ui)
				if accepted != nil {
					ui.Printf("The refreshed quote raises the maximum fee or lowers what %s receives; review the new terms.\n", quote.Destination)
				}
				printPayoutTerms(setupUIWriter{ui}, quote)
				proceed, err := ui.Continue(ctx, "Press Enter to approve this withdrawal, or type cancel")
				if err != nil {
					return err
				}
				if !proceed {
					return errors.New("withdrawal declined; no transaction was authorized")
				}
				copy := quote
				accepted = &copy
			}
			setupProgress(ui, "Submitting withdrawal...")
			state, err := service.Approve(ctx, quote.ID)
			if managementErrorCode(err) == zkapi.CodeQuoteChanged {
				// Refused before the authorization was saved (the quote
				// expired or was replaced): nothing was approved. The next
				// quote is approved without asking if it fits the accepted
				// terms.
				if changes++; changes > 3 {
					return fmt.Errorf("%w; the quote kept changing and nothing was approved; try again from zkapi-clientd config --menu", err)
				}
				setupProgress(ui, "The quote expired or was replaced; refreshing it within the approved maximum.")
				continue
			}
			if err != nil {
				// A lost response may follow a saved authorization or a
				// signature: only inspect and follow what was saved.
				refusal := err
				setupProgress(ui, "Checking saved withdrawal progress after an interrupted response.")
				if state, err = readGuidedWithdrawal(ctx, service, ui, wait); err != nil {
					return err
				}
				if state.Phase != "withdrawal_pending" && state.Phase != "confirming" && state.Phase != "complete" && !zkapi.GaslessPendingPhase(state.Phase) && !usableAuthorization(state) {
					if state.Phase == "gasless_refused" && withdrawalStateMatchesQuote(state, quote) {
						return sponsoredWithdrawalStopped(state)
					}
					if managementErrorCode(refusal) != "" {
						return guidedPayoutStopped(ui, refusal)
					}
					return errors.New("withdrawal was not confirmed; run zkapi-clientd config --menu to inspect saved progress before approving again")
				}
			}
			if !withdrawalStateMatchesQuote(state, quote) {
				return errors.New("saved withdrawal no longer matches the approved operation; preserve recovery files")
			}
			if state.Phase == "gasless_refused" && !state.GaslessRetryable {
				return sponsoredWithdrawalStopped(state)
			}
			return finishGuidedWithdrawal(ctx, service, state, ui, wait)
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
			ui.Printf("Fees funded. Maximum network fee: %s ETH.\n", fundingUnits(quote.FeeReserveWei, 18))
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

// payoutRefusal is a payout refusal's reason as shown: the daemon's message,
// without any advice to fall back to a wallet-paid fee.
func payoutRefusal(err error) string {
	var failed *managementError
	if errors.As(withoutWalletFeeAdviceError(err), &failed) {
		return failed.message
	}
	return withoutWalletFeeAdvice(err.Error())
}

// guidedPayoutStopped stops a payout withdrawal the payout path refused
// (bundler unavailable, fee above the paymaster's ceiling, sponsorship
// paused, ...) with the reason and what can be done; it keeps the refusal
// code and never offers a wallet-paid fee.
func guidedPayoutStopped(ui setupPrompter, err error) error {
	clearSetupProgress(ui)
	code := managementErrorCode(err)
	remedy := "try again later from zkapi-clientd config --menu (choose withdraw)"
	if code == "bundler_unavailable" {
		remedy += ", or use your own ERC-4337 bundler with zkapi-clientd config --bundler-url URL"
	}
	return &managementError{message: fmt.Sprintf("the network fee cannot be paid from the payout now (%s). Nothing further was approved or signed; %s", payoutRefusal(err), remedy), code: code, scope: "withdrawal"}
}

// sponsoredWithdrawalStopped is the stop of a payout withdrawal whose
// approval no longer applies (a refusal the daemon does not retry within
// it): a new quote and approval are needed. It never points at a wallet-paid
// fee.
func sponsoredWithdrawalStopped(state zkapi.AddressWithdrawalStatus) error {
	return fmt.Errorf("the sponsored withdrawal stopped: %s. Its approval no longer applies and nothing further was signed; choose withdraw again in zkapi-clientd config --menu later to review a new quote", withoutWalletFeeAdvice(state.GaslessRefusal))
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
	if (!validWithdrawalTransactionHash(initial.TransactionHash) && !validWithdrawalTransactionHash(initial.UserOpHash) && !usableAuthorization(initial)) || initial.Destination == "" {
		return errors.New("saved withdrawal transaction is missing; preserve recovery files")
	}
	if usableAuthorization(initial) && initial.AuthorizedMaxFeeWei != "" && initial.AuthorizedMinNetPayoutWei != "" {
		clearSetupProgress(ui)
		ui.Printf("Continuing the approved withdrawal to %s within its maximum fee: at most %s ETH may be taken from the payout, and %s receives at least %s ETH. No new approval is needed.\n", initial.Destination, fundingUnits(initial.AuthorizedMaxFeeWei, 18), initial.Destination, fundingUnits(initial.AuthorizedMinNetPayoutWei, 18))
	}
	state, announced := initial, ""
	for {
		if !sameGuidedWithdrawalWallet(initial, state) || state.Amount != initial.Amount || !strings.EqualFold(state.Destination, initial.Destination) || !sameGuidedWithdrawalOperation(initial, state) {
			return errors.New("saved withdrawal changed during recovery; preserve recovery files")
		}
		progress := ""
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
			progress = "Withdrawal submitted; waiting for Ethereum finality (usually about 15 minutes). Ctrl+C preserves progress."
		case "op_built", "op_submitted", "forward_op_built", "forward_op_submitted":
			progress = "Sponsored operation sent to the bundler; waiting for inclusion and Ethereum finality (usually about 15 minutes). Ctrl+C preserves progress."
		case "quoted":
			// Approved, not yet signed: the next resume builds and sends it
			// within the authorization.
			if !usableAuthorization(state) {
				return errors.New("withdrawal needs attention; run zkapi-clientd config --menu to recover it; a reverted transaction is never retried automatically")
			}
			progress = "Sending the approved withdrawal within its maximum fee; this can take a few minutes. Ctrl+C preserves progress."
		case "gasless_refused":
			if !state.GaslessRetryable {
				clearSetupProgress(ui)
				return sponsoredWithdrawalStopped(state)
			}
			progress = fmt.Sprintf("The sponsored operation could not be sent yet (%s); waiting; your authorization still holds. Ctrl+C preserves progress.", withoutWalletFeeAdvice(state.GaslessRefusal))
		default:
			return errors.New("withdrawal needs attention; run zkapi-clientd config --menu to recover it; a reverted transaction is never retried automatically")
		}
		if progress != announced {
			setupProgress(ui, "%s", progress)
			announced = progress
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
			announced = "" // Restore the stage after a temporary status message.
		}
		state = next
	}
}
