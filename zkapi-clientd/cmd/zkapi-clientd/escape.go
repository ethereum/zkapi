package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// The escape withdrawal (design §6.4 E4, §6.7): an exit that needs no
// operator. The first run shows the decision (what the escape pays and
// concedes, and why); the owner confirms that concession with --conceded,
// which quotes the fee of initiateEscapeWithdrawal; --approve signs it.
// After the challenge period the same command quotes finalizeEscapeWithdrawal.
// --claim delivers a payout the vault credited.

type escapeOptions struct {
	destination string
	conceded    *uint64
	earlyExit   string
	claim       bool
	gasless     gaslessOptions
}

func parseEarlyExit(value string) (string, error) {
	switch value {
	case "":
		return "", nil
	case "nothing", "concede_nothing":
		return "concede_nothing", nil
	case "bound", "concede_bound":
		return "concede_bound", nil
	}
	return "", errors.New("--early-exit must be nothing or bound")
}

func runEscape(ctx context.Context, c config.Config, o escapeOptions, out io.Writer) error {
	c, err := activeFundingConfig(ctx, c)
	if err != nil {
		return err
	}
	if o.claim {
		quote, err := requestPaymentQuote(ctx, c, http.MethodPost, "/admin/escape/claim/quote", "escape_claim", map[string]any{"destination": o.destination})
		if err != nil {
			return err
		}
		printPaymentQuote(out, quote, "zkapi-clientd withdraw")
		return nil
	}
	state, err := requestWithdrawalPath(ctx, c, http.MethodGet, "/admin/escape", nil)
	if err != nil {
		return err
	}
	if state.Phase == "no_note" {
		return errors.New("there is no private balance to withdraw")
	}
	body := map[string]any{"destination": o.destination, "note_id": state.NoteID}
	o.gasless.apply(body, savedWithdrawal(state))
	if o.earlyExit != "" {
		body["early_exit"] = o.earlyExit
	}
	if o.conceded != nil {
		body["conceded"] = *o.conceded
		quote, err := requestPaymentQuote(ctx, c, http.MethodPost, "/admin/escape/quote", "escape", body)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Escape conceding %s ETH of the private balance; the payout is %s ETH unless the operator raises the concession, never beyond the state's bound.\n", fundingUnits(strconv.FormatUint(*o.conceded, 10), 9), fundingUnits(strconv.FormatUint(quote.Amount, 10), 9))
		printPaymentQuote(out, quote, "zkapi-clientd withdraw")
		return nil
	}
	state, err = requestWithdrawalPath(ctx, c, http.MethodPost, "/admin/escape", body)
	if err != nil {
		return err
	}
	printEscapeStatus(out, state)
	if state.Phase == "escape_initiated" && state.ChallengeDeadline != 0 && time.Now().Unix() > int64(state.ChallengeDeadline) {
		quote, err := requestPaymentQuote(ctx, c, http.MethodPost, "/admin/escape/quote", "escape_finalize", body)
		if err != nil {
			return err
		}
		printPaymentQuote(out, quote, "zkapi-clientd withdraw")
	}
	if state.Phase == "complete" && state.FundsWaitingInTransit {
		// Finalized by someone else: the sponsored forward of the payout
		// waiting in the transit account is quoted now.
		quote, err := requestPaymentQuote(ctx, c, http.MethodPost, "/admin/escape/quote", "withdrawal", body)
		if err != nil {
			return err
		}
		printPaymentQuote(out, quote, "zkapi-clientd withdraw")
	}
	return nil
}

// runEscapeCancel cancels an escape that released no exit proof (design
// §6.4 E6): the decision was only shown, or the escape waits for a request
// to settle. Requests from the note resume.
func runEscapeCancel(ctx context.Context, c config.Config, out io.Writer) error {
	c, err := activeFundingConfig(ctx, c)
	if err != nil {
		return err
	}
	state, err := requestWithdrawalPath(ctx, c, http.MethodPost, "/admin/escape/cancel", map[string]any{})
	if err != nil {
		return err
	}
	fmt.Fprintln(out, state.Message)
	return nil
}

func printEscapeStatus(out io.Writer, state zkapi.AddressWithdrawalStatus) {
	fmt.Fprintf(out, "Escape to %s\n", state.Destination)
	if state.StateBalance != 0 {
		fmt.Fprintf(out, "Private balance: %s ETH; concession: %s ETH (the state's bound: %s ETH); payout: %s ETH\n", fundingUnits(strconv.FormatUint(state.StateBalance, 10), 9), fundingUnits(strconv.FormatUint(state.Conceded, 10), 9), fundingUnits(strconv.FormatUint(state.BoundAtState, 10), 9), fundingUnits(strconv.FormatUint(state.Amount, 10), 9))
	}
	if state.Reason != "" {
		fmt.Fprintln(out, "Decision:", escapeReasonText(state.Reason))
	}
	printWithdrawalProgress(out, state, "ETH")
}

func escapeReasonText(reason string) string {
	switch reason {
	case "requested":
		return "you asked for an escape; nothing was sent from this state that the operator could charge"
	case "mutual_cutoff":
		return "too close to the note's expiry for a mutual close; the escape concedes nothing"
	case "mutual_refused":
		return "the operator refused or could not be reached for a mutual close; the escape concedes nothing"
	case "lost_epsilon":
		return "the operator settled this state for a request whose receipt cannot be installed; the escape concedes its reported charge"
	case "at_deadline":
		return "a request from this state never settled in time; the escape concedes its bound, so the request stays off chain"
	case "forced_early":
		return "you chose to exit before a sent request could settle"
	}
	return strings.ReplaceAll(reason, "_", " ")
}

// approveEscapeQuote approves a saved escape quote (initiation, finalization
// or claim) and follows the escape until it is on chain.
func approveEscapeQuote(ctx context.Context, c config.Config, id string, out io.Writer) (bool, error) {
	var saved *zkapi.AddressPaymentQuote
	if err := requestManagementJSON(ctx, c, http.MethodGet, "/admin/escape/quote", nil, &saved); err != nil {
		return false, err
	}
	if saved == nil || saved.ID != id {
		return false, nil
	}
	quote, err := requestPaymentQuote(ctx, c, http.MethodGet, "/admin/escape/quote", saved.Kind, nil)
	if err != nil {
		return true, err
	}
	printPaymentQuote(out, quote, "zkapi-clientd withdraw")
	state, err := requestWithdrawalPath(ctx, c, http.MethodPost, "/admin/escape/approve", map[string]string{"quote_id": id})
	if err != nil {
		return true, err
	}
	printEscapeStatus(out, state)
	if quote.Kind == "escape_claim" {
		return true, nil
	}
	previous := state.Phase
	for state.Phase == "escape_pending" || state.Phase == "finalize_pending" || zkapi.GaslessPendingPhase(state.Phase) {
		if err := waitFundingPoll(ctx); err != nil {
			return true, errWithdrawalWaitStopped
		}
		state, err = requestWithdrawalPath(ctx, c, http.MethodPost, "/admin/escape", map[string]any{"destination": state.Destination, "note_id": state.NoteID})
		if err != nil {
			return true, err
		}
		if state.Phase != previous {
			printEscapeStatus(out, state)
			previous = state.Phase
		}
	}
	return true, nil
}
