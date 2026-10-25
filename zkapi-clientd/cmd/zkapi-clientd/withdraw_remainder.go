package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// Complete both legs under one temporary runtime. A second transaction still
// requires review of its concrete amount/fee; no blanket remote quote approval.
func withdrawWithRemainder(ctx context.Context, c config.Config, ui setupPrompter) error {
	if err := runGuidedWithdrawal(ctx, c, ui); err != nil {
		return err
	}
	closed, err := requestWithdrawal(ctx, c, http.MethodGet, nil)
	if err != nil {
		return err
	}
	if closed.Phase == "no_note" {
		ui.Printf("No saved private withdrawal destination. Use zkapi-clientd withdraw --public to return public ETH.\n")
		return nil
	}
	if closed.Phase != "complete" {
		return errors.New("private withdrawal has not completed; public fee funds were not swept")
	}
	if closed.PayoutCredited || closed.PaymasterCredited || closed.FundsWaitingInTransit {
		return errors.New("private payout still needs collection; public fee funds were not swept; recover with withdraw --claim, --claim-credit, --collect or --sweep as appropriate")
	}
	destination, err := zkapi.NormalizeWithdrawalDestination(closed.Destination)
	if err != nil {
		return err
	}
	var state zkapi.AddressReturnStatus
	if err := requestManagementJSON(ctx, c, http.MethodGet, "/admin/return", nil, &state); err != nil {
		return err
	}
	action, err := remainderAction(closed, state)
	if err != nil {
		return err
	}
	switch action {
	case "done":
		ui.Printf("Public return already completed; no duplicate sweep. Any later funds or fee dust can be returned with zkapi-clientd withdraw --public.\n")
		return nil
	case "empty":
		if closed.FeePayer == "payout" {
			ui.Printf("No public ETH remains to return: the network fee was paid from the payout, and this wallet holds no ETH.\n")
			return nil
		}
		ui.Printf("No public ETH remains to return.\n")
		return nil
	case "resume":
		ui.Printf("Resuming the saved public ETH return to the withdrawal destination.\n")
		return runPublicReturn(ctx, c, []string{"--resume"}, setupUIWriter{ui})
	}
	quote, err := requestPaymentQuote(ctx, c, http.MethodPost, "/admin/return/quote", "return", map[string]string{"destination": destination, "amount_wei": ""})
	if returnBelowFee(err) {
		// Dust that cannot pay its own transfer is not a failure of the
		// withdrawal: nothing was signed, and later funds can join it.
		ui.Printf("The private withdrawal is complete. The remaining public ETH (%s ETH) does not cover the network fee of returning it, so nothing was sent; return it later with %s.\n", fundingUnits(state.ETHBalance, 18), publicReturnCommand)
		return nil
	}
	if err != nil {
		return fmt.Errorf("private withdrawal completed; public return could not be quoted; retry %s: %w", publicReturnCommand, err)
	}
	if !strings.EqualFold(quote.Destination, destination) || !strings.EqualFold(quote.Address, closed.Address) || quote.ChainID != closed.ChainID {
		return errors.New("public return quote changed wallet or destination; stopped without approval")
	}
	ui.Printf("Returning the remaining public ETH to the same withdrawal destination.\n")
	printPaymentQuote(setupUIWriter{ui}, quote, "")
	ok, err := ui.Confirm(ctx, "Authorize returning the remaining public ETH to this destination with the displayed maximum network fee")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("public return declined; private withdrawal is complete and public ETH remains recoverable with zkapi-clientd withdraw --public")
	}
	return runPublicReturn(ctx, c, []string{"--approve", quote.ID}, setupUIWriter{ui})
}

// returnBelowFee reports the daemon's refusal of a sweep whose balance does
// not exceed its maximum network fee (its "send more ETH" refusal).
func returnBelowFee(err error) bool {
	var failed *managementError
	return errors.As(err, &failed) && strings.Contains(failed.message, "send more ETH to the payment address for Ethereum network fees")
}

func remainderAction(closed zkapi.AddressWithdrawalStatus, state zkapi.AddressReturnStatus) (string, error) {
	if closed.Phase != "complete" || closed.PayoutCredited || closed.PaymasterCredited || closed.FundsWaitingInTransit || !strings.EqualFold(closed.Address, state.Address) || closed.ChainID != state.ChainID || !fundingBalance(state.ETHBalance) {
		return "", errors.New("public return status does not match completed withdrawal")
	}
	if state.Phase == "return_pending" || state.Phase == "confirming" || state.Phase == "complete" {
		if !strings.EqualFold(state.Destination, closed.Destination) {
			return "", errors.New("a saved public return uses another destination; recover it with withdraw --public")
		}
		if state.Phase == "complete" {
			return "done", nil
		}
		return "resume", nil
	}
	if state.Phase != "ready" && state.Phase != "quoted" {
		return "", errors.New("public return needs explicit recovery with withdraw --public")
	}
	if state.ETHBalance == "0" {
		return "empty", nil
	}
	return "quote", nil
}
