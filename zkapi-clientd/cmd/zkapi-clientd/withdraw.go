package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

var errWithdrawalWaitStopped = errors.New("stopped waiting; the withdrawal may still be progressing; inspect saved status")

func runWithdrawal(ctx context.Context, c config.Config, args []string, out io.Writer) (result error) {
	submitted := false
	defer func() {
		if errors.Is(result, errFundingWaitStopped) {
			result = errWithdrawalWaitStopped
		}
		if result != nil && submitted {
			result = fmt.Errorf("%w; recover saved progress with zkapi-clientd config --menu, choose withdraw, and use the same --config-dir", result)
		}
	}()
	flags := flag.NewFlagSet("withdraw", flag.ContinueOnError)
	destinationText := flags.String("to", "", "destination for a full private-balance withdrawal quote, or saved transaction recovery")
	confirmationText := flags.String("confirm", "", "confirm an independently submitted matching withdrawal after a finalized local revert")
	approval := flags.String("approve", "", "approve the displayed withdrawal quote ID")
	resume := flags.Bool("resume", false, "recover a saved signed withdrawal, or continue one approved within its maximum fee, without authorizing anything new")
	escape := flags.Bool("escape", false, "withdraw by escape, without the operator: shows the decision, then --conceded quotes it")
	concededText := flags.String("conceded", "", "with --escape: the concession the escape decision showed, confirming it")
	earlyExitText := flags.String("early-exit", "", "with --escape: exit before a sent request can settle, conceding nothing or the state's bound (nothing|bound)")
	claim := flags.Bool("claim", false, "deliver an escape payout the vault credited to --to")
	cancel := flags.Bool("cancel", false, "with --escape: cancel an escape that released no exit proof, so chats resume")
	feesText := flags.String("fees", "", "how the network fee is paid. Where the deployment sponsors withdrawals, a new withdrawal pays it from the payout (payout, the only option; this wallet needs no ETH) and this flag is not needed. wallet (the local signing address) is only for a saved wallet-paid withdrawal, explicit recovery of a refused sponsored withdrawal, escapes, and deployments without sponsorship")
	feeCapGwei := flags.Uint64("fee-cap-gwei", 0, "for a fee paid from the payout: tightens the authorized maximum the payout may lose to the network fee and the paymaster's fee (for a contract destination, plus the credit surcharge of a failed push), in gwei; the approval binds it")
	bundlerText := flags.String("bundler-url", "", "for a fee paid from the payout: your own ERC-4337 bundler (HTTPS, or http:// to this machine); overrides zkapi.bundler_url and the deployment's bundler")
	allowExpensiveGas := flags.Bool("allow-expensive-gas", false, "for a fee paid from the payout: accept a fee above the deployment's uneconomic fraction of the payout")
	collect := flags.Bool("collect", false, "with --to: forward a payout waiting in the transit account with a sponsored operation (its fee is taken from the payout)")
	sweep := flags.Bool("sweep", false, "with --to: deliver a payout waiting in the transit account with a wallet-paid sweep (the account is created first when it has no code)")
	claimCredit := flags.Bool("claim-credit", false, "with --to: deliver a payout the paymaster credited (wallet-paid claimCredit)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	options, err := resolveGaslessOptions(c, *feesText, *feeCapGwei, *bundlerText, *allowExpensiveGas, *collect, *sweep, *claimCredit)
	if err != nil {
		return err
	}
	if *cancel {
		if !*escape || *claim || *approval != "" || *resume || *confirmationText != "" || *concededText != "" || *earlyExitText != "" || *destinationText != "" || flags.NArg() != 0 {
			return errors.New("use --escape --cancel alone")
		}
		return runEscapeCancel(ctx, c, out)
	}
	if *escape || *claim || *concededText != "" || *earlyExitText != "" {
		if *approval != "" || *resume || *confirmationText != "" || flags.NArg() != 0 || *destinationText == "" || (*escape && *claim) || (!*escape && (*concededText != "" || *earlyExitText != "")) || options.transitAction() {
			return errors.New("use --escape --to ADDRESS [--conceded AMOUNT] [--early-exit nothing|bound], or --claim --to ADDRESS (--collect, --sweep and --claim-credit go with --to alone)")
		}
		destination, err := zkapi.NormalizeWithdrawalDestination(*destinationText)
		if err != nil {
			return err
		}
		escapeFlow := escapeOptions{destination: destination, claim: *claim, gasless: options}
		if escapeFlow.earlyExit, err = parseEarlyExit(*earlyExitText); err != nil {
			return err
		}
		if *concededText != "" {
			conceded, err := strconv.ParseUint(*concededText, 10, 64)
			if err != nil {
				return errors.New("--conceded must be the concession in gwei that the escape decision showed")
			}
			escapeFlow.conceded = &conceded
		}
		return runEscape(ctx, c, escapeFlow, out)
	}
	emptyApproval := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "approve" && f.Value.String() == "" {
			emptyApproval = true
		}
	})
	if emptyApproval {
		return errors.New("approval ID cannot be empty")
	}
	if flags.NArg() != 0 || (*approval != "" && (*destinationText != "" || *confirmationText != "" || *resume)) || (*resume && (*destinationText != "" || *confirmationText != "")) {
		return errors.New("use --to ADDRESS, --approve QUOTE_ID, or --resume separately")
	}
	if options.transitAction() && (*destinationText == "" || *confirmationText != "" || *approval != "" || *resume) {
		return errors.New("use --collect, --sweep or --claim-credit with --to ADDRESS alone")
	}
	if (*collect && *sweep) || (*collect && *claimCredit) || (*sweep && *claimCredit) {
		return errors.New("use one of --collect, --sweep and --claim-credit")
	}
	destinationSet, confirmationSet := false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "to" {
			destinationSet = true
		}
		if f.Name == "confirm" {
			confirmationSet = true
		}
	})
	if confirmationSet && (!destinationSet || !validWithdrawalTransactionHash(*confirmationText)) {
		return errors.New("--confirm requires --to and a valid 32-byte transaction hash")
	}
	destination := ""
	if destinationSet {
		destination, err = zkapi.NormalizeWithdrawalDestination(*destinationText)
		if err != nil {
			return err
		}
	}
	if *approval != "" && !validQuoteID(*approval) {
		return errors.New("invalid quote ID")
	}
	c, err = activeFundingConfig(ctx, c)
	if err != nil {
		return err
	}
	if *approval != "" {
		// An escape quote (initiation, finalization or claim) is approved
		// through the escape route.
		if handled, err := approveEscapeQuote(ctx, c, *approval, out); handled || err != nil {
			submitted = handled
			return err
		}
	}
	state, err := requestWithdrawal(ctx, c, http.MethodGet, nil)
	if err != nil {
		return err
	}
	if daemonPredatesPayoutOnly(state) {
		// Only reading the status, following a withdrawal it already
		// signed and confirming a separately relayed payout go through an
		// older daemon; nothing new is quoted, approved or sent through it.
		readOnly := !destinationSet && *approval == "" && !*resume
		following := followsSignedWithdrawal(state) && *approval == "" && !options.transitAction()
		if !readOnly && !following && !confirmationSet {
			return errDaemonPredatesPayoutOnly
		}
		if readOnly {
			fmt.Fprintln(out, "Note: the running daemon was started by an older build; restart zkapi-clientd serve with this build before withdrawing.")
		}
	}
	noteID := state.NoteID
	if destinationSet && options.feesNamed && options.fees == "wallet" && state.NewWithdrawalFees == "payout" && !savedWithdrawal(state) && !options.transitAction() {
		// The payout pays a new withdrawal's fee on this deployment; the
		// daemon would refuse a wallet-paid quote, so none is requested.
		return errors.New("--fees wallet is not available for a new withdrawal on this deployment: the network fee is paid from the payout, so this wallet needs no ETH; rerun withdraw --to ADDRESS without --fees")
	}
	fmt.Fprintf(out, "%s withdrawal\nPrivate balance: %s ETH\nLocal signing address: %s\n", fundingNetwork(state.ChainID), fundingUnits(strconv.FormatUint(state.PrivateBalance, 10), 9), state.Address)
	if state.NewWithdrawalFees == "payout" && !walletBoundWithdrawal(state) {
		fmt.Fprintln(out, "Network fee: paid from the payout (this wallet needs no ETH)")
		if strings.TrimLeft(state.ETHBalance, "0") != "" {
			fmt.Fprintf(out, "Public ETH at the local signing address: %s ETH (not needed for this withdrawal)\n", fundingUnits(state.ETHBalance, 18))
		}
	} else {
		fmt.Fprintf(out, "Available for network fees: %s ETH\n", fundingUnits(state.ETHBalance, 18))
	}
	printWithdrawalProgress(out, state, "ETH")
	if !destinationSet && *approval == "" && !*resume {
		withdrawalResumeInstructions(out, state)
		return nil
	}
	if options.transitAction() {
		// A payout waiting in the transit account or the paymaster: quote
		// the operation or the wallet-paid transaction that delivers it.
		if state.Destination != "" && !strings.EqualFold(destination, state.Destination) {
			return errors.New("the saved withdrawal has another destination; use the saved destination")
		}
		body := map[string]any{"destination": destination, "note_id": noteID}
		options.apply(body, savedWithdrawal(state))
		quote, err := requestPaymentQuote(ctx, c, http.MethodPost, "/admin/withdrawal/quote", "", body)
		if err != nil {
			return err
		}
		printPaymentQuote(out, quote, "zkapi-clientd withdraw")
		return nil
	}
	if confirmationSet {
		if state.Phase == "confirming" || state.Phase == "complete" {
			if !strings.EqualFold(*confirmationText, state.TransactionHash) {
				return errors.New("resume with the same saved confirmation transaction; existing evidence cannot be replaced")
			}
		} else if state.Phase != "reverted" {
			return errors.New("--confirm is available only after the saved withdrawal finalized as reverted")
		}
	}
	if state.Phase == "complete" {
		if destination != "" && !strings.EqualFold(destination, state.Destination) {
			return errors.New("the completed withdrawal went to its saved destination; no new private balance is ready")
		}
		return nil
	}
	if state.Phase == "no_note" {
		return errors.New("there is no private balance to withdraw")
	}
	if state.Phase == "recovery_required" {
		return errors.New("withdrawal requires recovery; preserve the local funding and companion files")
	}
	if *resume {
		signed := (state.Phase == "withdrawal_pending" || state.Phase == "confirming" || zkapi.GaslessPendingPhase(state.Phase)) && (state.TransactionHash != "" || state.UserOpHash != "")
		if state.Destination == "" || (!signed && !usableAuthorization(state)) {
			return errors.New("no signed or approved withdrawal to resume; use --to to prepare and approve a quote")
		}
		destination = state.Destination
	}
	expectedAmount := state.Amount
	if *approval != "" {
		quote, err := requestPaymentQuote(ctx, c, http.MethodGet, "/admin/withdrawal/quote", "", nil)
		if err != nil {
			return err
		}
		if quote.ID != *approval || quote.NoteID != noteID {
			return errors.New("the saved quote or private note changed; review a fresh quote")
		}
		destination = quote.Destination
		expectedAmount = quote.Amount
		printPaymentQuote(out, quote, "zkapi-clientd withdraw")
		submitted = true
		state, err = requestWithdrawalPath(ctx, c, http.MethodPost, "/admin/withdrawal/approve", map[string]string{"quote_id": *approval})
		if managementErrorCode(err) == zkapi.CodeQuoteChanged {
			// Refused before the authorization was saved: nothing was
			// approved or signed.
			submitted = false
			return fmt.Errorf("%w; the quote expired or was replaced, and nothing was approved; rerun withdraw --to %s to review a new quote", err, destination)
		}
		if err != nil && quote.FeePolicy == "payout" {
			return withoutWalletFeeAdviceError(err)
		}
		if err != nil {
			return err
		}
	} else {
		if state.Phase != "ready" && state.Destination != "" && !strings.EqualFold(destination, state.Destination) {
			return errors.New("a withdrawal to a different destination is already saved; use the saved destination")
		}
		if confirmationSet {
			fmt.Fprintln(out, "Confirming the saved receipt; this does not authorize another transaction.")
			resuming := state.Phase == "confirming" && strings.EqualFold(*confirmationText, state.TransactionHash)
			if state.Phase != "reverted" && !resuming {
				return errors.New("--confirm is available only after the saved withdrawal finalized as reverted, or to resume its saved confirmation")
			}
			submitted = true
			state, err = requestWithdrawal(ctx, c, http.MethodPost, map[string]any{"destination": destination, "note_id": noteID, "confirmation_transaction_hash": *confirmationText})
			if err != nil {
				return err
			}
		} else if state.Phase == "withdrawal_pending" || state.Phase == "confirming" || zkapi.GaslessPendingPhase(state.Phase) || (usableAuthorization(state) && (*resume || !options.flagged)) {
			// A signed withdrawal is followed; one approved within its
			// maximum fee continues within it (rebuilt, re-signed or
			// re-proved by the daemon), unless new gasless options ask for a
			// new quote, whose approval replaces the authorization.
			if usableAuthorization(state) {
				fmt.Fprintln(out, "Continuing the approved withdrawal within its maximum fee; no new approval is needed.")
			}
			submitted = true
			state, err = requestWithdrawal(ctx, c, http.MethodPost, map[string]any{"destination": destination, "note_id": noteID})
			if err != nil {
				return err
			}
		} else {
			switch state.Phase {
			case "ready", "quoted", "waiting_settlement", "waiting_funds", "reverted", "gasless_refused", "op_reverted":
			default:
				return errors.New("unknown withdrawal status; no request was submitted")
			}
			body := map[string]any{"destination": destination, "note_id": noteID}
			if state.Phase == "reverted" {
				if !validWithdrawalTransactionHash(state.TransactionHash) {
					return errors.New("the reverted withdrawal has no valid saved transaction hash")
				}
				body["retry_transaction_hash"] = state.TransactionHash
			}
			if state.Phase == "op_reverted" {
				// A reverted operation is proved again only with its hash.
				if !validWithdrawalTransactionHash(state.UserOpHash) {
					return errors.New("the reverted operation has no valid saved hash")
				}
				body["retry_transaction_hash"] = state.UserOpHash
			}
			options.apply(body, savedWithdrawal(state))
			quote, err := requestPaymentQuote(ctx, c, http.MethodPost, "/admin/withdrawal/quote", "withdrawal", body)
			if managementErrorCode(err) == zkapi.CodeWalletFeesUnavailable {
				return fmt.Errorf("%w; the network fee of this withdrawal is paid from the payout (this wallet needs no ETH): rerun withdraw --to %s without --fees", err, destination)
			}
			if err != nil && state.NewWithdrawalFees == "payout" && !walletBoundWithdrawal(state) && !(options.feesNamed && options.fees == "wallet") {
				return withoutWalletFeeAdviceError(err)
			}
			if err != nil {
				return err
			}
			if quote.NoteID != noteID || !strings.EqualFold(quote.Destination, destination) {
				return errors.New("withdrawal quote changed the selected note or destination")
			}
			if quote.FeePolicy != "payout" && state.NewWithdrawalFees == "payout" && !walletBoundWithdrawal(state) && !(options.feesNamed && options.fees == "wallet") {
				// Never fall back to a wallet-paid fee the owner did not name.
				return errors.New("the daemon quoted a wallet-paid fee for a withdrawal whose fee is paid from the payout; nothing was approved")
			}
			printPaymentQuote(out, quote, "zkapi-clientd withdraw")
			return nil
		}
	}
	previous, waiting := "", false
	for {
		if state.NoteID != noteID || state.Amount != expectedAmount || (state.Destination != "" && !strings.EqualFold(destination, state.Destination)) {
			return errors.New("withdrawal response changed the selected note, amount, or destination; stopped polling")
		}
		progress := state.Phase + state.Message + state.TransactionHash
		if progress != previous {
			printWithdrawalProgress(out, state, "ETH")
			previous = progress
		}
		switch state.Phase {
		case "complete":
			return nil
		case "withdrawal_pending", "confirming", "op_built", "op_submitted", "forward_op_built", "forward_op_submitted":
		case "quoted":
			// Approved but not yet signed (for example a restart before
			// signing): the next request builds and sends it within the
			// authorization.
			if !usableAuthorization(state) {
				return errors.New("withdrawal stopped; preserve saved progress and follow the status message")
			}
		case "op_reverted":
			return errors.New("the sponsored operation reverted; follow the status message (withdraw --collect or --sweep when the payout waits in the transit account, or rerun --to to prove again)")
		case "gasless_refused":
			if !state.GaslessRetryable {
				return fmt.Errorf("the sponsored withdrawal stopped: %s; its approval no longer applies: rerun withdraw --to %s to review a new quote", withoutWalletFeeAdvice(state.GaslessRefusal), destination)
			}
			if !waiting {
				fmt.Fprintln(out, "Waiting; your authorization still holds, and the withdrawal is retried within its maximum fee (Ctrl+C stops waiting; withdraw --resume continues later).")
				waiting = true
			}
		case "waiting_settlement":
			return errors.New("withdrawal is waiting for the inference lease to settle; rerun --to to prepare a fresh quote afterward")
		case "waiting_funds":
			if !walletBoundWithdrawal(state) {
				return fmt.Errorf("withdrawal stopped: %s; rerun withdraw --to %s to review a new quote", state.Message, destination)
			}
			return errors.New("withdrawal needs ETH for fees; fund the signing address, then rerun --to for a fresh quote")
		case "reverted":
			return errors.New("withdrawal reverted; rerun --to to review and approve a fresh quote before another transaction")
		default:
			return errors.New("withdrawal stopped; preserve saved progress and follow the status message")
		}
		if err := waitFundingPoll(ctx); err != nil {
			return errWithdrawalWaitStopped
		}
		state, err = requestWithdrawal(ctx, c, http.MethodPost, map[string]any{"destination": destination, "note_id": noteID})
		if err != nil {
			return err
		}
	}
}

func printWithdrawalProgress(out io.Writer, state zkapi.AddressWithdrawalStatus, token string) {
	decimals := 6
	if state.BillingAsset == "native_eth" {
		decimals = 9
	}
	if state.Destination != "" && state.Phase != "ready" {
		fmt.Fprintf(out, "Saved withdrawal: %s %s to %s\n", fundingUnits(strconv.FormatUint(state.Amount, 10), decimals), token, state.Destination)
	}
	phase := state.Phase
	if state.PayoutCredited {
		phase = "payout credited, not delivered"
	}
	fmt.Fprintf(out, "%s: %s\n", phase, state.Message)
	if state.TransactionHash != "" {
		fmt.Fprintln(out, "Transaction:", state.TransactionHash)
	}
	if state.UserOpHash != "" {
		fmt.Fprintln(out, "Operation:", state.UserOpHash)
	}
	if state.TransitAccount != "" {
		fmt.Fprintf(out, "Fee: %s; transit account: %s\n", state.FeePayer, state.TransitAccount)
	}
	if state.GaslessAdvisory != "" {
		fmt.Fprintln(out, "Note:", state.GaslessAdvisory)
	}
	if state.AuthorizedMaxFeeWei != "" && state.AuthorizedMinNetPayoutWei != "" {
		fmt.Fprintf(out, "Approved: at most %s ETH may be taken from the payout; %s receives at least %s ETH\n", fundingUnits(state.AuthorizedMaxFeeWei, 18), state.Destination, fundingUnits(state.AuthorizedMinNetPayoutWei, 18))
		if state.EstimatedFeeWei != "" {
			fmt.Fprintf(out, "Latest fee estimate: about %s ETH (an estimate; the actual fee may change)\n", fundingUnits(state.EstimatedFeeWei, 18))
		}
	}
	if state.ReceivedWei != "" {
		fmt.Fprintf(out, "Received by the payout address: %s ETH (sponsored fee %s ETH, earlier debt paid %s ETH)\n", fundingUnits(state.ReceivedWei, 18), fundingUnits(zeroIfEmpty(state.ChargedWei), 18), fundingUnits(zeroIfEmpty(state.OwedPaidWei), 18))
	}
	if state.ActualFeeWei != "" {
		fmt.Fprintf(out, "Actual network fee: %s ETH\n", fundingUnits(state.ActualFeeWei, 18))
	}
	printEscapePayoutCredits(out, state.EscapePayoutCredits)
}

func withdrawalResumeInstructions(out io.Writer, state zkapi.AddressWithdrawalStatus) {
	switch state.Phase {
	case "complete", "no_note", "recovery_required":
		return
	}
	if state.Destination != "" && state.Phase != "ready" {
		if state.Phase == "withdrawal_pending" || state.Phase == "confirming" || zkapi.GaslessPendingPhase(state.Phase) {
			fmt.Fprintln(out, "To recover this signed withdrawal, run zkapi-clientd withdraw --resume (keep the same --config-dir if used).")
		} else if usableAuthorization(state) {
			fmt.Fprintln(out, "This withdrawal is approved within its maximum fee. To continue it, run zkapi-clientd withdraw --resume (keep the same --config-dir if used); no new approval is needed.")
		} else {
			fmt.Fprintf(out, "To quote this saved withdrawal again, run zkapi-clientd withdraw --to %s (keep the same --config-dir if used).\n", state.Destination)
		}
	} else {
		fmt.Fprintln(out, "To quote withdrawal of the full remaining balance, run zkapi-clientd withdraw --to ADDRESS, replacing ADDRESS with your Ethereum destination (keep the same --config-dir if used).")
	}
	fmt.Fprintln(out, "Showing this status does not authorize a transaction.")
}

func requestWithdrawal(ctx context.Context, c config.Config, method string, body any) (zkapi.AddressWithdrawalStatus, error) {
	return requestWithdrawalPath(ctx, c, method, "/admin/withdrawal", body)
}

func requestWithdrawalPath(ctx context.Context, c config.Config, method, path string, body any) (zkapi.AddressWithdrawalStatus, error) {
	var state zkapi.AddressWithdrawalStatus
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return state, errors.New("invalid local withdrawal request")
		}
	}
	timeout := 75 * time.Second
	if method == http.MethodPost {
		timeout = 10 * time.Minute
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+c.Listen+path, bytes.NewReader(payload))
	if err != nil {
		return state, errors.New("invalid local withdrawal request")
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("X-OA-Management-Token", c.ManagementToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return state, errWithdrawalWaitStopped
		}
		return state, errors.New("local withdrawal request did not complete; inspect saved status before continuing")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil && ctx.Err() != nil {
		return state, errWithdrawalWaitStopped
	}
	if err != nil || len(raw) > 16<<10 {
		return state, errors.New("invalid local withdrawal response; check saved status before retrying")
	}
	if response.StatusCode != http.StatusOK {
		// The refusal code (quote_changed, a gasless refusal) is kept for
		// the flows that act on it.
		var result struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(raw, &result) == nil && result.Error != "" {
			return state, &managementError{message: result.Error, code: result.Code, scope: "withdrawal"}
		}
		return state, errors.New("local withdrawal request failed; check saved status before retrying")
	}
	chain, err := zkapi.ChainID(c.ZKAPI.Network)
	if err != nil || json.Unmarshal(raw, &state) != nil || state.ChainID != chain || !validBillingAsset(state.BillingAsset, state.BillingUnit, state.WeiPerUnit, state.TokenAddress, state.TokenDecimals) || !fundingAddress(state.Address) || !fundingBalance(state.ETHBalance) || (state.ActualFeeWei != "" && !fundingBalance(state.ActualFeeWei)) {
		return state, errors.New("invalid local withdrawal address, token, or network")
	}
	if state.Destination != "" {
		if _, err := zkapi.NormalizeWithdrawalDestination(state.Destination); err != nil {
			return state, errors.New("invalid saved withdrawal destination")
		}
	} else if state.Phase == "withdrawal_pending" || state.Phase == "confirming" || state.Phase == "complete" || state.Phase == "reverted" || zkapi.GaslessPhase(state.Phase) {
		return state, errors.New("saved withdrawal destination is missing")
	}
	if state.TransactionHash != "" && !validWithdrawalTransactionHash(state.TransactionHash) {
		return state, errors.New("invalid saved withdrawal transaction")
	}
	if (state.UserOpHash != "" && !validWithdrawalTransactionHash(state.UserOpHash)) || (state.TransitAccount != "" && !fundingAddress(state.TransitAccount)) || (state.ReceivedWei != "" && !fundingBalance(state.ReceivedWei)) || (state.ChargedWei != "" && !fundingBalance(state.ChargedWei)) {
		return state, errors.New("invalid saved withdrawal operation")
	}
	if (state.NewWithdrawalFees != "" && state.NewWithdrawalFees != "payout" && state.NewWithdrawalFees != "wallet") || (state.AuthorizedMaxFeeWei != "" && !fundingBalance(state.AuthorizedMaxFeeWei)) || (state.AuthorizedMinNetPayoutWei != "" && !fundingBalance(state.AuthorizedMinNetPayoutWei)) || (state.EstimatedFeeWei != "" && !fundingBalance(state.EstimatedFeeWei)) || ((state.AuthorizedMaxFeeWei != "" || state.GaslessRetryable) && state.TransitAccount == "") {
		return state, errors.New("invalid withdrawal fee authorization")
	}
	return state, nil
}

func zeroIfEmpty(value string) string {
	if value == "" {
		return "0"
	}
	return value
}

// gaslessOptions are the gasless flags of a withdrawal command (design
// 3.3), resolved from the flags, then the configuration. No fee mode is the
// default: the daemon applies the deployment's policy (the payout pays a new
// withdrawal's fee where the deployment sponsors it, the only option there)
// and a saved withdrawal keeps its mode. feesNamed records that --fees was
// given on the command line: a named mode is always sent (a named "wallet"
// is a saved wallet-paid withdrawal, explicit recovery of a refused
// sponsored one, an escape, or a deployment without sponsorship; the daemon
// refuses it otherwise). A configured payout default is sent only for a new
// withdrawal; a configured wallet default is never sent. flagged records
// that any gasless option came from the command line, which asks for a new
// quote instead of continuing an approved withdrawal.
type gaslessOptions struct {
	fees              string
	feesNamed         bool
	flagged           bool
	feeCapGwei        uint64
	bundlerURL        string
	allowExpensiveGas bool
	collect           bool
	sweep             bool
	claimCredit       bool
}

func resolveGaslessOptions(c config.Config, fees string, feeCapGwei uint64, bundlerURL string, allowExpensiveGas, collect, sweep, claimCredit bool) (gaslessOptions, error) {
	feesNamed := fees != ""
	flagged := feesNamed || feeCapGwei != 0 || bundlerURL != "" || allowExpensiveGas
	if fees == "" {
		fees = c.ZKAPI.WithdrawalFees
	}
	if fees != "" && fees != "wallet" && fees != "payout" {
		return gaslessOptions{}, errors.New("--fees must be wallet or payout")
	}
	if !feesNamed && fees == "wallet" {
		fees = ""
	}
	if bundlerURL == "" {
		bundlerURL = c.ZKAPI.BundlerURL
	}
	if bundlerURL != "" {
		if err := zkapi.ValidateBundlerURL(bundlerURL); err != nil {
			return gaslessOptions{}, err
		}
	}
	return gaslessOptions{fees: fees, feesNamed: feesNamed, flagged: flagged, feeCapGwei: feeCapGwei, bundlerURL: bundlerURL, allowExpensiveGas: allowExpensiveGas, collect: collect, sweep: sweep, claimCredit: claimCredit}, nil
}

func (o gaslessOptions) transitAction() bool { return o.collect || o.sweep || o.claimCredit }

// apply adds the options a quote request carries. The fee mode is sent
// when --fees was named, or, for a configured payout default, only when no
// withdrawal is saved (saved): a plain rerun keeps the saved withdrawal's
// mode, so a record the owner moved to the wallet is not switched back to
// the sponsored path.
func (o gaslessOptions) apply(body map[string]any, saved bool) {
	if o.feesNamed || (o.fees == "payout" && !saved) {
		body["fees"] = o.fees
	}
	if o.bundlerURL != "" {
		body["bundler_url"] = o.bundlerURL
	}
	if o.feeCapGwei != 0 {
		body["fee_cap_gwei"] = o.feeCapGwei
	}
	if o.allowExpensiveGas {
		body["allow_expensive_gas"] = true
	}
	if o.collect {
		body["collect"] = true
	}
	if o.sweep {
		body["sweep"] = true
	}
	if o.claimCredit {
		body["claim_credit"] = true
	}
}

// savedWithdrawal reports a status with a saved withdrawal or escape (a
// reservation for its destination), whose fee mode a plain rerun keeps.
func savedWithdrawal(state zkapi.AddressWithdrawalStatus) bool {
	return state.Destination != "" && state.Phase != "ready" && state.Phase != "no_note"
}

// walletBoundWithdrawal reports a saved withdrawal whose fee the local
// signing address pays: one reserved wallet-paid (no transit account), as
// before sponsorship, or a sponsored one the owner moved to the wallet as
// explicit recovery. It keeps its wallet-paid flow (funding, QR, approval).
func walletBoundWithdrawal(state zkapi.AddressWithdrawalStatus) bool {
	return savedWithdrawal(state) && (state.TransitAccount == "" || state.FeePayer == "wallet")
}

// usableAuthorization reports a payout withdrawal whose bounded
// authorization still holds without a signed operation in flight: approved
// but unsigned (phase quoted, as after a restart before signing), or a
// refused attempt the daemon retries within the authorization. POST
// /admin/withdrawal continues it (rebuilding, re-signing, bumping the fee or
// re-proving within the maximum) without a new approval.
func usableAuthorization(state zkapi.AddressWithdrawalStatus) bool {
	if state.Destination == "" || state.TransitAccount == "" || state.FeePayer == "wallet" {
		return false
	}
	switch state.Phase {
	case "quoted":
		return state.AuthorizedMaxFeeWei != ""
	case "gasless_refused":
		return state.GaslessRetryable
	}
	return false
}

// withoutWalletFeeAdvice drops a refusal's advice to pay the fee from the
// wallet (older daemon messages end with "use --fees wallet"): a withdrawal
// whose fee the payout pays is never pointed at a wallet-paid fallback.
func withoutWalletFeeAdvice(reason string) string {
	var kept []string
	for _, clause := range strings.Split(reason, "; ") {
		if i := strings.Index(clause, ", or use --fees wallet"); i >= 0 {
			clause = clause[:i]
		}
		if clause != "" && !strings.Contains(clause, "--fees wallet") {
			kept = append(kept, clause)
		}
	}
	if len(kept) == 0 {
		return "the sponsored path refused it"
	}
	return strings.Join(kept, "; ")
}

// withoutWalletFeeAdviceError is a refusal of a withdrawal whose fee the
// payout pays, with its code, minus any advice to pay a wallet-paid fee.
func withoutWalletFeeAdviceError(err error) error {
	var failed *managementError
	if !errors.As(err, &failed) {
		return err
	}
	return &managementError{message: withoutWalletFeeAdvice(failed.message), code: failed.code, scope: failed.scope}
}

func validWithdrawalTransactionHash(value string) bool {
	if len(value) != 66 || !strings.HasPrefix(value, "0x") {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}
