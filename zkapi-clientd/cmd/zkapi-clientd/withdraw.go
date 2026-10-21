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
	resume := flags.Bool("resume", false, "recover a saved signed withdrawal without authorizing a new transaction")
	escape := flags.Bool("escape", false, "withdraw by escape, without the operator: shows the decision, then --conceded quotes it")
	concededText := flags.String("conceded", "", "with --escape: the concession the escape decision showed, confirming it")
	earlyExitText := flags.String("early-exit", "", "with --escape: exit before a sent request can settle, conceding nothing or the state's bound (nothing|bound)")
	claim := flags.Bool("claim", false, "deliver an escape payout the vault credited to --to")
	cancel := flags.Bool("cancel", false, "with --escape: cancel an escape that released no exit proof, so chats resume")
	feesText := flags.String("fees", "", "how the network fee is paid: wallet (the local signing address; the default, or zkapi.withdrawal_fees) or payout (a sponsored operation paid from the payout; the payout address needs no ETH)")
	feeCapGwei := flags.Uint64("fee-cap-gwei", 0, "with --fees payout: the most the payout may lose to the network fee and the paymaster's flat fee (for a contract destination, plus the credit surcharge of a failed push), in gwei")
	bundlerText := flags.String("bundler-url", "", "with --fees payout: your own ERC-4337 bundler (HTTPS, or http:// to this machine); overrides zkapi.bundler_url and the deployment's bundler")
	allowExpensiveGas := flags.Bool("allow-expensive-gas", false, "with --fees payout: accept a sponsored fee above the deployment's uneconomic fraction of the payout")
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
	noteID := state.NoteID
	fmt.Fprintf(out, "%s withdrawal\nPrivate balance: %s ETH\nLocal signing address: %s\nAvailable for network fees: %s ETH\n", fundingNetwork(state.ChainID), fundingUnits(strconv.FormatUint(state.PrivateBalance, 10), 9), state.Address, fundingUnits(state.ETHBalance, 18))
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
		if (state.Phase != "withdrawal_pending" && state.Phase != "confirming" && !zkapi.GaslessPendingPhase(state.Phase)) || state.Destination == "" || (state.TransactionHash == "" && state.UserOpHash == "") {
			return errors.New("no signed withdrawal to resume; use --to to prepare and approve a quote")
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
		} else if state.Phase == "withdrawal_pending" || state.Phase == "confirming" || zkapi.GaslessPendingPhase(state.Phase) {
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
			if err != nil {
				return err
			}
			if quote.NoteID != noteID || !strings.EqualFold(quote.Destination, destination) {
				return errors.New("withdrawal quote changed the selected note or destination")
			}
			printPaymentQuote(out, quote, "zkapi-clientd withdraw")
			return nil
		}
	}
	previous := ""
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
		case "op_reverted":
			return errors.New("the sponsored operation reverted; follow the status message (withdraw --collect or --sweep when the payout waits in the transit account, or rerun --to to prove again)")
		case "gasless_refused":
			return errors.New("the gasless path stopped: " + state.GaslessRefusal + "; rerun --to to try again, or --to with --fees wallet to pay the fee from the local signing address")
		case "waiting_settlement":
			return errors.New("withdrawal is waiting for the inference lease to settle; rerun --to to prepare a fresh quote afterward")
		case "waiting_funds":
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
		var result struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &result) == nil && result.Error != "" {
			return state, fmt.Errorf("withdrawal: %s", result.Error)
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
	if (state.UserOpHash != "" && !validWithdrawalTransactionHash(state.UserOpHash)) || (state.TransitAccount != "" && !fundingAddress(state.TransitAccount)) || (state.ReceivedWei != "" && !fundingBalance(state.ReceivedWei)) {
		return state, errors.New("invalid saved withdrawal operation")
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
// 3.3), resolved from the flags, then the configuration. feesNamed records
// that --fees was given on the command line: a named mode is always sent to
// the daemon (a named "wallet" falls a saved sponsored withdrawal back to
// the wallet-paid path, a named "payout" takes it back), while the
// configured default is sent only for a new withdrawal (a plain rerun keeps
// a saved withdrawal's fee mode, whatever zkapi.withdrawal_fees says).
type gaslessOptions struct {
	fees              string
	feesNamed         bool
	feeCapGwei        uint64
	bundlerURL        string
	allowExpensiveGas bool
	collect           bool
	sweep             bool
	claimCredit       bool
}

func resolveGaslessOptions(c config.Config, fees string, feeCapGwei uint64, bundlerURL string, allowExpensiveGas, collect, sweep, claimCredit bool) (gaslessOptions, error) {
	feesNamed := fees != ""
	if fees == "" {
		fees = c.ZKAPI.WithdrawalFees
	}
	if fees == "" {
		fees = "wallet"
	}
	if fees != "wallet" && fees != "payout" {
		return gaslessOptions{}, errors.New("--fees must be wallet or payout")
	}
	if bundlerURL == "" {
		bundlerURL = c.ZKAPI.BundlerURL
	}
	if bundlerURL != "" {
		if err := zkapi.ValidateBundlerURL(bundlerURL); err != nil {
			return gaslessOptions{}, err
		}
	}
	return gaslessOptions{fees: fees, feesNamed: feesNamed, feeCapGwei: feeCapGwei, bundlerURL: bundlerURL, allowExpensiveGas: allowExpensiveGas, collect: collect, sweep: sweep, claimCredit: claimCredit}, nil
}

func (o gaslessOptions) transitAction() bool { return o.collect || o.sweep || o.claimCredit }

// apply adds the options a quote request carries. The fee mode is sent
// when --fees was named, or, for a configured payout default, only when no
// withdrawal is saved (saved): a plain rerun keeps the saved withdrawal's
// mode, so a record the owner moved to the wallet is not switched back to
// the sponsored path. The wallet default adds nothing.
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

func validWithdrawalTransactionHash(value string) bool {
	if len(value) != 66 || !strings.HasPrefix(value, "0x") {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}
