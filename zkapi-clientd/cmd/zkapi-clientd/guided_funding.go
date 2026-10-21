package main

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// The wizard uses the same owner-authenticated quote/approval endpoints as
// manual funding. It never reads signing keys or signs transactions itself.
type guidedFundingService interface {
	Readiness(context.Context) (zkapi.WalletReadiness, error)
	Address(context.Context) (zkapi.AddressFundingStatus, error)
	Withdrawal(context.Context) (zkapi.AddressWithdrawalStatus, error)
	Quote(context.Context, uint64, uint64) (zkapi.AddressPaymentQuote, error)
	Approve(context.Context, string) (zkapi.AddressFundingStatus, error)
	Resume(context.Context, uint64) (zkapi.AddressFundingStatus, error)
}

type localGuidedFunding struct {
	config config.Config
	wallet *zkapi.Client
}

func (s localGuidedFunding) Readiness(ctx context.Context) (zkapi.WalletReadiness, error) {
	return s.wallet.Readiness(ctx)
}
func (s localGuidedFunding) Address(ctx context.Context) (zkapi.AddressFundingStatus, error) {
	return requestFunding(ctx, s.config, http.MethodGet, "/admin/funding/address", nil)
}
func (s localGuidedFunding) Withdrawal(ctx context.Context) (zkapi.AddressWithdrawalStatus, error) {
	return requestWithdrawal(ctx, s.config, http.MethodGet, nil)
}
func (s localGuidedFunding) Quote(ctx context.Context, amount, usd uint64) (zkapi.AddressPaymentQuote, error) {
	body := map[string]uint64{"amount": amount}
	if usd != 0 {
		body = map[string]uint64{"micro_usd": usd}
	}
	return requestPaymentQuote(ctx, s.config, http.MethodPost, "/admin/funding/quote", "deposit", body)
}
func (s localGuidedFunding) Approve(ctx context.Context, id string) (zkapi.AddressFundingStatus, error) {
	return requestFunding(ctx, s.config, http.MethodPost, "/admin/funding/approve", map[string]string{"quote_id": id})
}
func (s localGuidedFunding) Resume(ctx context.Context, amount uint64) (zkapi.AddressFundingStatus, error) {
	return requestFunding(ctx, s.config, http.MethodPost, "/admin/funding/deposit", map[string]uint64{"amount": amount})
}

func runGuidedFunding(ctx context.Context, c config.Config, usdText, _ string, ui setupPrompter) error {
	transport, err := relay.NewClient(c.RelayURL)
	if err != nil {
		return err
	}
	wallet, err := zkapi.New(zkConfig(c, transport))
	if err != nil {
		return err
	}
	return guidedFunding(ctx, localGuidedFunding{c, wallet}, usdText, ui, waitFundingPoll)
}

// A fixed label: the daemon's detailed status stays out of the guided output.
var errGuidedDepositConflict = errors.New("deposit needs attention: the payment RPC, the vault state, and the zkAPI indexer disagree about this mined deposit, so its private note was not activated; the funds stay on chain. Run zkapi-clientd config again to re-check. If this persists, compare the transaction on a block explorer and run zkapi-clientd config --menu, then choose repair")

// A conflict about an earlier, retired deposit can clear on re-check; no
// deposit is saved then, so there is nothing to resume.
var errGuidedDepositRechecked = errors.New("the zkAPI indexer no longer shows the earlier deposit and no deposit is saved; run zkapi-clientd config again to review a new deposit quote")

// runGuidedRepair binds the saved deposit to the vault note that finalized
// vault state and the zkAPI indexer agree holds it, through the
// owner-authenticated rebind endpoint. The daemon verifies everything itself
// and never changes the deposit's secret, commitment, or amount.
func runGuidedRepair(ctx context.Context, c config.Config, ui setupPrompter) error {
	ui.Printf("Repair binds the saved deposit to the vault note that finalized vault state and the zkAPI indexer agree holds it. It never changes the deposit's secret, commitment, or amount.\n")
	noteText, err := ui.Ask(ctx, "Vault note ID that holds the deposit (blank to find it from the saved transaction)", "")
	if err != nil {
		return err
	}
	replaceText, err := ui.Ask(ctx, "Unspent companion note ID to replace (blank if none)", "")
	if err != nil {
		return err
	}
	body := map[string]uint64{}
	for name, text := range map[string]string{"note_id": strings.TrimSpace(noteText), "replace_note_id": strings.TrimSpace(replaceText)} {
		if text == "" {
			continue
		}
		id, err := parseNoteID(text)
		if err != nil {
			return err
		}
		body[name] = id
	}
	approved, err := ui.Confirm(ctx, "Repair the saved deposit's note binding")
	if err != nil {
		return err
	}
	if !approved {
		return errors.New("repair canceled; nothing was changed")
	}
	state, err := requestFunding(ctx, c, http.MethodPost, "/admin/funding/rebind", body)
	if err != nil {
		return err
	}
	if state.Phase != "active" {
		return errors.New("repair did not activate the private balance; " + state.Message)
	}
	ui.Printf("Deposit note binding repaired. Private inference balance activated.\n")
	return nil
}

func setupUSD(amount uint64) string {
	return strings.TrimRight(strings.TrimRight(fundingUnits(strconv.FormatUint(amount, 10), 6), "0"), ".")
}

const defaultSetupDepositMicroUSD uint64 = 20_000_000

func chooseSetupDepositUSD(ctx context.Context, usdText string, ui setupPrompter) (uint64, error) {
	interactive := usdText == ""
	for {
		if interactive {
			var err error
			usdText, err = ui.Ask(ctx, "Deposit amount in USD (network fees are extra)", setupUSD(defaultSetupDepositMicroUSD))
			if err != nil {
				return 0, err
			}
		}
		usd, err := parseFundingAmountForAsset(usdText, 6, "USD")
		if err == nil || !interactive {
			return usd, err
		}
		ui.Printf("%s. Please enter a deposit amount in USD.\n", err)
	}
}

func guidedFunding(ctx context.Context, service guidedFundingService, usdText string, ui setupPrompter, wait func(context.Context) error) error {
	defer clearSetupProgress(ui)
	setupProgress(ui, "Checking wallet status...")
	ready, err := waitSetupWallet(ctx, service, ui, wait)
	if err != nil {
		return err
	}
	if ready.HasNote {
		return checkSetupBalance(ready, ui)
	}

	state, err := service.Address(ctx)
	if err != nil {
		return err
	}
	if state.BillingAsset != "native_eth" {
		return errors.New("this setup requires the native ETH deployment")
	}
	switch state.Phase {
	case "deposit_pending", "confirming":
		ui.Printf("Resuming your saved deposit; no new deposit will be created.\n")
		if err := finishGuidedDeposit(ctx, service, state, ui, wait); err != nil {
			return err
		}
	case "verification_conflict":
		// A saved conflict is never terminal: resuming re-reads the receipt
		// and verifies it again against the vault and the zkAPI indexer.
		ui.Printf("Re-verifying your saved deposit; no new deposit will be created.\n")
		next, err := service.Resume(ctx, state.Amount)
		if err != nil {
			return err
		}
		if next.Phase == "verification_conflict" {
			return errGuidedDepositConflict
		}
		if next.TransactionHash == "" && (next.Phase == "ready" || next.Phase == "waiting_funds") {
			return errGuidedDepositRechecked
		}
		if err := finishGuidedDeposit(ctx, service, next, ui, wait); err != nil {
			return err
		}
	case "ready", "waiting_funds":
		if state.TransactionHash != "" {
			return errors.New("a saved transaction needs recovery; run zkapi-clientd config before continuing")
		}
		if err := showSetupEscapePayoutCredits(ctx, service, state, ui); err != nil {
			return err
		}
		var usd uint64
		if state.Amount == 0 {
			usd, err = chooseSetupDepositUSD(ctx, usdText, ui)
			if err != nil {
				return err
			}
			ui.Printf("Selected deposit: $%s (network fees are extra).\n", setupUSD(usd))
		} else {
			ui.Printf("Resuming the saved fixed deposit of %s ETH.\n", fundingUnits(strconv.FormatUint(state.Amount, 10), 9))
			if usdText != "" {
				ui.Printf("The --usd option applies only to a new deposit; the saved amount is preserved.\n")
			}
		}
		setupProgress(ui, "Preparing your deposit quote from the current ETH price and network fees...")
		quote, err := service.Quote(ctx, state.Amount, usd)
		if err != nil {
			return err
		}
		if (usd != 0 && quote.InputMicroUSD != usd) || (state.Amount != 0 && quote.Amount != state.Amount) || !strings.EqualFold(quote.Address, state.Address) || quote.ChainID != state.ChainID || quote.DeploymentID != state.DeploymentID {
			return errors.New("deposit quote changed the selected wallet or amount; stopped setup")
		}
		if err := waitAndDeposit(ctx, service, quote, ui, wait); err != nil {
			return err
		}
	default:
		return errors.New("saved funding needs attention; run zkapi-clientd config with the same configuration before restarting setup")
	}
	ready, err = waitSetupWallet(ctx, service, ui, wait)
	if err != nil {
		return err
	}
	if !ready.HasNote {
		return errors.New("deposit recovery did not activate the private balance; run zkapi-clientd config with the same configuration")
	}
	return checkSetupBalance(ready, ui)
}

// showSetupEscapePayoutCredits names every escape payout the vault credited
// instead of paying before a new deposit: the deposit replaces a credited
// withdrawal's record (its credit is then listed in the funding status), and
// nothing has reached those destinations until someone claims the credit.
func showSetupEscapePayoutCredits(ctx context.Context, service guidedFundingService, state zkapi.AddressFundingStatus, ui setupPrompter) error {
	withdrawal, err := service.Withdrawal(ctx)
	if err != nil {
		return err
	}
	if withdrawal.Phase == "complete" && withdrawal.PayoutCredited {
		ui.Printf("Unclaimed escape payout: %s\n", withdrawal.Message)
	}
	for _, credit := range state.EscapePayoutCredits {
		ui.Printf("Unclaimed escape payout: %s\n", credit.Message)
	}
	return nil
}

func waitSetupWallet(ctx context.Context, service guidedFundingService, ui setupPrompter, wait func(context.Context) error) (zkapi.WalletReadiness, error) {
	defer clearSetupProgress(ui)
	waiting := false
	for {
		state, err := service.Readiness(ctx)
		if err != nil {
			return state, err
		}
		withdrawal, err := service.Withdrawal(ctx)
		if err != nil {
			return state, err
		}
		switch withdrawal.Phase {
		case "no_note", "ready", "waiting_settlement", "complete":
		default:
			return state, errors.New("a withdrawal needs attention; run zkapi-clientd config --menu and choose withdraw before restarting setup")
		}
		if state.WithdrawalPending {
			return state, errors.New("a private withdrawal is reserved; run zkapi-clientd config --menu and choose withdraw to recover it")
		}
		if !state.PendingRequest && withdrawal.Phase != "waiting_settlement" {
			return state, nil
		}
		if !waiting {
			setupProgress(ui, "Waiting for your previous inference to settle; checking automatically.")
			waiting = true
		}
		if err := wait(ctx); err != nil {
			return state, err
		}
	}
}

// Wallet setup is independent of model choice. Inference checks the selected
// model's request cap against the current private balance on every request.
func checkSetupBalance(state zkapi.WalletReadiness, ui setupPrompter) error {
	if state.Balance == 0 {
		return errors.New("the private balance is empty; choose withdraw in zkapi-clientd config --menu to close this note before adding funding")
	}
	ui.Printf("Private balance: %s ETH.\n", fundingUnits(strconv.FormatUint(state.Balance, 10), 9))
	return nil
}

func sameSetupDeposit(a, b zkapi.AddressPaymentQuote) bool {
	return a.Kind == "deposit" && b.Kind == a.Kind && a.ChainID == b.ChainID && a.DeploymentID == b.DeploymentID && strings.EqualFold(a.Contract, b.Contract) && strings.EqualFold(a.Address, b.Address) && a.Amount == b.Amount && a.PrincipalWei == b.PrincipalWei && a.Commitment != "" && a.Commitment == b.Commitment && a.Nonce == b.Nonce && a.RetryHash == "" && b.RetryHash == "" && b.Destination == "" && b.NoteID == 0
}

func setupFeeWithin(quote zkapi.AddressPaymentQuote, maximum string) bool {
	fee, ok := new(big.Int).SetString(quote.FeeReserveWei, 10)
	cap, valid := new(big.Int).SetString(maximum, 10)
	return ok && valid && fee.Sign() >= 0 && cap.Sign() >= 0 && fee.Cmp(cap) <= 0
}

// Compare only the displayed amount, not sub-display fee/balance movements.
// Becoming funded also clears any stale payment card.
func depositPaymentDisplayKey(q zkapi.AddressPaymentQuote) string {
	if q.ShortfallWei == "0" {
		return ""
	}
	return minimumETH(q.RecommendedTopUpWei)
}

func showSetupDeposit(ui setupPrompter, q zkapi.AddressPaymentQuote) error {
	return showSetupDepositPayment(ui, q, false)
}

func showSetupDepositPayment(ui setupPrompter, q zkapi.AddressPaymentQuote, updated bool) error {
	// Validate the payment quantities before displaying even the text address
	// and amount, so an inconsistent quote cannot invite an incorrect transfer.
	uri, err := paymentRequestURI(q)
	if err != nil {
		return err
	}
	if uri == "" {
		setupPayment(ui, "")
		return nil
	}
	var payment strings.Builder
	if updated {
		payment.WriteString("\nPayment information updated.\n")
	}
	if err := printSetupPaymentQR(&payment, q); err != nil {
		return err
	}
	setupPayment(ui, payment.String())
	return nil
}

func waitAndDeposit(ctx context.Context, service guidedFundingService, initial zkapi.AddressPaymentQuote, ui setupPrompter, wait func(context.Context) error) error {
	defer clearSetupProgress(ui)
	if !sameSetupDeposit(initial, initial) {
		return errors.New("saved deposit requires explicit recovery; it cannot be automatically funded")
	}
	if _, err := paymentRequestURI(initial); err != nil {
		return err
	}
	if _, automatic := ui.(automaticDepositUI); automatic {
		ui.Printf("Watching the receiving account on %s at %s; checking every five seconds. Once enough ETH arrives, serve automatically opens the note. Ctrl+C preserves progress.\n", fundingNetwork(initial.ChainID), initial.Address)
	} else {
		ui.Printf("Watching the receiving account on %s at %s; checking every five seconds. Once enough ETH arrives, press Enter to continue with the deposit. Ctrl+C preserves progress.\n", fundingNetwork(initial.ChainID), initial.Address)
	}
	if err := showSetupDeposit(ui, initial); err != nil {
		return err
	}
	showSetupFundingProgress(ui, initial)
	lastProgress := setupFundingProgressKey(initial)
	displayed := initial
	approved, retrying, approvalWaiting := false, false, false
	sweepSized := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Refresh the fixed principal while waiting and again after Enter so a
		// potentially long terminal pause never approves an expired quote.
		quote, err := service.Quote(ctx, initial.Amount, 0)
		if err != nil {
			// Another owner command may have advanced the journal. A failed
			// quote never authorizes a different saved operation.
			state, statusErr := service.Address(ctx)
			if statusErr == nil {
				if !sameSetupFunding(state, initial) {
					return errors.New("saved funding changed while waiting; stopped setup")
				}
				switch state.Phase {
				case "deposit_pending", "confirming", "active":
					if !validWithdrawalTransactionHash(state.TransactionHash) {
						return errors.New("saved deposit transaction is missing; preserve recovery files")
					}
					return finishGuidedDeposit(ctx, service, state, ui, wait)
				case "ready", "waiting_funds":
					if state.TransactionHash != "" {
						return errors.New("saved funding has inconsistent transaction state; preserve recovery files")
					}
				case "verification_conflict":
					// An earlier deposit of this note shows on chain after all.
					return errGuidedDepositConflict
				default:
					return errors.New("saved funding needs attention; run zkapi-clientd config before continuing")
				}
			}
			if !retrying {
				setupProgress(ui, "Could not refresh the funding quote; retrying without authorizing a transaction.")
				retrying = true
			}
			lastProgress = ""
			if err := wait(ctx); err != nil {
				return err
			}
			continue
		}
		retrying = false
		if !sameSetupDeposit(initial, quote) {
			return errors.New("the saved deposit changed while waiting; stopped without approving another transaction")
		}
		if _, err := paymentRequestURI(quote); err != nil {
			return err
		}
		if depositPaymentDisplayKey(quote) != depositPaymentDisplayKey(displayed) {
			if err := showSetupDepositPayment(ui, quote, true); err != nil {
				return err
			}
			displayed = quote
		}
		progress := setupFundingProgressKey(quote)
		if progress != lastProgress {
			showSetupFundingProgress(ui, quote)
			lastProgress = progress
		}
		balance, _ := new(big.Int).SetString(quote.BalanceWei, 10)
		required, _ := new(big.Int).SetString(quote.RequiredTotalWei, 10)
		if balance.Cmp(required) >= 0 {
			if _, automatic := ui.(automaticDepositUI); automatic && !sweepSized {
				resized, err := maximizeUnsignedDeposit(ctx, service, quote)
				if err != nil {
					return err
				}
				sweepSized = true
				if resized.Amount != quote.Amount {
					// The new commitment is now the fixed intent checked by every
					// refresh, approval and recovery step below.
					initial = resized
					continue
				}
			}
			if !approved {
				clearSetupProgress(ui)
				ui.Printf("Ready to deposit %s ETH. Current maximum network fee: %s ETH.\n", fundingUnits(quote.PrincipalWei, 18), fundingUnits(quote.FeeReserveWei, 18))
				ui.Printf("Network fees adjust automatically while the receiving balance covers this deposit and its fees.\n")
				proceed, err := ui.Continue(ctx, "Press Enter to continue with this deposit, or type cancel")
				if err != nil {
					return err
				}
				if !proceed {
					return errors.New("deposit declined; no transaction was authorized")
				}
				approved = true
				continue // Recheck identity, balance, and fees after terminal input.
			}
			// Enter covers fresh, affordable fees for this same fixed deposit.
			// The signer still enforces this quote's ceiling and current balance.
			setupProgress(ui, "Preparing deposit of %s ETH...", fundingUnits(quote.PrincipalWei, 18))
			state, approveErr := service.Approve(ctx, quote.ID)
			if approveErr != nil {
				// An HTTP error does not tell us whether signing committed.
				// The serialized address read waits for any in-flight signing
				// operation before exposing its durable journal. Never retry an
				// approval until that read establishes a safely unsigned intent.
				setupProgress(ui, "Checking saved deposit progress after an interrupted response.")
				state, err = readGuidedDeposit(ctx, service, ui, wait)
				if err != nil {
					return err
				}
			}
			if !sameSetupFunding(state, initial) {
				return errors.New("saved deposit no longer matches the approved amount or wallet; preserve its recovery files")
			}
			switch state.Phase {
			case "deposit_pending", "confirming", "active":
				if !validWithdrawalTransactionHash(state.TransactionHash) {
					return errors.New("saved deposit transaction is missing; preserve recovery files")
				}
				return finishGuidedDeposit(ctx, service, state, ui, wait)
			case "ready", "waiting_funds":
				if state.TransactionHash != "" {
					return errors.New("saved funding has inconsistent transaction state; preserve recovery files")
				}
				currentBalance, valid := new(big.Int).SetString(state.ETHBalance, 10)
				if !valid || currentBalance.Sign() < 0 || currentBalance.BitLen() > 256 {
					return errors.New("saved funding returned an invalid receiving balance; preserve recovery files")
				}
				if currentBalance.Cmp(required) < 0 {
					ui.Printf("The receiving balance no longer covers the deposit and fees. Waiting for ETH again; press Enter again once funded.\n")
					approved = false
				}
				if !approvalWaiting {
					setupProgress(ui, "No deposit transaction was sent. Refreshing the receiving balance and network fees automatically.")
					approvalWaiting = true
				}
				lastProgress = ""
				// Approval can lose its fee quote or funding before signing. Keep
				// the same principal, commitment and nonce: the next fresh quote
				// must pass sameSetupDeposit and fit the receiving balance again.
				// Yield even when funding still looks sufficient so a repeated
				// unsigned response cannot create a tight approval retry loop.
				if err := wait(ctx); err != nil {
					return err
				}
				continue
			case "verification_conflict":
				return errGuidedDepositConflict
			default:
				return errors.New("saved funding needs attention; run zkapi-clientd config before continuing (a reverted transaction is never retried automatically)")
			}
		}
		if approved {
			ui.Printf("The receiving balance no longer covers the deposit and fees. Waiting for ETH again; press Enter again once funded.\n")
			approved = false
			// A durable warning gives the terminal back to the transcript;
			// restore the live wait even if the next quote is unchanged.
			showSetupFundingProgress(ui, quote)
		}
		if err := wait(ctx); err != nil {
			return err
		}
	}
}

func showSetupFundingProgress(ui setupPrompter, quote zkapi.AddressPaymentQuote) {
	if quote.ShortfallWei == "0" {
		setupProgress(ui, "Funds available. Receiving account balance: %s ETH.", fundingUnits(quote.BalanceWei, 18))
		return
	}
	// The payment card already shows the amount to send. Also clear a stale
	// retry message when a refreshed quote becomes available.
	clearSetupProgress(ui)
}

func setupFundingProgressKey(quote zkapi.AddressPaymentQuote) string {
	return quote.BalanceWei + ":" + quote.ShortfallWei + ":" + quote.FeeReserveWei
}

func sameSetupFunding(state zkapi.AddressFundingStatus, quote zkapi.AddressPaymentQuote) bool {
	return state.BillingAsset == "native_eth" && state.ChainID == quote.ChainID && state.DeploymentID == quote.DeploymentID && strings.EqualFold(state.Address, quote.Address) && state.Amount == quote.Amount
}

func readGuidedDeposit(ctx context.Context, service guidedFundingService, ui setupPrompter, wait func(context.Context) error) (zkapi.AddressFundingStatus, error) {
	defer clearSetupProgress(ui)
	warned := false
	for {
		state, err := service.Address(ctx)
		if err == nil {
			return state, nil
		}
		if !warned {
			setupProgress(ui, "Deposit status is temporarily unavailable; checking saved progress again.")
			warned = true
		}
		if err := wait(ctx); err != nil {
			return state, err
		}
	}
}

func finishGuidedDeposit(ctx context.Context, service guidedFundingService, initial zkapi.AddressFundingStatus, ui setupPrompter, wait func(context.Context) error) error {
	defer clearSetupProgress(ui)
	if initial.Amount == 0 {
		return errors.New("saved deposit amount is missing; preserve recovery files")
	}
	if initial.Phase != "active" && !validWithdrawalTransactionHash(initial.TransactionHash) {
		return errors.New("saved deposit transaction is missing; preserve recovery files")
	}
	state, previous, retrying := initial, "", false
	for {
		if state.BillingAsset != "native_eth" || state.Amount != initial.Amount || state.Address != initial.Address || state.ChainID != initial.ChainID || state.DeploymentID != initial.DeploymentID || (initial.TransactionHash != "" && state.TransactionHash != initial.TransactionHash) {
			return errors.New("saved deposit changed during recovery; preserve its recovery files")
		}
		progress := state.Phase + state.TransactionHash + state.DepositStage
		if progress != previous {
			// Fixed labels only; remote messages and recovery internals do not
			// enter the guided session's output.
			switch state.Phase {
			case "active":
				clearSetupProgress(ui)
				ui.Printf("Deposit confirmed. Private inference balance activated.\n")
			case "confirming":
				if state.DepositStage == "verifying" {
					setupProgress(ui, "Deposit mined; waiting for the zkAPI indexer to confirm it before activation.")
				} else {
					setupProgress(ui, "Deposit confirmed; activating your private balance.")
				}
			case "deposit_pending":
				switch state.DepositStage {
				case "activating":
					setupProgress(ui, "Deposit confirmed; activating your private balance.")
				case "fee_wait":
					setupProgress(ui, "Current Ethereum fees exceed this transaction's signed fee cap. Waiting for fees to fall; retrying the same saved transaction.")
				case "failed_finalizing":
					setupProgress(ui, "Deposit receipt reports failure; waiting for Ethereum finality before an explicit retry is allowed.")
				case "finalizing":
					// Older compatible daemons can still wait for successful
					// receipt finality. Do not misreport that as a failed deposit.
					setupProgress(ui, "Deposit mined; waiting for Ethereum finality.")
				case "pending":
					setupProgress(ui, "Deposit transaction saved; waiting to be mined. Retrying the same transaction as needed.")
				default:
					setupProgress(ui, "Waiting for deposit confirmation; checking the saved transaction.")
				}
			}
			previous = progress
		}
		if state.Phase == "active" {
			return nil
		}
		if state.Phase == "verification_conflict" {
			return errGuidedDepositConflict
		}
		if state.Phase != "deposit_pending" && state.Phase != "confirming" {
			return errors.New("deposit needs attention; run zkapi-clientd config with this configuration before continuing (a reverted transaction is never retried automatically)")
		}
		if err := wait(ctx); err != nil {
			return err
		}
		next, err := service.Resume(ctx, initial.Amount)
		if err != nil {
			if !retrying {
				setupProgress(ui, "Could not confirm deposit progress; retrying the saved transaction only.")
				retrying = true
			}
			// A failed response may have persisted a revert or completion.
			// Inspect it before another recovery call, especially because a
			// reverted transaction must never be retried automatically.
			recovered, readErr := readGuidedDeposit(ctx, service, ui, wait)
			if readErr != nil {
				return readErr
			}
			state = recovered
			previous = "" // Restore the stage after the temporary status message.
			continue
		}
		retrying, state = false, next
	}
}
