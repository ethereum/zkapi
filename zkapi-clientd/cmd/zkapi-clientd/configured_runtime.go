package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func configurationRequired(err error) error {
	return fmt.Errorf("%w. Run zkapi-clientd config to review and complete configuration (use the same --config-dir if set)", err)
}

func configuredRuntime(expected config.Config) startRuntime {
	return startRuntime{
		testnet: prepareSepoliaAccess,
		probe:   probeSetupService, companion: checkSetupCompanion,
		serve: func(ctx context.Context, dir string, c config.Config, out io.Writer) error {
			return serveSnapshot(ctx, dir, c, expected, out)
		},
		fund:     runGuidedFunding,
		interval: 500 * time.Millisecond, timeout: 90 * time.Second,
	}
}

// Serve opens a missing note through the authenticated funding flow, then stays running.
// A reserved withdrawal or uncertain transaction is never replaced.
func runConfiguredServe(ctx context.Context, dir string, c, expected config.Config, out io.Writer) error {
	ctx = context.WithValue(ctx, coverServeKey{}, true)
	ui := &noninteractiveSetup{out: out}
	runtime := configuredRuntime(expected)
	runtime.testnet = checkSepoliaAccess
	runtime.fund = ensureServeFunding
	err := guidedStart(ctx, dir, startOptions{prepared: &c, checkOnly: true}, ui, out, runtime)
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return configurationRequired(err)
	}
	return nil
}

type noninteractiveSetup struct{ out io.Writer }

func (p *noninteractiveSetup) Ask(context.Context, string, string) (string, error) {
	return "", errors.New("configuration needs interactive input; run zkapi-clientd config")
}
func (p *noninteractiveSetup) Confirm(context.Context, string) (bool, error) {
	return false, errors.New("funding needs your approval; run zkapi-clientd config")
}
func (p *noninteractiveSetup) Continue(context.Context, string) (bool, error) {
	return false, errors.New("funding needs your approval; run zkapi-clientd config")
}
func (p *noninteractiveSetup) Printf(format string, args ...any) {
	fmt.Fprintf(p.out, format, args...)
}

type setupUIWriter struct{ ui setupPrompter }

func (w setupUIWriter) Write(p []byte) (int, error) {
	w.ui.Printf("%s", p)
	return len(p), nil
}

func checkConfiguredZKAPI(ctx context.Context, c config.Config, _, _ string, ui setupPrompter) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client, err := relay.NewClient(c.RelayURL)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	wallet, err := zkapi.New(zkConfig(c, client))
	if err != nil {
		return err
	}
	return configuredWalletReady(ctx, localGuidedFunding{c, wallet}, ui)
}

// Deliberately does not call Address, Quote, Approve, Resume, or Withdrawal:
// even generating an unused local signing address belongs in config.
func configuredWalletReady(ctx context.Context, service guidedFundingService, ui setupPrompter) error {
	state, err := service.Readiness(ctx)
	if err != nil {
		return err
	}
	if state.WithdrawalPending {
		return errors.New("a private withdrawal is reserved; complete wallet recovery")
	}
	if !state.HasNote {
		return errors.New("the zkAPI wallet has no private balance; configure funding")
	}
	if state.PendingRequest {
		ui.Printf("A previous inference is settling; new requests will wait automatically.\n")
		return nil
	}
	return checkSetupBalance(state, ui)
}

// Config owns a temporary runtime only for the selected wallet operation. It
// returns after readiness/recovery, leaving a foreign compatible service alone.
func runConfigAction(ctx context.Context, dir string, c config.Config, action string, ui setupPrompter, out io.Writer) error {
	return runConfigActionWithUSD(ctx, dir, c, action, "", ui, out)
}

func runConfigActionWithUSD(ctx context.Context, dir string, c config.Config, action, usd string, ui setupPrompter, out io.Writer) error {
	if action == "password" {
		if c.ZKAPI.Network != "sepolia" {
			return errors.New("password configuration applies only to Sepolia zkAPI")
		}
		if err := changeSepoliaAccess(ctx, dir, c, ui); err != nil {
			return err
		}
		ui.Printf("Sepolia password saved. Restart any running daemon to use it. Run zkapi-clientd config to check readiness.\n")
		return nil
	}
	runtime := configuredRuntime(c)
	switch action {
	case "setup":
	case "withdraw", "return":
		runtime.fund = func(ctx context.Context, c config.Config, _, _ string, ui setupPrompter) error {
			return configurePayment(ctx, c, action, ui)
		}
	case "repair":
		runtime.fund = func(ctx context.Context, c config.Config, _, _ string, ui setupPrompter) error {
			return runGuidedRepair(ctx, c, ui)
		}
	case "status":
		runtime.fund = checkConfiguredZKAPI
	default:
		return errors.New("unknown configuration action")
	}
	err := guidedStart(ctx, dir, startOptions{prepared: &c, setupOnly: true, quietStartup: action == "withdraw", usd: usd}, ui, out, runtime)
	if err != nil {
		return err
	}
	if action == "setup" || action == "status" {
		ui.Printf("\nConfiguration ready.\n")
		showClientConnection(c, ui)
		ui.Printf("Run zkapi-clientd serve to serve inference.\n")
		showCustomProfileHint(dir, ui)
	} else if action != "withdraw" {
		ui.Printf("\nWallet operation complete. Run zkapi-clientd config to check readiness before serving.\n")
	}
	return nil
}

func configurePayment(ctx context.Context, c config.Config, action string, ui setupPrompter) error {
	if action == "withdraw" {
		return withdrawWithRemainder(ctx, c, ui)
	}
	out := setupUIWriter{ui}
	var selectedDestination, selectedAmount string
	var state zkapi.AddressReturnStatus
	if err := requestManagementJSON(ctx, c, http.MethodGet, "/admin/return", nil, &state); err != nil {
		return err
	}
	if state.Phase == "return_pending" || state.Phase == "confirming" {
		ui.Printf("Resuming the saved signed public ETH return.\n")
		return runPublicReturn(ctx, c, []string{"--resume"}, out)
	}
	destination, err := ui.Ask(ctx, "Return public ETH to Ethereum address", "")
	if err != nil {
		return err
	}
	amount, err := ui.Ask(ctx, "Amount in ETH, or all to return the available balance after fees", "all")
	if err != nil {
		return err
	}
	selectedDestination = destination
	args := []string{"--to", destination}
	if strings.ToLower(amount) != "all" {
		selectedAmount, err = parseReturnAmount(amount)
		if err != nil {
			return err
		}
		args = append(args, "--amount", amount)
	}
	if err := runPublicReturn(ctx, c, args, out); err != nil {
		return err
	}
	path, kind := "/admin/return/quote", "return"
	quote, err := requestPaymentQuote(ctx, c, http.MethodGet, path, kind, nil)
	if err != nil {
		return err
	}
	if !strings.EqualFold(quote.Destination, selectedDestination) || (selectedAmount != "" && quote.PrincipalWei != selectedAmount) {
		return errors.New("the saved payment quote changed your selected destination, note, or amount; no transaction authorized")
	}
	// Display the very quote whose ID is authorized, even if an earlier quote
	// was replaced concurrently. Approval endpoints re-check its exact binding.
	printPaymentQuote(out, quote, "")
	approved, err := ui.Confirm(ctx, "Authorize this destination, fixed amount, and maximum network fee")
	if err != nil {
		return err
	}
	if !approved {
		return errors.New("payment was not authorized; saved progress is preserved")
	}
	return runPublicReturn(ctx, c, []string{"--approve", quote.ID}, out)
}
