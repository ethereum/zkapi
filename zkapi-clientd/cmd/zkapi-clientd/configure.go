package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

type configureAction func(context.Context, string, config.Config, string, setupPrompter, io.Writer) error

type configureOptions struct {
	network, listen, relay, binary, proofs    string
	exitRPC                                   string
	bundlerURL, withdrawalFees                string
	usd                                       string
	keyReuseWindowSeconds                     int
	status, apiKey, edit, menu, requireAPIKey bool
	fields                                    map[string]bool
}

// exitRPCHelp states everything the exit RPC is used for, and so what its
// provider sees. The wallet companion reads an escape's chain state through
// it too, but only through the configured transport, which carries HTTPS
// alone, so a plain-HTTP RPC on this machine cannot serve an escape yet.
const exitRPCHelp = "your own Ethereum RPC: escapes read the chain and send their transactions only through it; deployment checks, every withdrawal's completion, and deposit recording and repair when the zkAPI indexer does not confirm a deposit also read through it, so its provider sees those transactions and note IDs, with your IP address under direct HTTPS (HTTPS goes through the configured transport; http:// to this machine is dialed directly but cannot serve escapes yet, which need an HTTPS exit RPC; 'none' clears it)"

func parseConfigureOptions(args []string, out io.Writer) (configureOptions, error) {
	var o configureOptions
	f := flag.NewFlagSet("config", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&o.network, "network", "", "zkAPI network: mainnet or sepolia")
	f.StringVar(&o.listen, "listen", "", "numeric loopback API address and port")
	f.StringVar(&o.relay, "relay-url", "", "Wisp, socks5://IP:PORT, or conversation-isolated tor://IP:PORT; empty selects direct HTTPS")
	f.StringVar(&o.binary, "zkapi-binary", "", "path to the installed zkAPI companion")
	f.StringVar(&o.proofs, "proof-setup-dir", "", "path to the installed proving assets")
	f.StringVar(&o.exitRPC, "exit-rpc-url", "", exitRPCHelp)
	f.StringVar(&o.bundlerURL, "bundler-url", "", "your own ERC-4337 bundler for gasless withdrawals (--fees payout): HTTPS, or http:// to this machine; 'none' clears it and the deployment's published bundler is used")
	f.StringVar(&o.withdrawalFees, "withdrawal-fees", "", "how withdrawals pay the network fee by default: wallet (the local signing address) or payout (a sponsored operation paid from the payout, no ETH needed)")
	f.StringVar(&o.usd, "usd", "", "skip the new-deposit USD amount prompt (prompt default: 20; network fees are extra)")
	f.BoolVar(&o.status, "status", false, "show saved configuration status without setup")
	f.BoolVar(&o.apiKey, "api-key", false, "print the local inference API key explicitly")
	f.IntVar(&o.keyReuseWindowSeconds, "key-reuse-window-seconds", config.DefaultKeyReuseWindowSeconds, "fixed ephemeral key reuse window (default 60 seconds; 1-300 shares keys across chats and local clients; 0 uses a fresh key per inference request)")
	f.BoolVar(&o.requireAPIKey, "require-api-key", false, "require a local API key for inference (default: no key required)")
	f.BoolVar(&o.edit, "edit", false, "edit network, listener, and transport interactively")
	f.BoolVar(&o.menu, "menu", false, "open configuration and wallet management actions")
	f.Bool("setup", false, "explicitly prepare/fund wallet (bare config only displays JSON)")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	o.fields = make(map[string]bool)
	invalid := false
	f.Visit(func(field *flag.Flag) {
		if field.Name == "setup" || field.Name == "status" || field.Name == "api-key" || field.Name == "edit" || field.Name == "menu" {
			return
		}
		if field.Name != "usd" {
			o.fields[field.Name] = true
		}
		invalid = invalid || (field.Name != "relay-url" && strings.TrimSpace(field.Value.String()) == "")
	})
	if invalid || f.NArg() != 0 {
		return o, errors.New("config flags require nonempty values except --relay-url; unexpected arguments are not accepted")
	}
	selectors := 0
	for _, selected := range []bool{o.status, o.apiKey, o.edit, o.menu} {
		if selected {
			selectors++
		}
	}
	if selectors > 1 || selectors != 0 && (len(o.fields) != 0 || o.usd != "") {
		return o, errors.New("use --status, --api-key, --edit, or --menu by itself, without other configuration options")
	}
	if o.fields["network"] && o.network != "mainnet" && o.network != "sepolia" {
		return o, errors.New("network must be mainnet or sepolia")
	}
	if o.fields["key-reuse-window-seconds"] && (o.keyReuseWindowSeconds < 0 || o.keyReuseWindowSeconds > config.MaxKeyReuseWindowSeconds) {
		return o, errors.New("key-reuse-window-seconds must be between 0 and 300")
	}
	if o.fields["withdrawal-fees"] && o.withdrawalFees != "wallet" && o.withdrawalFees != "payout" {
		return o, errors.New("withdrawal-fees must be wallet or payout")
	}
	if o.fields["bundler-url"] && o.bundlerURL != "none" {
		if err := zkapi.ValidateBundlerURL(o.bundlerURL); err != nil {
			return o, err
		}
	}
	if o.usd != "" {
		if _, err := parseFundingAmountForAsset(o.usd, 6, "USD"); err != nil {
			return o, err
		}
	}
	return o, nil
}

func runConfigure(ctx context.Context, dir string, args []string, ui setupPrompter, out io.Writer) error {
	err := configure(ctx, dir, args, ui, out, nil)
	if errors.Is(err, errSetupSelectionCanceled) {
		ui.Printf("Configuration canceled. Your saved settings are unchanged.\n")
		return nil
	}
	if ctx.Err() != nil {
		ui.Printf("\nStopped. Your saved configuration and wallet state are preserved; run zkapi-clientd config to continue.\n")
		return nil
	}
	return err
}

func configure(ctx context.Context, dir string, args []string, ui setupPrompter, out io.Writer, action configureAction) error {
	o, err := parseConfigureOptions(args, out)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	// Tests may supply a side-effect-free action. The production action carries
	// the new-deposit preference without persisting it or changing recovery intent.
	if action == nil {
		action = func(ctx context.Context, dir string, c config.Config, operation string, ui setupPrompter, out io.Writer) error {
			return runConfigActionWithUSD(ctx, dir, c, operation, o.usd, ui, out)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := config.EnsureDir(dir); err != nil {
		return err
	}
	_, err = os.Lstat(filepath.Join(dir, "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		if o.apiKey || o.menu {
			return errors.New("configuration is missing; run zkapi-clientd config to create it")
		}
		ui.Printf("Configuration: not configured.\n")
		if o.status {
			return nil
		}
		for _, name := range []string{"funding", "zkapi", "tickets.json", "management-token"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
				return errors.New("config.json is missing but wallet state exists; restore your configuration backup or use a separate --config-dir")
			}
		}
		c, err := config.Default()
		if err != nil {
			return err
		}
		c.Backend = "zkapi"
		c = applyConfigureOptions(c, o)
		if o.edit {
			c, err = promptConfigure(ctx, c, ui, true)
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := config.Init(dir, c); err != nil {
			return err
		}
		c, err = config.Load(dir)
		if err != nil {
			return err
		}
		ui.Printf("Created private configuration. Back up your configuration directory to preserve your wallets and their recovery state.\n")
		showConfigureSummary(c, ui)
		return action(ctx, dir, c, "setup", ui, out)
	}
	if err != nil {
		return errors.New("cannot inspect configuration; preserve the profile and check its permissions")
	}
	c, err := config.Load(dir)
	if err != nil {
		return err
	}
	if o.apiKey {
		_, err := fmt.Fprintln(out, c.APIKey)
		return err
	}
	if o.menu {
		ui.Printf("Wallet menu (zkAPI network: %s).\n", c.ZKAPI.Network)
	} else {
		showConfigureSummary(c, ui)
	}
	if o.status {
		return nil
	}
	if len(o.fields) != 0 {
		return saveConfiguredSettings(ctx, dir, c, applyConfigureOptions(c, o), ui, out, action)
	}
	if o.edit {
		next, err := promptConfigure(ctx, c, ui, true)
		if err != nil {
			return err
		}
		return saveConfiguredSettings(ctx, dir, c, next, ui, out, action)
	}
	if !o.menu {
		return action(ctx, dir, c, "setup", ui, out)
	}
	for {
		choices := "check setup, edit settings, withdraw, return public ETH, repair deposit, api-key, or quit"
		menu := []setupChoice{
			{value: "check", label: "Check setup / fund wallet"},
			{value: "edit", label: "Edit settings"},
		}
		sepolia := c.ZKAPI.Network == "sepolia"
		if sepolia {
			choices = "check setup, edit settings, password, withdraw, return public ETH, repair deposit, api-key, or quit"
			menu = append(menu, setupChoice{value: "password", label: "Set Sepolia password"})
		}
		menu = append(menu,
			setupChoice{value: "withdraw", label: "Withdraw private balance"},
			setupChoice{value: "return", label: "Return public ETH"},
			setupChoice{value: "repair", label: "Repair deposit note binding"},
			setupChoice{value: "api-key", label: "Show local API key"},
			setupChoice{value: "quit", label: "Quit"},
		)
		choice, err := selectSetupChoice(ctx, ui, "Choose: "+choices, "check", menu)
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "", "check", "setup":
			return action(ctx, dir, c, "setup", ui, out)
		case "edit":
			next, err := promptConfigure(ctx, c, ui, true)
			if err != nil {
				return err
			}
			return saveConfiguredSettings(ctx, dir, c, next, ui, out, action)
		case "withdraw", "return", "repair":
			return action(ctx, dir, c, strings.ToLower(strings.TrimSpace(choice)), ui, out)
		case "password":
			if sepolia {
				return action(ctx, dir, c, "password", ui, out)
			}
			ui.Printf("Password configuration applies only to Sepolia zkAPI.\n")
		case "api-key":
			_, err := fmt.Fprintln(out, c.APIKey)
			return err
		case "quit", "q":
			return nil
		default:
			ui.Printf("Choose one of the listed actions.\n")
		}
	}
}

func applyConfigureOptions(c config.Config, o configureOptions) config.Config {
	if o.fields["network"] {
		c = config.SelectNetwork(c, o.network)
	}
	if o.fields["key-reuse-window-seconds"] {
		c.KeyReuseWindowSeconds = o.keyReuseWindowSeconds
	}
	if o.fields["require-api-key"] {
		c.RequireAPIKey = o.requireAPIKey
	}
	if o.fields["listen"] {
		c.Listen = o.listen
	}
	if o.fields["relay-url"] {
		c.RelayURL = o.relay
	}
	if o.fields["zkapi-binary"] {
		c.ZKAPI.Binary = o.binary
	}
	if o.fields["proof-setup-dir"] {
		c.ZKAPI.ProofSetupDir = o.proofs
	}
	if o.fields["exit-rpc-url"] {
		c.ZKAPI.ExitRPCURL = o.exitRPC
		if o.exitRPC == "none" {
			c.ZKAPI.ExitRPCURL = ""
		}
	}
	if o.fields["bundler-url"] {
		c.ZKAPI.BundlerURL = o.bundlerURL
		if o.bundlerURL == "none" {
			c.ZKAPI.BundlerURL = ""
		}
	}
	if o.fields["withdrawal-fees"] {
		c.ZKAPI.WithdrawalFees = o.withdrawalFees
		if o.withdrawalFees == "wallet" {
			c.ZKAPI.WithdrawalFees = ""
		}
	}
	return c
}

func showConfigureSummary(c config.Config, ui setupPrompter) {
	transport := "direct HTTPS"
	if strings.HasPrefix(c.RelayURL, "tor://") {
		transport = "Tor conversation isolation enabled (Tor IsolateSOCKSAuth required)"
	} else if strings.HasPrefix(c.RelayURL, "socks5://") {
		transport = "SOCKS5 proxy enabled"
	} else if c.RelayURL != "" {
		transport = "Wisp relay enabled"
	}
	ui.Printf("Configuration: saved.\nzkAPI network: %s\nTransport: %s\n", c.ZKAPI.Network, transport)
	if c.ZKAPI.ExitRPCURL != "" {
		ui.Printf("Exit RPC: %s (deployment checks, deposit and withdrawal confirmation, exit transactions; it sees those transactions and note IDs)\n", c.ZKAPI.ExitRPCURL)
		// The scheme is case-insensitive: HTTP://127.0.0.1 is plain HTTP too.
		if u, err := url.Parse(c.ZKAPI.ExitRPCURL); err == nil && u.Scheme == "http" {
			ui.Printf("Escapes cannot use a plain-HTTP exit RPC yet; set an HTTPS exit RPC before you escape.\n")
		}
	}
	if c.ZKAPI.BundlerURL != "" {
		ui.Printf("Bundler: %s (gasless withdrawals)\n", c.ZKAPI.BundlerURL)
	}
	if c.ZKAPI.WithdrawalFees == "payout" {
		ui.Printf("Withdrawal fees: paid from the payout by default (--fees payout)\n")
	}
	showClientConnection(c, ui)
	if c.KeyReuseWindowSeconds == 0 {
		ui.Printf("Ephemeral key reuse: disabled; fresh key per inference request. New keys may wait for earlier settlement.\n")
	} else if strings.HasPrefix(c.RelayURL, "tor://") || c.Rewriter.Enabled() {
		ui.Printf("Ephemeral key reuse: up to %d seconds within prefix-continuing conversations only; fresh key on each conversation change.\n", c.KeyReuseWindowSeconds)
	} else {
		ui.Printf("Ephemeral key reuse: fixed window up to %d seconds; different chats and local clients can share a key and its spending cap. The provider can link those requests.\n", c.KeyReuseWindowSeconds)
	}
	ui.Printf("Change settings: zkapi-clientd config --edit\nWallet actions: zkapi-clientd config --menu\nUse the same --config-dir for these commands if set.\n")
}

func saveConfiguredSettings(ctx context.Context, dir string, previous, next config.Config, ui setupPrompter, out io.Writer, action configureAction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if next != previous {
		if err := config.Update(dir, previous, next); err != nil {
			return err
		}
		if next.ZKAPI.Network != previous.ZKAPI.Network {
			ui.Printf("Selected %s. Your %s wallet and recovery files remain saved separately in this configuration directory.\n", next.ZKAPI.Network, previous.ZKAPI.Network)
		}
		ui.Printf("Saved configuration.\n")
		showConfigureSummary(next, ui)
	}
	return action(ctx, dir, next, "setup", ui, out)
}

func promptConfigure(ctx context.Context, c config.Config, ui setupPrompter, edit bool) (config.Config, error) {
	network, err := configureChoice(ctx, ui, "Choose network: mainnet (real ETH) or sepolia (test ETH)", c.ZKAPI.Network, "mainnet", "sepolia")
	if err != nil {
		return c, err
	}
	c = config.SelectNetwork(c, network)
	if !edit {
		return c, nil
	}
	for {
		value, err := ui.Ask(ctx, "Local API listen address", c.Listen)
		if err != nil {
			return c, err
		}
		candidate := c
		if strings.TrimSpace(value) != "" {
			candidate.Listen = strings.TrimSpace(value)
		}
		if err := config.Validate(candidate); err != nil {
			ui.Printf("%s\n", err)
			continue
		}
		c = candidate
		break
	}
	for {
		fallback := "direct"
		if c.RelayURL != "" {
			// Relay query parameters can carry credentials. Keep the saved URL
			// out of the prompt just as it is kept out of the status summary.
			fallback = "keep"
		}
		value, err := ui.Ask(ctx, "Transport: direct, keep existing route, Wisp URL, or loopback socks5://IP:PORT", fallback)
		if err != nil {
			return c, err
		}
		value = strings.TrimSpace(value)
		if value == "" {
			value = fallback
		}
		candidate := c
		candidate.RelayURL = value
		if strings.EqualFold(value, "direct") {
			candidate.RelayURL = ""
		} else if strings.EqualFold(value, "keep") {
			candidate.RelayURL = c.RelayURL
		}
		if err := config.Validate(candidate); err != nil {
			ui.Printf("Invalid transport setting; enter direct, a valid Wisp URL, or a loopback SOCKS5 URL.\n")
			continue
		}
		c = candidate
		break
	}
	return c, nil
}

func configureChoice(ctx context.Context, ui setupPrompter, question, fallback string, choices ...string) (string, error) {
	options := make([]setupChoice, 0, len(choices))
	for _, choice := range choices {
		label := choice
		switch choice {
		case "mainnet":
			label = "Mainnet (real ETH)"
		case "sepolia":
			label = "Sepolia (test ETH)"
		}
		options = append(options, setupChoice{value: choice, label: label})
	}
	for {
		answer, err := selectSetupChoice(ctx, ui, question, fallback, options)
		if err != nil {
			return "", err
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer == "" {
			answer = fallback
		}
		for _, choice := range choices {
			if answer == choice {
				return answer, nil
			}
		}
		ui.Printf("Enter %s.\n", strings.Join(choices, " or "))
	}
}
