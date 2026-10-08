// zkapi-clientd runs in the foreground under launchd/Homebrew services or systemd.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "zkapi-clientd:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	var dir string
	var err error
	global := flag.NewFlagSet("zkapi-clientd", flag.ContinueOnError)
	global.StringVar(&dir, "config-dir", dir, "private configuration and wallet directory")
	showVersion := global.Bool("version", false, "print version")
	global.Usage = help
	if err := global.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Println("zkapi-clientd", version)
		return nil
	}
	args = global.Args()
	if len(args) == 0 {
		help()
		return nil
	}
	if args[0] == "version" {
		fmt.Println("zkapi-clientd", version)
		return nil
	}
	if args[0] == "help" {
		help()
		return nil
	}
	switch args[0] {
	case "config", "serve", "fund", "withdraw":
	default:
		return errors.New("unknown command; use zkapi-clientd config, serve, fund, or withdraw (--help for usage)")
	}
	if dir == "" {
		dir, err = config.DefaultDir()
		if err != nil {
			return err
		}
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	if args[0] == "config" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ui := &terminalSetupPrompter{out: os.Stdout}
		defer ui.Close()
		return runConfigure(ctx, dir, args[1:], ui, os.Stdout)
	}
	if args[0] == "fund" || args[0] == "withdraw" {
		return runWalletCommand(dir, args[0], args[1:], os.Stdout)
	}
	if args[0] == "serve" && len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Println("Usage: zkapi-clientd serve [--allow-unfunded]\nRun the saved configuration. Run zkapi-clientd config to configure missing prerequisites.\n  --allow-unfunded  keep running while the wallet cannot spend (no deposit, empty balance, or reserved withdrawal);\n                    inference returns funding_required or withdrawal_pending until it can")
		return nil
	}
	c, err := config.Load(dir)
	if err != nil {
		return configurationRequired(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	expected := c
	c, allowUnfunded, err := serveConfig(c, args[1:])
	if err != nil {
		return err
	}
	return runConfiguredServe(ctx, dir, c, expected, os.Stdout, allowUnfunded)

}

// Wallet commands are clients of the running daemon's authenticated admin API.
// Quoting never signs; only --approve with the exact displayed quote ID spends.
func runWalletCommand(dir, command string, args []string, out io.Writer) error {
	c, err := config.Load(dir)
	if helpRequested(args) {
		// Help wins even where the flag parser would read it as a value
		// (fund --approve --help), so it never runs the command.
		help := []string{"--help"}
		if command == "fund" && len(args) > 0 && args[0] == "return" {
			help = []string{"return", "--help"}
		}
		args = help
	} else if err != nil {
		return configurationRequired(err)
	}
	// Help needs no configuration: flag parsing returns before any request.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "fund" {
		err = runFunding(ctx, c, args, out)
	} else {
		err = runWithdrawal(ctx, c, args, out)
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func helpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			return true
		}
	}
	return false
}

func help() {
	fmt.Fprintln(os.Stderr, `Usage: zkapi-clientd [--config-dir DIR] COMMAND

  config                 Show status, configure or edit settings, and prepare the wallet
  serve                  Run inference using the saved configuration
                         (--allow-unfunded keeps it running until the wallet can spend)
  fund                   Quote, approve, or resume a deposit through the running daemon
  withdraw               Quote, approve, or resume a withdrawal through the running daemon

Run zkapi-clientd config --help for configuration options.
Run zkapi-clientd fund --help or zkapi-clientd withdraw --help for wallet options.
Run zkapi-clientd --version to show the installed version.
Config: ZKAPI_CLIENTD_CONFIG_DIR or the OS user config directory / zkapi-clientd.
Mainnet is the default; Sepolia keeps a separate wallet.
The network proxy is off by default. No prompts or responses are stored.`)
}

func initialize(dir string, args []string) error {
	c, err := config.Default()
	if err != nil {
		return err
	}
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	f.StringVar(&c.ZKAPI.Network, "network", c.ZKAPI.Network, "mainnet or sepolia")
	f.StringVar(&c.VerifierURL, "verifier-url", c.VerifierURL, "verifier HTTPS origin")
	f.StringVar(&c.RelayURL, "relay-url", c.RelayURL, "Wisp relay URL or loopback SOCKS5 proxy (default: direct HTTPS)")
	f.StringVar(&c.Listen, "listen", c.Listen, "loopback IP:port")
	f.StringVar(&c.ZKAPI.Binary, "zkapi-binary", "", "path to zkapi-walletd wallet/prover")
	f.StringVar(&c.ZKAPI.ProofSetupDir, "proof-setup-dir", "", "verified deployed circuit proving assets")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected init arguments")
	}
	verifierExplicit := false
	f.Visit(func(field *flag.Flag) { verifierExplicit = verifierExplicit || field.Name == "verifier-url" })
	if !verifierExplicit {
		c.VerifierURL = config.DefaultVerifierURL(c.ZKAPI.Network)
	}
	if err := config.Init(dir, c); err != nil {
		return err
	}
	fmt.Printf("Initialized zkAPI configuration.\nAPI base: http://%s/v1\nRun zkapi-clientd serve.\n", c.Listen)
	return nil
}

// Serving uses the saved network without rewriting wallet state.
func serveConfig(c config.Config, args []string) (config.Config, bool, error) {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	allowUnfunded := f.Bool("allow-unfunded", false, "keep running while the wallet cannot spend; inference returns funding_required until it can")
	if err := f.Parse(args); err != nil {
		return config.Config{}, false, err
	}
	if f.NArg() != 0 {
		return config.Config{}, false, errors.New("serve accepts no arguments; use zkapi-clientd config to change settings")
	}
	if err := config.Validate(c); err != nil {
		return config.Config{}, false, err
	}
	return c, *allowUnfunded, nil
}

func zkConfig(c config.Config, client *http.Client) zkapi.Config {
	return zkapi.Config{ClientURL: c.ZKAPI.ClientURL, BridgeToken: c.ZKAPI.BridgeToken, Network: c.ZKAPI.Network, HTTPClient: client, KeyReuseWindow: time.Duration(c.KeyReuseWindowSeconds) * time.Second}
}

type zkInference struct{ *zkapi.Client }

func (z zkInference) Complete(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	response, err := z.Client.Complete(ctx, body)
	var remote *zkapi.Error
	if errors.As(err, &remote) {
		switch remote.Code {
		case "testnet_password_required":
			return nil, &server.BackendError{Status: 401, Code: "testnet_password_required", Message: remote.Error()}
		case "invalid_model":
			return nil, &server.BackendError{Status: 400, Code: "invalid_model", Message: "Select a model from /v1/models."}
		case "model_budget_unavailable":
			return nil, &server.BackendError{Status: 400, Code: "model_budget_unavailable", Message: "The model is unavailable or has no reviewed request budget. Select a model from /v1/models."}
		case "model_policy_unavailable":
			return nil, &server.BackendError{Status: 502, Code: "model_policy_unavailable", Message: "The current model policy could not be loaded. Retry when the model service is available."}
		}
		switch remote.Status {
		case http.StatusPaymentRequired:
			return nil, &server.BackendError{Status: 402, Code: "funding_required", Message: "The private balance needs funding. Run zkapi-clientd config or zkapi-clientd fund to add funding."}
		case http.StatusConflict:
			if remote.Code == "withdrawal_pending" || remote.Code == "withdrawal_conflict" {
				return nil, &server.BackendError{Status: 409, Code: "withdrawal_pending", Message: "The private balance is reserved for withdrawal. Run zkapi-clientd withdraw, or zkapi-clientd config --menu and choose withdraw, to recover the saved destination."}
			}
			return nil, &server.BackendError{Status: 409, Code: "wallet_conflict", Message: "The wallet could not safely prepare fresh anonymous access. Run zkapi-clientd config to check its state."}
		}
	}
	return response, err
}

func serve(ctx context.Context, dir string, c config.Config, out io.Writer) error {
	return serveSnapshot(ctx, dir, c, c, out)
}

func serveSnapshot(ctx context.Context, dir string, c, expected config.Config, out io.Writer) error {
	logger := log.New(out, "zkapi-clientd ", log.LstdFlags)
	logger.Print("Starting local API service")
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("a zkAPI client daemon is already using this config directory")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	// Configuration may have been edited after command dispatch but before
	// acquiring the service lock. Never start with that stale snapshot.
	saved, err := config.Load(dir)
	if err != nil {
		return configurationRequired(err)
	}
	if !reflect.DeepEqual(saved, expected) {
		return errors.New("configuration changed before startup; run zkapi-clientd config to review it, then retry serve")
	}
	client, err := relay.NewClient(c.RelayURL)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return errors.New("could not bind local API address; check for an existing service")
	}
	defer listener.Close()
	c.Listen = listener.Addr().String()
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	var backend server.Backend
	var funding *zkapi.FundingHandler
	var childDone chan error
	var sessions sessionEventReader
	password, err := config.SepoliaPassword(dir, c.ZKAPI.Network)
	if err != nil {
		return err
	}
	checkCtx, checkCancel := context.WithTimeout(ctx, 20*time.Second)
	err = zkapi.CheckTestnetPassword(checkCtx, c.ZKAPI.Network, password, client)
	checkCancel()
	if err != nil {
		return err
	}
	zc := zkConfig(c, client)
	wallet, err := zkapi.New(zc)
	if err != nil {
		return err
	}
	if !c.ZKAPI.ExternalCompanion {
		// Keep the local HTTPS-only bridge in both routing modes so the
		// companion cannot follow a redirect to plaintext HTTP.
		proxy, err := relay.StartConnectProxy(life, c.RelayURL)
		if err != nil {
			return err
		}
		defer proxy.Close()
		cmd, err := zkapi.CompanionCommand(life, zc, zkapi.CompanionConfig{Binary: c.ZKAPI.Binary, SetupDir: c.ZKAPI.ProofSetupDir, StateDir: filepath.Join(dir, "zkapi"), VerifierURL: c.VerifierURL, ProxyURL: proxy.URL, TestnetPassword: password})
		if err != nil {
			return err
		}
		// The companion may emit wallet/proof details. Inherit no verbose
		// output into system service logs; readiness is checked by policy API.
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 5 * time.Second
		if err := cmd.Start(); err != nil {
			return errors.New("failed to start zkAPI companion")
		}
		childDone = make(chan error, 1)
		go func() { childDone <- cmd.Wait(); close(childDone) }()
		defer func() {
			cancel()
			select {
			case <-childDone:
			case <-time.After(7 * time.Second):
				_ = cmd.Process.Kill()
			}
		}()
	}
	backend = zkInference{wallet}
	sessions = wallet
	funding, err = zkapi.NewFundingHandler(wallet, "http://"+c.Listen, filepath.Join(dir, "funding"))
	if err != nil {
		return err
	}
	api, err := server.New(backend, c.APIKey, c.Concurrency)
	if err != nil {
		return err
	}
	api.RequireAPIKey = c.RequireAPIKey
	api.Status = server.ServiceStatus{Backend: c.Backend}
	api.Status.Network = c.ZKAPI.Network
	api.Status.RequestBudgetPolicy = "model"
	if funding != nil {
		// server.API rejects browser origins and requires both the local bearer
		// and owner-only credential before dispatching any wallet operation.
		api.ManagementToken = c.ManagementToken
		api.Admin = http.HandlerFunc(funding.ServeAdminHTTP)
	}
	httpServer := &http.Server{Handler: server.LogRequests(api, logger), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return life }}
	serverDone := make(chan error, 1)
	go func() { serverDone <- httpServer.Serve(listener) }()
	transport := "direct HTTPS (network proxy off)"
	if strings.HasPrefix(c.RelayURL, "socks5://") {
		transport = "SOCKS5 proxy required"
	} else if c.RelayURL != "" {
		transport = "encrypted relay required"
	}
	logger.Printf("zkAPI client %s listening at http://%s/v1 (%s); %s", version, c.Listen, c.Backend, transport)
	logger.Printf("zkAPI network: %s", c.ZKAPI.Network)
	if c.RequireAPIKey {
		logger.Print("Use zkapi-clientd config --api-key to configure your client; Ctrl+C stops the service")
	} else {
		logger.Print("Localhost inference needs no API key; Ctrl+C stops the service")
	}
	if c.KeyReuseWindowSeconds > 0 {
		logger.Printf("Ephemeral key reuse enabled for up to %d seconds: different chats and local clients can share a key and spending cap. Run zkapi-clientd config --key-reuse-window-seconds 0 to isolate every request", c.KeyReuseWindowSeconds)
	} else {
		logger.Print("Ephemeral key isolation: fresh OpenRouter key for every completion, including background UI requests")
	}
	logger.Print("Request key_ref numbers identify keys within this process. Wallet session numbers track settlement separately; settled cost can arrive after the response ends")
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		monitorSessions(life, logger, sessions, 5*time.Second)
	}()
	settlementDone := make(chan struct{})
	go func() {
		defer close(settlementDone)
		runAutomaticSettlement(life, logger, wallet)
	}()
	var result error
	select {
	case <-ctx.Done():
	case err := <-serverDone:
		if !errors.Is(err, http.ErrServerClosed) {
			result = errors.New("local API server stopped unexpectedly")
		}
	case <-childDone:
		result = errors.New("zkAPI service stopped unexpectedly; run zkapi-clientd config to check the installation, then restart zkapi-clientd serve")
	}
	if result != nil {
		// These lifecycle errors are fixed local messages, never raw child output.
		logger.Printf("ERROR %s", result)
	}
	logger.Print("Stopping local API service")
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		_ = httpServer.Close()
	}
	<-statusDone
	<-settlementDone
	logger.Print("Local API service stopped")
	return result
}

func status(ctx context.Context, dir string, c config.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result := map[string]any{"default_backend": c.Backend, "api_base": "http://" + c.Listen + "/v1", "relay_required": c.RelayURL != ""}
	active, err := resolveActiveConfig(ctx, c)
	result["service_running"] = err == nil
	if err == nil {
		c = active
	} else if _, healthErr := localRequest(ctx, c, "GET", "/healthz"); healthErr == nil {
		return errors.New("local service is running but its active mode could not be authenticated; restart it with the current client and configuration")
	}
	result["backend"] = c.Backend
	client, _ := relay.NewClient(c.RelayURL)
	result["network"] = c.ZKAPI.Network
	result["billing_asset"] = "native_eth"
	result["billing_unit"] = "gwei"
	result["request_budget_policy"] = "model"
	wallet, err := zkapi.New(zkConfig(c, client))
	if err != nil {
		return err
	}
	data, err := wallet.WalletStatus(ctx)
	result["companion_ready"] = err == nil
	if err == nil {
		var state struct {
			HasNote        bool `json:"has_note"`
			PendingRequest bool `json:"pending_request"`
			Note           struct {
				CurrentBalance any `json:"current_balance"`
			} `json:"note"`
		}
		if json.Unmarshal(data, &state) == nil {
			result["funded"] = state.HasNote
			result["private_balance"] = state.Note.CurrentBalance
			result["pending_settlement"] = state.PendingRequest
		}
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(result)
}

// Management commands authenticate the running daemon and its network.
// This copy does not migrate or modify wallet state.
func resolveActiveConfig(ctx context.Context, c config.Config) (config.Config, error) {
	data, err := localRequest(ctx, c, http.MethodGet, "/admin/status")
	if err != nil {
		return config.Config{}, err
	}
	var active server.ServiceStatus
	if json.Unmarshal(data, &active) != nil ||
		active.Backend != "zkapi" ||
		(active.Network != "mainnet" && active.Network != "sepolia") {
		return config.Config{}, errors.New("local service returned invalid active-mode metadata; restart it with the current client")
	}
	c.Backend = active.Backend
	c.ZKAPI.Network = active.Network
	return c, nil
}

func localRequest(ctx context.Context, c config.Config, method, path string) ([]byte, error) {
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(ctx, method, "http://"+c.Listen+path, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := client.Do(r)
	if err != nil {
		return nil, errors.New("local service is unavailable; start it with Homebrew services, systemd, or zkapi-clientd serve")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("local management request failed")
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
