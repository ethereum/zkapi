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
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
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
	protocolFlag := global.String("vault-protocol", os.Getenv("ZKAPI_VAULT_PROTOCOL"), "override saved vault stack: concession or legacy")
	showVersion := global.Bool("version", false, "print version")
	global.Usage = help
	if err := global.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	protocol, err := vaultProtocol(*protocolFlag)
	if err != nil {
		return err
	}
	explicitDir := false
	global.Visit(func(f *flag.Flag) {
		if f.Name == "config-dir" && dir != "" {
			explicitDir = true
		}
	})
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
	if args[0] != "config" && args[0] != "serve" && args[0] != "withdraw" && args[0] != "list-models" {
		return errors.New("unknown command; use config, serve, withdraw or list-models (--help for usage); saved settings belong under config")
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
		if handled, err := runConfigSettings(dir, args[1:], os.Stdout); handled || err != nil {
			return err
		}
	}
	savedProtocol, err := config.LoadVaultProtocol(dir)
	if err != nil {
		return err
	}
	if *protocolFlag == "" {
		protocol, err = vaultProtocol(savedProtocol)
		if err != nil {
			return err
		}
	}
	if protocol == "legacy" {
		// A saved legacy choice explicitly binds the resolved profile; no need
		// to repeat --config-dir on every command for the default profile.
		return dispatchLegacy(dir, explicitDir || savedProtocol == "legacy", args)
	}
	if args[0] == "config" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ui := &terminalSetupPrompter{out: os.Stdout}
		defer ui.Close()
		return runConfigure(ctx, dir, args[1:], ui, os.Stdout)
	}
	if args[0] == "serve" && len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Println("Usage: zkapi-clientd serve [--model MODEL] [--semi-verbose | --verbose]\nOpens a missing private note automatically when the funding address has enough ETH. Verbose modes log private prompt/response content. Run the saved configuration. Run zkapi-clientd config --setup to configure missing prerequisites.")
		return nil
	}
	if args[0] == "withdraw" && len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Println("Usage: zkapi-clientd withdraw [--public | OPTIONS]\nWithout options: guided private withdrawal, then public ETH return with separate approval. --public: standalone public return. Explicit options below use the protocol's quote/approval and recovery flow without an automatic public sweep.")
		_ = runWithdrawal(context.Background(), config.Config{}, []string{"--help"}, os.Stdout)
		return nil
	}
	if args[0] == "list-models" && len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Println("Usage: zkapi-clientd list-models\nList public model IDs/caps. Set the default with config --model MODEL. No payments.")
		return nil
	}
	c, err := config.Load(dir)
	if err != nil {
		return configurationRequired(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if args[0] == "list-models" {
		return runModels(ctx, dir, c, args[0], args[1:], os.Stdout)
	}
	if args[0] == "withdraw" {
		// Stderr: explicit withdraw options print machine-readable results.
		printEarlierDeployments(os.Stderr, dir, c.ZKAPI.Network)
		action := "withdraw"
		if len(args) == 2 && args[1] == "--public" {
			action = "return"
		} else if len(args) != 1 {
			return runConfiguredWithdrawal(ctx, dir, c, args[1:], os.Stdout)
		}
		ui := &terminalSetupPrompter{out: os.Stdout}
		defer ui.Close()
		if err := runConfigAction(ctx, dir, c, action, ui, os.Stdout); err != nil {
			return err
		}
		return nil
	}
	expected := c
	c, err = serveConfig(c, args[1:])
	if err != nil {
		return err
	}
	level, err := serveLogLevel(args[1:])
	if err != nil {
		return err
	}
	if level != activity.Normal {
		logger := log.New(os.Stdout, "zkapi-clientd ", log.LstdFlags)
		logger.Print("WARNING: diagnostic mode logs private prompt/response content; terminal output may be retained by your service manager")
		ctx = activity.WithDiagnostics(ctx, level, logger)
	}
	modelFlags := flag.NewFlagSet("serve", flag.ContinueOnError)
	model := modelFlags.String("model", "", "")
	modelFlags.Bool("verbose", false, "")
	modelFlags.Bool("semi-verbose", false, "")
	if err := modelFlags.Parse(args[1:]); err != nil {
		return err
	}
	fundingModel := *model
	if fundingModel == "" {
		fundingModel = c.DefaultModel
	}
	if fundingModel != "" && !config.ValidModelID(fundingModel) {
		return errors.New("invalid model ID")
	}
	ctx = context.WithValue(ctx, serveModelKey{}, fundingModel)
	return runConfiguredServe(ctx, dir, c, expected, os.Stdout)

}

func help() {
	fmt.Fprintln(os.Stderr, `Usage: zkapi-clientd [--config-dir DIR] [--vault-protocol concession|legacy] COMMAND

  config                 Print saved config as JSON; --help for settings
                         --setup: prepare wallet; --menu: wallet actions
  serve [--model MODEL]  Open a missing note when funded, then serve inference
  withdraw [OPTIONS]     Guided withdrawal (fee paid from the payout where sponsored); --escape / --public
  list-models            List supported model IDs and per-query caps

Run zkapi-clientd config --help for configuration options.
Run zkapi-clientd --version to show the installed version.
Vault: flag > ZKAPI_VAULT_PROTOCOL > saved config --vault-protocol > concession.
Legacy selects the pinned old executable, requires a saved legacy choice or explicit --config-dir,
and preserves native rewriter/cover settings. No automatic fallback or note conversion.
Config: ZKAPI_CLIENTD_CONFIG_DIR or the OS user config directory / zkapi-clientd.
Mainnet is the default; Sepolia keeps a separate wallet.
The network proxy is off by default. Verbose modes log private message content.`)
}

func initialize(dir string, args []string) error {
	c, err := config.Default()
	if err != nil {
		return err
	}
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	f.StringVar(&c.ZKAPI.Network, "network", c.ZKAPI.Network, "mainnet or sepolia")
	f.StringVar(&c.VerifierURL, "verifier-url", c.VerifierURL, "verifier HTTPS origin")
	f.StringVar(&c.RelayURL, "relay-url", c.RelayURL, "Wisp, socks5://IP:PORT, or conversation-isolated tor://IP:PORT (default: direct HTTPS)")
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
func serveConfig(c config.Config, args []string) (config.Config, error) {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	f.String("model", "", "model for opening-balance recommendation")
	f.Bool("verbose", false, "log messages and detailed operations (private content)")
	f.Bool("semi-verbose", false, "one-line operations and message previews (private content)")
	if _, err := serveLogLevel(args); err != nil {
		return config.Config{}, err
	}
	if err := f.Parse(args); err != nil {
		return config.Config{}, err
	}
	if f.NArg() != 0 {
		return config.Config{}, errors.New("serve accepts no arguments; use zkapi-clientd config to change settings")
	}
	if err := config.Validate(c); err != nil {
		return config.Config{}, err
	}
	return c, nil
}

func zkConfig(c config.Config, client *http.Client) zkapi.Config {
	return zkapi.Config{ClientURL: c.ZKAPI.ClientURL, BridgeToken: c.ZKAPI.BridgeToken, Network: c.ZKAPI.Network, HTTPClient: client, KeyReuseWindow: time.Duration(c.KeyReuseWindowSeconds) * time.Second, TorMode: relay.IsTor(c.RelayURL), TorEndpoint: c.RelayURL, Rewriter: c.Rewriter, ExitRPCURL: c.ZKAPI.ExitRPCURL, BundlerURL: c.ZKAPI.BundlerURL}
}

type zkInference struct{ *zkapi.Client }

func (z zkInference) Complete(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	response, err := z.Client.Complete(ctx, body)
	err = accessPreparationError(ctx, err)
	var remote *zkapi.Error
	if errors.As(err, &remote) {
		switch remote.Code {
		case "receipt_journal_missing":
			// The message names the nullifier the operator needs.
			return nil, &server.BackendError{Status: 409, Code: "receipt_journal_missing", Message: err.Error()}
		case "ownership_proof_sent":
			// The note stays withdrawal-only; waiting or retrying cannot help.
			return nil, &server.BackendError{Status: 409, Code: "ownership_proof_sent", Message: "A withdrawal sent, or may have sent, the ownership proof of the note's current state, so no chat request is made from it. Run zkapi-clientd config --menu and choose withdraw to finish the withdrawal."}
		case "clearance_reserved_state":
			// No chat can settle this state; waiting or retrying cannot help.
			return nil, &server.BackendError{Status: 409, Code: "clearance_reserved_state", Message: "The note's current state is reserved for withdrawal on the zkAPI server (for example because the operator released it), so no chat request can settle it. Run zkapi-clientd config --menu and choose withdraw to withdraw the private balance."}
		case "testnet_password_required":
			return nil, &server.BackendError{Status: 401, Code: "testnet_password_required", Message: remote.Error()}
		case "invalid_model":
			return nil, &server.BackendError{Status: 400, Code: "invalid_model", Message: "Select a model from /v1/models."}
		case "model_not_found":
			return nil, &server.BackendError{Status: 400, Code: "model_not_found", Message: "Model not found. Use a full provider/model ID from /v1/models."}
		case "model_budget_unavailable":
			return nil, &server.BackendError{Status: 400, Code: "model_budget_unavailable", Message: "The model is unavailable or has no reviewed request budget. Select a model from /v1/models."}
		case "model_policy_unavailable":
			return nil, &server.BackendError{Status: 502, Code: "model_policy_unavailable", Message: "The current model policy could not be loaded. Retry when the model service is available."}
		}
		switch remote.Status {
		case http.StatusPaymentRequired:
			return nil, &server.BackendError{Status: 402, Code: "funding_required", Message: "The private balance needs funding. Run zkapi-clientd config --setup to add funding."}
		case http.StatusConflict:
			if remote.Code == "withdrawal_pending" || remote.Code == "withdrawal_conflict" {
				return nil, &server.BackendError{Status: 409, Code: "withdrawal_pending", Message: "The private balance is reserved for withdrawal. Run zkapi-clientd config --menu and choose withdraw to recover the saved destination."}
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
	lockPath := filepath.Join(dir, "daemon.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("a zkAPI client daemon is already using this config directory (lock file: %s%s)", lockPath, config.LockHint(lockPath))
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	// Record the holder so a lock error elsewhere (for example a shell in a
	// different environment sharing this filesystem) can name this process.
	host, _ := os.Hostname()
	_ = lock.Truncate(0)
	_, _ = lock.WriteAt([]byte(fmt.Sprintf("pid=%d host=%s exe=zkapi-clientd-serve", os.Getpid(), host)), 0)
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
	// Earlier deployments' wallets (including the earlier release's payment
	// files) sit beside this one in the profile; name them in either
	// companion mode. They never stop the service.
	for _, warning := range zkapi.EarlierDeploymentWarnings(dir, c.ZKAPI.Network) {
		logger.Print(warning)
	}
	if !c.ZKAPI.ExternalCompanion {
		// Keep the local HTTPS-only bridge in both routing modes so the
		// companion cannot follow a redirect to plaintext HTTP.
		proxy, err := relay.StartConnectProxy(life, c.RelayURL)
		if err != nil {
			return err
		}
		defer proxy.Close()
		cmd, err := zkapi.CompanionCommand(life, zc, zkapi.CompanionConfig{Binary: c.ZKAPI.Binary, SetupDir: c.ZKAPI.ProofSetupDir, StateDir: filepath.Join(dir, "zkapi"), VerifierURL: c.VerifierURL, ProxyURL: proxy.URL, TestnetPassword: password, ExitRPCURL: c.ZKAPI.ExitRPCURL})
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
	// Design §6.7: check the deployment on chain at startup (deposits check
	// again before signing). A mismatch refuses deposits; exits stay open.
	go func() {
		checkCtx, cancel := context.WithTimeout(life, 2*time.Minute)
		defer cancel()
		if err := wallet.CheckDeployment(checkCtx); err != nil {
			logger.Printf("zkAPI deployment check: %v", err)
		}
	}()
	api, err := server.New(backend, c.APIKey, c.Concurrency)
	if err != nil {
		return err
	}
	api.DefaultModel = c.DefaultModel
	api.RewriterNotice = c.Rewriter.Notice
	if c.Rewriter.Enabled() {
		fmt.Fprintln(out, "WARNING: rewriter enabled: uncached user text goes DIRECTLY to the configured rewriter, outside Tor/zkAPI. Target history replays saved rewrites; cache misses rewrite historical user turns. Style rewriting does not guarantee anonymity.")
	}
	api.RequireAPIKey = c.RequireAPIKey
	api.WebSearch = c.WebSearch
	api.Status = server.ServiceStatus{Backend: c.Backend}
	api.Status.Network = c.ZKAPI.Network
	api.Status.RequestBudgetPolicy = "model"
	if deployment, err := zkapi.PackagedDeployment(c.ZKAPI.Network); err == nil {
		api.Status.DeploymentID = deployment.ID
	}
	if funding != nil {
		// server.API rejects browser origins and requires both the local bearer
		// and owner-only credential before dispatching any wallet operation.
		api.ManagementToken = c.ManagementToken
		api.Admin = http.HandlerFunc(funding.ServeAdminHTTP)
	}
	stopCover, err := startServeCover(life, c, logger)
	if err != nil {
		return err
	}
	defer stopCover()
	httpServer := &http.Server{Handler: server.LogRequests(api, logger), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return life }}
	serverDone := make(chan error, 1)
	go func() { serverDone <- httpServer.Serve(listener) }()
	transport := "direct HTTPS (network proxy off)"
	if relay.IsTor(c.RelayURL) {
		transport = "Tor required (conversation isolation; IsolateSOCKSAuth required on Tor)"
	} else if strings.HasPrefix(c.RelayURL, "socks5://") {
		transport = "SOCKS5 proxy required"
	} else if c.RelayURL != "" {
		transport = "encrypted relay required"
	}
	logger.Printf("zkAPI client %s listening at http://%s/v1 (%s); %s", version, c.Listen, c.Backend, transport)
	logger.Printf("zkAPI network: %s", deploymentSummary(c.ZKAPI.Network))
	if c.WebSearch {
		logger.Print("Web search: on by default (OpenRouter; search charges apply)")
	} else {
		logger.Print("Web search: off by default")
	}
	if c.RequireAPIKey {
		logger.Print("Use zkapi-clientd config --api-key to configure your client; Ctrl+C stops the service")
	} else {
		logger.Print("Localhost inference needs no API key; Ctrl+C stops the service")
	}
	if c.KeyReuseWindowSeconds > 0 && relay.IsTor(c.RelayURL) {
		logger.Printf("Tor key reuse: up to %d seconds within prefix-continuing conversations only; new conversations always acquire fresh keys", c.KeyReuseWindowSeconds)
	} else if c.KeyReuseWindowSeconds > 0 {
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

func status(ctx context.Context, dir string, c config.Config, out, warnings io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result := map[string]any{"default_backend": c.Backend, "api_base": "http://" + c.Listen + "/v1", "relay_required": c.RelayURL != ""}
	active, err := resolveActiveConfig(ctx, c)
	result["service_running"] = err == nil
	var mismatch *daemonDeploymentError
	if errors.As(err, &mismatch) {
		return err
	}
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
	// Public identity only. Earlier deployments list which recovery files
	// exist, never their contents.
	if deployment, err := zkapi.PackagedDeployment(c.ZKAPI.Network); err == nil {
		result["deployment_id"] = deployment.ID
		result["deployment_display"] = deployment.Display
		result["contract_address"] = deployment.Contract
		result["protocol_server_url"] = deployment.ProtocolServerURL
	}
	earlier := zkapi.EarlierDeploymentState(dir, c.ZKAPI.Network)
	if earlier == nil {
		earlier = []zkapi.EarlierDeployment{}
	}
	result["earlier_deployments"] = earlier
	printEarlierDeployments(warnings, dir, c.ZKAPI.Network)
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
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(result)
}

// deploymentSummary names the network's packaged deployment for people: its
// display name, ID and vault, all from this build (never from a server URL).
func deploymentSummary(network string) string {
	if network == "" {
		network = "mainnet"
	}
	deployment, err := zkapi.PackagedDeployment(network)
	if err != nil {
		return network
	}
	var details []string
	// An unnamed deployment's fallback name already carries its ID.
	if !strings.Contains(deployment.Display, deployment.ID) {
		details = append(details, "deployment "+deployment.ID)
	}
	if deployment.Deployed {
		details = append(details, "vault "+deployment.Contract)
	} else {
		details = append(details, "not deployed")
	}
	return fmt.Sprintf("%s — %s (%s)", network, deployment.Display, strings.Join(details, ", "))
}

// printEarlierDeployments repeats the earlier-deployment warnings; they
// inform and never stop the command.
func printEarlierDeployments(w io.Writer, dir, network string) {
	for _, warning := range zkapi.EarlierDeploymentWarnings(dir, network) {
		fmt.Fprintln(w, "WARNING:", warning)
	}
}

// daemonDeploymentError refuses a running daemon whose build serves another
// zkAPI deployment: its wallet directories are not this build's.
type daemonDeploymentError struct{ running, packaged string }

func (e *daemonDeploymentError) Error() string {
	return fmt.Sprintf("the running daemon serves zkAPI deployment %s, but this build serves %s; restart the daemon with this build; your other wallet is untouched", e.running, e.packaged)
}

// A daemon from a build before deployment reporting is noted once per
// process on daemonNotices, then attached as before.
var (
	daemonNotices    io.Writer = os.Stderr
	daemonNoticeOnce sync.Once
)

// Management commands authenticate the running daemon, its network and,
// when it reports one, its deployment. This copy does not migrate or modify
// wallet state.
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
	packaged, err := zkapi.PackagedDeployment(active.Network)
	if err != nil {
		return config.Config{}, err
	}
	if active.DeploymentID == "" {
		daemonNoticeOnce.Do(func() {
			fmt.Fprintf(daemonNotices, "WARNING: the running daemon does not report its zkAPI deployment (an earlier build); continuing as if it serves %s. Restart it with this build to confirm.\n", packaged.ID)
		})
	} else if active.DeploymentID != packaged.ID {
		return config.Config{}, &daemonDeploymentError{running: active.DeploymentID, packaged: packaged.ID}
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
