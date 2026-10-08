package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
	"golang.org/x/sys/unix"
)

type setupPrompter interface {
	Ask(context.Context, string, string) (string, error)
	Confirm(context.Context, string) (bool, error)
	Continue(context.Context, string) (bool, error)
	Printf(string, ...any)
}

// Open the controlling terminal only when a question is necessary. In
// particular, never interpret a piped installation script as spending consent.
type terminalSetupPrompter struct {
	out       io.Writer
	input     *bufio.Reader
	device    *setupTerminal
	displayMu sync.Mutex
	display   setupDisplay
}

// Read directly from a nonblocking descriptor. Darwin can report POLLNVAL for
// /dev/tty; a subsequent blocking read would wait for another complete line
// even after cancellation. Avoid both that read and os.File's runtime poller.
type setupTerminal struct{ fd int }

func (d *setupTerminal) Read(buffer []byte) (int, error) {
	n, err := unix.Read(d.fd, buffer)
	if n < 0 {
		n = 0
	}
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

func (p *terminalSetupPrompter) Close() {
	p.ClearProgress()
	if p.device != nil {
		_ = unix.Close(p.device.fd)
		p.device = nil
	}
}

func (p *terminalSetupPrompter) Printf(format string, args ...any) {
	p.displayMu.Lock()
	defer p.displayMu.Unlock()
	p.finishDisplayLocked()
	_, _ = fmt.Fprintf(p.out, format, args...)
}

func (p *terminalSetupPrompter) openTerminal() error {
	if p.input == nil {
		fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return errors.New("setup needs an interactive terminal; run zkapi-clientd config in a terminal to answer the setup questions")
		}
		device := &setupTerminal{fd: fd}
		p.device, p.input = device, bufio.NewReader(device)
	}
	return nil
}

func (p *terminalSetupPrompter) Secret(ctx context.Context, question string) (string, error) {
	p.ClearProgress()
	if err := p.openTerminal(); err != nil {
		return "", err
	}
	if p.device == nil {
		return "", errors.New("password entry requires a controlling terminal")
	}
	restore, err := disableTerminalEcho(p.device.fd)
	if err != nil {
		return "", errors.New("could not hide password input")
	}
	defer restore()
	defer p.Printf("\n")
	return p.Ask(ctx, question, "")
}

func (p *terminalSetupPrompter) Ask(ctx context.Context, question, fallback string) (string, error) {
	p.ClearProgress()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := p.openTerminal(); err != nil {
		return "", err
	}
	p.Printf("%s", question)
	if fallback != "" {
		p.Printf(" [%s]", fallback)
	}
	p.Printf(": ")
	var line strings.Builder
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if p.device != nil && p.input.Buffered() == 0 {
			fds := []unix.PollFd{{Fd: int32(p.device.fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 100)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return "", errors.New("could not read setup terminal")
			}
			if n == 0 {
				continue
			}
		}
		b, err := p.input.ReadByte()
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			// Some terminal devices return an immediate poll event while no
			// canonical input is available. Bound retries without busy-spinning.
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			case <-timer.C:
				continue
			}
		}
		if err != nil {
			return "", errors.New("setup input ended; run zkapi-clientd config again to continue")
		}
		if b == '\n' {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			answer := strings.TrimSpace(line.String())
			if answer == "" {
				answer = fallback
			}
			return answer, nil
		}
		if line.Len() >= 4096 {
			return "", errors.New("setup input is too long")
		}
		line.WriteByte(b)
	}
}

func (p *terminalSetupPrompter) Confirm(ctx context.Context, question string) (bool, error) {
	for {
		answer, err := p.Ask(ctx, question+" (yes/no)", "no")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "yes", "y":
			return true, nil
		case "no", "n":
			return false, nil
		default:
			p.Printf("Please enter yes or no.\n")
		}
	}
}

// Continue accepts a fresh Enter only after the payment is ready. Discard both
// reader lookahead and terminal input accumulated while waiting for funds so an
// earlier keypress cannot authorize the newly displayed deposit.
func (p *terminalSetupPrompter) Continue(ctx context.Context, question string) (bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if err := p.openTerminal(); err != nil {
			return false, err
		}
		if p.device != nil {
			p.input.Reset(p.device)
			if err := flushTerminalInput(p.device.fd); err != nil {
				return false, errors.New("could not clear pending setup input; run zkapi-clientd config again to continue")
			}
		}
		answer, err := p.Ask(ctx, question, "")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "":
			return true, nil
		case "cancel", "no", "n":
			return false, nil
		default:
			p.Printf("Press Enter to continue, or type cancel.\n")
		}
	}
}

type startOptions struct {
	network, usd, model, listen        string
	prepared                           *config.Config
	setupOnly, checkOnly, quietStartup bool
	allowUnfunded                      bool // serve --allow-unfunded; only changes the resume hint here
}

func parseStartOptions(args []string) (startOptions, error) {
	var options startOptions
	f := flag.NewFlagSet("start", flag.ContinueOnError)
	f.StringVar(&options.network, "network", "", "network for new setup; must match an existing wallet")
	f.StringVar(&options.usd, "usd", "", "preferred USD deposit amount; spending still requires confirmation")
	f.StringVar(&options.model, "model", "", "deprecated compatibility option; select the model on each inference request")
	f.StringVar(&options.listen, "listen", "", "loopback API address for new setup")
	if err := f.Parse(args); err != nil {
		return options, err
	}
	empty := false
	f.Visit(func(f *flag.Flag) { empty = empty || f.Value.String() == "" })
	if empty || f.NArg() != 0 {
		return options, errors.New("start flags require nonempty values; unexpected arguments are not accepted")
	}
	if options.network != "" && options.network != "mainnet" && options.network != "sepolia" {
		return options, errors.New("network must be mainnet or sepolia")
	}
	if options.usd != "" {
		if _, err := parseFundingAmountForAsset(options.usd, 6, "USD"); err != nil {
			return options, err
		}
	}
	return options, nil
}

func prepareStartConfig(ctx context.Context, dir string, options startOptions, ui setupPrompter) (config.Config, error) {
	if err := ctx.Err(); err != nil {
		return config.Config{}, err
	}
	// Lstat distinguishes absent configuration from invalid files and dangling
	// symlinks. Load errors must never trigger reinitialization of a wallet.
	if err := config.EnsureDir(dir); err != nil {
		return config.Config{}, err
	}
	_, err := os.Lstat(filepath.Join(dir, "config.json"))
	if err == nil {
		c, err := config.Load(dir)
		if err != nil {
			return c, err
		}
		if options.network != "" && options.network != c.ZKAPI.Network {
			return c, fmt.Errorf("this configuration uses %s; use that network or select a separate --config-dir for %s", c.ZKAPI.Network, options.network)
		}
		if options.listen != "" && options.listen != c.Listen {
			return c, errors.New("--listen differs from the saved configuration; reuse its address or choose a separate --config-dir")
		}
		ui.Printf("Using saved configuration.\n")
		return c, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return config.Config{}, errors.New("cannot inspect existing configuration; preserve it and check directory permissions")
	}
	for _, name := range []string{"funding", "zkapi", "tickets.json", "management-token"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return config.Config{}, errors.New("config.json is missing but wallet state exists; restore your configuration backup or use a separate --config-dir")
		}
	}
	c, err := config.Default()
	if err != nil {
		return c, err
	}
	c.Backend = "zkapi"
	defaultNetwork := c.ZKAPI.Network
	c.ZKAPI.Network = options.network
	for c.ZKAPI.Network == "" {
		answer, err := ui.Ask(ctx, "Choose network: mainnet (real ETH) or sepolia (test ETH)", defaultNetwork)
		if err != nil {
			return c, err
		}
		switch strings.ToLower(answer) {
		case "mainnet", "sepolia":
			c.ZKAPI.Network = strings.ToLower(answer)
		default:
			ui.Printf("Enter mainnet or sepolia.\n")
		}
	}
	c.VerifierURL = config.DefaultVerifierURL(c.ZKAPI.Network)
	if options.listen != "" {
		c.Listen = options.listen
	}
	if err := ctx.Err(); err != nil {
		return c, err
	}
	if err := config.Init(dir, c); err != nil {
		return c, err
	}
	c, err = config.Load(dir) // Also creates the separate owner-only management credential.
	if err == nil {
		ui.Printf("Created private configuration. Back up your configuration directory to preserve your wallet and recovery state.\n")
	}
	return c, err
}

// Drop routine daemon logs while questions are displayed; enable them once
// setup finishes. Both writes and activation are serialized with the logger.
type setupLogWriter struct {
	mu      sync.Mutex
	out     io.Writer
	enabled bool
}

func (w *setupLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.enabled {
		return len(p), nil
	}
	return w.out.Write(p)
}

func (w *setupLogWriter) enable() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = true
}

type startRuntime struct {
	testnet   func(context.Context, string, config.Config, setupPrompter) error
	active    func(context.Context, config.Config) (config.Config, error)
	probe     func(context.Context, config.Config) (bool, error)
	serve     func(context.Context, string, config.Config, io.Writer) error
	companion func(context.Context, config.Config) error
	fund      func(context.Context, config.Config, string, string, setupPrompter) error
	interval  time.Duration
	timeout   time.Duration
}

func runGuidedStart(ctx context.Context, dir string, args []string, ui setupPrompter, out io.Writer) error {
	options, err := parseStartOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	runtime := startRuntime{
		testnet: prepareSepoliaAccess,
		active:  resolveActiveConfig, probe: probeSetupService, serve: serve, companion: checkSetupCompanion,
		fund:     runGuidedFunding,
		interval: 500 * time.Millisecond, timeout: 90 * time.Second,
	}
	// A legacy start override also needs the original saved snapshot. Capture
	// it before prepareStartConfig applies the requested runtime mode.
	if saved, loadErr := config.Load(dir); loadErr == nil {
		runtime.serve = configuredRuntime(saved).serve
	}
	err = guidedStart(ctx, dir, options, ui, out, runtime)
	if ctx.Err() != nil {
		ui.Printf("\nStopped. Your saved wallet state is preserved; rerun the same start command to continue.\n")
		return nil
	}
	return err
}

func guidedStart(ctx context.Context, dir string, options startOptions, ui setupPrompter, out io.Writer, runtime startRuntime) (result error) {
	defer clearSetupProgress(ui)
	var c config.Config
	var err error
	if options.prepared != nil {
		c = *options.prepared
	} else {
		c, err = prepareStartConfig(ctx, dir, options, ui)
	}
	if err != nil {
		return err
	}
	if options.prepared == nil && runtime.active != nil {
		checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
		active, activeErr := runtime.active(checkCtx, c)
		checkCancel()
		if activeErr == nil {
			if active.Backend != "zkapi" || active.ZKAPI.Network != c.ZKAPI.Network {
				return errors.New("the running daemon's network differs from this configuration; preserve the wallet and stop the conflicting service yourself")
			}
			// Match an existing service only in memory. Keep the configured
			// network, wallet identity, and saved default unchanged.
			c.Backend = active.Backend
		}
	}
	if options.model != "" {
		ui.Printf("The legacy --model option does not affect funding; select a model on each inference request.\n")
	}
	if !options.quietStartup {
		ui.Printf("Network: %s.\n", c.ZKAPI.Network)
	}
	attached, err := runtime.probe(ctx, c)
	if err != nil {
		return err
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	logs := &setupLogWriter{out: out, enabled: options.checkOnly}
	var done chan error
	if attached {
		if !options.quietStartup {
			ui.Printf("Using the compatible daemon already running at http://%s.\n", c.Listen)
		}
	} else {
		if runtime.testnet != nil {
			if err := runtime.testnet(ctx, dir, c, ui); err != nil {
				return err
			}
		}
		if !options.quietStartup {
			setupProgress(ui, "Starting the local API...")
		}
		done = make(chan error, 1)
		go func() {
			done <- runtime.serve(life, dir, c, logs)
			cancel()
		}()
		defer func() {
			cancel()
			if done != nil {
				if err := <-done; err != nil && (result == nil || errors.Is(result, context.Canceled)) {
					result = err
				}
			}
		}()
	}
	readyCtx, readyCancel := context.WithTimeout(life, runtime.timeout)
	defer readyCancel()
	previousStartup := ""
	for {
		running, err := runtime.probe(readyCtx, c)
		if err != nil && attached {
			return err
		}
		// The process we own binds before validating companion assets. Until
		// its HTTP handler starts, even authentication probes can time out.
		// Retry during that bounded startup period, but remain strict about a
		// service found by the initial probe or an attached daemon changing.
		if err == nil && running && runtime.companion(readyCtx, c) == nil {
			break
		}
		if !options.quietStartup {
			status := "Waiting for the local API to start..."
			if err == nil && running {
				status = "Preparing the wallet companion and proving assets..."
			}
			if status != previousStartup {
				setupProgress(ui, "%s", status)
				previousStartup = status
			}
		}
		timer := time.NewTimer(runtime.interval)
		select {
		case <-readyCtx.Done():
			timer.Stop()
			if life.Err() != nil {
				return life.Err()
			}
			return errors.New("setup timed out waiting for the local API and companion; check that zkapi-clientd, zkapi-walletd, and proving assets are installed together, then run zkapi-clientd config")
		case <-timer.C:
		}
	}
	readyCancel()
	clearSetupProgress(ui)
	err = runtime.fund(life, c, options.usd, options.model, ui)
	waiting := errors.Is(err, errWalletNotReady)
	if err != nil && !waiting {
		return err
	}
	if err := life.Err(); err != nil {
		return err
	}
	if options.setupOnly {
		return nil
	}
	if waiting {
		ui.Printf("\nLocal API running; inference is unavailable until the wallet can spend.\n")
	} else {
		ui.Printf("\nReady for inference.\n")
	}
	showClientConnection(c, ui)
	showCustomProfileHint(dir, ui)
	if attached {
		ui.Printf("The existing daemon continues running.\n")
		return nil
	}
	resume := "zkapi-clientd serve"
	if options.allowUnfunded {
		resume += " --allow-unfunded"
	}
	ui.Printf("Leave this terminal running. Ctrl+C stops the daemon; run %s to resume.\n", resume)
	logs.enable()
	result = <-done
	done = nil
	return result
}

// Keep machine-specific paths out of normal configuration and serve output.
func showClientConnection(c config.Config, ui setupPrompter) {
	ui.Printf("OpenAI base URL: http://%s/v1\n", c.Listen)
	if c.RequireAPIKey {
		ui.Printf("API key: required. Get it with zkapi-clientd config --api-key.\n")
	} else {
		ui.Printf("API key: not required (localhost only).\n")
	}
}

func showCustomProfileHint(dir string, ui setupPrompter) {
	defaultDir, err := config.DefaultDir()
	if err != nil || filepath.Clean(dir) != filepath.Clean(defaultDir) {
		ui.Printf("For this custom profile, keep using the same --config-dir option.\n")
	}
}

func probeSetupService(ctx context.Context, c config.Config) (bool, error) {
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", c.Listen)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	_ = connection.Close()
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	active, err := resolveActiveConfig(checkCtx, c)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, errors.New("the configured API port is occupied but its daemon could not be authenticated; stop the conflicting service yourself or choose a separate configuration and listen address")
	}
	if active.Backend != "zkapi" || active.ZKAPI.Network != c.ZKAPI.Network {
		return false, errors.New("the running daemon uses a different network; stop it before changing configuration")
	}
	return true, nil
}

func checkSetupCompanion(ctx context.Context, c config.Config) error {
	client, err := relay.NewClient(c.RelayURL)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	wallet, err := zkapi.New(zkConfig(c, client))
	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := wallet.WalletStatus(checkCtx)
	if err != nil {
		return err
	}
	var state struct {
		HasNote *bool `json:"has_note"`
	}
	if json.Unmarshal(raw, &state) != nil || state.HasNote == nil {
		return errors.New("invalid companion wallet status")
	}
	return nil
}
