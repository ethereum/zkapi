package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/cover"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

// Compatible requests share a provider credential within this fixed window,
// including requests from different chats and local clients. Zero disables reuse.
const DefaultKeyReuseWindowSeconds = 60
const MaxKeyReuseWindowSeconds = 300

const mainnetVerifierURL = "https://verifier-production-20260917.openanonymity.ai"
const sepoliaVerifierURL = "https://verifier2.openanonymity.ai"

// DefaultVerifierURL is the reviewed verifier for this network. Unknown networks
// have no default and are rejected by Validate.
func DefaultVerifierURL(network string) string {
	switch network {
	case "mainnet":
		return mainnetVerifierURL
	case "sepolia":
		return sepoliaVerifierURL
	default:
		return ""
	}
}

// SelectNetwork follows the network's verifier only when the profile uses its
// default. A separately configured verifier stays explicit across network edits.
func SelectNetwork(c Config, network string) Config {
	if isVerifierOrigin(c.VerifierURL, DefaultVerifierURL(c.ZKAPI.Network)) ||
		(c.ZKAPI.Network == "mainnet" && isVerifierOrigin(c.VerifierURL, sepoliaVerifierURL)) {
		c.VerifierURL = DefaultVerifierURL(network)
	}
	c.ZKAPI.Network = network
	return c
}

func isVerifierOrigin(value, origin string) bool {
	return origin != "" && (value == origin || value == origin+"/")
}

type ZKAPI struct {
	ClientURL         string `json:"client_url"`
	BridgeToken       string `json:"bridge_token"`
	Network           string `json:"network"`
	Binary            string `json:"binary,omitempty"`
	ProofSetupDir     string `json:"proof_setup_dir,omitempty"`
	ExternalCompanion bool   `json:"external_companion,omitempty"`
	// Retained only to load older configurations. Each new request chooses its
	// budget from the selected model; a saved fixed limit has no effect.
	RequestLimitMicroUSD uint64 `json:"request_limit_micro_usd,omitempty"`
	// ExitRPCURL is the owner's own Ethereum RPC for exits (--exit-rpc-url):
	// deployment checks also run through it, the companion reads expiry,
	// roots and logs through it, and exit transactions are sent through it.
	ExitRPCURL string `json:"exit_rpc_url,omitempty"`
	// WithdrawalFees is how a withdrawal pays its network fee by default:
	// "wallet" (the local signing address; the default) or "payout" (a
	// sponsored operation paid from the payout, --fees payout).
	WithdrawalFees string `json:"withdrawal_fees,omitempty"`
	// BundlerURL is the owner's ERC-4337 bundler for gasless withdrawals
	// (--bundler-url); empty uses the deployment's published bundler.
	BundlerURL string `json:"bundler_url,omitempty"`
}

type Config struct {
	Cover    cover.Config    `json:"cover,omitzero"`
	Rewriter rewriter.Config `json:"rewriter,omitzero"`
	// ManagementToken is a separate owner-only credential. It must never be
	// published with config.json or shared with inference API clients.
	ManagementToken       string `json:"-"`
	DefaultModel          string `json:"default_model,omitempty"`
	Listen                string `json:"listen"`
	APIKey                string `json:"api_key"`
	KeyReuseWindowSeconds int    `json:"key_reuse_window_seconds"`
	WebSearch             bool   `json:"web_search"`        // automatically enable OpenRouter web search for chat completions
	RequireAPIKey         bool   `json:"require_api_key"`   // opt in to bearer authentication for loopback inference
	Backend               string `json:"backend"`           // fixed to zkapi; retained for existing profile compatibility
	OrgURL                string `json:"org_url,omitempty"` // legacy profile field; unused
	VerifierURL           string `json:"verifier_url"`
	RelayURL              string `json:"relay_url"` // empty: direct; wss: Wisp; socks5: proxy; tor: conversation isolation
	Concurrency           int    `json:"concurrency"`
	// BillingMode is "metered" (the default when empty) or "ticket":
	// fixed-price tickets that settle when bought and run concurrently.
	BillingMode string `json:"billing_mode,omitempty"`
	ZKAPI       ZKAPI  `json:"zkapi"`
}

// ValidModelID excludes whitespace and terminal control characters.
func ValidModelID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, r := range id {
		if r <= 32 || r >= 127 {
			return false
		}
	}
	return true
}

func DefaultDir() (string, error) {
	if dir := os.Getenv("ZKAPI_CLIENTD_CONFIG_DIR"); dir != "" {
		return filepath.Abs(dir)
	}
	// Honor the previous explicit override only when the renamed one is unset.
	if dir := os.Getenv("OA_CHAT_CONFIG_DIR"); dir != "" {
		return filepath.Abs(dir)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return defaultDirAt(base)
}

// Preserve an existing native wallet in place. Never silently create a fresh
// receiving address while a saved profile or recovery files need attention.
func defaultDirAt(base string) (string, error) {
	target := filepath.Join(base, "zkapi-clientd")
	if _, err := os.Lstat(target); err == nil {
		return target, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	legacy := filepath.Join(base, "oa-chat")
	info, err := os.Lstat(legacy)
	if errors.Is(err, os.ErrNotExist) {
		return target, nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("the configuration directory must be a private real directory; select a valid --config-dir")
	}
	entries, err := os.ReadDir(legacy)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return target, nil
	}
	if _, err := readConfig(legacy); err != nil {
		return "", fmt.Errorf("the profile needs attention; check the saved configuration or select a valid --config-dir: %w", err)
	}
	return legacy, nil
}

func Secret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Default() (Config, error) {
	key, err := Secret()
	if err != nil {
		return Config{}, err
	}
	bridge, err := Secret()
	return Config{KeyReuseWindowSeconds: DefaultKeyReuseWindowSeconds, WebSearch: true, Listen: "127.0.0.1:8787", APIKey: key, Backend: "zkapi", VerifierURL: DefaultVerifierURL("mainnet"), Concurrency: 4, ZKAPI: ZKAPI{ClientURL: "http://127.0.0.1:8790", BridgeToken: bridge, Network: "mainnet"}}, err
}

func Validate(c Config) error {
	if err := c.Cover.Validate(c.RelayURL); err != nil {
		return err
	}
	if err := c.Rewriter.Validate(); err != nil {
		return err
	}
	if c.DefaultModel != "" && !ValidModelID(c.DefaultModel) {
		return errors.New("invalid default model ID")
	}
	if c.BillingMode != "" && c.BillingMode != "metered" && c.BillingMode != "ticket" {
		return errors.New("billing_mode must be metered or ticket")
	}
	if c.KeyReuseWindowSeconds < 0 || c.KeyReuseWindowSeconds > MaxKeyReuseWindowSeconds {
		return errors.New("key_reuse_window_seconds must be between 0 and 300 (0 disables reuse)")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" {
		return errors.New("listen must be a loopback IP and port")
	}
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return errors.New("listen port must be between 1 and 65535")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen must be a numeric loopback IP; use a shared Docker network namespace or an SSH tunnel for remote clients")
	}
	if len(c.APIKey) < 32 || strings.ContainsAny(c.APIKey, "\r\n ") {
		return errors.New("api_key must contain at least 32 non-space characters")
	}
	if c.Backend != "zkapi" {
		return errors.New("this client requires a zkAPI native ETH profile")
	}
	if c.Concurrency < 1 || c.Concurrency > 64 {
		return errors.New("concurrency must be between 1 and 64")
	}
	for _, endpoint := range []string{c.VerifierURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("verifier_url must be an HTTPS origin without credentials, query, or path")
		}
	}
	if _, err := relay.NewClient(c.RelayURL); err != nil {
		return err
	}
	if relay.IsTor(c.RelayURL) && c.ZKAPI.ExternalCompanion {
		return errors.New("Tor mode requires the managed companion so payment traffic uses the configured Tor bridge")
	}
	if c.ZKAPI.Network != "mainnet" && c.ZKAPI.Network != "sepolia" {
		return errors.New("ZKAPI network must be mainnet or sepolia")
	}
	if len(c.ZKAPI.BridgeToken) < 32 {
		return errors.New("ZKAPI bridge_token must have at least 32 characters")
	}
	u, err := url.Parse(c.ZKAPI.ClientURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("ZKAPI client_url must be a local HTTP origin")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return errors.New("ZKAPI client_url must use a numeric loopback IP")
	}
	if c.ZKAPI.ExitRPCURL != "" && !validExitRPC(c.ZKAPI.ExitRPCURL) {
		return errors.New("ZKAPI exit_rpc_url must be an HTTPS URL, or plain HTTP to a node on this machine, without credentials, query or fragment")
	}
	if c.ZKAPI.BundlerURL != "" && !validExitRPC(c.ZKAPI.BundlerURL) {
		return errors.New("ZKAPI bundler_url must be an HTTPS URL, or plain HTTP to a bundler on this machine, without credentials, query or fragment")
	}
	if c.ZKAPI.WithdrawalFees != "" && c.ZKAPI.WithdrawalFees != "wallet" && c.ZKAPI.WithdrawalFees != "payout" {
		return errors.New("ZKAPI withdrawal_fees must be wallet or payout")
	}
	return nil
}

// validExitRPC mirrors zkapi.ValidateExitRPCURL: the owner's own Ethereum RPC
// for exits, over HTTPS or plain HTTP to this machine.
func validExitRPC(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

func Init(dir string, c Config) error {
	if err := Validate(c); err != nil {
		return err
	}
	if err := EnsureDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// O_EXCL means init never overwrites an existing wallet configuration.
	f, err := os.OpenFile(filepath.Join(dir, "config.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("configuration already exists or cannot be created")
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return syncDir(dir)
}

func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("config directory must be a real directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("config directory must be private (chmod 700)")
	}
	return nil
}

func Load(dir string) (Config, error) {
	if err := EnsureDir(dir); err != nil {
		return Config{}, err
	}
	c, err := readConfig(dir)
	if err != nil {
		return Config{}, err
	}
	c.ManagementToken, err = loadManagementToken(dir)
	if err != nil {
		return Config{}, err
	}
	if c.ManagementToken == c.APIKey {
		return Config{}, errors.New("management credential must differ from the inference API key")
	}
	return c, nil
}

func readConfig(dir string) (Config, error) {
	path := filepath.Join(dir, "config.json")
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, errors.New("configuration missing")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return Config{}, errors.New("config.json must be a regular owner-only file (chmod 600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	// Missing fields in older profiles adopt the defaults. Preserve explicit
	// opt-outs, including zero for strict per-request keys and web_search=false.
	c := Config{KeyReuseWindowSeconds: DefaultKeyReuseWindowSeconds, WebSearch: true}
	decoded := struct {
		*Config
		ReuseWindow json.RawMessage `json:"key_reuse_window_seconds"`
		WebSearch   json.RawMessage `json:"web_search"`
	}{Config: &c}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return Config{}, errors.New("invalid config.json; check the configuration field names and values")
	}
	if len(decoded.ReuseWindow) > 0 {
		var seconds *int
		if json.Unmarshal(decoded.ReuseWindow, &seconds) != nil || seconds == nil {
			return Config{}, errors.New("key_reuse_window_seconds must be an integer between 0 and 300")
		}
		c.KeyReuseWindowSeconds = *seconds
	}
	if len(decoded.WebSearch) > 0 {
		var enabled *bool
		if json.Unmarshal(decoded.WebSearch, &enabled) != nil || enabled == nil {
			return Config{}, errors.New("web_search must be a boolean")
		}
		c.WebSearch = *enabled
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return Config{}, errors.New("config.json must contain one JSON object")
	}
	// Older releases saved the former shared default in Mainnet profiles. Adopt
	// the reviewed Mainnet rotation in memory; loading does not rewrite private
	// configuration or touch wallet/recovery files. Preserve other verifier URLs.
	if c.ZKAPI.Network == "mainnet" && isVerifierOrigin(c.VerifierURL, sepoliaVerifierURL) {
		c.VerifierURL = mainnetVerifierURL
	}
	if err := Validate(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
