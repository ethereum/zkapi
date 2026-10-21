package zkapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// Design §6.7 "Go deployment checks": before the first use and before every
// deposit, the client checks through the pinned RPC, and through the user's
// --exit-rpc-url when one is configured, that the deployment it trusts is the
// one on chain: the runtime code of the vault, its proof adapter and the
// Poseidon library hash to the build's pins, the vault names the pinned
// adapter, and the vault's and adapter's getters return the pinned keys,
// periods, versions, circuit and verifying keys. A mismatch refuses deposits
// (deployment_mismatch); exits stay allowed.

// errDeploymentMismatch prefixes every failed deployment check.
var errDeploymentMismatch = errors.New("deployment_mismatch")

// Vault and adapter getters the checks read.
const (
	selectorProofAdapter            = "0xefc91e58"
	selectorStateSigningKeyX        = "0x15fa2a9a"
	selectorStateSigningKeyY        = "0x230e2a24"
	selectorClearanceSigningKeyX    = "0xdc41d636"
	selectorClearanceSigningKeyY    = "0x112cd6bc"
	selectorChallengePeriod         = "0xf3f480d9"
	selectorNoteTTL                 = "0x225af2e7"
	selectorMaxPauseDuration        = "0x64433d27"
	selectorConcessionEscapeVersion = "0x5e00b426"
	selectorRootHistoryWindow       = "0x1fe72de0"
	selectorCircuitIDHash           = "0xda0e8385"
	selectorRequestVKHash           = "0xfe351488"
	selectorWithdrawalVKHash        = "0x7fcd0926"
)

// ValidateExitRPCURL accepts the user's exit RPC: HTTPS, or plain HTTP to a
// node on this machine. No credentials, query or fragment.
func ValidateExitRPCURL(raw string) error {
	u, err := url.Parse(raw)
	invalid := errors.New("the exit RPC must be an HTTPS URL, or plain HTTP to a node on this machine, without credentials, query or fragment")
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return invalid
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return invalid
}

type rpcCaller struct {
	url    string
	client *http.Client
}

func (r rpcCaller) call(ctx context.Context, method string, params []any, result any) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid RPC request")
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("the RPC %s is unavailable", r.url)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != http.StatusOK {
		return fmt.Errorf("the RPC %s is unavailable", r.url)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Error) != 0 || len(envelope.Result) == 0 || json.Unmarshal(envelope.Result, result) != nil {
		return fmt.Errorf("invalid answer from the RPC %s", r.url)
	}
	return nil
}

func (r rpcCaller) word(ctx context.Context, to, data string) (string, error) {
	var result string
	if err := r.call(ctx, "eth_call", []any{map[string]string{"to": to, "data": data}, "latest"}, &result); err != nil {
		return "", err
	}
	if !isHex(result, 32) {
		return "", fmt.Errorf("invalid eth_call answer from the RPC %s", r.url)
	}
	return strings.ToLower(result[2:]), nil
}

func (r rpcCaller) codeHash(ctx context.Context, address string) (string, error) {
	var code string
	if err := r.call(ctx, "eth_getCode", []any{address, "latest"}, &code); err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(code, "0x"))
	if err != nil || !strings.HasPrefix(code, "0x") {
		return "", fmt.Errorf("invalid eth_getCode answer from the RPC %s", r.url)
	}
	return crypto.Keccak256Hash(raw).Hex(), nil
}

func uintWord(value uint64) string {
	return fmt.Sprintf("%064x", value)
}

// verifyDeploymentCode runs every check of deployment d through rpcURL.
func verifyDeploymentCode(ctx context.Context, client *http.Client, rpcURL string, d deploymentIdentity) error {
	if !d.deployed() {
		return ErrDeploymentNotDeployed
	}
	rpc := rpcCaller{url: rpcURL, client: client}
	mismatch := func(what string) error {
		return fmt.Errorf("%w: %s through %s does not match this release's pin; deposits are refused (exits stay available)", errDeploymentMismatch, what, rpcURL)
	}
	for _, code := range []struct{ label, address, pin string }{
		{"the vault's runtime code", d.Contract, d.Evidence.VaultCode},
		{"the proof adapter's runtime code", d.ProofAdapter, d.Evidence.AdapterCode},
		{"the Poseidon library's runtime code", d.PoseidonLibrary, d.Evidence.PoseidonCode},
	} {
		hash, err := rpc.codeHash(ctx, code.address)
		if err != nil {
			return err
		}
		if !strings.EqualFold(hash, code.pin) {
			return mismatch(code.label)
		}
	}
	adapter, err := rpc.word(ctx, d.Contract, selectorProofAdapter)
	if err != nil {
		return err
	}
	if adapter != addressABIWord(strings.ToLower(d.ProofAdapter)) {
		return mismatch("the vault's proofAdapter()")
	}
	circuitHash := strings.ToLower(crypto.Keccak256Hash([]byte(d.Proof.Circuit)).Hex()[2:])
	for _, getter := range []struct {
		label, contract, selector, want string
	}{
		{"stateSigningKeyX()", d.Contract, selectorStateSigningKeyX, addressABIWord(strings.ToLower(d.StateSigningKey.X))},
		{"stateSigningKeyY()", d.Contract, selectorStateSigningKeyY, addressABIWord(strings.ToLower(d.StateSigningKey.Y))},
		{"clearanceSigningKeyX()", d.Contract, selectorClearanceSigningKeyX, addressABIWord(strings.ToLower(d.ClearanceSigning.X))},
		{"clearanceSigningKeyY()", d.Contract, selectorClearanceSigningKeyY, addressABIWord(strings.ToLower(d.ClearanceSigning.Y))},
		{"challengePeriod()", d.Contract, selectorChallengePeriod, uintWord(d.ChallengePeriod)},
		{"noteTtl()", d.Contract, selectorNoteTTL, uintWord(d.NoteTTL)},
		{"maxPauseDuration()", d.Contract, selectorMaxPauseDuration, uintWord(d.MaxPauseDuration)},
		{"CONCESSION_ESCAPE_VERSION()", d.Contract, selectorConcessionEscapeVersion, uintWord(1)},
		{"ROOT_HISTORY_WINDOW()", d.Contract, selectorRootHistoryWindow, uintWord(86400)},
		{"the adapter's CIRCUIT_ID_HASH()", d.ProofAdapter, selectorCircuitIDHash, circuitHash},
		{"the adapter's REQUEST_VK_HASH()", d.ProofAdapter, selectorRequestVKHash, addressABIWord(strings.ToLower(d.Proof.RequestVKKeccak256))},
		{"the adapter's WITHDRAWAL_VK_HASH()", d.ProofAdapter, selectorWithdrawalVKHash, addressABIWord(strings.ToLower(d.Proof.WithdrawalVKKeccak256))},
	} {
		got, err := rpc.word(ctx, getter.contract, getter.selector)
		if err != nil {
			return err
		}
		if got != getter.want {
			return mismatch(getter.label)
		}
	}
	var chain string
	if err := rpc.call(ctx, "eth_chainId", []any{}, &chain); err != nil {
		return err
	}
	if id, ok := new(big.Int).SetString(strings.TrimPrefix(chain, "0x"), 16); !ok || !id.IsUint64() || id.Uint64() != d.ChainID {
		return mismatch("the chain ID")
	}
	return nil
}

// CheckDeployment runs the deployment checks through the pinned RPC and,
// when one is configured, the user's exit RPC. Every configured RPC must
// agree with the pins.
func (c *Client) CheckDeployment(ctx context.Context) error {
	deployment, _, err := deployedDeployment(c.config.Network)
	if err != nil {
		return err
	}
	endpoints, err := c.packagedEndpoints()
	if err != nil {
		return err
	}
	if err := verifyDeploymentCode(ctx, c.inference, endpoints.RPC, deployment); err != nil {
		return err
	}
	if c.config.ExitRPCURL != "" {
		if err := ValidateExitRPCURL(c.config.ExitRPCURL); err != nil {
			return err
		}
		if err := verifyDeploymentCode(ctx, c.inference, c.config.ExitRPCURL, deployment); err != nil {
			return err
		}
	}
	return nil
}
