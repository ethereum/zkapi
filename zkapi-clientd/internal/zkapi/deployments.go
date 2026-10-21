package zkapi

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// These public manifests match the reviewed frontend deployment profiles. A
// mutable remote manifest must not silently change the vault, signer or oracle
// that owns an existing wallet. Updating deployments requires a source release.
//
// This release serves only the concession-exit vault (revision 3, circuit
// zkapi-v2-concession-v1). Until it is deployed on a network, the network's
// manifest is a "not_deployed" placeholder that pins only the circuit, the
// setup and the vault parameters, and nothing starts against it.
//
//go:embed deployments/*.json
var deploymentFiles embed.FS

// packagedDeployments is deploymentFiles, except in tests, which substitute
// deployed fixture profiles (SetPackagedDeploymentsForTesting).
var packagedDeployments fs.FS = deploymentFiles

// SetPackagedDeploymentsForTesting replaces the packaged deployments with
// fsys (holding deployments/<network>.json) and returns a restore function.
// Tests only: production always uses the embedded manifests.
func SetPackagedDeploymentsForTesting(fsys fs.FS) func() {
	previous := packagedDeployments
	packagedDeployments = fsys
	return func() { packagedDeployments = previous }
}

// RequiredCircuitID is the statement this release proves and verifies.
const RequiredCircuitID = "zkapi-v2-concession-v1"

// ErrDeploymentNotDeployed refuses a network whose packaged manifest is a
// placeholder: its vault is not deployed yet.
var ErrDeploymentNotDeployed = errors.New("deployment_not_deployed: the zkAPI concession-exit vault is not deployed on this network yet, so this release cannot fund, use or withdraw a note there; a note of the earlier vault is withdrawn with the earlier (legacy) zkapi-clientd release")

// LegacyRelease is the earlier vault's point release (design §10.7 D step
// 2): deposits closed, the mutual close, and an escape with its runbook
// (docs/LEGACY_ESCAPE.md on that line). A note of the earlier vault is
// withdrawn with it.
const LegacyRelease = "zkapi-clientd 0.1.7 (release line release/v2-note-bound)"

// legacyDeploymentIDs are the earlier vaults' deployments (circuit
// zkapi-v2-note-bound-v1). Their wallets live in their own state directories,
// which this release never opens; an open note there gets a warning.
var legacyDeploymentIDs = map[string][]string{
	"mainnet": {"zkapi-native-eth-mainnet-note-bound-v1-fresh-20260930", "zkapi-native-eth-mainnet-note-bound-v1-fresh-20260928"},
	"sepolia": {"zkapi-native-eth-sepolia-note-bound-v1-fresh-20260930"},
}

// LegacyWalletWarning reports an open note of an earlier vault in stateDir
// (the companion state root), with the way out; "" when there is none. The
// release no longer refuses to start: the two wallets never share a state
// directory.
func LegacyWalletWarning(stateDir, network string) string {
	if network == "" {
		network = "mainnet"
	}
	for _, id := range legacyDeploymentIDs[network] {
		dir := filepath.Join(stateDir, network, id)
		if _, err := os.Lstat(filepath.Join(dir, "note_state.json")); err == nil {
			return fmt.Sprintf("A private note of the earlier zkAPI vault (deployment %s) is still open in %s. This release serves only the concession-exit vault and never opens that wallet; withdraw the note with the earlier zkapi-clientd release, %s, which closes deposits there and keeps that vault's mutual close and escape (withdraw --escape), then fund this release.", id, dir, LegacyRelease)
		}
	}
	return ""
}

type deploymentIdentity struct {
	// Status is "not_deployed" for a placeholder, else "deployed" (or empty).
	Status   string `json:"deployment_status"`
	ID       string `json:"deployment_id"`
	ChainID  uint64 `json:"chain_id"`
	Contract string `json:"contract_address"`
	Asset    string `json:"billing_asset"`
	Unit     string `json:"billing_unit"`
	// Go sends chain and indexer reads only to these packaged origins. A
	// companion's copies are compared with them as a substitution tripwire.
	RPC               string `json:"rpc_url"`
	IndexerURL        string `json:"indexer_url"`
	ProtocolServerURL string `json:"protocol_server_url"`
	NoteTTL           uint64 `json:"note_ttl_seconds"`
	// The concession vault's parameters, pinned by the build (design §10.3).
	ChallengePeriod  uint64 `json:"challenge_period_seconds"`
	MaxPauseDuration uint64 `json:"max_pause_duration_seconds"`
	SettlementWindow uint64 `json:"settlement_window_seconds"`
	ExitConcession   int    `json:"exit_concession"`
	DeployBlock      uint64 `json:"deploy_block"`
	// The contracts the client checks before trusting the vault.
	ProofAdapter     string             `json:"proof_adapter_address"`
	PoseidonLibrary  string             `json:"poseidon_library_address"`
	StateSigningKey  *curvePoint        `json:"state_signing_key"`
	ClearanceSigning *curvePoint        `json:"clearance_signing_key"`
	Evidence         deploymentEvidence `json:"deployment_evidence"`
	// Gasless is the deployment's gasless withdrawal paymaster (design 4.3);
	// nil (absent or null) hides --fees payout and changes nothing else.
	Gasless *gaslessProfile `json:"gasless"`
	deploymentCapabilities
	Proof   proofSetupIdentity `json:"proof_setup"`
	Privacy struct {
		IssuerURL   string `json:"issuer_url"`
		VerifierURL string `json:"verifier_url"`
	} `json:"privacy_mode"`
}

type curvePoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// deploymentEvidence pins the runtime code of the vault, the proof adapter and
// the Poseidon library (keccak256 of eth_getCode), checked before deposits.
type deploymentEvidence struct {
	VaultCode    string `json:"vault_runtime_keccak256"`
	AdapterCode  string `json:"adapter_runtime_keccak256"`
	PoseidonCode string `json:"poseidon_runtime_keccak256"`
	// The gasless contracts' pins (design 4.3), checked before a gasless
	// withdrawal only; absent for a deployment without the paymaster.
	EntryPointCode    string `json:"entry_point_runtime_keccak256,omitempty"`
	SenderCreatorCode string `json:"sender_creator_runtime_keccak256,omitempty"`
	PaymasterCode     string `json:"paymaster_runtime_keccak256,omitempty"`
	FactoryCode       string `json:"factory_runtime_keccak256,omitempty"`
	// ImplementationCode pins the transit accounts' logic.
	ImplementationCode string `json:"account_implementation_runtime_keccak256,omitempty"`
}

// deployed reports whether this is a deployed vault rather than a placeholder.
func (d deploymentIdentity) deployed() bool {
	return d.Status != "not_deployed"
}

// deploymentCapabilities are optional manifest keys for redeployed vaults.
// Absent keys describe the currently deployed vaults and legacy servers.
type deploymentCapabilities struct {
	VaultRevision           int    `json:"vault_revision"`
	ClearanceOwnershipProof string `json:"clearance_ownership_proof"`
}

// A server that may require withdrawal-clearance ownership proofs needs a
// companion able to send them before any note is reserved for withdrawal.
func (c deploymentCapabilities) requiresClearanceOwnershipProof() bool {
	return c.ClearanceOwnershipProof == "required" || c.ClearanceOwnershipProof == "optional" || c.VaultRevision >= 2
}

type proofSetupIdentity struct {
	Circuit                      string `json:"circuit_id"`
	SetupID                      string `json:"setup_id"`
	RequestVKKeccak256           string `json:"request_vk_keccak256"`
	WithdrawalVKKeccak256        string `json:"withdrawal_vk_keccak256"`
	RequestProvingKeySHA256      string `json:"request_proving_key_sha256"`
	RequestVerifyingKeySHA256    string `json:"request_verifying_key_sha256"`
	WithdrawalProvingKeySHA256   string `json:"withdrawal_proving_key_sha256"`
	WithdrawalVerifyingKeySHA256 string `json:"withdrawal_verifying_key_sha256"`
}

// MatchesDeployment checks a public management response against this release's
// immutable network/vault identity without a network read or wallet operation.
func MatchesDeployment(network, deploymentID, contract string) bool {
	deployment, _, err := deployedDeployment(network)
	return err == nil && deployment.ID == deploymentID && strings.EqualFold(deployment.Contract, contract)
}

// deployedDeployment is pinnedDeployment for a network whose vault is
// deployed; a placeholder is ErrDeploymentNotDeployed.
// RequireDeployment checks the embedded release profile without network access.
// CLI entry points call it before attaching to any daemon or opening a wallet.
func RequireDeployment(network string) error {
	_, _, err := deployedDeployment(network)
	return err
}

func deployedDeployment(network string) (deploymentIdentity, []byte, error) {
	identity, raw, err := pinnedDeployment(network)
	if err != nil {
		return identity, raw, err
	}
	if !identity.deployed() {
		return identity, raw, ErrDeploymentNotDeployed
	}
	return identity, raw, nil
}

func pinnedDeployment(network string) (deploymentIdentity, []byte, error) {
	if network == "" {
		network = "mainnet"
	}
	if _, err := ChainID(network); err != nil {
		return deploymentIdentity{}, nil, err
	}
	raw, err := fs.ReadFile(packagedDeployments, "deployments/"+network+".json")
	if err != nil {
		return deploymentIdentity{}, nil, errors.New("invalid packaged zkAPI deployment")
	}
	identity, err := parseDeploymentIdentity(network, raw)
	if err != nil {
		return deploymentIdentity{}, nil, err
	}
	return identity, raw, nil
}

func parseDeploymentIdentity(network string, raw []byte) (deploymentIdentity, error) {
	invalid := errors.New("invalid packaged zkAPI deployment")
	chain, err := ChainID(network)
	if err != nil {
		return deploymentIdentity{}, err
	}
	var identity deploymentIdentity
	if json.Unmarshal(raw, &identity) != nil || identity.ChainID != chain || identity.ID == "" || identity.Asset != "native_eth" || identity.Unit != "gwei" || identity.Proof.Circuit != RequiredCircuitID || identity.Proof.SetupID == "" || identity.NoteTTL == 0 {
		return deploymentIdentity{}, invalid
	}
	// Only the concession vault: revision 3 with the concession exit, whose
	// clearances require an ownership proof.
	if identity.VaultRevision != 3 || identity.ExitConcession != 1 || identity.ClearanceOwnershipProof != "required" || identity.SettlementWindow == 0 || identity.ChallengePeriod == 0 || identity.MaxPauseDuration < 2*identity.ChallengePeriod {
		return deploymentIdentity{}, invalid
	}
	for _, pin := range []string{identity.Proof.RequestVKKeccak256, identity.Proof.WithdrawalVKKeccak256} {
		if !isHex(pin, 32) {
			return deploymentIdentity{}, invalid
		}
	}
	switch identity.Status {
	case "not_deployed":
		// A placeholder pins no vault, endpoints or keys yet.
		if _, ok := canonicalEndpoint(identity.RPC); !ok {
			return deploymentIdentity{}, invalid
		}
		return identity, nil
	case "", "deployed":
	default:
		return deploymentIdentity{}, invalid
	}
	for _, endpoint := range []string{identity.RPC, identity.IndexerURL, identity.ProtocolServerURL} {
		if _, ok := canonicalEndpoint(endpoint); !ok {
			return deploymentIdentity{}, invalid
		}
	}
	for _, address := range []string{identity.Contract, identity.ProofAdapter, identity.PoseidonLibrary} {
		if !isHex(address, 20) {
			return deploymentIdentity{}, invalid
		}
	}
	for _, code := range []string{identity.Evidence.VaultCode, identity.Evidence.AdapterCode, identity.Evidence.PoseidonCode} {
		if !isHex(code, 32) {
			return deploymentIdentity{}, invalid
		}
	}
	if identity.StateSigningKey == nil || identity.ClearanceSigning == nil || !isField(identity.StateSigningKey.X) || !isField(identity.StateSigningKey.Y) || !isField(identity.ClearanceSigning.X) || !isField(identity.ClearanceSigning.Y) {
		return deploymentIdentity{}, invalid
	}
	return identity, nil
}

// canonicalEndpoint normalizes only spellings that address the same HTTPS
// origin and path: scheme and host case, an explicit :443 and one trailing
// slash. Anything else (credentials, query, fragment, another port or path,
// a trailing-dot host) stays distinct. The result is used for comparison
// only; requests always use the packaged string.
func canonicalEndpoint(raw string) (string, bool) {
	if strings.Contains(raw, "#") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(u.Host, ":") {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	if port := u.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host + strings.TrimSuffix(u.EscapedPath(), "/"), true
}

func sameEndpoint(a, b string) bool {
	left, leftOK := canonicalEndpoint(a)
	right, rightOK := canonicalEndpoint(b)
	return leftOK && rightOK && left == right
}

// The companion reads this local, package-pinned manifest. It still validates
// its contents and local proving keys before opening any wallet state.
func writeDeploymentManifest(dir string, raw []byte) (string, error) {
	path := filepath.Join(dir, "deployment-manifest.json")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return "", errors.New("zkAPI deployment manifest must be a private regular file")
		}
		saved, err := os.ReadFile(path)
		if err != nil {
			return "", errors.New("deployment manifest does not match this client's pinned configuration")
		}
		if bytes.Equal(saved, raw) {
			return path, nil
		}
		// No exception: a saved manifest is never rebound or rewritten. The
		// earlier vaults' origin migrations do not apply to this deployment.
		return "", errors.New("deployment manifest does not match this client's pinned configuration")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("cannot read saved zkAPI deployment")
	}
	f, err := os.CreateTemp(dir, ".deployment-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err == nil {
		err = syncDirectoryChain(dir)
	}
	return path, err
}

// Validate the installed proving assets before the companion opens its wallet.
// A structurally valid key for another setup is not evidence for the pinned
// vault: all four artifacts must match the immutable deployment manifest.
func verifyProofSetup(setupDir string, proof proofSetupIdentity) error {
	files := []struct{ name, digest string }{
		{"request.pk", proof.RequestProvingKeySHA256},
		{"request.vk", proof.RequestVerifyingKeySHA256},
		{"withdrawal.pk", proof.WithdrawalProvingKeySHA256},
		{"withdrawal.vk", proof.WithdrawalVerifyingKeySHA256},
	}
	for _, asset := range files {
		if decoded, err := hex.DecodeString(asset.digest); err != nil || len(decoded) != sha256.Size || asset.digest != hex.EncodeToString(decoded) {
			return fmt.Errorf("zkAPI proving setup pin for %s is invalid", asset.name)
		}
		path := filepath.Join(setupDir, asset.name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("zkAPI proving setup file %s is missing or not regular", asset.name)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("cannot read zkAPI proving setup file %s", asset.name)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			return fmt.Errorf("zkAPI proving setup file %s is not regular", asset.name)
		}
		hash := sha256.New()
		_, readErr := io.Copy(hash, file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != asset.digest {
			return fmt.Errorf("zkAPI proving setup file %s does not match the deployment SHA-256 pin", asset.name)
		}
	}
	return nil
}
