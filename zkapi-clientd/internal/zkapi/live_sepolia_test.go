package zkapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
)

// Opt-in read-only acceptance against the actual packaged Sepolia deployment.
// It never starts a wallet, funds an address, signs a proof, or sends a
// transaction. ZKAPI_TEST_EXIT_RPC replaces the pinned RPC for the chain
// reads, as an exit RPC would.
func TestLiveSepoliaDeployment(t *testing.T) {
	if os.Getenv("ZKAPI_TEST_SEPOLIA") != "1" {
		t.Skip("set ZKAPI_TEST_SEPOLIA=1 for read-only Sepolia acceptance")
	}
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	deployment, _, err := deployedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 25 * time.Second}
	rpcURL := deployment.RPC
	if override := os.Getenv("ZKAPI_TEST_EXIT_RPC"); override != "" {
		if err := ValidateExitRPCURL(override); err != nil {
			t.Fatal(err)
		}
		rpcURL = override
	}
	if err := verifyDeploymentCode(ctx, client, rpcURL, deployment); err != nil {
		t.Fatal(err)
	}
	if err := verifyProofSetup(devSetupDir, deployment.Proof); err != nil {
		t.Fatal(err)
	}
	gasless, err := deployment.Gasless.validate()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGaslessCode(ctx, client, rpcURL, deployment); err != nil {
		t.Fatal(err)
	}
	var entries []string
	if err := (rpcCaller{url: gasless.BundlerURL, client: client}).call(ctx, "eth_supportedEntryPoints", []any{}, &entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		found = found || strings.EqualFold(entry, gasless.EntryPoint)
	}
	if !found {
		t.Fatal("the bundler does not support the pinned EntryPoint")
	}
	var remote struct {
		ID       string `json:"deployment_id"`
		Contract string `json:"contract_address"`
		// Optional in the public configuration; compared when present.
		VaultRevision *int `json:"vault_revision"`
		Proof         struct {
			Circuit string `json:"circuit_id"`
			SetupID string `json:"setup_id"`
		} `json:"proof_setup"`
	}
	liveJSON(ctx, t, client, deployment.ProtocolServerURL+"/config.json", &remote)
	if remote.ID != deployment.ID || !strings.EqualFold(remote.Contract, deployment.Contract) || remote.Proof.Circuit != deployment.Proof.Circuit || (remote.Proof.SetupID != "" && remote.Proof.SetupID != deployment.Proof.SetupID) || (remote.VaultRevision != nil && *remote.VaultRevision != deployment.VaultRevision) {
		t.Fatal("the live server configuration does not match the packaged vault, circuit and setup")
	}
	var attestation struct {
		ChainID          uint64     `json:"chain_id"`
		Contract         string     `json:"contract_address"`
		StateSigningKey  curvePoint `json:"state_signing_key"`
		ClearanceSigning curvePoint `json:"clearance_signing_key"`
		Circuit          string     `json:"circuit_id"`
		SetupID          string     `json:"setup_id"`
		VaultRevision    int        `json:"vault_revision"`
		ExitConcession   int        `json:"exit_concession"`
		LeafBoundExit    int        `json:"leaf_bound_exit"`
		SettlementWindow uint64     `json:"settlement_window_seconds"`
	}
	liveJSON(ctx, t, client, deployment.ProtocolServerURL+"/v1/attestation", &attestation)
	// The server encodes field elements and addresses as hex words; compare
	// their values.
	for _, pair := range [][2]string{
		{attestation.Contract, deployment.Contract},
		{attestation.StateSigningKey.X, deployment.StateSigningKey.X},
		{attestation.StateSigningKey.Y, deployment.StateSigningKey.Y},
		{attestation.ClearanceSigning.X, deployment.ClearanceSigning.X},
		{attestation.ClearanceSigning.Y, deployment.ClearanceSigning.Y},
	} {
		if !sameHexValue(pair[0], pair[1]) {
			t.Fatalf("the live attestation's %s differs from the pinned %s", pair[0], pair[1])
		}
	}
	if attestation.ChainID != deployment.ChainID || attestation.Circuit != deployment.Proof.Circuit || attestation.SetupID != deployment.Proof.SetupID || attestation.VaultRevision != deployment.VaultRevision || attestation.ExitConcession != deployment.ExitConcession || attestation.LeafBoundExit != deployment.LeafBoundExit || attestation.SettlementWindow != deployment.SettlementWindow {
		t.Fatal("the live attestation does not match the packaged deployment")
	}
	t.Logf("verified %s (%s): chain, runtime hashes, signing keys, circuit, proving assets, vault getters, gasless contracts, bundler EntryPoint and the server's configuration and attestation", deployment.ID, DeploymentDisplay(deployment.ID))
}

func liveJSON(ctx context.Context, t *testing.T, client *http.Client, url string, into any) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s returned HTTP %d", url, response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(into); err != nil {
		t.Fatal(fmt.Errorf("%s: %w", url, err))
	}
}

func sameHexValue(a, b string) bool {
	left, leftOK := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(a), "0x"), 16)
	right, rightOK := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(b), "0x"), 16)
	return leftOK && rightOK && left.Cmp(right) == 0
}

// This exercises the real Go-to-Rust bridge with a fresh empty temporary
// wallet against the packaged Sepolia deployment. It checks policy and status
// only; no proof, lease, deposit or withdrawal is sent. The companion must
// be built with the dev-setup feature (docs/DEVELOPMENT.md).
func TestLiveSepoliaCompanion(t *testing.T) {
	binary := os.Getenv("ZKAPI_TEST_COMPANION")
	if os.Getenv("ZKAPI_TEST_SEPOLIA") != "1" || binary == "" {
		t.Skip("requires ZKAPI_TEST_SEPOLIA=1 and ZKAPI_TEST_COMPANION")
	}
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	proxy, err := relay.StartConnectProxy(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientURL := "http://" + listener.Addr().String()
	listener.Close()
	cfg := Config{Network: "sepolia", ClientURL: clientURL, BridgeToken: testBridgeToken, HTTPClient: &http.Client{Timeout: 20 * time.Second}}
	setup, err := filepath.Abs(devSetupDir)
	if err != nil {
		t.Fatal(err)
	}
	if override := os.Getenv("ZKAPI_TEST_SETUP_DIR"); override != "" {
		setup = override
	}
	password := ""
	if file := os.Getenv("ZKAPI_TEST_PASSWORD_FILE"); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal("cannot read the Sepolia test password file")
		}
		password = strings.TrimSpace(string(raw))
	}
	cmd, err := CompanionCommand(ctx, cfg, CompanionConfig{Binary: binary, SetupDir: setup, StateDir: t.TempDir(), ProxyURL: proxy.URL, TestnetPassword: password, ExitRPCURL: os.Getenv("ZKAPI_TEST_EXIT_RPC")})
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for {
		err = client.Check(ctx)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the real companion did not become ready: %v", err)
		case <-time.After(250 * time.Millisecond):
		}
	}
	status, err := client.WalletStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wallet struct {
		HasNote bool `json:"has_note"`
	}
	if err := json.Unmarshal(status, &wallet); err != nil {
		t.Fatal(err)
	}
	if wallet.HasNote {
		t.Fatal("a new temporary companion unexpectedly has a note")
	}
	t.Log("the real managed companion accepted the pinned deployment, proving setup, authenticated bridge and empty wallet status")
}
