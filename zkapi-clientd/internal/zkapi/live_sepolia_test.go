package zkapi

import (
	"context"
	"encoding/json"
	"io"
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
// It never starts a wallet, funds an address, signs a proof, or sends a transaction.
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
	if err := verifyDeploymentCode(ctx, client, deployment.RPC, deployment); err != nil {
		t.Fatal(err)
	}
	if err := verifyProofSetup(devSetupDir, deployment.Proof); err != nil {
		t.Fatal(err)
	}
	if deployment.Gasless != nil {
		if err := verifyGaslessCode(ctx, client, deployment.RPC, deployment); err != nil {
			t.Fatal(err)
		}
		if deployment.Gasless.BundlerURL == "" {
			t.Fatal("gasless deployment has no default bundler")
		}
		var entries []string
		rpc := rpcCaller{url: deployment.Gasless.BundlerURL, client: client}
		if err := rpc.call(ctx, "eth_supportedEntryPoints", []any{}, &entries); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			found = found || strings.EqualFold(entry, deployment.Gasless.EntryPoint)
		}
		if !found {
			t.Fatal("bundler does not support the pinned EntryPoint")
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, deployment.ProtocolServerURL+"/config.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public configuration returned HTTP %d", response.StatusCode)
	}
	var remote struct {
		ID       string `json:"deployment_id"`
		Contract string `json:"contract_address"`
		Proof    struct {
			Circuit string `json:"circuit_id"`
		} `json:"proof_setup"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&remote); err != nil {
		t.Fatal(err)
	}
	if remote.ID != deployment.ID || remote.Contract != deployment.Contract || remote.Proof.Circuit != deployment.Proof.Circuit {
		t.Fatal("live server configuration does not match the packaged vault/circuit")
	}
	t.Logf("verified %s: chain, runtime hashes, signing keys, circuit, proving assets, vault getters and public server configuration", deployment.ID)
}

// This exercises the real Go-to-Rust bridge with a fresh empty temporary wallet.
// It checks policy and status only; no proof, lease, deposit or withdrawal is sent.
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
			t.Fatal("cannot read Sepolia test password file")
		}
		password = strings.TrimSpace(string(raw))
	}
	cmd, err := CompanionCommand(ctx, cfg, CompanionConfig{Binary: binary, SetupDir: setup, StateDir: t.TempDir(), ProxyURL: proxy.URL, TestnetPassword: password})
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
			t.Fatalf("real companion did not become ready: %v", err)
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
		t.Fatal("new temporary companion unexpectedly has a note")
	}
	t.Log("real managed companion accepted pinned deployment, proving setup, authenticated bridge and empty wallet status")
}
