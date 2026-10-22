package zkapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Sepolia ships the deployed concession vault and gasless paymaster. Mainnet
// remains an undeployed placeholder; the legacy route owns existing notes.
// Both profiles must match the browser's circuit, keys and deployment pins.
func TestPackagedDeploymentsMatchTheBrowserProfiles(t *testing.T) {
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	for _, network := range []string{"mainnet", "sepolia"} {
		t.Run(network, func(t *testing.T) {
			identity, raw, err := pinnedDeployment(network)
			if err != nil {
				t.Fatal(err)
			}
			if network == "mainnet" {
				if identity.deployed() || identity.Status != "not_deployed" {
					t.Fatal("mainnet must remain an undeployed placeholder")
				}
				if _, _, err := deployedDeployment(network); !errors.Is(err, ErrDeploymentNotDeployed) {
					t.Fatalf("a placeholder was used as a deployment: %v", err)
				}
			} else {
				if !identity.deployed() || identity.Status != "deployed" {
					t.Fatal("Sepolia must ship the deployed vault")
				}
				if _, _, err := deployedDeployment(network); err != nil {
					t.Fatal(err)
				}
				if !MatchesDeployment(network, identity.ID, identity.Contract) {
					t.Fatal("the deployed vault did not match its manifest")
				}
				gasless, err := identity.Gasless.validate()
				if err != nil || gasless.BundlerURL == "" || gasless.GasSchedule == nil || *gasless.GasSchedule != 1 {
					t.Fatalf("Sepolia must publish a usable Glamsterdam gasless profile: %v", err)
				}
			}
			if MatchesDeployment(network, identity.ID, "0x0000000000000000000000000000000000000000") {
				t.Fatal("a placeholder matched a deployment")
			}
			var manifest map[string]any
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			profileRaw, err := os.ReadFile(filepath.Join("testdata", "browser-profiles", network+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var profile struct {
				Trusted map[string]any `json:"trusted_deployment"`
			}
			if err := json.Unmarshal(profileRaw, &profile); err != nil {
				t.Fatal(err)
			}
			for field, browser := range map[string]string{"deployment_status": "deployment_status", "chain_id": "chain_id", "contract_address": "contract_address", "billing_asset": "billing_asset", "billing_unit": "billing_unit", "billing_token_address": "billing_token_address", "native_asset_wei_per_unit": "native_asset_wei_per_unit", "native_price_feed_address": "native_price_feed_address", "native_price_feed_decimals": "native_price_feed_decimals", "native_price_max_age_seconds": "native_price_max_age_seconds", "rpc_url": "rpc_url", "request_charge_cap": "request_charge_cap", "challenge_period_seconds": "challenge_period", "note_ttl_seconds": "note_ttl", "max_pause_duration_seconds": "max_pause_duration", "settlement_window_seconds": "settlement_window_seconds", "vault_revision": "vault_revision", "exit_concession": "exit_concession", "leaf_bound_exit": "leaf_bound_exit", "min_deposit_units": "min_deposit_units", "fresh_slot_gas": "fresh_slot_gas", "clearance_ownership_proof": "clearance_ownership_proof"} {
				if !reflect.DeepEqual(manifest[field], profile.Trusted[browser]) {
					t.Errorf("%s differs from the browser profile's %s", field, browser)
				}
			}
			for _, field := range []string{"proof_adapter_address", "poseidon_library_address", "deploy_block", "protocol_server_url", "indexer_url", "state_signing_key", "clearance_signing_key", "gasless"} {
				if !reflect.DeepEqual(manifest[field], profile.Trusted[field]) {
					t.Errorf("%s differs from the browser profile", field)
				}
			}
			if identity.deployed() && manifest["deployment_id"] != profile.Trusted["deployment_id"] {
				t.Error("deployment ID differs from the browser profile")
			}
			evidence := manifest["deployment_evidence"].(map[string]any)
			for field, browser := range map[string]string{"vault_runtime_keccak256": "vault_runtime_codehash", "adapter_runtime_keccak256": "adapter_runtime_codehash", "poseidon_runtime_keccak256": "poseidon_runtime_codehash"} {
				if !reflect.DeepEqual(evidence[field], profile.Trusted[browser]) {
					t.Errorf("%s differs from the browser profile's runtime pin", field)
				}
			}
			proof := manifest["proof_setup"].(map[string]any)
			for _, field := range []string{"circuit_id", "setup_id", "request_proving_key_sha256", "withdrawal_proving_key_sha256", "request_verifying_key_sha256", "request_vk_keccak256", "withdrawal_vk_keccak256"} {
				if proof[field] != profile.Trusted[field] {
					t.Errorf("%s differs from the browser profile's proof pin", field)
				}
			}
			if identity.Proof.Circuit != RequiredCircuitID || RequiredCircuitID != "zkapi-v2-concession-v2" || identity.VaultRevision != 4 || identity.ExitConcession != 1 || identity.LeafBoundExit != 1 || identity.MinDepositUnits != 1_000_000 {
				t.Fatal("wrong concession deployment identity")
			}
			// EIP-8037 prices a fresh slot at about 110,000 gas on Sepolia;
			// mainnet rules at 22,100.
			if want := map[string]uint64{"mainnet": 22_100, "sepolia": 110_000}[network]; identity.FreshSlotGas != want {
				t.Fatalf("fresh_slot_gas %d, want %d", identity.FreshSlotGas, want)
			}
		})
	}
	mainnet, mainnetRaw, err := pinnedDeployment("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	fallback, fallbackRaw, err := pinnedDeployment("")
	if err != nil || mainnet.ID != fallback.ID || string(mainnetRaw) != string(fallbackRaw) {
		t.Fatal("empty network stopped selecting mainnet")
	}
	if _, _, err := pinnedDeployment("../sepolia"); err == nil {
		t.Fatal("unsupported network path accepted")
	}
}

// Only the leaf-bound concession vault is accepted: circuit
// zkapi-v2-concession-v2, vault revision 4 with the concession exit and
// leaf-bound exits, a minimum deposit and a fresh-slot gas pin, required
// ownership proofs, the vault parameters and, once deployed, every code and
// key pin. A revision-3 profile (circuit zkapi-v2-concession-v1) is refused.
func TestDeployedProfilesNeedEveryConcessionPin(t *testing.T) {
	_, raw, err := pinnedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDeploymentIdentity("sepolia", raw); err != nil {
		t.Fatalf("the fixture is invalid: %v", err)
	}
	for _, change := range []struct{ name, before, after string }{
		{"legacy circuit", `"circuit_id": "zkapi-v2-concession-v2"`, `"circuit_id": "zkapi-v2-note-bound-v1"`},
		{"revision-3 circuit", `"circuit_id": "zkapi-v2-concession-v2"`, `"circuit_id": "zkapi-v2-concession-v1"`},
		{"revision-3 vault", `"vault_revision": 4`, `"vault_revision": 3`},
		{"hardened vault", `"vault_revision": 4`, `"vault_revision": 2`},
		{"no leaf-bound exit", `"leaf_bound_exit": 1,`, ``},
		{"another leaf-bound exit", `"leaf_bound_exit": 1`, `"leaf_bound_exit": 2`},
		{"no minimum deposit", `"min_deposit_units": 1,`, ``},
		{"zero minimum deposit", `"min_deposit_units": 1`, `"min_deposit_units": 0`},
		{"minimum deposit above 2^53-1", `"min_deposit_units": 1`, `"min_deposit_units": 9007199254740992`},
		{"no fresh-slot gas", `"fresh_slot_gas": 110000,`, ``},
		{"tiny fresh-slot gas", `"fresh_slot_gas": 110000`, `"fresh_slot_gas": 100`},
		{"no concession exit", `"exit_concession": 1`, `"exit_concession": 0`},
		{"optional ownership proofs", `"clearance_ownership_proof": "required"`, `"clearance_ownership_proof": "optional"`},
		{"no setup", `"setup_id": "dev"`, `"setup_id": ""`},
		{"no settlement window", `"settlement_window_seconds": 14705`, `"settlement_window_seconds": 0`},
		{"short pause bound", `"max_pause_duration_seconds": 604800`, `"max_pause_duration_seconds": 60`},
		{"no vault code pin", `"vault_runtime_keccak256": "0x`, `"vault_runtime_keccak256": "0xzz`},
		{"no adapter", `"proof_adapter_address": "0x`, `"proof_adapter_address": "0xzz`},
		{"unknown status", `"deployment_status": "deployed"`, `"deployment_status": "retired"`},
	} {
		changed := bytes.Replace(raw, []byte(change.before), []byte(change.after), 1)
		if bytes.Equal(changed, raw) {
			t.Fatalf("%s: the fixture has no %s", change.name, change.before)
		}
		if _, err := parseDeploymentIdentity("sepolia", changed); err == nil {
			t.Fatalf("%s accepted", change.name)
		}
	}
}

func TestDeploymentManifestPersistenceIsPrivateAndNeverRebinds(t *testing.T) {
	_, raw, err := pinnedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, err := writeDeploymentManifest(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("manifest is not a private regular file")
	}
	before, err := os.ReadFile(path)
	if err != nil || string(before) != string(raw) {
		t.Fatal("saved manifest differs from pin")
	}
	if again, err := writeDeploymentManifest(dir, raw); err != nil || again != path {
		t.Fatalf("same deployment did not resume: %v", err)
	}
	_, other, err := pinnedDeployment("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeDeploymentManifest(dir, other); err == nil {
		t.Fatal("existing manifest silently rebound")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("mismatch overwrote existing manifest")
	}
}

func TestDeploymentManifestRejectsSymlinksAndUnsafeFiles(t *testing.T) {
	_, raw, err := pinnedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "public", "directory", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "deployment-manifest.json")
			target := filepath.Join(dir, "original.json")
			switch kind {
			case "symlink":
				if err := os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(path, raw, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(path, []byte(`{"deployment_id":"unrelated"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writeDeploymentManifest(dir, raw); err == nil {
				t.Fatalf("accepted %s manifest", kind)
			}
			if kind == "symlink" {
				info, err := os.Lstat(path)
				contents, readErr := os.ReadFile(target)
				if err != nil || info.Mode()&os.ModeSymlink == 0 || readErr != nil || string(contents) != string(raw) {
					t.Fatal("refusal modified symlink or target")
				}
			}
			if kind == "malformed" {
				contents, _ := os.ReadFile(path)
				if !strings.Contains(string(contents), "unrelated") {
					t.Fatal("refusal overwrote recovery manifest")
				}
			}
		})
	}
}

// devSetupDir is the committed development setup, whose hashes the test
// profiles pin.
const devSetupDir = "../../../protocol/setup/v2-concession-dev"

// Design §10.5: an open note of an earlier vault no longer stops the
// release. Its state directory is left alone, and the owner is told how to
// withdraw it.
func TestAnOpenLegacyNoteWarnsInsteadOfRefusingToStart(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"zkapi-native-eth-mainnet-note-bound-v1-fresh-20260928", "zkapi-native-eth-mainnet-note-bound-v1-fresh-20260930"} {
		stateDir := t.TempDir()
		legacy := filepath.Join(stateDir, "mainnet", id)
		if err := os.MkdirAll(legacy, 0700); err != nil {
			t.Fatal(err)
		}
		if warning := LegacyWalletWarning(stateDir, "mainnet"); warning != "" {
			t.Fatalf("a legacy directory without an open note warned: %s", warning)
		}
		wallet := filepath.Join(legacy, "note_state.json")
		const recovery = "synthetic legacy mainnet note"
		if err := os.WriteFile(wallet, []byte(recovery), 0600); err != nil {
			t.Fatal(err)
		}
		warning := LegacyWalletWarning(stateDir, "mainnet")
		if !strings.Contains(warning, id) || !strings.Contains(warning, "earlier zkapi-clientd release") || !strings.Contains(warning, LegacyRelease) || !strings.Contains(LegacyRelease, "0.1.7") {
			t.Fatalf("no warning for an open legacy note: %q", warning)
		}
		cmd, err := CompanionCommand(context.Background(), Config{Network: "mainnet", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}}, CompanionConfig{Binary: binary, SetupDir: devSetupDir, StateDir: stateDir, ProxyURL: "http://bridge:private-local-token@127.0.0.1:8791"})
		if err != nil || cmd == nil {
			t.Fatalf("an open legacy note stopped the release: %v", err)
		}
		state, _ := os.ReadFile(wallet)
		if string(state) != recovery {
			t.Fatal("the legacy wallet changed")
		}
		if _, err := os.Stat(filepath.Join(stateDir, "mainnet", "zkapi-native-eth-mainnet-concession-v1-test", "deployment-manifest.json")); err != nil {
			t.Fatal("the concession wallet was not set up beside the legacy one")
		}
		if LegacyWalletWarning(stateDir, "sepolia") != "" {
			t.Fatal("a mainnet legacy note warned on sepolia")
		}
	}
}

// A placeholder deployment starts nothing and checks nothing.
func TestAPlaceholderDeploymentStartsNothing(t *testing.T) {
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	cmd, err := CompanionCommand(context.Background(), Config{Network: "mainnet", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}}, CompanionConfig{Binary: binary, SetupDir: devSetupDir, StateDir: stateDir, ProxyURL: "http://bridge:private-local-token@127.0.0.1:8791"})
	if !errors.Is(err, ErrDeploymentNotDeployed) || cmd != nil {
		t.Fatalf("a placeholder started the companion: %v", err)
	}
	if !strings.Contains(err.Error(), "deployment_not_deployed") {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(stateDir); len(entries) != 0 {
		t.Fatal("a placeholder created wallet state")
	}
	client, err := New(Config{Network: "mainnet", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckDeployment(context.Background()); !errors.Is(err, ErrDeploymentNotDeployed) {
		t.Fatalf("checked a placeholder: %v", err)
	}
}

func testProofSetup(t *testing.T) (string, proofSetupIdentity) {
	t.Helper()
	dir := t.TempDir()
	hashes := make(map[string]string)
	for _, name := range []string{"request.pk", "request.vk", "withdrawal.pk", "withdrawal.vk"} {
		contents := []byte("distinct test proving artifact " + name)
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		hashes[name] = hex.EncodeToString(digest[:])
	}
	return dir, proofSetupIdentity{Circuit: RequiredCircuitID, RequestProvingKeySHA256: hashes["request.pk"], RequestVerifyingKeySHA256: hashes["request.vk"], WithdrawalProvingKeySHA256: hashes["withdrawal.pk"], WithdrawalVerifyingKeySHA256: hashes["withdrawal.vk"]}
}

func TestProofSetupRequiresEveryPinnedArtifact(t *testing.T) {
	dir, proof := testProofSetup(t)
	if err := verifyProofSetup(dir, proof); err != nil {
		t.Fatalf("matching setup rejected: %v", err)
	}
	for _, name := range []string{"request.pk", "request.vk", "withdrawal.pk", "withdrawal.vk"} {
		for _, mutation := range []string{"modified", "missing", "directory"} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				dir, proof := testProofSetup(t)
				path := filepath.Join(dir, name)
				switch mutation {
				case "modified":
					if err := os.WriteFile(path, []byte("different proof setup"), 0600); err != nil {
						t.Fatal(err)
					}
				case "missing":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if err := verifyProofSetup(dir, proof); err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("%s %s accepted or wrong error: %v", mutation, name, err)
				}
			})
		}
	}
	for _, invalid := range []string{"", "abc", strings.Repeat("g", 64), strings.ToUpper(proof.RequestProvingKeySHA256)} {
		mutated := proof
		mutated.RequestProvingKeySHA256 = invalid
		if err := verifyProofSetup(dir, mutated); err == nil {
			t.Fatal("invalid artifact pin accepted")
		}
	}
}

func TestCompanionCommandChecksInstalledProofsBeforeCreatingWallet(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	setupDir, _ := testProofSetup(t) // Valid files from a different setup must fail too.
	for _, dir := range []string{t.TempDir(), setupDir} {
		stateDir := filepath.Join(t.TempDir(), "must-not-exist")
		cmd, err := CompanionCommand(context.Background(), Config{Network: "sepolia", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}}, CompanionConfig{Binary: binary, SetupDir: dir, StateDir: stateDir, ProxyURL: "http://bridge:private-local-token@127.0.0.1:8791"})
		if err == nil || cmd != nil || !strings.Contains(err.Error(), "request.pk") {
			t.Fatalf("companion did not reject wrong installed proofs: %v", err)
		}
		if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
			t.Fatal("invalid setup created or opened private wallet state")
		}
	}
}

func TestMatchesDeploymentUsesExactNetworkIDAndVault(t *testing.T) {
	for _, network := range []string{"mainnet", "sepolia"} {
		deployment, _, err := pinnedDeployment(network)
		if err != nil {
			t.Fatal(err)
		}
		if !MatchesDeployment(network, deployment.ID, strings.ToLower(deployment.Contract)) {
			t.Fatal("matching deployment rejected")
		}
		if MatchesDeployment("unknown", deployment.ID, deployment.Contract) || MatchesDeployment(network, deployment.ID+"-other", deployment.Contract) || MatchesDeployment(network, deployment.ID, "0x1111111111111111111111111111111111111111") {
			t.Fatal("mismatched deployment accepted")
		}
	}
}

// shippedSepoliaID is the leaf-bound staging deployment this build serves on
// Sepolia, displayed as "zkAPI v0.2".
const shippedSepoliaID = "zkapi-native-eth-sepolia-leaf-v4-20261020"

// Sepolia ships the newest deployed leaf-bound vault: its ID, contract,
// endpoints, revision-4 leaf-bound exits and development setup, displayed as
// zkAPI v0.2. Its wallet lives in per-deployment directories of its own.
func TestShippedSepoliaIsTheLeafBoundV4Deployment(t *testing.T) {
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	identity, raw, err := deployedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	gasless, err := identity.Gasless.validate()
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://zkapi-sepolia.openanonymity.ai/v0.4"
	if identity.ID != shippedSepoliaID || identity.Contract != "0x67eb750d9c0d63a99684ac3f3e65f0c610276993" || identity.ChainID != 11155111 {
		t.Fatalf("Sepolia ships %s at %s", identity.ID, identity.Contract)
	}
	if identity.RPC != "https://ethereum-sepolia-rpc.publicnode.com" || identity.IndexerURL != server || identity.ProtocolServerURL != server || gasless.BundlerURL != server+"/bundler" {
		t.Fatal("Sepolia's packaged endpoints changed")
	}
	if identity.VaultRevision != 4 || identity.LeafBoundExit != 1 || identity.ExitConcession != 1 || identity.Proof.Circuit != RequiredCircuitID || identity.Proof.SetupID != "dev" {
		t.Fatal("Sepolia does not ship the leaf-bound revision-4 vault with the development setup")
	}
	info, err := PackagedDeployment("sepolia")
	if err != nil || info != (PackagedDeploymentInfo{ID: shippedSepoliaID, Display: "zkAPI v0.2", Contract: identity.Contract, ProtocolServerURL: server, BundlerURL: server + "/bundler", VaultRevision: 4, ChainID: 11155111, Deployed: true}) {
		t.Fatalf("packaged Sepolia deployment %+v, %v", info, err)
	}
	// The label belongs to the deployment, not to a URL path: /v0.2 was the
	// revision-3 server's.
	for id, want := range map[string]string{"zkapi-native-eth-sepolia-concession-v1-r3": "zkAPI deployment zkapi-native-eth-sepolia-concession-v1-r3", "zkapi-native-eth-sepolia-concession-v2-r4-20261017": "zkAPI deployment zkapi-native-eth-sepolia-concession-v2-r4-20261017"} {
		if DeploymentDisplay(id) != want {
			t.Fatalf("%s is displayed as %q", id, DeploymentDisplay(id))
		}
	}
	mainnet, err := PackagedDeployment("mainnet")
	if err != nil || mainnet.Deployed || mainnet.Contract != "" || mainnet.Display != "zkAPI deployment "+mainnet.ID {
		t.Fatalf("mainnet placeholder %+v, %v", mainnet, err)
	}
	cfg := t.TempDir()
	funding, err := fundingStateDir(filepath.Join(cfg, "funding"), "sepolia")
	if err != nil || funding != filepath.Join(cfg, "funding", "sepolia", shippedSepoliaID) {
		t.Fatalf("payment state directory %s, %v", funding, err)
	}
	client, err := New(Config{Network: "sepolia", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewFundingHandler(client, "http://127.0.0.1:8787", filepath.Join(cfg, "funding"))
	if err != nil || handler.statePath != filepath.Join(funding, "pending-deposit.json") {
		t.Fatalf("payment handler state %v", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := CompanionCommand(context.Background(), Config{Network: "sepolia", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}}, CompanionConfig{Binary: binary, SetupDir: devSetupDir, StateDir: filepath.Join(cfg, "zkapi"), ProxyURL: "http://bridge:private-local-token@127.0.0.1:8791"})
	if err != nil || cmd == nil {
		t.Fatalf("the shipped Sepolia deployment did not start its companion: %v", err)
	}
	wallet := filepath.Join(cfg, "zkapi", "sepolia", shippedSepoliaID)
	if !strings.Contains(strings.Join(cmd.Args, " "), "--state-dir "+wallet) {
		t.Fatal("the companion does not use the per-deployment wallet directory")
	}
	saved, err := os.ReadFile(filepath.Join(wallet, "deployment-manifest.json"))
	if err != nil || !bytes.Equal(saved, raw) {
		t.Fatal("the companion did not save the exact embedded manifest")
	}
}

// Existing leaf-v4 wallets saved these exact bytes as their deployment
// manifest, and writeDeploymentManifest refuses any other: editing
// deployments/sepolia.json would strand every one of them. Another Sepolia
// vault gets another deployment ID, and so its own directories, instead.
func TestEmbeddedSepoliaManifestBytesArePinned(t *testing.T) {
	raw, err := fs.ReadFile(deploymentFiles, "deployments/sepolia.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != "0da4ccbaa8bebd0dbb59801a87a4e483382f9af14bd75840a7c081dcefc998ca" {
		t.Fatalf("deployments/sepolia.json changed (SHA-256 %s); saved leaf-v4 wallets would no longer load", got)
	}
}

// The staging deployment pins the committed development setup: the setup's
// manifest and its key files carry exactly the embedded hashes.
func TestShippedSepoliaPinsTheCommittedDevelopmentSetup(t *testing.T) {
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	identity, raw, err := pinnedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	var embedded struct {
		Proof struct {
			Path string `json:"repository_path"`
		} `json:"proof_setup"`
	}
	if err := json.Unmarshal(raw, &embedded); err != nil || embedded.Proof.Path != "protocol/setup/v2-concession-dev" {
		t.Fatalf("Sepolia names setup %q", embedded.Proof.Path)
	}
	setupRaw, err := os.ReadFile(filepath.Join(devSetupDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var setup struct {
		Circuit string            `json:"circuit_id"`
		SetupID string            `json:"setup_id"`
		Files   map[string]string `json:"files"`
		VK      struct {
			Request    string `json:"request"`
			Withdrawal string `json:"withdrawal"`
		} `json:"vk_keccak256"`
	}
	if err := json.Unmarshal(setupRaw, &setup); err != nil {
		t.Fatal(err)
	}
	proof := identity.Proof
	if setup.Circuit != proof.Circuit || setup.SetupID != proof.SetupID || setup.VK.Request != proof.RequestVKKeccak256 || setup.VK.Withdrawal != proof.WithdrawalVKKeccak256 {
		t.Fatal("the embedded circuit, setup or verifying-key hashes differ from the development setup")
	}
	for name, pin := range map[string]string{"request.pk": proof.RequestProvingKeySHA256, "request.vk": proof.RequestVerifyingKeySHA256, "withdrawal.pk": proof.WithdrawalProvingKeySHA256, "withdrawal.vk": proof.WithdrawalVerifyingKeySHA256} {
		if setup.Files[name] != pin {
			t.Fatalf("the embedded %s hash differs from the development setup's", name)
		}
	}
	if err := verifyProofSetup(devSetupDir, proof); err != nil {
		t.Fatal(err)
	}
}

// Wallets of the deployments earlier builds served stay beside this one in
// the profile. Each is named, with its directories and its way out, and
// never opened: starting this build's companion and payment handler on the
// same profile leaves every byte, mode and modification time alone. Empty
// directories, or a saved manifest alone, are no wallet and warn nothing.
func TestEarlierDeploymentsAreWarnedNeverOpened(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if len(earlierDeployments["sepolia"]) != 4 || len(earlierDeployments["mainnet"]) != 2 {
		t.Fatal("an earlier deployment is missing from the registry")
	}
	stamp := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for network, earlier := range earlierDeployments {
		for _, deployment := range earlier {
			t.Run(deployment.id, func(t *testing.T) {
				cfg := t.TempDir()
				walletDir := filepath.Join(cfg, "zkapi", network, deployment.id)
				fundingDir := filepath.Join(cfg, "funding", network, deployment.id)
				for _, dir := range []string{walletDir, fundingDir} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(walletDir, "deployment-manifest.json"), []byte(`{"deployment_id":"`+deployment.id+`"}`), 0600); err != nil {
					t.Fatal(err)
				}
				if state, warnings := EarlierDeploymentState(cfg, network), EarlierDeploymentWarnings(cfg, network); len(state) != 0 || len(warnings) != 0 {
					t.Fatalf("an empty earlier wallet warned: %v", warnings)
				}
				files := map[string]os.FileMode{}
				for _, name := range companionRecoveryFiles {
					files[filepath.Join("zkapi", network, deployment.id, name)] = 0600
				}
				for _, name := range fundingRecoveryFiles {
					files[filepath.Join("funding", network, deployment.id, name)] = 0400
				}
				for relative, mode := range files {
					path := filepath.Join(cfg, relative)
					if err := os.WriteFile(path, []byte("synthetic recovery file "+relative), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(path, stamp, stamp); err != nil {
						t.Fatal(err)
					}
				}
				state := EarlierDeploymentState(cfg, network)
				if len(state) != 1 || state[0].ID != deployment.id || state[0].Display != deployment.display || state[0].Recovery != deployment.recovery || len(state[0].Files) != len(files) {
					t.Fatalf("earlier deployment state %+v", state)
				}
				for _, relative := range state[0].Files {
					if _, ok := files[relative]; !ok {
						t.Fatalf("listed %s, which was not written", relative)
					}
				}
				warnings := EarlierDeploymentWarnings(cfg, network)
				if len(warnings) != 1 {
					t.Fatalf("warnings %v", warnings)
				}
				for _, want := range []string{deployment.id, walletDir, fundingDir, deployment.recovery, "never opens, changes or migrates"} {
					if !strings.Contains(warnings[0], want) {
						t.Fatalf("the warning does not name %q: %s", want, warnings[0])
					}
				}
				if deployment.noteBound != strings.Contains(warnings[0], LegacyRelease) || !deployment.noteBound && !strings.Contains(warnings[0], "origin/v0.2") {
					t.Fatalf("the warning names the wrong way out: %s", warnings[0])
				}
				if strings.Contains(warnings[0], "synthetic recovery file") {
					t.Fatal("the warning read a recovery file")
				}
				cmd, err := CompanionCommand(context.Background(), Config{Network: network, BridgeToken: testBridgeToken, HTTPClient: &http.Client{}}, CompanionConfig{Binary: binary, SetupDir: devSetupDir, StateDir: filepath.Join(cfg, "zkapi"), ProxyURL: "http://bridge:private-local-token@127.0.0.1:8791"})
				if err != nil || cmd == nil {
					t.Fatalf("an earlier wallet stopped this build's companion: %v", err)
				}
				client, err := New(Config{Network: network, BridgeToken: testBridgeToken, HTTPClient: &http.Client{}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := NewFundingHandler(client, "http://127.0.0.1:8787", filepath.Join(cfg, "funding")); err != nil {
					t.Fatal(err)
				}
				for relative, mode := range files {
					path := filepath.Join(cfg, relative)
					info, err := os.Lstat(path)
					contents, readErr := os.ReadFile(path)
					if err != nil || readErr != nil || string(contents) != "synthetic recovery file "+relative || info.Mode().Perm() != mode || !info.ModTime().Equal(stamp) {
						t.Fatalf("%s changed", relative)
					}
				}
				for dir, want := range map[string]int{walletDir: len(companionRecoveryFiles) + 1, fundingDir: len(fundingRecoveryFiles)} {
					if entries, err := os.ReadDir(dir); err != nil || len(entries) != want {
						t.Fatalf("this build wrote into %s", dir)
					}
				}
				if manifest, err := os.ReadFile(filepath.Join(walletDir, "deployment-manifest.json")); err != nil || string(manifest) != `{"deployment_id":"`+deployment.id+`"}` {
					t.Fatal("the earlier deployment's saved manifest changed")
				}
			})
		}
	}
	// The earlier release kept its payment files per network.
	cfg := t.TempDir()
	root := filepath.Join(cfg, "funding", "sepolia")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "address-funding.json"), []byte("synthetic earlier payment key"), 0600); err != nil {
		t.Fatal(err)
	}
	state := EarlierDeploymentState(cfg, "sepolia")
	warnings := EarlierDeploymentWarnings(cfg, "sepolia")
	if len(state) != 1 || state[0].ID != "" || len(state[0].Files) != 1 || state[0].Files[0] != filepath.Join("funding", "sepolia", "address-funding.json") || len(warnings) != 1 || warnings[0] != LegacyFundingWarning(filepath.Join(cfg, "funding"), "sepolia") {
		t.Fatalf("earlier release payment files: %+v %v", state, warnings)
	}
	if EarlierDeploymentState(cfg, "mainnet") != nil {
		t.Fatal("Sepolia's earlier files were reported on mainnet")
	}
}

// Compatibility exception: this build cannot load the exact manifests of the
// earlier Sepolia concession deployments. Revision 3
// (zkapi-native-eth-sepolia-concession-v1-r3) proves another circuit, and
// zkapi-native-eth-sepolia-concession-v2-r4-20261017 has no leaf-bound exits
// (and other verifying keys). Their wallets keep their own directories and
// are recovered with the origin/v0.2 local CLI bundle.
func TestEarlierConcessionDeploymentsCannotLoadInThisBuild(t *testing.T) {
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	_, raw, err := pinnedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	for id, changes := range map[string][][2]string{
		"zkapi-native-eth-sepolia-concession-v1-r3":          {{`"vault_revision": 4`, `"vault_revision": 3`}, {`"circuit_id": "zkapi-v2-concession-v2"`, `"circuit_id": "zkapi-v2-concession-v1"`}, {`"leaf_bound_exit": 1,`, ``}},
		"zkapi-native-eth-sepolia-concession-v2-r4-20261017": {{`"leaf_bound_exit": 1,`, ``}},
	} {
		earlier := bytes.Replace(raw, []byte(shippedSepoliaID), []byte(id), 1)
		for _, change := range changes {
			changed := bytes.Replace(earlier, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(changed, earlier) {
				t.Fatalf("%s: the manifest has no %s", id, change[0])
			}
			earlier = changed
		}
		if _, err := parseDeploymentIdentity("sepolia", earlier); err == nil {
			t.Fatalf("this build loaded the %s profile", id)
		}
	}
}
