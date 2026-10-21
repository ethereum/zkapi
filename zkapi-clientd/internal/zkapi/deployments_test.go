package zkapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The packaged deployments are not_deployed placeholders of the
// concession-exit vault that pin the same circuit, setup, proving-key hashes
// and vault parameters as the browser SDK's build profiles; nothing starts
// against them.
func TestPackagedDeploymentsArePlaceholdersMatchingTheBrowserProfiles(t *testing.T) {
	restore := SetPackagedDeploymentsForTesting(deploymentFiles)
	defer restore()
	for _, network := range []string{"mainnet", "sepolia"} {
		t.Run(network, func(t *testing.T) {
			identity, raw, err := pinnedDeployment(network)
			if err != nil {
				t.Fatal(err)
			}
			if identity.deployed() || identity.Status != "not_deployed" {
				t.Fatal("the packaged deployment must stay a not_deployed placeholder until the vault exists")
			}
			if _, _, err := deployedDeployment(network); !errors.Is(err, ErrDeploymentNotDeployed) {
				t.Fatalf("a placeholder was used as a deployment: %v", err)
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
			for field, browser := range map[string]string{"deployment_status": "deployment_status", "chain_id": "chain_id", "contract_address": "contract_address", "billing_asset": "billing_asset", "billing_unit": "billing_unit", "billing_token_address": "billing_token_address", "native_asset_wei_per_unit": "native_asset_wei_per_unit", "native_price_feed_address": "native_price_feed_address", "native_price_feed_decimals": "native_price_feed_decimals", "native_price_max_age_seconds": "native_price_max_age_seconds", "rpc_url": "rpc_url", "request_charge_cap": "request_charge_cap", "challenge_period_seconds": "challenge_period", "note_ttl_seconds": "note_ttl", "max_pause_duration_seconds": "max_pause_duration", "settlement_window_seconds": "settlement_window_seconds", "vault_revision": "vault_revision", "exit_concession": "exit_concession", "clearance_ownership_proof": "clearance_ownership_proof"} {
				if !reflect.DeepEqual(manifest[field], profile.Trusted[browser]) {
					t.Errorf("%s differs from the browser profile's %s", field, browser)
				}
			}
			proof := manifest["proof_setup"].(map[string]any)
			for _, field := range []string{"circuit_id", "setup_id", "request_proving_key_sha256", "withdrawal_proving_key_sha256", "request_verifying_key_sha256", "request_vk_keccak256", "withdrawal_vk_keccak256"} {
				if proof[field] != profile.Trusted[field] {
					t.Errorf("%s differs from the browser profile's proof pin", field)
				}
			}
			if identity.Proof.Circuit != RequiredCircuitID || identity.VaultRevision != 3 || identity.ExitConcession != 1 {
				t.Fatal("wrong concession deployment identity")
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

// Only the concession vault is accepted: circuit zkapi-v2-concession-v1,
// vault revision 3 with the concession exit, required ownership proofs, the
// vault parameters and, once deployed, every code and key pin.
func TestDeployedProfilesNeedEveryConcessionPin(t *testing.T) {
	_, raw, err := pinnedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDeploymentIdentity("sepolia", raw); err != nil {
		t.Fatalf("the fixture is invalid: %v", err)
	}
	for _, change := range []struct{ name, before, after string }{
		{"legacy circuit", `"circuit_id": "zkapi-v2-concession-v1"`, `"circuit_id": "zkapi-v2-note-bound-v1"`},
		{"hardened vault", `"vault_revision": 3`, `"vault_revision": 2`},
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
	cmd, err := CompanionCommand(context.Background(), Config{Network: "sepolia", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}}, CompanionConfig{Binary: binary, SetupDir: devSetupDir, StateDir: stateDir, ProxyURL: "http://bridge:private-local-token@127.0.0.1:8791"})
	if !errors.Is(err, ErrDeploymentNotDeployed) || cmd != nil {
		t.Fatalf("a placeholder started the companion: %v", err)
	}
	if !strings.Contains(err.Error(), "deployment_not_deployed") {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(stateDir); len(entries) != 0 {
		t.Fatal("a placeholder created wallet state")
	}
	client, err := New(Config{Network: "sepolia", BridgeToken: testBridgeToken, HTTPClient: &http.Client{}})
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
