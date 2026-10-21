package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/cover"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func legacySelectionConfig() config.Config {
	return config.Config{ZKAPI: config.ZKAPI{Binary: "/bundle/bin/zkapi-walletd", ProofSetupDir: "/bundle/share/proof-setup"}}
}
func TestVaultProtocolSelection(t *testing.T) {
	for input, want := range map[string]string{"": "concession", "legacy": "legacy", "concession": "concession"} {
		got, err := vaultProtocol(input)
		if err != nil || got != want {
			t.Fatal(input, got, err)
		}
	}
	for _, input := range []string{"auto", "old", "new", "3", "LEGACY"} {
		if _, err := vaultProtocol(input); err == nil {
			t.Fatal("ambiguous protocol accepted")
		}
	}
}
func TestLegacyDispatchPreservesProfileAndCommand(t *testing.T) {
	c := legacySelectionConfig()
	c.Rewriter = rewriter.Config{URL: "http://localhost:8012", Model: "m"}
	c.Cover = cover.Config{Rate: 5, Concurrency: 4, URLs: "https://cover.example/static"}
	for _, args := range [][]string{{"serve", "--model", "example/model"}, {"withdraw", "--public"}, {"config", "--usd", "20"}, {"config", "--setup"}, {"config", "--menu"}} {
		bin, got, err := legacyDispatchPlan("/private/legacy", true, c, args, "/bundle/bin/zkapi-clientd-concession-tor")
		want := append([]string{"/bundle/bin/zkapi-clientd-legacy-privacy", "--config-dir", "/private/legacy"}, args...)
		if err != nil || bin != want[0] || !reflect.DeepEqual(got, want) {
			t.Fatal("wrong protocol dispatch", got, err)
		}
	}
}
func TestLegacyDispatchRefusesPrivacyDowngradesAndStackMixing(t *testing.T) {
	good := legacySelectionConfig()
	cases := []config.Config{good, good, good, good}
	cases[0].ZKAPI.ExternalCompanion = true
	cases[1].ZKAPI.Binary = "zkapi-walletd"
	cases[2].ZKAPI.ExitRPCURL = "http://127.0.0.1:8545"
	cases[3].ZKAPI.ProofSetupDir = ""
	for _, c := range cases {
		if _, _, err := legacyDispatchPlan("/legacy", true, c, []string{"serve"}, "/bundle/bin/client"); err == nil {
			t.Fatal("unsafe downgrade accepted")
		}
	}
	if _, _, err := legacyDispatchPlan("/legacy", false, good, []string{"serve"}, "/bundle/bin/client"); err == nil {
		t.Fatal("implicit profile accepted")
	}
	for _, args := range [][]string{{"config", "--zkapi-binary=/wrong/companion"}, {"config", "-proof-setup-dir", "/wrong/keys"}} {
		if _, _, err := legacyDispatchPlan("/legacy", true, good, args, "/bundle/bin/client"); err == nil {
			t.Fatal("stack override accepted", args)
		}
	}
}
func TestProtocolArtifactPins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client")
	body := []byte("local fixture")
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	pin := hex.EncodeToString(hash[:])
	if err := checkProtocolArtifact(path, pin); err != nil {
		t.Fatal(err)
	}
	if checkProtocolArtifact(path, legacyClientHash) == nil {
		t.Fatal("unknown binary accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if checkProtocolArtifact(link, pin) == nil {
		t.Fatal("symlink executable accepted")
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if checkProtocolArtifact(path, pin) == nil {
		t.Fatal("writable executable accepted")
	}
}
func TestVaultProtocolFlagPrecedenceAndNoImplicitLegacy(t *testing.T) {
	t.Setenv("ZKAPI_VAULT_PROTOCOL", "invalid")
	if err := run([]string{"--vault-protocol", "concession", "version"}); err != nil {
		t.Fatal("flag did not override environment", err)
	}
	if err := run([]string{"version"}); err == nil {
		t.Fatal("invalid environment accepted")
	}
	t.Setenv("ZKAPI_VAULT_PROTOCOL", "legacy")
	if err := run([]string{"serve"}); err == nil {
		t.Fatal("legacy accepted implicit profile")
	}
	if err := run([]string{"--config-dir", "", "serve"}); err == nil {
		t.Fatal("legacy accepted empty explicit profile")
	}
}
