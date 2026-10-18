package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func revision3SelectionConfig() config.Config {
	c := legacySelectionConfig()
	c.ZKAPI.Network = "sepolia"
	c.ZKAPI.Binary = "/bundle/bin/zkapi-walletd-concession-v1"
	c.ZKAPI.ProofSetupDir = "/bundle/share/concession-v1"
	return c
}

func TestConcessionV1DispatchPreservesOriginalProfile(t *testing.T) {
	c := revision3SelectionConfig()
	c.ZKAPI.ExitRPCURL = "https://independent-rpc.example"
	for _, args := range [][]string{{"serve"}, {"withdraw", "--escape", "--to", "0x1234"}, {"withdraw", "--resume"}} {
		binary, got, err := concessionV1DispatchPlan("/private/r3", true, c, args, "/bundle/bin/client")
		want := append([]string{"/bundle/bin/zkapi-clientd-concession-v1", "--config-dir", "/private/r3"}, args...)
		if err != nil || binary != want[0] || !reflect.DeepEqual(got, want) {
			t.Fatalf("wrong revision-3 dispatch: %v %v", got, err)
		}
	}
	for _, mutate := range []func(*config.Config){
		func(c *config.Config) { c.ZKAPI.Network = "mainnet" },
		func(c *config.Config) { c.ZKAPI.ExternalCompanion = true },
		func(c *config.Config) { c.ZKAPI.Binary = "zkapi-walletd" },
		func(c *config.Config) { c.ZKAPI.ProofSetupDir = "" },
	} {
		bad := c
		mutate(&bad)
		if _, _, err := concessionV1DispatchPlan("/private/r3", true, bad, []string{"serve"}, "/bundle/bin/client"); err == nil {
			t.Fatal("mixed or undeployed stack accepted")
		}
	}
	if _, _, err := concessionV1DispatchPlan("/private/r3", false, c, []string{"serve"}, "/bundle/bin/client"); err == nil {
		t.Fatal("implicit original profile accepted")
	}
	for _, arg := range []string{"--zkapi-binary=/different", "--proof-setup-dir=/different", "--external-companion"} {
		if _, _, err := concessionV1DispatchPlan("/private/r3", true, c, []string{"config", arg}, "/bundle/bin/client"); err == nil {
			t.Fatal("companion override accepted")
		}
	}
}

func TestSavedConcessionV1SelectionUsesPinnedEngine(t *testing.T) {
	dir, original := startTestConfig(t)
	c := original
	c.ZKAPI.Network = "sepolia"
	c.ZKAPI.Binary = revision3SelectionConfig().ZKAPI.Binary
	c.ZKAPI.ProofSetupDir = revision3SelectionConfig().ZKAPI.ProofSetupDir
	if err := config.Update(dir, original, c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZKAPI_CLIENTD_CONFIG_DIR", dir)
	t.Setenv("ZKAPI_VAULT_PROTOCOL", "")
	if err := run([]string{"config", "--vault-protocol", "concession-v1"}); err != nil {
		t.Fatal(err)
	}
	saved, err := config.LoadVaultProtocol(dir)
	if err != nil || saved != "concession-v1" {
		t.Fatal(saved, err)
	}
	// There is no installed engine beside the test executable: reaching its pin
	// check proves the saved choice selects revision 3 without opening a wallet.
	if err := run([]string{"serve"}); err == nil || !strings.Contains(err.Error(), "protocol executable") {
		t.Fatalf("did not check the pinned historical executable: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("selection changed the original wallet configuration")
	}
	if err := run([]string{"config", "--vault-protocol", "concession"}); err != nil {
		t.Fatal(err)
	}
}
