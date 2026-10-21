package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/cover"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func TestSavedVaultProtocolRoundTripAndLock(t *testing.T) {
	dir, c := startTestConfig(t)
	initial, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runSetVaultProtocol(dir, []string{"concession"}, &out); err != nil {
		t.Fatal(err)
	}
	saved, err := config.LoadVaultProtocol(dir)
	if err != nil || saved != "concession" {
		t.Fatal(saved, err)
	}
	if err := config.UpdateVaultProtocol(dir, c, "", "legacy"); err == nil {
		t.Fatal("stale selection accepted")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := runSetVaultProtocol(dir, []string{"--clear"}, &out); err == nil {
		t.Fatal("edited running profile")
	}
	syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := runSetVaultProtocol(dir, []string{"--clear"}, &out); err != nil {
		t.Fatal(err)
	}
	saved, err = config.LoadVaultProtocol(dir)
	if err != nil || saved != "" {
		t.Fatal("clear failed")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || !bytes.Equal(initial, after) {
		t.Fatal("legacy config bytes changed")
	}
}

func TestSavedLegacyNeedsNoRepeatedFlagAndEditorRemainsLocal(t *testing.T) {
	dir, c := startTestConfig(t)
	next := c
	next.ZKAPI.Binary = "/bundle/bin/zkapi-walletd"
	next.ZKAPI.ProofSetupDir = "/bundle/share/proof-setup"
	next.RelayURL = "tor://127.0.0.1:9050"
	next.Rewriter = rewriter.Config{URL: "http://localhost:8012", Model: "m", APIKey: "rewriter-test-secret"}
	next.Cover = cover.Config{Rate: 5, Concurrency: 4, URLs: "https://cover.example/static"}
	if err := config.Update(dir, c, next); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZKAPI_CLIENTD_CONFIG_DIR", dir)
	t.Setenv("ZKAPI_VAULT_PROTOCOL", "")
	if err := run([]string{"config", "--vault-protocol", "legacy"}); err != nil {
		t.Fatal(err)
	}
	// No installed sibling artifact in the test directory: reaching its pin
	// check proves dispatch selected legacy using only the saved preference.
	err := run([]string{"serve"})
	if err == nil || !strings.Contains(err.Error(), "protocol executable") {
		t.Fatal("saved legacy not selected", err)
	}
	if err := run([]string{"config", "--vault-protocol", "concession"}); err != nil {
		t.Fatal("cannot switch out of legacy", err)
	}
	after, err := config.Load(dir)
	if err != nil || after != next {
		t.Fatal("vault selection changed privacy/configuration settings", err)
	}
	info, err := os.Stat(filepath.Join(dir, "vault-protocol"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("preference not private")
	}
}

func TestUnsafeSavedProtocolRefused(t *testing.T) {
	dir, _ := startTestConfig(t)
	path := filepath.Join(dir, "vault-protocol")
	if err := os.WriteFile(path, []byte("unknown\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadVaultProtocol(dir); err == nil {
		t.Fatal("unknown saved choice accepted")
	}
	os.Remove(path)
	if err := os.Symlink("config.json", path); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadVaultProtocol(dir); err == nil {
		t.Fatal("symlink preference accepted")
	}
	if err := run([]string{"--config-dir", t.TempDir(), "config", "--help"}); err != nil {
		t.Fatal(err)
	}
}
