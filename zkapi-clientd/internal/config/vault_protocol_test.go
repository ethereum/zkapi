package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The local CLI bundle from git branch origin/v0.2 saved concession-v1 for
// its Sepolia revision-3 stack. This build names that value and its way out
// instead of calling it invalid, and never rewrites the file.
func TestSavedConcessionV1IsNamedAndNeverRewritten(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profile")
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, c); err != nil {
		t.Fatal(err)
	}
	c, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault-protocol")
	if err := os.WriteFile(path, []byte("concession-v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := LoadVaultProtocol(dir)
	if value != "" || !errors.Is(err, ErrConcessionV1Protocol) {
		t.Fatalf("loaded %q, %v", value, err)
	}
	for _, want := range []string{"concession-v1", "zkapi-native-eth-sepolia-concession-v1-r3", "origin/v0.2", "same --config-dir", "left unchanged"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not name %q: %v", want, err)
		}
	}
	for _, next := range []string{"", "concession", "legacy", "concession-v1"} {
		if err := UpdateVaultProtocol(dir, c, "concession-v1", next); err == nil {
			t.Fatalf("saved %q over concession-v1", next)
		}
		info, statErr := os.Lstat(path)
		contents, readErr := os.ReadFile(path)
		if statErr != nil || readErr != nil || string(contents) != "concession-v1\n" || info.Mode().Perm() != 0600 {
			t.Fatal("the saved selection was rewritten")
		}
	}
	if err := os.WriteFile(path, []byte("concession-v9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVaultProtocol(dir); err == nil || errors.Is(err, ErrConcessionV1Protocol) {
		t.Fatalf("an unknown value was not refused as invalid: %v", err)
	}
}
