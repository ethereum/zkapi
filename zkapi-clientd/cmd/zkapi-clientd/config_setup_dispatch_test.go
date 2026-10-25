package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// The live Sepolia setup command: explicit --setup with the profile options
// configure applies before preparing the wallet, and the new-deposit amount.
var explicitSepoliaSetup = []string{"--setup", "--network", "sepolia", "--listen", "127.0.0.1:18877", "--zkapi-binary", "/abs/target/release/zkapi-walletd", "--proof-setup-dir", "/abs/protocol/setup/v2-concession-dev", "--usd", "3"}

func TestExplicitSetupWithProfileOptionsReachesConfigure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "isolated")
	if err := config.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	password := filepath.Join(dir, config.TestnetPasswordFile)
	if err := os.WriteFile(password, []byte("shared-test-password"), 0600); err != nil {
		t.Fatal(err)
	}
	handled, err := runConfigSettings(dir, explicitSepoliaSetup, io.Discard)
	if handled || err != nil {
		t.Fatalf("settings editor intercepted explicit setup: handled=%v err=%v", handled, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "config.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("settings editor wrote a profile before setup")
	}
	o, err := parseConfigureOptions(explicitSepoliaSetup, io.Discard)
	if err != nil || o.usd != "3" {
		t.Fatal("setup options rejected or deposit amount lost", o.usd, err)
	}
	called := false
	err = configure(context.Background(), dir, explicitSepoliaSetup, &startTestUI{}, io.Discard, func(_ context.Context, _ string, c config.Config, action string, _ setupPrompter, _ io.Writer) error {
		called = true
		if action != "setup" || c.ZKAPI.Network != "sepolia" || c.Listen != "127.0.0.1:18877" || c.ZKAPI.Binary != "/abs/target/release/zkapi-walletd" || c.ZKAPI.ProofSetupDir != "/abs/protocol/setup/v2-concession-dev" {
			t.Fatalf("setup did not apply the profile options: %s %+v", action, c.ZKAPI)
		}
		return nil
	})
	if err != nil || !called {
		t.Fatal("explicit setup did not run", err)
	}
	if data, err := os.ReadFile(password); err != nil || string(data) != "shared-test-password" {
		t.Fatal("setup changed the provisioned Sepolia password file")
	}
	for _, args := range [][]string{{"--setup"}, {"--usd", "20"}, {"--setup", "--usd", "20"}, {"--network=sepolia", "--setup=true"}, {"--edit"}, {"--menu"}, {"--api-key"}} {
		if handled, err := runConfigSettings(dir, args, io.Discard); handled || err != nil {
			t.Fatal("wallet action intercepted by the settings editor", args, err)
		}
	}
}

func TestSettingsOnlyEditsNeverPrepareOrFund(t *testing.T) {
	fresh := filepath.Join(t.TempDir(), "fresh")
	if err := config.EnsureDir(fresh); err != nil {
		t.Fatal(err)
	}
	// Without --setup a missing profile is reported, not created or funded.
	handled, err := runConfigSettings(fresh, explicitSepoliaSetup[1:9], io.Discard)
	if !handled || err == nil {
		t.Fatal("settings-only edit on a missing profile did not stop", handled, err)
	}
	if _, err := os.Lstat(filepath.Join(fresh, "config.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("settings-only edit created a profile")
	}
	dir, original := startTestConfig(t)
	var out bytes.Buffer
	if handled, err := runConfigSettings(dir, []string{"--network", "sepolia", "--listen", "127.0.0.1:18877", "--bundler-url", "none"}, &out); !handled || err != nil {
		t.Fatal("settings-only edit failed", handled, err)
	}
	if !bytes.Contains(out.Bytes(), []byte("No setup, network request or payment performed.")) {
		t.Fatal("settings-only edit did not state that it performed no setup")
	}
	saved, err := config.Load(dir)
	if err != nil || saved.Listen != "127.0.0.1:18877" || saved.APIKey != original.APIKey || saved.ZKAPI.Network != "sepolia" {
		t.Fatal("settings-only edit not saved", err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	for _, args := range [][]string{
		{"--usd", "3", "--network", "sepolia"},   // a deposit amount needs --setup
		{"--listen", "127.0.0.1:1", "--usd=3"},   // in either order
		{"--setup", "--model", "provider/model"}, // settings-only options are saved first
		{"--setup", "--cover-urls", "https://c.example/x"},
		{"--setup", "--vault-protocol", "legacy"},
		{"--usd", "3", "--clear-rewriter"},
	} {
		if handled, err := runConfigSettings(dir, args, io.Discard); !handled || err == nil {
			t.Fatal("mixed setup/settings edit accepted", args, handled, err)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
		if !bytes.Equal(before, after) {
			t.Fatal("refused edit wrote the profile", args)
		}
	}
	// --setup=false is routed to configure, which refuses it before any action.
	args := []string{"--setup=false", "--network", "sepolia"}
	if handled, err := runConfigSettings(dir, args, io.Discard); handled || err != nil {
		t.Fatal(handled, err)
	}
	err = configure(context.Background(), dir, args, &startTestUI{}, io.Discard, func(context.Context, string, config.Config, string, setupPrompter, io.Writer) error {
		t.Fatal("--setup=false prepared the wallet")
		return nil
	})
	if err == nil {
		t.Fatal("--setup=false accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("--setup=false wrote the profile")
	}
}
