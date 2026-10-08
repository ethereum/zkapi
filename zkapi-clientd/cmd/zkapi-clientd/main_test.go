package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestInitializeNetworkProxySelection(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "default"},
		{name: "opt-in", args: []string{"--relay-url", "wss://relay.example/"}, want: "wss://relay.example/"},
		{name: "explicit-off", args: []string{"--relay-url", ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "config")
			if err := initialize(dir, test.args); err != nil {
				t.Fatal(err)
			}
			loaded, err := config.Load(dir)
			if err != nil || loaded.RelayURL != test.want {
				t.Fatalf("incorrect proxy selection: %q, %v", loaded.RelayURL, err)
			}
		})
	}
}

func TestRemovedCommandsStayUnavailable(t *testing.T) {
	t.Setenv("ZKAPI_CLIENTD_CONFIG_DIR", filepath.Join(t.TempDir(), "profile"))
	for _, command := range []string{"tickets", "init", "start", "status", "api-key"} {
		if err := run([]string{command}); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("accepted removed command %s: %v", command, err)
		}
	}
}

func TestWalletCommandsUseSavedConfigurationAndRunningDaemon(t *testing.T) {
	for _, command := range []string{"fund", "withdraw"} {
		t.Run(command, func(t *testing.T) {
			if err := run([]string{"--config-dir", filepath.Join(t.TempDir(), "profile"), command, "--help"}); err != nil {
				t.Fatalf("help failed: %v", err)
			}
			missing := filepath.Join(t.TempDir(), "missing")
			if err := run([]string{"--config-dir", missing, command}); err == nil || !strings.Contains(err.Error(), "Run zkapi-clientd config") {
				t.Fatalf("missing configuration guidance: %v", err)
			}
			if _, err := os.Stat(filepath.Join(missing, "config.json")); !os.IsNotExist(err) {
				t.Fatal("wallet command initialized configuration")
			}
			c, err := config.Default()
			if err != nil {
				t.Fatal(err)
			}
			c.Listen = "127.0.0.1:1"
			dir := filepath.Join(t.TempDir(), "saved")
			if err := config.Init(dir, c); err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"--config-dir", dir, command}); err == nil || !strings.Contains(err.Error(), "local service is unavailable") {
				t.Fatalf("wallet command did not require the running daemon: %v", err)
			}
		})
	}
}

func TestWalletCommandHelpWinsOverFlagValues(t *testing.T) {
	c, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = "127.0.0.1:1"
	saved := filepath.Join(t.TempDir(), "saved")
	if err := config.Init(saved, c); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for _, args := range [][]string{
		{"fund", "--approve", "--help"},
		{"fund", "--usd", "-h", "--json"},
		{"fund", "return", "--approve", "--help"},
		{"withdraw", "--approve", "-h"},
		{"withdraw", "--to", "--help"},
	} {
		for _, dir := range []string{saved, missing} {
			if err := run(append([]string{"--config-dir", dir}, args...)); err != nil {
				t.Fatalf("%v ran instead of printing help: %v", args, err)
			}
		}
	}
}

type inferenceTestTransport func(*http.Request) (*http.Response, error)

func (f inferenceTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExplicitConfigurationDirectoryOverridesLegacySelection(t *testing.T) {
	unused := filepath.Join(t.TempDir(), "unused")
	t.Setenv("ZKAPI_CLIENTD_CONFIG_DIR", unused)
	dir := filepath.Join(t.TempDir(), "selected")
	if err := run([]string{"--config-dir", dir, "config", "--status"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("explicit profile not selected", err)
	}
	if _, err := os.Stat(unused); !os.IsNotExist(err) {
		t.Fatal("default override was used despite explicit directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Fatal("status created a wallet")
	}
}
