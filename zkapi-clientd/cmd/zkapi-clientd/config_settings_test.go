package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func TestConfigSettingsAtomicPreservationAndStatus(t *testing.T) {
	dir, c := startTestConfig(t)
	t.Setenv("EDITOR_KEY_TEST", "private-test-secret")
	var out bytes.Buffer
	apply := func(args ...string) {
		t.Helper()
		ok, err := runConfigSettings(dir, args, &out)
		if !ok || err != nil {
			t.Fatalf("handled=%v err=%v", ok, err)
		}
	}
	apply("--relay-url", "tor://127.0.0.1:19050", "--model", "provider/model", "--rewriter-url", "http://localhost:8012", "--rewriter-model", "qwen3.8-flash-next", "--rewriter-api-key-env", "EDITOR_KEY_TEST", "--cover-urls", "https://controlled.example/cover")
	next, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if next.APIKey != c.APIKey || next.ManagementToken != c.ManagementToken || next.ZKAPI != c.ZKAPI || next.Cover.Rate != 5 || next.Rewriter.APIKey != "private-test-secret" {
		t.Fatal("settings/credentials changed")
	}
	apply("--rewriter-notice", "metadata", "--cover-rate", "1")
	changed, _ := config.Load(dir)
	if changed.Rewriter.APIKey != next.Rewriter.APIKey || changed.Rewriter.URL != next.Rewriter.URL || changed.Cover.URLs != next.Cover.URLs {
		t.Fatal("partial edit erased settings")
	}
	var jsonOut bytes.Buffer
	if handled, err := runConfigSettings(dir, nil, &jsonOut); !handled || err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(jsonOut.Bytes(), &doc) != nil || !strings.Contains(jsonOut.String(), "\n  \"") {
		t.Fatal("bare config not pretty JSON")
	}
	apply("--status")
	for _, s := range []string{"vault_protocol", "provider/model", "qwen3.8-flash-next", "cover", "tor://127.0.0.1:19050"} {
		if !strings.Contains(out.String(), s) {
			t.Fatal("missing status", s)
		}
	}
	if strings.Contains(out.String(), "private-test-secret") {
		t.Fatal("editor secret/endpoint echoed")
	}
	before, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	for _, args := range [][]string{{"--model", "provider/new", "--cover-rate", "99"}, {"--vault-protocol", "concession", "--model", "provider/new"}, {"--clear-rewriter", "--rewriter-model", "new"}, {"--status", "--model", "provider/new"}, {"--model", ""}, {"--rewriter-api-key-env", "MISSING_TEST_KEY"}, {"--model", "provider/new", "--usd", "20"}} {
		if _, err := runConfigSettings(dir, args, &out); err == nil {
			t.Fatal("accepted invalid edit", args)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
		if !bytes.Equal(before, after) {
			t.Fatal("partial write on error")
		}
	}
	apply("--clear-rewriter", "--clear-cover", "--clear-model", "--relay-url", c.RelayURL)
	restored, _ := config.Load(dir)
	if restored != c {
		t.Fatal("clear changed unrelated settings")
	}
	apply("--vault-protocol", "concession")
	saved, err := config.LoadVaultProtocol(dir)
	if err != nil || saved != "concession" {
		t.Fatal(saved, err)
	}
	apply("--vault-protocol", "default")
	saved, err = config.LoadVaultProtocol(dir)
	if err != nil || saved != "" {
		t.Fatal(saved, err)
	}
}

func TestConfigDisplayRedactionAndAbsentProfile(t *testing.T) {
	dir, c := startTestConfig(t)
	next := c
	next.Rewriter = rewriter.Config{URL: "https://editor.example/private-path-secret", Model: "editor", APIKey: "editor-secret", Notice: "reasoning"}
	next.ZKAPI.RequestLimitMicroUSD = 9007199254740993
	if err := config.Update(dir, c, next); err != nil {
		t.Fatal(err)
	}
	if err := config.UpdateVaultProtocol(dir, next, "", "legacy"); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := printSavedConfig(dir, &out); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-path-secret", "editor-secret", c.APIKey, c.ManagementToken, c.ZKAPI.BridgeToken} {
		if secret != "" && strings.Contains(out.String(), secret) {
			t.Fatal("secret leaked")
		}
	}
	for _, s := range []string{"9007199254740993", `"vault_protocol": "legacy"`, `"exit_rpc_url": ""`, `"cover": {`} {
		if !strings.Contains(out.String(), s) {
			t.Fatal("missing/exact field", s)
		}
	}
	if err := os.Remove(filepath.Join(dir, "management-token")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := printSavedConfig(dir, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "management-token")); !os.IsNotExist(err) {
		t.Fatal("display recreated credential")
	}
	missing := filepath.Join(t.TempDir(), "absent")
	out.Reset()
	if _, err := runConfigSettings(missing, nil, &out); err == nil || out.Len() != 0 {
		t.Fatal("missing config not an error")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("display created directory")
	}
}

func TestConfigSettingsRejectsLockedProfile(t *testing.T) {
	dir, _ := startTestConfig(t)
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, err := runConfigSettings(dir, []string{"--model", "provider/model"}, &bytes.Buffer{}); err == nil {
		t.Fatal("edited locked profile")
	}
}

func TestConfigSettingsWebSearch(t *testing.T) {
	dir, original := startTestConfig(t)
	for _, test := range []struct {
		args []string
		want bool
	}{
		{[]string{"--web-search=false"}, false},
		{[]string{"--model", "provider/model"}, false},
		{[]string{"--web-search=true", "--clear-model"}, true},
	} {
		var out bytes.Buffer
		if handled, err := runConfigSettings(dir, test.args, &out); !handled || err != nil {
			t.Fatalf("web search edit: handled=%v err=%v", handled, err)
		}
		saved, err := config.Load(dir)
		if err != nil || saved.WebSearch != test.want || saved.APIKey != original.APIKey || saved.ManagementToken != original.ManagementToken || saved.ZKAPI != original.ZKAPI {
			t.Fatal("web search edit lost the preference or changed wallet settings", err)
		}
		out.Reset()
		if handled, err := runConfigSettings(dir, []string{"--status"}, &out); !handled || err != nil {
			t.Fatal("status failed", err)
		}
		var status struct {
			WebSearch *bool `json:"web_search"`
		}
		if err := json.Unmarshal(out.Bytes(), &status); err != nil || status.WebSearch == nil || *status.WebSearch != test.want {
			t.Fatal("status omitted or changed the search preference", err)
		}
		for _, name := range []string{"funding", "zkapi"} {
			if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatalf("settings edit started wallet setup: %s", name)
			}
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if handled, err := runConfigSettings(dir, []string{"--web-search=invalid"}, &bytes.Buffer{}); !handled || err == nil {
		t.Fatal("invalid web search preference was not rejected")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid web search edit changed the profile", err)
	}
}
