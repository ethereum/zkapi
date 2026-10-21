package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestRewriterConfigPreservesWalletCredentialsAndHidesKey(t *testing.T) {
	dir, c := startTestConfig(t)
	t.Setenv("TEST_REWRITER_SECRET", "secret-rewriter-only")
	var out bytes.Buffer
	err := runRewriterConfig(dir, c, []string{"--url", "http://localhost:8011", "--model", "qwen3.8-flash-next", "--api-key-env", "TEST_REWRITER_SECRET"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	next, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if next.Rewriter.APIKey != "secret-rewriter-only" || next.APIKey != c.APIKey || next.ManagementToken != c.ManagementToken || next.ZKAPI != c.ZKAPI {
		t.Fatal("lost rewriter configuration or changed wallet credentials")
	}
	if err := runRewriterConfig(dir, next, nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "secret-rewriter-only") {
		t.Fatal("printed API key")
	}
	info, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("configuration not owner-only")
	}
	if err := runRewriterConfig(dir, next, []string{"--clear"}, &out); err != nil {
		t.Fatal(err)
	}
	cleared, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cleared != c {
		t.Fatal("clear did not restore original configuration")
	}
}

func TestRewriterConfigRejectsInvalidAndStaleUpdates(t *testing.T) {
	dir, c := startTestConfig(t)
	var out bytes.Buffer
	if err := runRewriterConfig(dir, c, []string{"--url", "http://remote.example", "--model", "model"}, &out); err == nil {
		t.Fatal("accepted plaintext remote service")
	}
	if err := runRewriterConfig(dir, c, []string{"--url", "http://localhost:8011", "--model", "model"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runRewriterConfig(dir, c, []string{"--clear"}, &out); err == nil {
		t.Fatal("accepted stale config snapshot")
	}
}
