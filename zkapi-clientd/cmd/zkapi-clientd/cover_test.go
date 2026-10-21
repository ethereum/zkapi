package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/cover"
)

func TestCoverConfigPreservesOtherSettings(t *testing.T) {
	dir, c := startTestConfig(t)
	original := c
	c.RelayURL = "tor://127.0.0.1:9050"
	if err := config.Update(dir, original, c); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runCoverConfig(dir, c, []string{"--urls", "https://cover.example/private-path"}, &out); err != nil {
		t.Fatal(err)
	}
	next, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if next.Cover.Rate != 5 || next.Cover.Concurrency != 4 {
		t.Fatal("missing cover settings")
	}
	without := next
	without.Cover = cover.Config{}
	if without != c {
		t.Fatal("changed wallet/other config")
	}
	if err := runCoverConfig(dir, next, nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "private-path") {
		t.Fatal("disclosed destination path")
	}
	if err := runCoverConfig(dir, c, []string{"--clear"}, &out); err == nil {
		t.Fatal("stale snapshot accepted")
	}
	if err := runCoverConfig(dir, next, []string{"--clear"}, &out); err != nil {
		t.Fatal(err)
	}
	final, err := config.Load(dir)
	if err != nil || final != c {
		t.Fatal("clear damaged config", err)
	}
}

func TestCoverDoesNotStartForTemporaryWalletRuntime(t *testing.T) {
	// Deliberately invalid settings: a temporary runtime must never even attempt
	// construction. Explicit serve must validate instead of direct fallback.
	c := config.Config{Cover: cover.Config{Rate: 1}}
	stop, err := startServeCover(context.Background(), c, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := startServeCover(context.WithValue(context.Background(), coverServeKey{}, true), c, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("invalid explicit serve accepted")
	}
}

func TestCoverConfigRequiresTorAndExplicitTargets(t *testing.T) {
	dir, c := startTestConfig(t)
	for _, args := range [][]string{{"--urls", "https://cover.example"}, {"--rate", "0.2"}, {"--clear", "--rate", "1"}} {
		if err := runCoverConfig(dir, c, args, io.Discard); err == nil {
			t.Fatal("unsafe settings accepted")
		}
	}
	after, err := config.Load(dir)
	if err != nil || after != c {
		t.Fatal("failed update changed config")
	}
	if err := run([]string{"--config-dir", t.TempDir(), "config", "--help"}); err != nil {
		t.Fatal(err)
	}
}
