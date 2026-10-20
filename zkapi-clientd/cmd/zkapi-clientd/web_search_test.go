package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestConfigureWebSearchDefaultsAndEdits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profile")
	var previous config.Config
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{"new default", nil, true},
		{"disable", []string{"--web-search=false"}, false},
		{"unrelated edit preserves opt-out", []string{"--key-reuse-window-seconds", "0"}, false},
		{"enable", []string{"--web-search"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ui := &startTestUI{}
			called := false
			err := configure(context.Background(), dir, test.args, ui, io.Discard, func(_ context.Context, _ string, c config.Config, _ string, _ setupPrompter, _ io.Writer) error {
				called = true
				if c.WebSearch != test.want {
					t.Fatalf("web search = %t, want %t", c.WebSearch, test.want)
				}
				if previous.APIKey != "" && (c.APIKey != previous.APIKey || c.ManagementToken != previous.ManagementToken || c.ZKAPI.BridgeToken != previous.ZKAPI.BridgeToken) {
					t.Fatal("web search edit changed credentials")
				}
				previous = c
				return nil
			})
			if err != nil || !called {
				t.Fatal("configuration failed", err)
			}
			saved, err := config.Load(dir)
			if err != nil || saved != previous {
				t.Fatal("web search preference was not persisted", err)
			}
			state := "off"
			if test.want {
				state = "on"
			}
			status := &startTestUI{}
			if err := configure(context.Background(), dir, []string{"--status"}, status, io.Discard, nil); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(status.output.String(), "Web search: "+state+" by default") {
				t.Fatal("status did not show the saved web search preference")
			}
		})
	}
	if _, err := parseConfigureOptions([]string{"--web-search=invalid"}, io.Discard); err == nil {
		t.Fatal("invalid web search flag accepted")
	}
}

func TestConfigureWebSearchInteractiveToggleAndKeep(t *testing.T) {
	dir, _ := startTestConfig(t)
	for _, answer := range []string{"off", "", "on", ""} {
		before, err := config.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		want := before
		if answer != "" {
			want.WebSearch = answer == "on"
		}
		ui := &startTestUI{answers: []string{"", "", "", answer}}
		err = configure(context.Background(), dir, []string{"--edit"}, ui, io.Discard, func(_ context.Context, _ string, c config.Config, _ string, _ setupPrompter, _ io.Writer) error {
			if c != want {
				t.Fatal("interactive web search edit changed unrelated settings or lost the preference")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		saved, err := config.Load(dir)
		if err != nil || saved != want {
			t.Fatal("interactive web search preference did not persist", err)
		}
	}
}
