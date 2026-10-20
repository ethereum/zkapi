package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWebSearchDefaultsAndSavedPreferences(t *testing.T) {
	for _, test := range []struct {
		name, value string
		want        bool
		invalid     bool
	}{
		{name: "older profile", want: true},
		{name: "enabled", value: "true", want: true},
		{name: "disabled", value: "false"},
		{name: "null", value: "null", invalid: true},
		{name: "string", value: `"false"`, invalid: true},
		{name: "number", value: "0", invalid: true},
		{name: "object", value: "{}", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, err := Default()
			if err != nil || !c.WebSearch {
				t.Fatal("web search must default to on", err)
			}
			dir := filepath.Join(t.TempDir(), "profile")
			if err := Init(dir, c); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["web_search"]) != "true" {
				t.Fatal("new profiles must save the enabled default")
			}
			delete(fields, "web_search")
			if test.value != "" {
				fields["web_search"] = json.RawMessage(test.value)
			}
			raw, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(dir)
			if test.invalid {
				if err == nil {
					t.Fatal("non-boolean web_search accepted")
				}
				return
			}
			if err != nil || loaded.WebSearch != test.want || loaded.APIKey != c.APIKey {
				t.Fatal("web search preference or credentials changed", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("loading rewrote the saved profile", err)
			}
			next := loaded
			next.WebSearch = !loaded.WebSearch
			if err := Update(dir, loaded, next); err != nil {
				t.Fatal(err)
			}
			saved, err := Load(dir)
			if err != nil || saved != next {
				t.Fatal("explicit web search setting did not round trip", err)
			}
		})
	}
}
