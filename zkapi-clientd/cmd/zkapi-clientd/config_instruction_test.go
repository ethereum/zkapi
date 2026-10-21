package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestConfigInstructionFileAndReset(t *testing.T) {
	dir, c := startTestConfig(t)
	path := filepath.Join(t.TempDir(), "style.txt")
	if err := os.WriteFile(path, []byte("Use neutral task-first prose."), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := runConfigSettings(dir, []string{"--rewriter-instruction-file", path}, &out); err != nil {
		t.Fatal(err)
	}
	saved, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Rewriter.Instruction != "Use neutral task-first prose." || saved.Rewriter.Enabled() {
		t.Fatal("instruction not saved independently")
	}
	if _, err := runConfigSettings(dir, []string{"--rewriter-instruction-file", path, "--rewriter-default-instruction"}, &out); err == nil {
		t.Fatal("accepted conflicting options")
	}
	if _, err := runConfigSettings(dir, []string{"--rewriter-default-instruction"}, &out); err != nil {
		t.Fatal(err)
	}
	reset, err := config.Load(dir)
	if err != nil || reset != c {
		t.Fatal("reset changed profile", err)
	}
	out.Reset()
	if err := printSavedConfig(dir, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"instruction_source": "default"`)) || !bytes.Contains(out.Bytes(), []byte("synonymous modifiers")) {
		t.Fatal("default not displayed")
	}
}
