package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// The legacy and concession stacks prove different statements. Dispatch a
// complete pinned legacy release; never replace the concession vault address,
// reinterpret notes, translate signed journals, or relax deployment gates.
//
//go:embed legacy_client.sha256
var legacyClientPin string

var legacyClientHash = strings.TrimSpace(legacyClientPin)

const legacyCompanionHash = "84d57456c3cdea682e5201d1bb29a5219753404d390140c30897fe0b3cf06909"

func vaultProtocol(flagValue string) (string, error) {
	switch flagValue {
	case "", "concession":
		return "concession", nil
	case "legacy":
		return "legacy", nil
	default:
		return "", errors.New("vault protocol must be legacy or concession (no automatic fallback)")
	}
}

func checkProtocolArtifact(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return errors.New("protocol executable missing or unsafe; use the matching pinned local build")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open protocol executable")
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return errors.New("cannot verify protocol executable")
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("protocol executable does not match the pinned legacy build; refusing mixed or unknown protocol code")
	}
	return nil
}

func legacyDispatchPlan(dir string, explicitDir bool, c config.Config, args []string, executable string) (string, []string, error) {
	if !explicitDir {
		return "", nil, errors.New("legacy selection requires an explicit --config-dir for an existing legacy profile; profiles and wallet state are never copied or converted")
	}
	if len(args) == 0 {
		return "", nil, errors.New("legacy selection requires a command")
	}
	switch args[0] {
	case "serve", "config", "withdraw", "list-models", "version", "help":
	default:
		return "", nil, errors.New("command unavailable in the legacy protocol stack")
	}
	// Companion/setup overrides would invalidate the stack checked below. Edit
	// a legacy profile with its own legacy tooling, not through this dispatch.
	for _, arg := range args[1:] {
		name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		switch name {
		case "zkapi-binary", "proof-setup-dir", "external-companion":
			return "", nil, errors.New("legacy dispatch cannot override its pinned companion/setup; use a prepared legacy profile")
		}
	}
	// Shared rewriter/cover settings pass unchanged to the privacy-enabled
	// legacy engine. Never fall back to the older privacy-less executable.
	if c.ZKAPI.ExitRPCURL != "" || c.ZKAPI.BundlerURL != "" || c.ZKAPI.WithdrawalFees != "" {
		return "", nil, errors.New("preserved legacy client cannot interpret concession exit options")
	}
	if c.ZKAPI.ExternalCompanion {
		return "", nil, errors.New("legacy dispatch requires its pinned managed companion")
	}
	if !filepath.IsAbs(c.ZKAPI.Binary) || !filepath.IsAbs(c.ZKAPI.ProofSetupDir) {
		return "", nil, errors.New("legacy profile must explicitly name absolute paths to its companion and original verified proving setup")
	}
	binary := filepath.Join(filepath.Dir(executable), "zkapi-clientd-legacy-privacy")
	// The legacy companion verifies its own deployment and proving-key pins.
	forwarded := append([]string{binary, "--config-dir", dir}, args...)
	return binary, forwarded, nil
}

func dispatchLegacy(dir string, explicitDir bool, args []string) error {
	if !explicitDir {
		return errors.New("legacy selection requires an explicit --config-dir for an existing legacy profile")
	}
	c, err := config.Load(dir)
	if err != nil {
		return configurationRequired(err)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	binary, forwarded, err := legacyDispatchPlan(dir, explicitDir, c, args, executable)
	if err != nil {
		return err
	}
	if err := checkProtocolArtifact(binary, legacyClientHash); err != nil {
		return err
	}
	if err := checkProtocolArtifact(c.ZKAPI.Binary, legacyCompanionHash); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Vault protocol: legacy (zkapi-v2-note-bound-v1), using pinned legacy protocol engine and companion; shared rewriter/cover settings preserved. Historical deposit gas is high; legacy admission may be closed or retired. Selection is not funding approval or proof of live availability.")
	// Replace, rather than detach: terminal interaction, signals, daemon locks
	// and exit status remain owned by the selected native protocol client.
	return syscall.Exec(binary, forwarded, os.Environ())
}
