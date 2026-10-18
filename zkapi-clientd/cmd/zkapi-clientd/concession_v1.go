package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// Revision 3 and revision 4 have different withdrawal statements and proving
// keys. Recovery dispatches the full, pinned revision-3 implementation; wallet
// state and signed transaction journals stay at their original paths.
//
//go:embed concession_v1_client.sha256
var concessionV1ClientPin string

//go:embed concession_v1_companion.sha256
var concessionV1CompanionPin string

func concessionV1DispatchPlan(dir string, explicitDir bool, c config.Config, args []string, executable string) (string, []string, error) {
	if !explicitDir {
		return "", nil, errors.New("concession-v1 requires an explicit --config-dir or saved selection for the original revision-3 profile")
	}
	if c.ZKAPI.Network != "sepolia" {
		return "", nil, errors.New("concession-v1 recovery is available only for its deployed Sepolia vault")
	}
	if len(args) == 0 {
		return "", nil, errors.New("concession-v1 requires a command")
	}
	switch args[0] {
	case "serve", "config", "withdraw", "list-models", "version", "help":
	default:
		return "", nil, errors.New("command unavailable in the concession-v1 protocol stack")
	}
	for _, arg := range args[1:] {
		switch strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0] {
		case "zkapi-binary", "proof-setup-dir", "external-companion":
			return "", nil, errors.New("concession-v1 cannot override its pinned companion or proving setup during dispatch")
		}
	}
	if c.ZKAPI.ExternalCompanion || !filepath.IsAbs(c.ZKAPI.Binary) || !filepath.IsAbs(c.ZKAPI.ProofSetupDir) {
		return "", nil, errors.New("concession-v1 requires absolute paths to its pinned managed companion and original revision-3 proving setup")
	}
	binary := filepath.Join(filepath.Dir(executable), "zkapi-clientd-concession-v1")
	return binary, append([]string{binary, "--config-dir", dir}, args...), nil
}

func dispatchConcessionV1(dir string, explicitDir bool, args []string) error {
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
	binary, forwarded, err := concessionV1DispatchPlan(dir, explicitDir, c, args, executable)
	if err != nil {
		return err
	}
	if err := checkProtocolArtifact(binary, strings.TrimSpace(concessionV1ClientPin)); err != nil {
		return err
	}
	if err := checkProtocolArtifact(c.ZKAPI.Binary, strings.TrimSpace(concessionV1CompanionPin)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Vault protocol: concession-v1 (Sepolia revision 3); using its original wallet, proving keys and pinned protocol engine.")
	return syscall.Exec(binary, forwarded, os.Environ())
}
