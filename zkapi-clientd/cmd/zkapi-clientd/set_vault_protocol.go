package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func runSetVaultProtocol(dir string, args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, "Usage: zkapi-clientd set-vault-protocol [legacy | concession | --clear]\nShow/save this profile's vault stack. Default: concession. Stop serve before edits. No wallet migration or payment. Both protocols preserve native rewriter/cover settings.")
		return nil
	}
	if len(args) > 1 {
		return errors.New("use set-vault-protocol [legacy | concession | --clear]")
	}
	c, err := config.Load(dir)
	if err != nil {
		return configurationRequired(err)
	}
	saved, err := config.LoadVaultProtocol(dir)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		effective, _ := vaultProtocol(saved)
		fmt.Fprintf(out, "Vault protocol: %s (profile preference; unset defaults to concession).\n", effective)
		if os.Getenv("ZKAPI_VAULT_PROTOCOL") != "" {
			fmt.Fprintln(out, "WARNING: ZKAPI_VAULT_PROTOCOL is set and overrides the saved choice for other commands.")
		}
		return nil
	}
	next := args[0]
	if next == "--clear" {
		next = ""
	} else if next != "legacy" && next != "concession" {
		return errors.New("vault protocol must be legacy or concession")
	}
	if next == "legacy" {
		// Check profile compatibility before persisting a selection. Artifact pins
		// are checked on dispatch; source tests/packaging need no installed bundle.
		if _, _, err := legacyDispatchPlan(dir, true, c, []string{"serve"}, filepath.Join(dir, "client")); err != nil {
			return err
		}
	}
	if err := config.UpdateVaultProtocol(dir, c, saved, next); err != nil {
		return err
	}
	effective, _ := vaultProtocol(next)
	fmt.Fprintf(out, "Vault protocol saved: %s. Subsequent commands use this profile's selection; no state migrated, request or transaction sent.\n", effective)
	if next == "legacy" {
		fmt.Fprintln(out, "Legacy uses its privacy-enabled protocol engine with unchanged rewriter/cover settings. Deposit gas remains high and service availability is not verified.")
	}
	return nil
}
