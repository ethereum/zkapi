package main

import (
	"context"
	"io"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// Explicit protocol options retain upstream's quote/approve separation, including
// escape and payout-funded exits. Never run automatic funding on this path.
func runConfiguredWithdrawal(ctx context.Context, dir string, c config.Config, args []string, out io.Writer) error {
	runtime := configuredRuntime(c)
	runtime.fund = func(ctx context.Context, c config.Config, _, _ string, _ setupPrompter) error {
		return runWithdrawal(ctx, c, args, out)
	}
	ui := &noninteractiveSetup{out: out}
	return guidedStart(ctx, dir, startOptions{prepared: &c, setupOnly: true, quietStartup: true}, ui, out, runtime)
}
