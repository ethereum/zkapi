//go:build live_acceptance

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// TestLiveSepoliaDaemon runs the real daemon with automatic funding disabled
// while a caller exercises the owner-authenticated CLI quote/approve endpoints.
// The explicit profile must be a separate Sepolia test profile. No transaction
// is authorized by starting this harness; approval commands remain separate.
func TestLiveSepoliaDaemon(t *testing.T) {
	dir := os.Getenv("ZKAPI_TEST_PROFILE")
	if os.Getenv("ZKAPI_TEST_SEPOLIA") != "1" || dir == "" {
		t.Skip("requires explicit Sepolia acceptance profile")
	}
	restore := zkapi.SetPackagedDeploymentsForTesting(os.DirFS("../../internal/zkapi"))
	defer restore()
	c, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.ZKAPI.Network != "sepolia" {
		t.Fatal("acceptance harness only permits Sepolia")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := serveSnapshot(ctx, dir, c, c, os.Stdout); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
}
