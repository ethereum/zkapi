package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestProtocolConfigRetainsTorAndExitOptions(t *testing.T) {
	c := config.Config{RelayURL: "tor://127.0.0.1:9050", KeyReuseWindowSeconds: 60}
	c.ZKAPI.ExitRPCURL = "http://127.0.0.1:8545"
	c.ZKAPI.BundlerURL = "https://bundler.example"
	client := &http.Client{}
	got := zkConfig(c, client)
	if !got.TorMode || got.HTTPClient != client || got.KeyReuseWindow != time.Minute || got.ExitRPCURL != c.ZKAPI.ExitRPCURL || got.BundlerURL != c.ZKAPI.BundlerURL {
		t.Fatal("protocol migration lost transport or exit configuration")
	}
}

func TestUndeployedStartStopsBeforeAttachingOrFunding(t *testing.T) {
	// Unlike the default deployed fixtures, use the actual shipping manifests.
	restore := zkapi.SetPackagedDeploymentsForTesting(os.DirFS("../../internal/zkapi"))
	defer restore()
	for _, network := range []string{"mainnet", "sepolia"} {
		c := config.Config{}
		c.ZKAPI.Network = network
		// Nil runtime callbacks deliberately fail if startup tries to probe a
		// daemon, prepare a companion, or fund before the embedded deployment gate.
		err := guidedStart(context.Background(), t.TempDir(), startOptions{prepared: &c}, &noninteractiveSetup{out: io.Discard}, io.Discard, startRuntime{})
		if !errors.Is(err, zkapi.ErrDeploymentNotDeployed) {
			t.Fatalf("%s did not stop at deployment gate: %v", network, err)
		}
	}
}
