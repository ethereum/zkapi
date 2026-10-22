package main

import (
	"os"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// Sepolia ships the deployed leaf-bound staging vault and mainnet a
// not_deployed placeholder. These tests run against the invented, deployed
// concession profiles of the zkapi package's test data, so no test depends
// on (or reaches) a live deployment; tests of the shipped manifests swap
// them in explicitly (useShippedDeployments).
func TestMain(m *testing.M) {
	restore := zkapi.SetPackagedDeploymentsForTesting(os.DirFS("../../internal/zkapi/testdata/deployed"))
	code := m.Run()
	restore()
	os.Exit(code)
}
