package main

import (
	"os"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// The packaged deployments are not_deployed placeholders until the
// concession-exit vault is deployed; these tests run against the invented,
// deployed concession profiles of the zkapi package's test data.
func TestMain(m *testing.M) {
	restore := zkapi.SetPackagedDeploymentsForTesting(os.DirFS("../../internal/zkapi/testdata/deployed"))
	code := m.Run()
	restore()
	os.Exit(code)
}
