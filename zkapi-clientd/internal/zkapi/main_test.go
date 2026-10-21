package zkapi

import (
	"os"
	"testing"
	"time"
)

// The packaged deployments are not_deployed placeholders until the
// concession-exit vault is deployed. Package tests run against invented,
// deployed concession profiles instead; tests of the packaged placeholders
// read deploymentFiles directly.
func TestMain(m *testing.M) {
	restore := SetPackagedDeploymentsForTesting(os.DirFS("testdata/deployed"))
	// An exit RPC that does not answer is retried after these waits.
	exitRPCRetryDelays = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	code := m.Run()
	restore()
	os.Exit(code)
}
