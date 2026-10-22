package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

const (
	shippedSepoliaID       = "zkapi-native-eth-sepolia-leaf-v4-20261020"
	shippedSepoliaVault    = "0x67eb750d9c0d63a99684ac3f3e65f0c610276993"
	shippedSepoliaSummary  = "sepolia — zkAPI v0.2 (deployment " + shippedSepoliaID + ", vault " + shippedSepoliaVault + ")"
	earlierConcessionID    = "zkapi-native-eth-sepolia-concession-v2-r4-20261017"
	earlierRecoveryContent = "synthetic recovery fixture; leave unchanged"
)

// useShippedDeployments swaps the test fixtures for the embedded manifests.
func useShippedDeployments(t *testing.T) {
	t.Helper()
	t.Cleanup(zkapi.SetPackagedDeploymentsForTesting(os.DirFS("../../internal/zkapi")))
}

// closedLoopback is a loopback address nothing listens on, so a test never
// reaches a real daemon or companion on the default ports.
func closedLoopback(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

// writeEarlierWallet leaves synthetic recovery files of an earlier Sepolia
// deployment in the profile.
func writeEarlierWallet(t *testing.T, dir string) []string {
	t.Helper()
	var paths []string
	for _, relative := range []string{filepath.Join("zkapi", "sepolia", earlierConcessionID, "note_state.json"), filepath.Join("funding", "sepolia", earlierConcessionID, "address-funding.json")} {
		path := filepath.Join(dir, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(earlierRecoveryContent), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

// The configuration summary, wallet menu and guided start name the shipped
// deployment by its display name, ID and vault; a placeholder says it is not
// deployed.
func TestSummaryNamesTheShippedSepoliaDeployment(t *testing.T) {
	useShippedDeployments(t)
	if got := deploymentSummary("sepolia"); got != shippedSepoliaSummary {
		t.Fatalf("summary %q", got)
	}
	if got := deploymentSummary("mainnet"); got != "mainnet — zkAPI deployment zkapi-native-eth-mainnet-concession-v1 (not deployed)" {
		t.Fatalf("placeholder summary %q", got)
	}
	dir, c := startTestConfig(t)
	ui := &startTestUI{}
	showConfigureSummary(c, ui)
	if !strings.Contains(ui.output.String(), "zkAPI network: "+shippedSepoliaSummary+"\n") {
		t.Fatalf("configure summary:\n%s", ui.output.String())
	}
	menu := &startTestUI{answers: []string{"quit"}}
	if err := configure(context.Background(), dir, []string{"--menu"}, menu, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(menu.output.String(), "Wallet menu for zkAPI network "+shippedSepoliaSummary+".") {
		t.Fatalf("wallet menu:\n%s", menu.output.String())
	}
	start := &startTestUI{}
	runtime := startRuntime{
		probe:     func(context.Context, config.Config) (bool, error) { return true, nil },
		companion: func(context.Context, config.Config) error { return nil },
		fund:      func(context.Context, config.Config, string, string, setupPrompter) error { return nil },
		interval:  time.Millisecond, timeout: time.Second,
	}
	if err := guidedStart(context.Background(), dir, startOptions{prepared: &c, setupOnly: true}, start, io.Discard, runtime); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(start.output.String(), "Network: "+shippedSepoliaSummary+".") {
		t.Fatalf("guided start:\n%s", start.output.String())
	}
}

// An earlier deployment's wallet in the profile is named, without a
// question, by config --setup and --menu; guided funding repeats it before
// a new deposit's address. The key-only view contains no warnings.
func TestEarlierDeploymentWarningsNeverAskOrBlock(t *testing.T) {
	dir, c := startTestConfig(t)
	paths := writeEarlierWallet(t, dir)
	for _, args := range [][]string{nil, {"--menu"}} {
		ui := &startTestUI{answers: []string{"check"}}
		called := false
		err := configure(context.Background(), dir, args, ui, io.Discard, func(context.Context, string, config.Config, string, setupPrompter, io.Writer) error {
			called = true
			return nil
		})
		output := ui.output.String()
		if err != nil || !called || !strings.Contains(output, "WARNING: Recovery files of the earlier concession vault") || !strings.Contains(output, earlierConcessionID) || !strings.Contains(output, filepath.Join(dir, "zkapi", "sepolia", earlierConcessionID)) || !strings.Contains(output, "origin/v0.2") {
			t.Fatalf("config %v: %v\n%s", args, err, output)
		}
	}
	var key bytes.Buffer
	if err := configure(context.Background(), dir, []string{"--api-key"}, &startTestUI{}, &key, nil); err != nil || strings.TrimSpace(key.String()) != c.APIKey {
		t.Fatal("key-only configuration output included extra text", err)
	}
	warnings := zkapi.EarlierDeploymentWarnings(dir, "sepolia")
	if len(warnings) != 1 {
		t.Fatalf("warnings %v", warnings)
	}
	ctx := context.WithValue(context.Background(), earlierDeploymentsKey{}, warnings)
	f := newWizardFixture()
	u := &fundingWizardUI{answers: []string{"20"}, confirmations: []bool{false}}
	if err := guidedFunding(ctx, f, "", u, immediateWizardPoll); err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("guided funding: %v", err)
	}
	warning, address := strings.Index(u.String(), "WARNING: "+warnings[0]), strings.Index(u.String(), "Watching the receiving account")
	if warning < 0 || address < 0 || warning > address || u.asks != 1 {
		t.Fatalf("the warning did not precede the new funding address:\n%s", u.String())
	}
	// A saved deposit shows no new address and repeats nothing.
	saved := newWizardFixture()
	saved.address = func() zkapi.AddressFundingStatus { s := wizardState("ready"); s.TransactionHash = ""; return s }
	resumed := &fundingWizardUI{confirmations: []bool{false}}
	_ = guidedFunding(ctx, saved, "", resumed, immediateWizardPoll)
	if strings.Contains(resumed.String(), "WARNING:") {
		t.Fatal("a saved deposit repeated the warning")
	}
	for _, path := range paths {
		if contents, err := os.ReadFile(path); err != nil || string(contents) != earlierRecoveryContent {
			t.Fatal("an earlier recovery file changed")
		}
	}
}

// Status reports the packaged deployment and which earlier recovery files
// exist, never their contents.
func TestStatusReportsTheDeploymentAndEarlierWallets(t *testing.T) {
	useShippedDeployments(t)
	dir, c := startTestConfig(t)
	c.Listen = closedLoopback(t)
	c.ZKAPI.ClientURL = "http://" + closedLoopback(t)
	writeEarlierWallet(t, dir)
	var out, warnings bytes.Buffer
	if err := status(context.Background(), dir, c, &out, &warnings); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), earlierRecoveryContent) || strings.Contains(warnings.String(), earlierRecoveryContent) {
		t.Fatal("status read a recovery file")
	}
	var result struct {
		ID       string                    `json:"deployment_id"`
		Display  string                    `json:"deployment_display"`
		Contract string                    `json:"contract_address"`
		Server   string                    `json:"protocol_server_url"`
		Earlier  []zkapi.EarlierDeployment `json:"earlier_deployments"`
		Running  bool                      `json:"service_running"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ID != shippedSepoliaID || result.Display != "zkAPI v0.2" || result.Contract != shippedSepoliaVault || result.Server != "https://zkapi-sepolia.openanonymity.ai/v0.4" || result.Running {
		t.Fatalf("status %s", out.String())
	}
	if len(result.Earlier) != 1 || result.Earlier[0].ID != earlierConcessionID || len(result.Earlier[0].Files) != 2 || !strings.Contains(result.Earlier[0].Recovery, "origin/v0.2") {
		t.Fatalf("earlier deployments %+v", result.Earlier)
	}
	if !strings.Contains(warnings.String(), "WARNING: Recovery files of the earlier concession vault") {
		t.Fatalf("status warnings %q", warnings.String())
	}
	empty, _ := startTestConfig(t)
	out.Reset()
	if err := status(context.Background(), empty, c, &out, io.Discard); err != nil || !strings.Contains(out.String(), `"earlier_deployments": []`) {
		t.Fatalf("status without earlier wallets: %v\n%s", err, out.String())
	}
}

// A profile a v0.2 bundle saved as concession-v1, or that selection through
// the environment or flag, is named with its way out and left unchanged.
func TestConcessionV1SelectionIsNamedAndLeftUnchanged(t *testing.T) {
	dir, _ := startTestConfig(t)
	path := filepath.Join(dir, "vault-protocol")
	if err := os.WriteFile(path, []byte("concession-v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"serve"}, {"withdraw"}, {"config"}, {"config", "--setup"}, {"config", "--vault-protocol", "concession"}, {"config", "--vault-protocol", "default"}} {
		err := run(append([]string{"--config-dir", dir}, args...))
		if !errors.Is(err, config.ErrConcessionV1Protocol) || !strings.Contains(err.Error(), "origin/v0.2") || !strings.Contains(err.Error(), "same --config-dir") {
			t.Fatalf("%v: %v", args, err)
		}
		info, statErr := os.Lstat(path)
		contents, readErr := os.ReadFile(path)
		if statErr != nil || readErr != nil || string(contents) != "concession-v1\n" || info.Mode().Perm() != 0600 {
			t.Fatalf("%v rewrote the saved selection", args)
		}
	}
	clean, _ := startTestConfig(t)
	if err := run([]string{"--config-dir", clean, "--vault-protocol", "concession-v1", "serve"}); !errors.Is(err, errConcessionV1Selected) {
		t.Fatalf("flag: %v", err)
	}
	t.Setenv("ZKAPI_VAULT_PROTOCOL", "concession-v1")
	if err := run([]string{"--config-dir", clean, "serve"}); !errors.Is(err, errConcessionV1Selected) || !strings.Contains(err.Error(), "origin/v0.2") {
		t.Fatalf("environment: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(clean, "vault-protocol")); !os.IsNotExist(err) {
		t.Fatal("a refused selection was saved")
	}
}

// A running daemon whose build serves another deployment is refused before
// any wallet operation; one that predates deployment reporting is noted
// once and attached as before.
func TestAttachRefusesADaemonOfAnotherDeployment(t *testing.T) {
	dir, c := startTestConfig(t)
	packaged, err := zkapi.PackagedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	var notices bytes.Buffer
	previous := daemonNotices
	daemonNotices, daemonNoticeOnce = &notices, sync.Once{}
	t.Cleanup(func() { daemonNotices, daemonNoticeOnce = previous, sync.Once{} })
	daemon := func(body string) config.Config {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/admin/status" || r.Header.Get("Authorization") != "Bearer "+c.APIKey {
				t.Error("the probe did not authenticate local status")
			}
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(s.Close)
		selected := c
		selected.Listen = strings.TrimPrefix(s.URL, "http://")
		return selected
	}
	other := daemon(`{"backend":"zkapi","network":"sepolia","deployment_id":"` + earlierConcessionID + `"}`)
	_, err = resolveActiveConfig(context.Background(), other)
	var mismatch *daemonDeploymentError
	if !errors.As(err, &mismatch) || !strings.Contains(err.Error(), earlierConcessionID) || !strings.Contains(err.Error(), packaged.ID) || !strings.Contains(err.Error(), "restart the daemon with this build; your other wallet is untouched") {
		t.Fatalf("resolve: %v", err)
	}
	if attached, err := probeSetupService(context.Background(), other); attached || !errors.As(err, &mismatch) {
		t.Fatalf("probe: %v, %v", attached, err)
	}
	if err := config.Update(dir, c, other); err != nil {
		t.Fatal(err)
	}
	refuse := startRuntime{
		active: resolveActiveConfig,
		probe: func(context.Context, config.Config) (bool, error) {
			t.Fatal("probed after refusing the daemon")
			return false, nil
		},
	}
	if err := guidedStart(context.Background(), dir, startOptions{}, &startTestUI{}, io.Discard, refuse); !errors.As(err, &mismatch) {
		t.Fatalf("guided start attached: %v", err)
	}
	if notices.Len() != 0 {
		t.Fatal("a reporting daemon was noted as unreported")
	}
	for i := 0; i < 2; i++ {
		if _, err := resolveActiveConfig(context.Background(), daemon(`{"backend":"zkapi","network":"sepolia","deployment_id":"`+packaged.ID+`"}`)); err != nil {
			t.Fatal(err)
		}
		if notices.Len() != 0 {
			t.Fatal("the matching daemon was noted")
		}
	}
	old := daemon(`{"backend":"zkapi","network":"sepolia"}`)
	for i := 0; i < 2; i++ {
		if attached, err := probeSetupService(context.Background(), old); !attached || err != nil {
			t.Fatalf("an unreported deployment was refused: %v", err)
		}
	}
	if strings.Count(notices.String(), "WARNING:") != 1 || !strings.Contains(notices.String(), "does not report its zkAPI deployment") {
		t.Fatalf("notices %q", notices.String())
	}
}
