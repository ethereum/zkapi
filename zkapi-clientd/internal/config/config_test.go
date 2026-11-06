package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInitPrivateAndNeverClobbers(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if c.RelayURL != "" || c.LeCoreContextRecall {
		t.Fatal("default configuration enabled optional request processing")
	}
	if c.ZKAPI.Network != "mainnet" || c.VerifierURL != mainnetVerifierURL {
		t.Fatal("new Mainnet profile did not select the production verifier")
	}
	dir := filepath.Join(t.TempDir(), "config")
	if err := Init(dir, c); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "config.json"): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("permissions %s", path)
		}
	}
	loaded, err := Load(dir)
	if err != nil || loaded.APIKey != c.APIKey || loaded.ZKAPI.Network != "mainnet" || loaded.RelayURL != "" {
		t.Fatalf("load failed %v", err)
	}
	other, _ := Default()
	if Init(dir, other) == nil {
		t.Fatal("init overwrote existing config")
	}
	loaded, _ = Load(dir)
	if loaded.APIKey != c.APIKey {
		t.Fatal("existing key replaced")
	}
	if err := os.Chmod(filepath.Join(dir, "config.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("accepted readable secrets")
	}
}

func TestLeCoreContextRecallProfileRoundTrip(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "config")
	if err := Init(dir, c); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil || loaded.LeCoreContextRecall {
		t.Fatal("recall was not off in the saved default profile", err)
	}
	original := loaded
	selected := loaded
	selected.LeCoreContextRecall = true
	if err := Update(dir, loaded, selected); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(dir)
	if err != nil || !loaded.LeCoreContextRecall || loaded.APIKey != c.APIKey {
		t.Fatal("recall opt-in did not persist without changing credentials", err)
	}
	if err := Update(dir, loaded, original); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(dir)
	if err != nil || loaded.LeCoreContextRecall {
		t.Fatal("recall opt-out did not persist", err)
	}
}

func TestLoadRotatesOnlyFormerMainnetDefaultVerifier(t *testing.T) {
	for _, test := range []struct {
		name, network, saved, want string
	}{
		{"old-mainnet", "mainnet", sepoliaVerifierURL, mainnetVerifierURL},
		{"old-mainnet-slash", "mainnet", sepoliaVerifierURL + "/", mainnetVerifierURL},
		{"production-mainnet", "mainnet", mainnetVerifierURL, mainnetVerifierURL},
		{"sepolia", "sepolia", sepoliaVerifierURL, sepoliaVerifierURL},
		{"sepolia-slash", "sepolia", sepoliaVerifierURL + "/", sepoliaVerifierURL + "/"},
		{"custom-mainnet", "mainnet", "https://verifier.example", "https://verifier.example"},
		{"custom-sepolia", "sepolia", "https://verifier.example/", "https://verifier.example/"},
		{"custom-port", "mainnet", sepoliaVerifierURL + ":8443", sepoliaVerifierURL + ":8443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, err := Default()
			if err != nil {
				t.Fatal(err)
			}
			c.ZKAPI.Network, c.VerifierURL = test.network, test.saved
			c.OrgURL = "https://legacy-unused-org.example"
			dir := filepath.Join(t.TempDir(), "profile")
			if err := Init(dir, c); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			walletPath := filepath.Join(dir, "wallet-recovery-fixture")
			wallet := []byte("private saved wallet and recovery remain unchanged")
			if err := os.WriteFile(walletPath, wallet, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			expected := c
			expected.VerifierURL, expected.ManagementToken = test.want, loaded.ManagementToken
			if loaded != expected {
				t.Fatal("loading changed profile fields other than the reviewed verifier rotation")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("load rewrote saved configuration", err)
			}
			walletAfter, err := os.ReadFile(walletPath)
			if err != nil || !bytes.Equal(wallet, walletAfter) {
				t.Fatal("load changed wallet recovery", err)
			}
			// A normal edit must accept the migrated snapshot and keep its
			// credentials; this is also where the new verifier is persisted.
			next := loaded
			next.Listen = "127.0.0.1:9876"
			if err := Update(dir, loaded, next); err != nil {
				t.Fatal("could not edit migrated profile", err)
			}
			again, err := Load(dir)
			if err != nil || again != next {
				t.Fatal("edited profile changed on reload", err)
			}
		})
	}
}

func TestSelectNetworkPreservesCustomVerifier(t *testing.T) {
	for _, test := range []struct {
		name, from, verifier, to, want string
	}{
		{"mainnet-to-sepolia", "mainnet", mainnetVerifierURL, "sepolia", sepoliaVerifierURL},
		{"sepolia-to-mainnet", "sepolia", sepoliaVerifierURL, "mainnet", mainnetVerifierURL},
		{"legacy-mainnet", "mainnet", sepoliaVerifierURL, "mainnet", mainnetVerifierURL},
		{"slash-default", "sepolia", sepoliaVerifierURL + "/", "mainnet", mainnetVerifierURL},
		{"custom", "mainnet", "https://verifier.example", "sepolia", "https://verifier.example"},
		{"explicit-production-on-sepolia", "sepolia", mainnetVerifierURL, "mainnet", mainnetVerifierURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, err := Default()
			if err != nil {
				t.Fatal(err)
			}
			c.ZKAPI.Network, c.VerifierURL = test.from, test.verifier
			selected := SelectNetwork(c, test.to)
			want := c
			want.ZKAPI.Network, want.VerifierURL = test.to, test.want
			if selected != want {
				t.Fatal("network selection changed unrelated profile fields or used the wrong verifier")
			}
		})
	}
}

func TestLoadPreservesRelaySelection(t *testing.T) {
	for _, relayURL := range []string{"", "wss://relay.example/", "ws://127.0.0.1:8765/", "socks5://127.0.0.1:9050", "tor://127.0.0.1:9050"} {
		t.Run(relayURL, func(t *testing.T) {
			c, err := Default()
			if err != nil {
				t.Fatal(err)
			}
			c.RelayURL = relayURL
			dir := filepath.Join(t.TempDir(), "config")
			if err := Init(dir, c); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(dir)
			if err != nil || loaded.RelayURL != relayURL {
				t.Fatalf("saved relay selection changed: %q, %v", loaded.RelayURL, err)
			}
		})
	}
}

func TestManagementTokenPersistsPrivatelyWithoutChangingConfig(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "config")
	if err := Init(dir, c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ManagementToken) != 64 || loaded.ManagementToken == loaded.APIKey {
		t.Fatal("management credential is missing or duplicates inference access")
	}
	again, err := Load(dir)
	if err != nil || again.ManagementToken != loaded.ManagementToken {
		t.Fatal("management credential changed on reload", err)
	}
	info, err := os.Lstat(filepath.Join(dir, managementTokenFile))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("management credential is not a private regular file")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("loading management credential changed existing config")
	}
	published, err := json.Marshal(loaded)
	if err != nil || bytes.Contains(published, []byte(loaded.ManagementToken)) || bytes.Contains(published, []byte("management")) {
		t.Fatal("management credential appeared in serialized config")
	}
}

func TestConcurrentLoadsShareOneDurableManagementToken(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "config")
	if err := Init(dir, c); err != nil {
		t.Fatal(err)
	}
	const workers = 32
	values := make([]Config, workers)
	failures := make([]error, workers)
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			values[i], failures[i] = Load(dir)
		}()
	}
	close(start)
	group.Wait()
	for i := range workers {
		if failures[i] != nil || values[i].ManagementToken == "" || values[i].ManagementToken != values[0].ManagementToken {
			t.Fatalf("concurrent load %d disagreed or failed: %v", i, failures[i])
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".management-token-") {
			t.Fatal("completed load left temporary credential files")
		}
	}
}

func TestManagementTokenRejectsUnsafeExistingFileWithoutReplacement(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "malformed", "inference-key", "directory"} {
		t.Run(kind, func(t *testing.T) {
			c, err := Default()
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "config")
			if err := Init(dir, c); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, managementTokenFile)
			content := []byte(strings.Repeat("a", 64) + "\n")
			switch kind {
			case "symlink":
				target := filepath.Join(dir, "existing-secret")
				if err := os.WriteFile(target, content, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if kind == "malformed" {
					content = []byte("partial")
				}
				if kind == "inference-key" {
					content = []byte(c.APIKey + "\n")
				}
				if err := os.WriteFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "public" {
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir); err == nil {
				t.Fatal("accepted unsafe management credential")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("failed load replaced or altered an existing credential")
			}
			if kind != "directory" {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, content) {
					t.Fatal("failed load changed credential content")
				}
			}
		})
	}
}

func TestRejectUnsafeRouting(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Listen = "0.0.0.0:8787" }, func(c *Config) { c.Listen = "localhost:8787" },
		func(c *Config) { c.Backend = "ticket" }, func(c *Config) { c.VerifierURL = "https://user:secret@example.com" },
		func(c *Config) { c.RelayURL = "ws://relay.example" }, func(c *Config) { c.ZKAPI.Network = "unknown" },
		func(c *Config) { c.ZKAPI.ClientURL = "http://remote.example:8790" }, func(c *Config) { c.ZKAPI.ClientURL = "http://127.0.0.1:8790?token=secret" },
	} {
		c, _ := Default()
		mutate(&c)
		if Validate(c) == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}

// The gasless withdrawal settings: the bundler follows the exit RPC's URL
// rules and the default fee mode is wallet or payout.
func TestGaslessSettingsAreValidated(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ZKAPI.BundlerURL = "http://bundler.example" },
		func(c *Config) { c.ZKAPI.BundlerURL = "https://user:pw@bundler.example" },
		func(c *Config) { c.ZKAPI.BundlerURL = "https://bundler.example/?key=1" },
		func(c *Config) { c.ZKAPI.WithdrawalFees = "sponsor" },
	} {
		c, _ := Default()
		mutate(&c)
		if Validate(c) == nil {
			t.Fatal("unsafe gasless setting accepted")
		}
	}
	c, _ := Default()
	c.ZKAPI.BundlerURL, c.ZKAPI.WithdrawalFees = "http://127.0.0.1:4337", "payout"
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "profile")
	if err := Init(dir, c); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil || loaded.ZKAPI.BundlerURL != "http://127.0.0.1:4337" || loaded.ZKAPI.WithdrawalFees != "payout" {
		t.Fatalf("gasless settings not saved: %+v %v", loaded.ZKAPI, err)
	}
}
