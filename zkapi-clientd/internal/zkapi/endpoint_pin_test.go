package zkapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestCanonicalEndpointComparison(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://ethereum-rpc.publicnode.com", "https://ethereum-rpc.publicnode.com/"},
		{"https://ethereum-rpc.publicnode.com", "HTTPS://Ethereum-RPC.PublicNode.com:443"},
		{"https://zkapi-mainnet.openanonymity.ai/rpc", "https://ZKAPI-mainnet.openanonymity.ai:443/rpc/"},
		{"https://127.0.0.1:8443", "https://127.0.0.1:8443/"},
		{"https://[::1]:443/x", "https://[::1]/x"},
	} {
		if !sameEndpoint(pair[0], pair[1]) || !sameEndpoint(pair[1], pair[0]) {
			t.Errorf("%q and %q should name the same endpoint", pair[0], pair[1])
		}
	}
	for _, other := range []string{
		"http://ethereum-rpc.publicnode.com",
		"https://ethereum-rpc.publicnode.com:8443",
		"https://ethereum-rpc.publicnode.com/rpc",
		"https://ethereum-rpc.publicnode.com//",
		"https://ethereum-rpc.publicnode.com.",
		"https://ethereum-rpc.publicnode.com.evil",
		"https://evil-ethereum-rpc.publicnode.com",
		"https://user:secret@ethereum-rpc.publicnode.com",
		"https://ethereum-rpc.publicnode.com?x=1",
		"https://ethereum-rpc.publicnode.com?",
		"https://ethereum-rpc.publicnode.com#fragment",
		"https://ethereum-rpc.publicnode.com/#",
		"https://ethereum-rpc.publicnode.com:",
		"https:///rpc",
		"https:ethereum-rpc.publicnode.com",
		"ethereum-rpc.publicnode.com",
		"",
	} {
		if sameEndpoint("https://ethereum-rpc.publicnode.com", other) {
			t.Errorf("%q accepted as the packaged RPC", other)
		}
	}
	for _, rejected := range []string{"https://user@host", "https://host?q", "https://host#f", "https://", "http://host", "https://host:"} {
		if _, ok := canonicalEndpoint(rejected); ok {
			t.Errorf("%q should be rejected outright", rejected)
		}
	}
}

func TestPinnedDeploymentRequiresHTTPSEndpoints(t *testing.T) {
	for _, network := range []string{"mainnet", "sepolia"} {
		identity, raw, err := pinnedDeployment(network)
		if err != nil || identity.RPC == "" || identity.IndexerURL == "" || identity.ProtocolServerURL == "" || identity.NoteTTL != 2592000 {
			t.Fatalf("%s: packaged endpoints not parsed: %+v %v", network, identity, err)
		}
		if !identity.requiresClearanceOwnershipProof() {
			t.Fatalf("%s: a concession deployment must require clearance ownership proofs", network)
		}
		for _, mutation := range []struct{ field, value string }{
			{"rpc_url", "http://ethereum-rpc.publicnode.com"},
			{"rpc_url", ""},
			{"indexer_url", "https://user:pass@zkapi.example"},
			{"indexer_url", "https://zkapi.example/?x=1"},
			{"protocol_server_url", "https://zkapi.example/#x"},
			{"protocol_server_url", "zkapi.example"},
			{"clearance_ownership_proof", "sometimes"},
		} {
			var manifest map[string]any
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			if mutation.value == "" {
				delete(manifest, mutation.field)
			} else {
				manifest[mutation.field] = mutation.value
			}
			mutated, _ := json.Marshal(manifest)
			if _, err := parseDeploymentIdentity(network, mutated); err == nil {
				t.Errorf("%s: accepted %s=%q", network, mutation.field, mutation.value)
			}
		}
		// Only the concession vault parses, and it always requires the
		// clearance ownership proof.
		for _, capability := range []struct {
			field string
			value any
		}{
			{"vault_revision", 1},
			{"vault_revision", 2},
			{"vault_revision", -1},
			{"clearance_ownership_proof", "optional"},
		} {
			var manifest map[string]any
			_ = json.Unmarshal(raw, &manifest)
			manifest[capability.field] = capability.value
			mutated, _ := json.Marshal(manifest)
			if _, err := parseDeploymentIdentity(network, mutated); err == nil {
				t.Errorf("%s=%v accepted", capability.field, capability.value)
			}
		}
	}
}

// Every chain endpoint the companion reports is checked before any RPC read
// and before custody state can be created. Equivalent spellings pass.
func TestFundingConfigRejectsCompanionEndpointMismatchBeforeRPC(t *testing.T) {
	cases := []struct {
		field, name string
		value       func(f *addressFixture, packaged string) any
		accepted    bool
	}{
		{"demo_rpc_url", "wrong host", func(*addressFixture, string) any { return "https://ethereum-rpc.publicnode.com" }, false},
		{"demo_rpc_url", "http", func(_ *addressFixture, p string) any { return strings.Replace(p, "https://", "http://", 1) }, false},
		{"demo_rpc_url", "extra path", func(_ *addressFixture, p string) any { return p + "/rpc" }, false},
		{"demo_rpc_url", "missing", func(*addressFixture, string) any { return nil }, false},
		{"demo_rpc_url", "equivalent", func(_ *addressFixture, p string) any { return strings.ToUpper(p[:5]) + p[5:] + "/" }, true},
		{"indexer_url", "wrong host", func(*addressFixture, string) any { return "https://zkapi-mainnet.openanonymity.ai" }, false},
		{"indexer_url", "http", func(_ *addressFixture, p string) any { return strings.Replace(p, "https://", "http://", 1) }, false},
		{"indexer_url", "extra path", func(_ *addressFixture, p string) any { return p + "/v1" }, false},
		{"indexer_url", "missing", func(*addressFixture, string) any { return nil }, false},
		{"indexer_url", "equivalent", func(_ *addressFixture, p string) any { return p + "/" }, true},
		{"protocol_server_url", "wrong host", func(*addressFixture, string) any { return "https://zkapi-sepolia.openanonymity.ai" }, false},
		{"protocol_server_url", "http", func(_ *addressFixture, p string) any { return strings.Replace(p, "https://", "http://", 1) }, false},
		{"protocol_server_url", "extra path", func(_ *addressFixture, p string) any { return p + "/v2" }, false},
		{"protocol_server_url", "missing", func(*addressFixture, string) any { return nil }, false},
		{"protocol_server_url", "equivalent", func(_ *addressFixture, p string) any { return "HTTPS://ZKAPI-MAINNET.openanonymity.ai:443/" }, true},
	}
	for _, native := range []bool{true, false} {
		for _, c := range cases {
			t.Run(c.field+"/"+c.name, func(t *testing.T) {
				f := newAddressFixture(t, native)
				pins := *f.h.client.endpoints
				packaged := map[string]string{"demo_rpc_url": pins.RPC, "indexer_url": pins.Indexer, "protocol_server_url": pins.ProtocolServer}[c.field]
				upstream := f.h.client.local.Transport
				f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
					response, err := upstream.RoundTrip(r)
					if err != nil || r.URL.Path != "/funding/config" {
						return response, err
					}
					defer response.Body.Close()
					var body map[string]any
					if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if value := c.value(f, packaged); value == nil {
						delete(body, c.field)
					} else {
						body[c.field] = value
					}
					return withdrawalJSONResponse(r, 200, body), nil
				})
				status, err := f.h.Address(context.Background())
				if c.accepted {
					if err != nil || status.Address == "" {
						t.Fatalf("equivalent endpoint spelling rejected: %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "chain endpoints do not match") {
					t.Fatalf("mismatched %s accepted: %v", c.field, err)
				}
				if len(f.rpcCalls) != 0 || f.snapshotReads != 0 || f.rootReads != 0 {
					t.Fatal("an RPC or indexer read happened before the endpoint check")
				}
				if _, err := os.Stat(f.h.addressStatePath()); !os.IsNotExist(err) {
					t.Fatal("mismatched endpoints created custody state")
				}
			})
		}
	}
}

// The companion's spelling is only a tripwire. Even an equivalent string is
// never used: every request goes to the packaged endpoint exactly.
func TestFundingUsesPackagedRPCInsteadOfCompanionString(t *testing.T) {
	f := newAddressFixture(t, true)
	pins := f.h.client.endpoints
	pins.RPC += "/rpc" // The fixture RPC answers on any path.
	var paths []string
	upstream := f.h.client.inference.Transport
	f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			paths = append(paths, r.URL.Path)
		}
		return upstream.RoundTrip(r)
	})
	local := f.h.client.local.Transport
	f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		response, err := local.RoundTrip(r)
		if err != nil || r.URL.Path != "/funding/config" {
			return response, err
		}
		defer response.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(response.Body).Decode(&body)
		body["demo_rpc_url"] = "HTTPS" + strings.TrimPrefix(pins.RPC, "https") + "/"
		body["indexer_url"] = "HTTPS" + strings.TrimPrefix(pins.Indexer, "https") + "/"
		return withdrawalJSONResponse(r, 200, body), nil
	})
	config, err := f.h.config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if config.RPC != pins.RPC || config.Indexer != pins.Indexer {
		t.Fatalf("funding used the companion's endpoint strings: %q %q", config.RPC, config.Indexer)
	}
	if _, err := f.h.Address(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no RPC request observed")
	}
	for _, path := range paths {
		if path != "/rpc" {
			t.Fatalf("request sent to %q instead of the packaged endpoint path", path)
		}
	}
}

func TestVaultNoteDecodingIsStrict(t *testing.T) {
	commitment := strings.Repeat("ab", 32)
	word := func(value string) string { return strings.Repeat("0", 64-len(value)) + value }
	valid := "0x" + commitment + word("186a0") + word("6a6b1a00") + word("1")
	note, err := decodeVaultNote(valid)
	if err != nil || note.Commitment != "0x"+commitment || note.Amount != 100000 || note.ExpiryTs != 0x6a6b1a00 || note.Status != noteActive {
		t.Fatalf("valid note rejected: %+v %v", note, err)
	}
	if note, err := decodeVaultNote("0x" + strings.Repeat("0", 256)); err != nil || note.Status != noteUninitialized {
		t.Fatalf("uninitialized note rejected: %+v %v", note, err)
	}
	for name, encoded := range map[string]string{
		"short":               valid[:len(valid)-2],
		"long":                valid + "00",
		"no prefix":           "00" + valid[2:],
		"not hex":             "0x" + commitment + word("186a0") + word("6a6b1a00") + word("zz"),
		"amount high bytes":   "0x" + commitment + "1" + word("186a0")[1:] + word("6a6b1a00") + word("1"),
		"amount above 2^53-1": "0x" + commitment + word("20000000000000") + word("6a6b1a00") + word("1"),
		"expiry high bytes":   "0x" + commitment + word("186a0") + "1" + word("6a6b1a00")[1:] + word("1"),
		"status high bytes":   "0x" + commitment + word("186a0") + word("6a6b1a00") + word("101"),
		"status 4":            "0x" + commitment + word("186a0") + word("6a6b1a00") + word("4"),
	} {
		if _, err := decodeVaultNote(encoded); err == nil {
			t.Errorf("%s note state accepted", name)
		}
	}
}
