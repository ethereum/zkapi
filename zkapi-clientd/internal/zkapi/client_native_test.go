package zkapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Bridge 5 (design §10.6): the companion must speak bridge 5, report the
// concession exit and its escape routes, and prove with the pinned circuit
// and setup; a bridge-4 (zkapi-v2-note-bound-v1) companion is refused.
func TestCheckRequiresExactV3NativeDeploymentIdentity(t *testing.T) {
	mutations := map[string]any{
		"deployment_id": "old-deployment", "contract_address": "0x1111111111111111111111111111111111111111",
		"chain_id": 42, "billing_asset": "erc20", "billing_unit": "micro_usd", "circuit_id": "zkapi-v2-note-bound-v1",
		"bridge_version": 4, "require_oa_org_key_source": false, "mode": "proxy",
		"exit_concession": 0, "setup_id": "mpc-1", "escape_routes_version": 0,
	}
	for _, network := range []string{"mainnet", "sepolia"} {
		for field, replacement := range mutations {
			t.Run(network+"/"+field, func(t *testing.T) {
				policy := testPolicy(network)
				policy[field] = replacement
				local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/oa/v1/status" || r.Header.Get("Authorization") != "Bearer "+testBridgeToken {
						t.Error("invalid companion check request")
					}
					_ = json.NewEncoder(w).Encode(policy)
				}))
				defer local.Close()
				client, err := New(Config{ClientURL: local.URL, BridgeToken: testBridgeToken, Network: network, HTTPClient: &http.Client{}})
				if err != nil {
					t.Fatal(err)
				}
				if err := client.Check(context.Background()); err == nil {
					t.Fatal("mismatched native policy accepted")
				}
				delete(policy, field)
				if err := client.Check(context.Background()); err == nil {
					t.Fatal("missing native policy field accepted")
				}
			})
		}
		t.Run(network+"/valid-checksummed-address", func(t *testing.T) {
			policy := testPolicy(network)
			policy["contract_address"] = strings.ToLower(policy["contract_address"].(string))
			local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(policy) }))
			defer local.Close()
			client, err := New(Config{ClientURL: local.URL, BridgeToken: testBridgeToken, Network: network, HTTPClient: &http.Client{}})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUsableVerificationAcceptsOnlyExactTrustedStates(t *testing.T) {
	for _, verified := range []bool{false, true} {
		for _, status := range []string{"", "verified", "verifier-unavailable", "pending", "unverified", "Verified", "verified ", "bypassed"} {
			for _, detail := range []string{"", "trusted_station_fallback", "trusted_station_fallback ", "recently_attested_outage", "rate_limited", "ownership_check_error", "recently_attested", "server_error", "verified"} {
				want := verified && status == "verified" && detail == ""
				if !verified && status == "verifier-unavailable" && detail == "trusted_station_fallback" {
					want = true
				}
				if got := usableVerification(verified, status, detail); got != want {
					t.Errorf("usableVerification(%v,%q,%q) = %v, want %v", verified, status, detail, got, want)
				}
			}
		}
	}
}

func TestCompleteOverridesProviderVerificationHeadersWithTrustedBridgeState(t *testing.T) {
	for _, detail := range []string{"", "trusted_station_fallback"} {
		t.Run(detail, func(t *testing.T) {
			status, verified := "verified", true
			if detail != "" {
				status, verified = "verifier-unavailable", false
			}
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer bounded-key" || r.Header.Get("Cookie") != "" || r.Header.Get("X-OA-Verification-Status") != "" {
					t.Error("unexpected inference authorization/identity")
				}
				w.Header().Add("X-OA-Verification-Status", "provider-spoof")
				w.Header().Add("X-OA-Verification-Status", "verified")
				w.Header().Add("X-OA-Verification-Detail", "provider-controlled-detail")
				_, _ = io.WriteString(w, `{"choices":[]}`)
			}))
			defer upstream.Close()
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oa/v1/lease" {
					t.Error("unexpected companion path")
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"request_limit_micro_usd":1000000}` {
					t.Error("prompt sent to proof companion")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"api_key": "bounded-key", "base_url": upstream.URL, "expires_at": time.Now().Unix() + 60, "verified": verified, "verification_status": status, "verification_detail": detail})
			}, upstream)
			response, err := client.Complete(context.Background(), json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"private"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			statuses := response.Header.Values("X-OA-Verification-Status")
			if len(statuses) != 1 || statuses[0] != status || response.Header.Get("X-OA-Verification-Detail") != detail {
				t.Fatal("provider overrode trusted verification state")
			}
			if detail == "" && len(response.Header.Values("X-OA-Verification-Detail")) != 0 {
				t.Fatal("verified response retained provider detail")
			}
		})
	}
}

func TestCompleteRejectsLegacyCompanionFallbackBeforeInference(t *testing.T) {
	for _, detail := range []string{"recently_attested_outage", "rate_limited", "ownership_check_error", "unverified_advisory"} {
		t.Run(detail, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("an unpinned legacy fallback reached inference")
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer upstream.Close()
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"api_key": "bounded-key", "base_url": upstream.URL, "expires_at": time.Now().Unix() + 60,
					"verified": false, "verification_status": "verifier-unavailable", "verification_detail": detail,
				})
			}, upstream)
			response, err := client.Complete(context.Background(), json.RawMessage(`{"model":"example/model","messages":[{"role":"user","content":"private"}]}`))
			if response != nil {
				response.Body.Close()
				t.Fatal("legacy fallback produced a provider response")
			}
			if failure, ok := err.(*Error); !ok || failure.Code != "invalid_verified_lease" {
				t.Fatalf("legacy fallback was not rejected at lease admission: %v", err)
			}
			if client.cachedLease != nil || len(client.usedLeases) != 0 {
				t.Fatal("rejected fallback entered the reuse cache")
			}
		})
	}
}
