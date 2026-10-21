package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTestnetPasswordAuthenticationAndRejection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/auth" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected authentication request")
		}
		if r.Header.Get(TestnetPasswordHeader) != "shared secret" {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, "private remote failure details")
			return
		}
		_, _ = io.WriteString(w, `{"authenticated":true}`)
	}))
	defer server.Close()
	for _, password := range []string{"", "wrong", "shared secret"} {
		err := checkTestnetPasswordURL(context.Background(), server.URL+"/v2/auth", password, server.Client())
		if password == "shared secret" {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		var auth *Error
		if !errors.As(err, &auth) || auth.Code != "testnet_password_required" || strings.Contains(err.Error(), "private remote") {
			t.Fatalf("unsafe rejection: %v", err)
		}
	}
	if err := CheckTestnetPassword(context.Background(), "mainnet", "shared secret", nil); err != nil {
		t.Fatal("mainnet should not authenticate", err)
	}
}

func TestTestnetPasswordNeverFollowsRedirect(t *testing.T) {
	leaked := false
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer server.Close()
	if err := checkTestnetPasswordURL(context.Background(), server.URL, "shared secret", server.Client()); err == nil || leaked {
		t.Fatal("redirect accepted or credential leaked")
	}
}

func TestCompanionPasswordOnlyReachesSepoliaEnvironment(t *testing.T) {
	if got := companionTestnetEnvironment("mainnet", "secret"); len(got) != 0 {
		t.Fatal("mainnet received password")
	}
	if got := companionTestnetEnvironment("sepolia", "secret"); len(got) != 1 || got[0] != "OA_ZKAPI_TESTNET_PASSWORD=secret" {
		t.Fatal("Sepolia lost password")
	}
}

func TestCompanionAuthenticationFailureIsActionableAndRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":{"code":"testnet_password_required","message":"private server details"}}`)
	}))
	defer server.Close()
	client, err := New(Config{ClientURL: server.URL, BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.request(context.Background(), http.MethodGet, "/oa/v1/billing/quote", nil)
	var rejected *Error
	if !errors.As(err, &rejected) || rejected.Code != "testnet_password_required" || !strings.Contains(err.Error(), "zkapi-clientd config") || strings.Contains(err.Error(), "private server") {
		t.Fatalf("authentication error was hidden or leaked: %v", err)
	}
}

func TestCompanionWithoutPasswordSupportIsRejectedBeforeFunding(t *testing.T) {
	policy := testPolicy("mainnet")
	policy["bridge_version"] = 3
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(policy) }))
	defer server.Close()
	client, err := New(Config{ClientURL: server.URL, BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	var rejected *Error
	if err := client.Check(context.Background()); !errors.As(err, &rejected) || rejected.Code != "companion_policy_mismatch" {
		t.Fatalf("old companion was not rejected: %v", err)
	}
}

// The companion refuses a withdrawal at a note state with an unsettled
// transmitted request (on a vault below revision 2) with its own code; it
// crosses the boundary with actionable guidance and without the companion's
// diagnostic message.
func TestUnsettledRequestStateIsActionableAndRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"unsettled_request_state","message":"private protocol state"}}`)
	}))
	defer server.Close()
	client, err := New(Config{ClientURL: server.URL, BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.request(context.Background(), http.MethodPost, "/oa/v1/withdraw/prepare", []byte(`{}`))
	var refused *Error
	if !errors.As(err, &refused) || refused.Code != "unsettled_request_state" || !strings.Contains(err.Error(), "chat request") || !strings.Contains(err.Error(), "choose withdraw again") || strings.Contains(err.Error(), "private protocol") {
		t.Fatalf("the unsettled-state refusal was hidden or leaked: %v", err)
	}
}

// A state the server already holds a clearance for is refused with its own
// code, which crosses the boundary so the guided withdrawal can ask for the
// owner's acknowledgement.
func TestClearanceReservedUnsettledStateIsActionableAndRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"unsettled_clearance_reserved","message":"private protocol state"}}`)
	}))
	defer server.Close()
	client, err := New(Config{ClientURL: server.URL, BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.request(context.Background(), http.MethodPost, "/oa/v1/withdraw/prepare", []byte(`{}`))
	var refused *Error
	if !errors.As(err, &refused) || refused.Code != "unsettled_clearance_reserved" || !strings.Contains(err.Error(), "choose withdraw to review the risk") || strings.Contains(err.Error(), "private protocol") {
		t.Fatalf("the clearance-reserved refusal was hidden or leaked: %v", err)
	}
}

// A chat at a note state the server holds a clearance for (as after the
// operator released it) can never settle it. The companion's code crosses the
// boundary with the remedy, never with its diagnostic message, and is not
// treated as a settlement to wait for.
func TestClearanceReservedStateStopsTheChatWithTheRemedy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"clearance_reserved_state","message":"private protocol state"}}`)
	}))
	defer server.Close()
	client, err := New(Config{ClientURL: server.URL, BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.request(context.Background(), http.MethodPost, "/oa/v1/lease", []byte(`{"request_limit_micro_usd":1000000}`))
	var refused *Error
	if !errors.As(err, &refused) || refused.Code != "clearance_reserved_state" || isPendingSettlement(err) || !strings.Contains(err.Error(), "choose withdraw") || strings.Contains(err.Error(), "private protocol") {
		t.Fatalf("the clearance-reserved state was hidden, leaked or polled: %v", err)
	}
}

// receipt_journal_missing carries the nullifier the operator needs, and only
// in the server's canonical form; the companion's message never crosses.
func TestReceiptJournalMissingCarriesOnlyACanonicalNullifier(t *testing.T) {
	for nullifier, forwarded := range map[string]bool{"0x1234ab": true, "0x0": true, "0x01234": false, "1234": false, "0xABCD": false, "0x" + strings.Repeat("f", 65): false, "0x12 private": false} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "receipt_journal_missing", "message": "private protocol state", "nullifier": nullifier}})
		}))
		client, err := New(Config{ClientURL: server.URL, BridgeToken: testBridgeToken, HTTPClient: http.DefaultClient})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.request(context.Background(), http.MethodPost, "/oa/v1/withdraw/prepare", []byte(`{}`))
		server.Close()
		var refused *Error
		var missing *ReceiptJournalMissingError
		if !errors.As(err, &refused) || refused.Code != "receipt_journal_missing" || strings.Contains(err.Error(), "private") || !strings.Contains(err.Error(), "Contact the zkAPI operator") {
			t.Fatalf("%q: %v", nullifier, err)
		}
		if errors.As(err, &missing) != forwarded || strings.Contains(err.Error(), nullifier) != forwarded {
			t.Fatalf("%q forwarded=%v: %v", nullifier, forwarded, err)
		}
	}
}
