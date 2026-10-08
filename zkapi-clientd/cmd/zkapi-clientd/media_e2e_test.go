package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// Exercise the loopback API, error mapping and wallet client together with a
// fake companion and a fake OpenRouter, without any real wallet or funds.
func TestMediaRoutesEndToEndWithoutFunds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var unfunded atomic.Bool
	var leases, settlements atomic.Int32
	var mu sync.Mutex
	var bridgeBodies []string
	videoStatus := "pending"
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bridgeBodies = append(bridgeBodies, string(body))
		mu.Unlock()
		switch r.URL.Path {
		case "/oa/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"bridge_version": 4, "chain_id": 1, "mode": "direct_openrouter", "require_oa_org_key_source": true, "deployment_id": "zkapi-native-eth-mainnet-note-bound-v1-fresh-20260930", "contract_address": "0x4386FDbdA35D995beB3BF8625118Ec5982ec81fe", "billing_asset": "native_eth", "billing_unit": "gwei", "circuit_id": "zkapi-v2-note-bound-v1"})
		case "/oa/v1/lease":
			if unfunded.Load() {
				w.WriteHeader(http.StatusPaymentRequired)
				_, _ = io.WriteString(w, `{"error":{"code":"insufficient_balance"}}`)
				return
			}
			n := leases.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"api_key": fmt.Sprintf("media-e2e-key-%d", n), "base_url": zkapi.DefaultInferenceBaseURL, "expires_at": time.Now().Unix() + 300, "verified": true, "verification_status": "verified"})
		case "/wallet/settle":
			settlements.Add(1)
			_, _ = io.WriteString(w, `{"pending_request":false}`)
		default:
			t.Errorf("unexpected companion route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer bridge.Close()
	remote := &http.Client{Transport: inferenceTestTransport(func(r *http.Request) (*http.Response, error) {
		header := http.Header{"Content-Type": {"application/json"}}
		reply := func(status int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		if r.URL.Host == "openrouter.ai" && r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer media-e2e-key-") {
			t.Error("provider request without a lease key")
		}
		switch r.URL.Path {
		case "/chat/model-tickets":
			return reply(200, `{"test/model":1,"embed/model":1,"video/model":100}`)
		case "/chat/pinned-models":
			return reply(200, `{"disabled_models":[]}`)
		case "/api/v1/embeddings/models":
			return reply(200, `{"data":[{"id":"embed/model"}]}`)
		case "/api/v1/videos/models":
			return reply(200, `{"data":[{"id":"video/model"}]}`)
		case "/api/v1/embeddings":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "strip-me") {
				t.Error("identity metadata reached the provider")
			}
			return reply(200, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5]}],"model":"embed/model"}`)
		case "/api/v1/videos":
			return reply(202, `{"id":"gen-vid-1-abcdefghijklmnopqrst","status":"pending"}`)
		case "/api/v1/videos/gen-vid-1-abcdefghijklmnopqrst":
			mu.Lock()
			status := videoStatus
			mu.Unlock()
			return reply(200, `{"id":"gen-vid-1-abcdefghijklmnopqrst","status":"`+status+`","unsigned_urls":["x"],"usage":{"cost":6}}`)
		case "/api/v1/videos/gen-vid-1-abcdefghijklmnopqrst/content":
			header.Set("Content-Type", "video/mp4")
			return reply(200, "mp4")
		}
		return nil, fmt.Errorf("unexpected fixture request %s", r.URL.Path)
	})}
	wallet, err := zkapi.New(zkapi.Config{ClientURL: bridge.URL, BridgeToken: strings.Repeat("b", 32), HTTPClient: remote})
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.New(zkInference{wallet}, strings.Repeat("a", 32), 2)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	var logMu sync.Mutex
	logger := log.New(writerFunc(func(p []byte) (int, error) { logMu.Lock(); defer logMu.Unlock(); return logs.Write(p) }), "", 0)
	local := httptest.NewServer(server.LogRequests(api, logger))
	defer local.Close()
	settlementDone := make(chan struct{})
	go func() { defer close(settlementDone); wallet.RunSettlement(ctx) }()
	defer func() { cancel(); <-settlementDone }()
	call := func(method, path, body string) (int, string) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, local.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := local.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}

	if status, body := call(http.MethodGet, "/v1/videos/models", ""); status != 200 || !strings.Contains(body, `"oa_request_limit_micro_usd":6000000`) {
		t.Fatalf("video models %d %s", status, body)
	}
	if status, body := call(http.MethodPost, "/v1/embeddings", `{"model":"embed/model","input":"private text","user":"strip-me"}`); status != 200 || !strings.Contains(body, "embedding") {
		t.Fatalf("embeddings %d %s", status, body)
	}
	if status, body := call(http.MethodPost, "/v1/embeddings", `{"model":"test/model","input":"private text"}`); status != 400 || !strings.Contains(body, "model_not_enabled") {
		t.Fatalf("chat model on embeddings %d %s", status, body)
	}
	unfunded.Store(true)
	if status, body := call(http.MethodPost, "/v1/videos", `{"model":"video/model","prompt":"private prompt"}`); status != 402 || !strings.Contains(body, "funding_required") {
		t.Fatalf("unfunded video %d %s", status, body)
	}
	unfunded.Store(false)
	status, body := call(http.MethodPost, "/v1/videos", `{"model":"video/model","prompt":"private prompt","callback_url":"https://strip-me.example"}`)
	var job struct {
		ID string `json:"id"`
	}
	if status != 202 || json.Unmarshal([]byte(body), &job) != nil || !zkapi.ValidVideoJobID(job.ID) {
		t.Fatalf("video submit %d %s", status, body)
	}
	if status, body := call(http.MethodGet, "/v1/videos/"+job.ID+"/content", ""); status != 409 || !strings.Contains(body, "video_not_ready") {
		t.Fatalf("early content %d %s", status, body)
	}
	mu.Lock()
	videoStatus = "completed"
	mu.Unlock()
	if status, body := call(http.MethodGet, "/v1/videos/"+job.ID, ""); status != 200 || !strings.Contains(body, `"/v1/videos/`+job.ID+`/content?index=0"`) {
		t.Fatalf("poll %d %s", status, body)
	}
	if status, body := call(http.MethodGet, "/v1/videos/"+job.ID+"/content", ""); status != 200 || body != "mp4" {
		t.Fatalf("content %d %s", status, body)
	}
	if status, body := call(http.MethodGet, "/v1/videos/"+job.ID+"/content", ""); status != 410 {
		t.Fatalf("content after release %d %s", status, body)
	}
	mu.Lock()
	for _, sent := range bridgeBodies {
		if strings.Contains(sent, "private") || strings.Contains(sent, "model") {
			t.Fatalf("request data crossed the wallet bridge: %s", sent)
		}
	}
	mu.Unlock()
	logMu.Lock()
	defer logMu.Unlock()
	for _, secret := range []string{"private", job.ID, "gen-vid", "media-e2e-key", "strip-me"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log exposed %q:\n%s", secret, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "route=/v1/videos/{id}/content") {
		t.Fatalf("missing fixed route label:\n%s", logs.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
