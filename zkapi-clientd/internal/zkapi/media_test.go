package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

const (
	testVideoPrompt     = "private video prompt"
	testEmbeddingInput  = "private embedding input"
	testUpstreamVideoID = "gen-vid-1789480874-Ab3dEf9hIjKlMnOpQrSt"
)

// mediaFixture is a fake wallet companion plus a fake OpenRouter that records
// which key each provider call used. All I/O stays inside a synctest bubble
// when the test uses one.
type mediaFixture struct {
	t           *testing.T
	client      *Client
	pending     atomic.Bool
	leases      atomic.Int32
	issued      atomic.Int32
	settlements atomic.Int32
	leaseStatus atomic.Int32 // non-zero: companion lease error status
	expires     time.Duration

	mu          sync.Mutex
	limits      []uint64
	calls       []string // "METHOD path key"
	videoStatus string
	videoURLs   []string
	submitCode  int
	contentBody string
	companion   []string // raw companion request bodies
}

func newMediaFixture(t *testing.T, window time.Duration) *mediaFixture {
	t.Helper()
	f := &mediaFixture{t: t, expires: 5 * time.Minute, videoStatus: "pending", submitCode: http.StatusAccepted, contentBody: "mp4-bytes"}
	client, err := New(Config{
		ClientURL: "http://127.0.0.1:43134", BridgeToken: testBridgeToken,
		InferenceBaseURL: "https://provider.invalid/api/v1", KeyReuseWindow: window,
		HTTPClient: &http.Client{Transport: budgetTransport(f.provider)},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.client = client
	client.settlementPoll = time.Second
	client.local.Transport = budgetTransport(f.companionHandler)
	addTestModelPolicy(client, map[string]uint64{"example/model": 1, "embed/model": 1, "video/model": 25, "video/unlisted": 1}, []string{"video/disabled"})
	return f
}

func (f *mediaFixture) companionHandler(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.companion = append(f.companion, string(body))
	f.mu.Unlock()
	switch r.URL.Path {
	case "/oa/v1/status":
		data, _ := json.Marshal(testPolicy("mainnet"))
		return automaticSettlementResponse(r, http.StatusOK, string(data)), nil
	case "/oa/v1/lease":
		f.leases.Add(1)
		if status := f.leaseStatus.Load(); status != 0 {
			return automaticSettlementResponse(r, int(status), `{"error":{"code":"insufficient_balance"}}`), nil
		}
		if f.pending.Load() {
			return automaticSettlementResponse(r, http.StatusConflict, `{"error":{"code":"lease_pending"}}`), nil
		}
		var request struct {
			Limit uint64 `json:"request_limit_micro_usd"`
		}
		_ = json.Unmarshal(body, &request)
		f.mu.Lock()
		f.limits = append(f.limits, request.Limit)
		f.mu.Unlock()
		f.pending.Store(true)
		data, _ := json.Marshal(map[string]any{
			"api_key":  fmt.Sprintf("media-key-%d", f.issued.Add(1)),
			"base_url": f.client.config.InferenceBaseURL, "expires_at": time.Now().Add(f.expires).Unix(),
			"verified": true, "verification_status": "verified",
		})
		return automaticSettlementResponse(r, http.StatusOK, string(data)), nil
	case "/wallet/settle":
		f.settlements.Add(1)
		f.pending.Store(false)
		return automaticSettlementResponse(r, http.StatusOK, `{"pending_request":false}`), nil
	}
	f.t.Errorf("unexpected companion path %s", r.URL.Path)
	return automaticSettlementResponse(r, http.StatusNotFound, `{}`), nil
}

func (f *mediaFixture) provider(r *http.Request) (*http.Response, error) {
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Host+r.URL.RequestURI()+" "+key)
	status, urls, submit, content := f.videoStatus, f.videoURLs, f.submitCode, f.contentBody
	f.mu.Unlock()
	if r.URL.Host != "provider.invalid" {
		f.t.Errorf("request left the inference origin: %s", r.URL.Host)
		return automaticSettlementResponse(r, http.StatusForbidden, `{}`), nil
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	json200 := func(body string) (*http.Response, error) {
		res := automaticSettlementResponse(r, http.StatusOK, body)
		res.Header.Set("Content-Type", "application/json")
		return res, nil
	}
	switch {
	case r.Method == http.MethodGet && path == "/models":
		return json200(`{"data":[{"id":"example/model"}]}`)
	case r.Method == http.MethodGet && path == "/embeddings/models":
		return json200(`{"data":[{"id":"embed/model"},{"id":"embed/unpriced"}]}`)
	case r.Method == http.MethodGet && path == "/videos/models":
		return json200(`{"data":[{"id":"video/model"},{"id":"video/disabled"},{"id":"video/unpriced"}]}`)
	case r.Method == http.MethodPost && path == "/chat/completions":
		return json200(`{"choices":[]}`)
	case r.Method == http.MethodPost && path == "/embeddings":
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), testEmbeddingInput) {
			f.t.Error("embedding input did not reach the provider unchanged")
		}
		return json200(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1]}],"model":"embed/model"}`)
	case r.Method == http.MethodPost && path == "/videos":
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), testVideoPrompt) {
			f.t.Error("video prompt did not reach the provider unchanged")
		}
		res := automaticSettlementResponse(r, submit, `{"id":"`+testUpstreamVideoID+`","polling_url":"https://provider.invalid/api/v1/videos/`+testUpstreamVideoID+`","status":"pending"}`)
		res.Header.Set("Content-Type", "application/json")
		return res, nil
	case r.Method == http.MethodGet && path == "/videos/"+testUpstreamVideoID:
		data, _ := json.Marshal(map[string]any{"id": testUpstreamVideoID, "status": status, "unsigned_urls": urls, "usage": map[string]any{"cost": 0.4, "is_byok": false}})
		return json200(string(data))
	case r.Method == http.MethodGet && path == "/videos/"+testUpstreamVideoID+"/content":
		res := automaticSettlementResponse(r, http.StatusOK, content)
		res.Header.Set("Content-Type", "video/mp4")
		return res, nil
	}
	f.t.Errorf("unexpected provider call %s %s", r.Method, r.URL.Path)
	return automaticSettlementResponse(r, http.StatusNotFound, `{}`), nil
}

func (f *mediaFixture) setVideo(status string, urls ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.videoStatus, f.videoURLs = status, urls
}

// providerCalls returns recorded calls whose "METHOD path" starts with prefix.
func (f *mediaFixture) providerCalls(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var matched []string
	for _, call := range f.calls {
		if strings.HasPrefix(call, prefix) {
			matched = append(matched, call)
		}
	}
	return matched
}

func (f *mediaFixture) leaseLimits() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.limits...)
}

func (f *mediaFixture) assertNoPromptCrossedCompanion() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, body := range f.companion {
		if strings.Contains(body, "private") || strings.Contains(body, "model") {
			f.t.Fatalf("request data crossed the wallet bridge: %q", body)
		}
	}
}

func videoBody() json.RawMessage {
	return json.RawMessage(`{"model":"video/model","prompt":"` + testVideoPrompt + `","duration":8}`)
}

func readJSON(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	defer response.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func errorCode(err error) string {
	var remote *Error
	if errors.As(err, &remote) {
		return remote.Code
	}
	return ""
}

func TestEmbeddingsUseALeaseFromTheModelPolicy(t *testing.T) {
	f := newMediaFixture(t, 0)
	body := json.RawMessage(`{"model":"embed/model","input":"` + testEmbeddingInput + `"}`)
	response, err := f.client.Embeddings(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	result := readJSON(t, response)
	if result["object"] != "list" || response.Header.Get("X-OA-Verification-Status") != "verified" {
		t.Fatalf("unexpected embeddings response %v", result)
	}
	if limits := f.leaseLimits(); len(limits) != 1 || limits[0] != 1_000_000 {
		t.Fatalf("embeddings lease used allowance %v", limits)
	}
	if calls := f.providerCalls("POST provider.invalid/api/v1/embeddings"); len(calls) != 1 || !strings.HasSuffix(calls[0], " media-key-1") {
		t.Fatalf("embeddings did not use the issued key: %v", calls)
	}
	f.assertNoPromptCrossedCompanion()
}

func TestMediaEndpointsRejectModelsTheIssuerHasNotEnabled(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(*Client) error
	}{
		// A chat model with a policy tier is not an embeddings model.
		{"chat model on embeddings", func(c *Client) error {
			_, err := c.Embeddings(context.Background(), json.RawMessage(`{"model":"example/model","input":"x"}`))
			return err
		}},
		// In the provider catalog, but without a policy tier: no fallback budget.
		{"unpriced embeddings model", func(c *Client) error {
			_, err := c.Embeddings(context.Background(), json.RawMessage(`{"model":"embed/unpriced","input":"x"}`))
			return err
		}},
		{"unpriced video model", func(c *Client) error {
			_, err := c.SubmitVideo(context.Background(), json.RawMessage(`{"model":"video/unpriced","prompt":"x"}`))
			return err
		}},
		{"disabled video model", func(c *Client) error {
			_, err := c.SubmitVideo(context.Background(), json.RawMessage(`{"model":"video/disabled","prompt":"x"}`))
			return err
		}},
		// A policy tier without a provider video catalog entry.
		{"policy model missing from video catalog", func(c *Client) error {
			_, err := c.SubmitVideo(context.Background(), json.RawMessage(`{"model":"video/unlisted","prompt":"x"}`))
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMediaFixture(t, time.Minute)
			if err := test.call(f.client); errorCode(err) != "model_not_enabled" {
				t.Fatalf("got %v, want model_not_enabled", err)
			}
			if f.leases.Load() != 0 || len(f.providerCalls("POST")) != 0 {
				t.Fatal("a model the issuer has not enabled acquired a lease or reached the provider")
			}
		})
	}
}

func TestMediaModelsListOnlyPolicyEnabledCatalogModels(t *testing.T) {
	f := newMediaFixture(t, 0)
	for kind, want := range map[string]string{MediaEmbeddings: "embed/model", MediaVideos: "video/model"} {
		data, err := f.client.MediaModels(context.Background(), kind)
		if err != nil {
			t.Fatal(err)
		}
		var list struct {
			Data []struct {
				ID    string `json:"id"`
				Limit uint64 `json:"oa_request_limit_micro_usd"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &list) != nil || len(list.Data) != 1 || list.Data[0].ID != want || list.Data[0].Limit == 0 {
			t.Fatalf("%s models = %s", kind, data)
		}
	}
	if f.leases.Load() != 0 {
		t.Fatal("listing models acquired a lease")
	}
}

func TestMediaFundingRequiredNeverReachesProvider(t *testing.T) {
	f := newMediaFixture(t, 0)
	f.leaseStatus.Store(http.StatusPaymentRequired)
	_, err := f.client.Embeddings(context.Background(), json.RawMessage(`{"model":"embed/model","input":"x"}`))
	var remote *Error
	if !errors.As(err, &remote) || remote.Status != http.StatusPaymentRequired {
		t.Fatalf("got %v, want a 402 wallet error", err)
	}
	_, err = f.client.SubmitVideo(context.Background(), videoBody())
	if !errors.As(err, &remote) || remote.Status != http.StatusPaymentRequired {
		t.Fatalf("got %v, want a 402 wallet error", err)
	}
	if len(f.providerCalls("POST")) != 0 {
		t.Fatal("an unfunded request reached the provider")
	}
}

func TestVideoJobHoldsItsLeaseUntilContentIsDownloaded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		submitted, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		job := readJSON(t, submitted)
		id, _ := job["id"].(string)
		if submitted.StatusCode != http.StatusAccepted || !ValidVideoJobID(id) || job["status"] != "pending" || job["polling_url"] != "/v1/videos/"+id {
			t.Fatalf("unexpected submit response %v", job)
		}
		if strings.Contains(fmt.Sprint(job), testUpstreamVideoID) || strings.Contains(fmt.Sprint(job), "media-key") {
			t.Fatal("local job view exposed the provider job ID or key")
		}
		if limits := f.leaseLimits(); len(limits) != 1 || limits[0] != 4_500_000 {
			t.Fatalf("video lease used allowance %v", limits)
		}

		// Chat waits while the job owns the wallet's lease.
		chatDone := make(chan error, 1)
		go func() {
			response, err := f.client.Complete(context.Background(), queuedTestPrompt)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			chatDone <- err
		}()
		for range 3 {
			time.Sleep(40 * time.Second)
			polled, err := f.client.VideoStatus(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if status := readJSON(t, polled)["status"]; status != "pending" {
				t.Fatalf("status %v", status)
			}
		}
		synctest.Wait()
		if f.settlements.Load() != 0 || len(f.providerCalls("POST provider.invalid/api/v1/chat")) != 0 {
			t.Fatal("the job's key was settled or shared while the job was running")
		}
		f.setVideo("completed", "https://provider.invalid/api/v1/videos/"+testUpstreamVideoID+"/content?index=0")
		polled, err := f.client.VideoStatus(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		done := readJSON(t, polled)
		if urls, _ := done["unsigned_urls"].([]any); done["status"] != "completed" || len(urls) != 1 || urls[0] != "/v1/videos/"+id+"/content?index=0" {
			t.Fatalf("unexpected completed view %v", done)
		}
		synctest.Wait()
		if f.settlements.Load() != 0 {
			t.Fatal("key settled before its content was downloaded")
		}
		content, err := f.client.VideoContent(context.Background(), id, 0)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(content.Body)
		content.Body.Close()
		if string(data) != "mp4-bytes" || content.Header.Get("Content-Type") != "video/mp4" {
			t.Fatal("content was not streamed unchanged")
		}
		for _, call := range f.providerCalls("GET provider.invalid/api/v1/videos/" + testUpstreamVideoID) {
			if !strings.HasSuffix(call, " media-key-1") {
				t.Fatalf("job call did not use the job's key: %s", call)
			}
		}
		if err := <-chatDone; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if f.settlements.Load() != 1 || f.issued.Load() != 2 {
			t.Fatalf("job key was not settled before chat took a fresh key: settlements=%d issued=%d", f.settlements.Load(), f.issued.Load())
		}
		if _, err := f.client.VideoContent(context.Background(), id, 0); errorCode(err) != "video_content_expired" {
			t.Fatalf("download after release: %v", err)
		}
		polled, err = f.client.VideoStatus(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if view := readJSON(t, polled); view["status"] != "completed" || view["oa_lease_expires_at"] != nil {
			t.Fatalf("released job view %v", view)
		}
		f.assertNoPromptCrossedCompanion()
	})
}

func TestVideoJobFailureReleasesLeaseForSettlement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		submitted, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		id := readJSON(t, submitted)["id"].(string)
		f.setVideo("failed")
		polled, err := f.client.VideoStatus(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if status := readJSON(t, polled)["status"]; status != "failed" {
			t.Fatalf("status %v", status)
		}
		synctest.Wait()
		if f.settlements.Load() != 1 {
			t.Fatal("failed job did not release its key for settlement")
		}
		if _, err := f.client.VideoContent(context.Background(), id, 0); errorCode(err) != "video_not_ready" {
			t.Fatalf("content of a failed job: %v", err)
		}
		polls := len(f.providerCalls("GET provider.invalid/api/v1/videos/" + testUpstreamVideoID))
		if _, err := f.client.VideoStatus(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		if len(f.providerCalls("GET provider.invalid/api/v1/videos/"+testUpstreamVideoID)) != polls {
			t.Fatal("a released job used its retired key")
		}
	})
}

func TestVideoJobExpiresWithItsLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		f.expires = 4*time.Minute + 30*time.Second
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		submitted, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		id := readJSON(t, submitted)["id"].(string)
		time.Sleep(4*time.Minute + 28*time.Second)
		synctest.Wait()
		if f.settlements.Load() != 0 {
			t.Fatal("job released before its lease ended")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if f.settlements.Load() != 1 {
			t.Fatal("expired job kept the wallet's lease")
		}
		polled, err := f.client.VideoStatus(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if view := readJSON(t, polled); view["status"] != "expired" || view["error"] == nil {
			t.Fatalf("expired view %v", view)
		}
	})
}

func TestIncompleteDownloadKeepsLeaseUntilExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		f.expires = 2 * time.Minute
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		submitted, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		id := readJSON(t, submitted)["id"].(string)
		f.setVideo("completed", "a", "b")
		if _, err := f.client.VideoStatus(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		first, err := f.client.VideoContent(context.Background(), id, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(first.Body)
		first.Body.Close()
		second, err := f.client.VideoContent(context.Background(), id, 1)
		if err != nil {
			t.Fatal(err)
		}
		second.Body.Close() // closed before EOF: not downloaded
		if _, err := f.client.VideoContent(context.Background(), id, 2); errorCode(err) != "video_content_not_found" {
			t.Fatalf("out-of-range output: %v", err)
		}
		synctest.Wait()
		if f.settlements.Load() != 0 {
			t.Fatal("released before every output was downloaded")
		}
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if f.settlements.Load() != 1 {
			t.Fatal("lease expiry did not release an incompletely downloaded job")
		}
		if _, err := f.client.VideoContent(context.Background(), id, 1); errorCode(err) != "video_content_expired" {
			t.Fatalf("download after expiry: %v", err)
		}
	})
}

func TestOnlyOneVideoJobHoldsTheLeaseAndDeleteNeedsAFinishedJob(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		submitted, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		id := readJSON(t, submitted)["id"].(string)
		if _, err := f.client.SubmitVideo(context.Background(), videoBody()); errorCode(err) != "video_job_active" {
			t.Fatalf("second job: %v", err)
		}
		if f.leases.Load() != 1 {
			t.Fatal("second job requested a lease")
		}
		if _, err := f.client.DeleteVideo(context.Background(), id); errorCode(err) != "video_job_in_progress" {
			t.Fatalf("delete of a running job: %v", err)
		}
		f.setVideo("completed")
		if _, err := f.client.VideoStatus(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		deleted, err := f.client.DeleteVideo(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if readJSON(t, deleted)["deleted"] != true {
			t.Fatal("delete did not confirm")
		}
		synctest.Wait()
		if f.settlements.Load() != 1 {
			t.Fatal("deleting a finished job did not release its key")
		}
		if _, err := f.client.VideoStatus(context.Background(), id); errorCode(err) != "video_job_not_found" {
			t.Fatalf("deleted job: %v", err)
		}
		for _, bad := range []string{"", "vidjob-", "vidjob-XYZ", testUpstreamVideoID, "vidjob-" + strings.Repeat("A", 32)} {
			if _, err := f.client.VideoStatus(context.Background(), bad); errorCode(err) != "video_job_not_found" {
				t.Fatalf("id %q: %v", bad, err)
			}
		}
	})
}

func TestConcurrentVideoSubmissionsStartOneJob(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		// Another request owns the slot, so both submissions arrive while it
		// is busy and neither has a job yet.
		f.client.requestSlot <- struct{}{}
		results := make(chan error, 2)
		for range 2 {
			go func() {
				response, err := f.client.SubmitVideo(context.Background(), videoBody())
				if err == nil {
					response.Body.Close()
				}
				results <- err
			}()
		}
		synctest.Wait()
		<-f.client.requestSlot
		synctest.Wait()
		var started, refused int
		for range 2 {
			select {
			case err := <-results:
				switch {
				case err == nil:
					started++
				case errorCode(err) == "video_job_active":
					refused++
				default:
					t.Fatalf("submission: %v", err)
				}
			default:
				t.Fatal("a submission is still waiting behind the first job")
			}
		}
		if started != 1 || refused != 1 {
			t.Fatalf("started=%d refused=%d", started, refused)
		}
		if calls := f.providerCalls("POST provider.invalid/api/v1/videos"); len(calls) != 1 {
			t.Fatalf("provider submissions %v", calls)
		}
	})
}

func TestVideoJobTakesAFreshKeyNotTheReusableChatKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		drainReuseResponse(t, f.client, context.Background(), queuedTestPrompt)
		submitted, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		submitted.Body.Close()
		if f.issued.Load() != 2 || f.settlements.Load() != 1 {
			t.Fatalf("video reused or skipped retiring the chat key: issued=%d settlements=%d", f.issued.Load(), f.settlements.Load())
		}
		if calls := f.providerCalls("POST provider.invalid/api/v1/videos"); len(calls) != 1 || !strings.HasSuffix(calls[0], " media-key-2") {
			t.Fatalf("video submit key %v", calls)
		}
	})
}

func TestRejectedVideoSubmissionReleasesItsKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newMediaFixture(t, time.Minute)
		f.submitCode = http.StatusBadRequest
		cancel, _ := startAutomaticSettlement(t, f.client)
		defer cancel()
		response, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", response.StatusCode)
		}
		synctest.Wait()
		if f.settlements.Load() != 1 {
			t.Fatal("rejected submission kept its key")
		}
		// No job was created, so another submission may start immediately.
		f.mu.Lock()
		f.submitCode = http.StatusAccepted
		f.mu.Unlock()
		again, err := f.client.SubmitVideo(context.Background(), videoBody())
		if err != nil {
			t.Fatal(err)
		}
		again.Body.Close()
		if len(f.providerCalls("POST provider.invalid/api/v1/videos")) != 2 {
			t.Fatal("submission was retried or skipped")
		}
	})
}
