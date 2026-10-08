package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testVideoID = "vidjob-0123456789abcdef0123456789abcdef"

type fakeMediaBackend struct {
	fakeBackend
	mu      sync.Mutex
	bodies  []string
	ids     []string
	index   int
	content func() *http.Response
}

func (b *fakeMediaBackend) record(body json.RawMessage, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if body != nil {
		b.bodies = append(b.bodies, string(body))
	}
	if id != "" {
		b.ids = append(b.ids, id)
	}
}

func jsonReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}, "X-Oa-Verification-Status": {"verified"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func (b *fakeMediaBackend) Embeddings(_ context.Context, body json.RawMessage) (*http.Response, error) {
	b.record(body, "")
	return jsonReply(200, `{"object":"list","data":[]}`), nil
}
func (b *fakeMediaBackend) MediaModels(_ context.Context, kind string) (json.RawMessage, error) {
	return json.RawMessage(`{"object":"list","data":[],"kind":"` + kind + `"}`), nil
}
func (b *fakeMediaBackend) SubmitVideo(_ context.Context, body json.RawMessage) (*http.Response, error) {
	b.record(body, "")
	return jsonReply(202, `{"id":"`+testVideoID+`","status":"pending"}`), nil
}
func (b *fakeMediaBackend) VideoStatus(_ context.Context, id string) (*http.Response, error) {
	b.record(nil, id)
	return jsonReply(200, `{"id":"`+id+`","status":"pending"}`), nil
}
func (b *fakeMediaBackend) VideoContent(_ context.Context, id string, index int) (*http.Response, error) {
	b.record(nil, id)
	b.mu.Lock()
	b.index = index
	b.mu.Unlock()
	if b.content != nil {
		return b.content(), nil
	}
	return &http.Response{StatusCode: 200, ContentLength: 9, Header: http.Header{"Content-Type": {"video/mp4"}}, Body: io.NopCloser(strings.NewReader("mp4-bytes"))}, nil
}
func (b *fakeMediaBackend) DeleteVideo(_ context.Context, id string) (*http.Response, error) {
	b.record(nil, id)
	return jsonReply(200, `{"id":"`+id+`","deleted":true}`), nil
}

func mediaRequest(t *testing.T, s *httptest.Server, method, path, body string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, s.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+testKey)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestMediaRequestsDropIdentityAndCallbackFields(t *testing.T) {
	backend := &fakeMediaBackend{}
	s := apiServer(t, backend)
	for _, test := range []struct {
		path, body      string
		status          int
		forbidden, kept []string
	}{
		{"/v1/embeddings", `{"model":"e/m","input":["private text"],"dimensions":8,"encoding_format":"float","input_type":"search_query","user":"id-user","session_id":"id-session","trace":{"id":"id-trace"},"provider":{"order":["id-provider"]}}`, 200,
			[]string{"id-user", "id-session", "id-trace", "id-provider"}, []string{"private text", `"dimensions":8`, "search_query"}},
		{"/v1/videos", `{"model":"v/m","prompt":"private prompt","duration":8,"resolution":"720p","frame_images":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA"},"frame_type":"first_frame"}],"callback_url":"https://id-callback.example","previous_job_id":"id-previous","user":"id-user","session_id":"id-session","provider":{"options":{"google-vertex":{"parameters":{"negativePrompt":"blur"}}},"order":["id-provider"]}}`, 202,
			[]string{"id-callback", "id-previous", "id-user", "id-session", "id-provider"}, []string{"private prompt", "negativePrompt", "first_frame", `"duration":8`}},
	} {
		response := mediaRequest(t, s, http.MethodPost, test.path, test.body)
		response.Body.Close()
		if response.StatusCode != test.status || response.Header.Get("X-OA-Verification-Status") != "verified" {
			t.Fatalf("%s: status %d", test.path, response.StatusCode)
		}
		backend.mu.Lock()
		sent := backend.bodies[len(backend.bodies)-1]
		backend.mu.Unlock()
		for _, value := range test.forbidden {
			if strings.Contains(sent, value) {
				t.Fatalf("%s forwarded %q: %s", test.path, value, sent)
			}
		}
		for _, value := range test.kept {
			if !strings.Contains(sent, value) {
				t.Fatalf("%s dropped %q: %s", test.path, value, sent)
			}
		}
	}
}

func TestMalformedMediaRequestsNeverReachBackend(t *testing.T) {
	backend := &fakeMediaBackend{}
	s := apiServer(t, backend)
	for _, test := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/embeddings", `{"input":"x"}`},
		{http.MethodPost, "/v1/embeddings", `{"model":"e/m"}`},
		{http.MethodPost, "/v1/embeddings", `{"model":"e/m","input":null}`},
		{http.MethodPost, "/v1/videos", `{"model":"v/m"}`},
		{http.MethodPost, "/v1/videos", `{"model":"v/m","prompt":7}`},
		{http.MethodPost, "/v1/videos", `[]`},
		{http.MethodGet, "/v1/videos/" + testVideoID + "/content?index=8", ""},
		{http.MethodGet, "/v1/videos/" + testVideoID + "/content?index=-1", ""},
		{http.MethodGet, "/v1/videos/" + testVideoID + "/content?index=x", ""},
	} {
		response := mediaRequest(t, s, test.method, test.path, test.body)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s %s %s: status %d", test.method, test.path, test.body, response.StatusCode)
		}
	}
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/v1/embeddings", 405},
		{http.MethodPost, "/v1/videos/models", 405},
		{http.MethodPost, "/v1/videos/" + testVideoID, 405},
		{http.MethodDelete, "/v1/videos/" + testVideoID + "/content", 405},
		{http.MethodGet, "/v1/videos/UPPER", 404},
		{http.MethodGet, "/v1/videos/" + testVideoID + "/content/extra", 404},
		{http.MethodGet, "/v1/videos/", 404},
	} {
		response := mediaRequest(t, s, test.method, test.path, "")
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("%s %s: status %d, want %d", test.method, test.path, response.StatusCode, test.status)
		}
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.bodies) != 0 || len(backend.ids) != 0 {
		t.Fatal("a malformed request reached the backend")
	}
}

func TestVideoJobRoutes(t *testing.T) {
	backend := &fakeMediaBackend{}
	s := apiServer(t, backend)
	status := mediaRequest(t, s, http.MethodGet, "/v1/videos/"+testVideoID, "")
	status.Body.Close()
	content := mediaRequest(t, s, http.MethodGet, "/v1/videos/"+testVideoID+"/content?index=3", "")
	data, _ := io.ReadAll(content.Body)
	content.Body.Close()
	deleted := mediaRequest(t, s, http.MethodDelete, "/v1/videos/"+testVideoID, "")
	deleted.Body.Close()
	models := mediaRequest(t, s, http.MethodGet, "/v1/videos/models", "")
	listed, _ := io.ReadAll(models.Body)
	models.Body.Close()
	if status.StatusCode != 200 || content.StatusCode != 200 || deleted.StatusCode != 200 || models.StatusCode != 200 {
		t.Fatal("job route failed")
	}
	if string(data) != "mp4-bytes" || content.Header.Get("Content-Type") != "video/mp4" || content.ContentLength != 9 {
		t.Fatal("video content was not forwarded unchanged")
	}
	if !strings.Contains(string(listed), `"kind":"videos"`) {
		t.Fatalf("models kind %s", listed)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.index != 3 || len(backend.ids) != 3 {
		t.Fatalf("routing index=%d ids=%v", backend.index, backend.ids)
	}
	for _, id := range backend.ids {
		if id != testVideoID {
			t.Fatalf("routed id %q", id)
		}
	}
}

func TestVideoContentMustBeVideo(t *testing.T) {
	backend := &fakeMediaBackend{content: func() *http.Response {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("<script>"))}
	}}
	s := apiServer(t, backend)
	response := mediaRequest(t, s, http.MethodGet, "/v1/videos/"+testVideoID+"/content", "")
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 502 || strings.Contains(string(data), "script") {
		t.Fatalf("non-video content forwarded: %d %s", response.StatusCode, data)
	}
}

func TestMediaBackendErrorsAreSafeAndBackendIsOptional(t *testing.T) {
	backend := &fakeMediaBackend{content: func() *http.Response {
		return &http.Response{StatusCode: 402, Header: http.Header{"Retry-After": {"7"}}, Body: io.NopCloser(strings.NewReader("provider-secret"))}
	}}
	s := apiServer(t, backend)
	response := mediaRequest(t, s, http.MethodGet, "/v1/videos/"+testVideoID+"/content", "")
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 402 || response.Header.Get("Retry-After") != "7" || strings.Contains(string(data), "provider-secret") {
		t.Fatalf("upstream error mapping: %d %s", response.StatusCode, data)
	}
	plain := apiServer(t, &fakeBackend{})
	for _, path := range []string{"/v1/embeddings", "/v1/videos"} {
		response := mediaRequest(t, plain, http.MethodPost, path, `{"model":"m","prompt":"p","input":"i"}`)
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatalf("%s without a media backend: %d", path, response.StatusCode)
		}
	}
}

func TestKeylessLocalAccessCoversMediaRoutes(t *testing.T) {
	backend := &fakeMediaBackend{}
	api, err := New(backend, testKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(api)
	defer s.Close()
	for _, test := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/embeddings", `{"model":"e/m","input":"x"}`},
		{http.MethodGet, "/v1/embeddings/models", ""},
		{http.MethodPost, "/v1/videos", `{"model":"v/m","prompt":"x"}`},
		{http.MethodGet, "/v1/videos/" + testVideoID, ""},
	} {
		r, _ := http.NewRequest(test.method, s.URL+test.path, strings.NewReader(test.body))
		r.Header.Set("Content-Type", "application/json")
		response, err := s.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode >= 300 {
			t.Fatalf("%s %s: status %d", test.method, test.path, response.StatusCode)
		}
	}
	r, _ := http.NewRequest(http.MethodGet, s.URL+"/v1/videos/"+testVideoID, nil)
	r.Header.Set("Origin", "https://evil.example")
	response, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("browser origin reached a video job")
	}
}

func TestMediaRequestLogsUseFixedRoutesWithoutJobIDs(t *testing.T) {
	for target, want := range map[string]string{
		"/v1/embeddings":                         "route=/v1/embeddings",
		"/v1/videos":                             "route=/v1/videos",
		"/v1/videos/models":                      "route=/v1/videos/models",
		"/v1/videos/" + testVideoID:              "route=/v1/videos/{id}",
		"/v1/videos/" + testVideoID + "/content": "route=/v1/videos/{id}/content",
	} {
		var output bytes.Buffer
		handler := LogRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}), log.New(&output, "", 0))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, target+"?index=0", strings.NewReader("private prompt")))
		got := output.String()
		if !strings.Contains(got, want) || strings.Contains(got, testVideoID) || strings.Contains(got, "private") || strings.Contains(got, "index") {
			t.Fatalf("%s logged %q", target, got)
		}
	}
	var output bytes.Buffer
	handler := LogRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), log.New(&output, "", 0))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/videos/Private-Secret", nil))
	if output.Len() != 0 {
		t.Fatalf("unroutable job path logged %q", output.String())
	}
}
