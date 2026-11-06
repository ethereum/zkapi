package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/OpenAnonymity/oa-chat/oa-clientd/pkg/server"
)

const lecoreRecallTestKey = "local-test-key-with-at-least-32-characters"

func longRecallRequest(t *testing.T, streaming bool) (string, int) {
	t.Helper()
	messages := []map[string]string{
		{"role": "system", "content": "Keep the system instruction."},
		{"role": "developer", "content": "Keep the developer instruction."},
	}
	for i := 0; i < 13; i++ {
		user := "Background discussion. " + strings.Repeat("background ", 100)
		assistant := "Background answer. " + strings.Repeat("context ", 100)
		if i == 1 {
			user = "Thermal aperture calibration uses a reference image. " + strings.Repeat("thermal aperture calibration ", 50)
			assistant = "We agreed on thermal aperture calibration against that reference image. " + strings.Repeat("thermal aperture calibration ", 40)
		}
		messages = append(messages, map[string]string{"role": "user", "content": user},
			map[string]string{"role": "assistant", "content": assistant})
	}
	messages = append(messages, map[string]string{"role": "user", "content": "What was the thermal aperture calibration discussed earlier?"})
	body, err := json.Marshal(map[string]any{
		"model": "test/model", "messages": messages, "stream": streaming,
		"temperature": 0.4, "user": "identity-must-not-forward",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body), len(messages)
}

func TestLeCoreRecallOptInBeforePaidBackend(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			name := "nonstream"
			if streaming {
				name = "stream"
			}
			if enabled {
				name += "_enabled"
			} else {
				name += "_disabled"
			}
			t.Run(name, func(t *testing.T) {
				var captured json.RawMessage
				backend := &recallFakeBackend{complete: func(_ context.Context, body json.RawMessage) (*http.Response, error) {
					captured = append(json.RawMessage(nil), body...)
					if streaming {
						return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
							Body: io.NopCloser(strings.NewReader("data: [DONE]\n\n"))}, nil
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
						Body: io.NopCloser(strings.NewReader(`{"choices":[]}`))}, nil
				}}
				var wired server.Backend = backend
				if enabled {
					wired = withLeCoreRecall(backend)
				}
				api, err := server.New(wired, lecoreRecallTestKey, 2)
				if err != nil {
					t.Fatal(err)
				}
				api.RequireAPIKey = true
				httpServer := httptest.NewServer(api)
				defer httpServer.Close()
				body, originalCount := longRecallRequest(t, streaming)
				response, err := http.DefaultClient.Do(recallRequest(t, httpServer.URL, body))
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != 200 || backend.calls.Load() != 1 {
					t.Fatalf("completion failed: status=%d calls=%d body=%s", response.StatusCode, backend.calls.Load(), captured)
				}
				var forwarded struct {
					Messages    []struct{ Role, Content string } `json:"messages"`
					Stream      bool                             `json:"stream"`
					Temperature float64                          `json:"temperature"`
					User        string                           `json:"user"`
				}
				if err := json.Unmarshal(captured, &forwarded); err != nil {
					t.Fatal(err)
				}
				if forwarded.Stream != streaming || forwarded.Temperature != 0.4 || forwarded.User != "" {
					t.Fatal("recall changed request options or forwarded identity metadata")
				}
				if enabled && len(forwarded.Messages) >= originalCount {
					t.Fatalf("enabled recall did not reduce long context: %d", len(forwarded.Messages))
				}
				if !enabled && len(forwarded.Messages) != originalCount {
					t.Fatalf("disabled recall changed context: %d", len(forwarded.Messages))
				}
				if forwarded.Messages[0].Role != "system" || forwarded.Messages[1].Role != "developer" ||
					forwarded.Messages[len(forwarded.Messages)-1].Content != "What was the thermal aperture calibration discussed earlier?" {
					t.Fatal("protected messages were lost")
				}
				if enabled {
					found := false
					for _, message := range forwarded.Messages {
						found = found || strings.Contains(message.Content, "reference image")
					}
					if !found {
						t.Fatal("relevant earlier exchange was not recalled")
					}
				}
			})
		}
	}
}

func TestLeCoreRecallPreservesDelegationCapability(t *testing.T) {
	plain := &recallFakeBackend{}
	if _, ok := withLeCoreRecall(plain).(server.Delegator); ok {
		t.Fatal("recall wrapper advertised delegation for a chat-only backend")
	}
	delegating := &recallDelegatingBackend{}
	wrapped, ok := withLeCoreRecall(delegating).(server.Delegator)
	if !ok {
		t.Fatal("recall wrapper dropped delegation")
	}
	body := json.RawMessage(`{"messages":[{"role":"user","content":"task"}]}`)
	if _, err := wrapped.Delegate(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if string(delegating.body) != string(body) {
		t.Fatalf("delegation body changed: %s", delegating.body)
	}
}

type recallFakeBackend struct {
	complete func(context.Context, json.RawMessage) (*http.Response, error)
	calls    atomic.Int32
}

func (b *recallFakeBackend) Models(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"object":"list","data":[{"id":"test/model","object":"model","owned_by":"test"}]}`), nil
}

func (b *recallFakeBackend) Complete(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	b.calls.Add(1)
	if b.complete == nil {
		return nil, io.EOF
	}
	return b.complete(ctx, body)
}

type recallDelegatingBackend struct {
	recallFakeBackend
	body json.RawMessage
}

func (b *recallDelegatingBackend) Delegate(_ context.Context, body json.RawMessage) (*http.Response, error) {
	b.body = append(json.RawMessage(nil), body...)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
}

func recallRequest(t *testing.T, url, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, url+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+lecoreRecallTestKey)
	r.Header.Set("Content-Type", "application/json")
	return r
}
