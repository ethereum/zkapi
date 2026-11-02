package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenAnonymity/oa-chat/oa-clientd/pkg/activity"
)

func TestFreshKeysRetirePreviousLeaseAfterItsResponseEnds(t *testing.T) {
	var leases, settlements, calls atomic.Int32
	keys := make(chan string, 2)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		keys <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oa/v1/lease":
			n := leases.Add(1)
			if n > 1 && settlements.Load() == 0 {
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"error":{"code":"lease_pending"}}`)
				return
			}
			writeQueuedTestLease(w, upstream.URL, n)
		case "/wallet/settle":
			body, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || len(body) != 0 || r.Header.Get("Origin") != "" {
				t.Error("retirement must use an authenticated prompt-free local request")
			}
			settlements.Add(1)
			_, _ = io.WriteString(w, `{"pending_request":false}`)
		default:
			t.Errorf("unexpected companion request %s", r.URL.Path)
		}
	}, upstream)
	// Successful retirement retries issuance immediately, without waiting
	// for either this long poll interval or the provider's five-minute TTL.
	client.settlementPoll = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, err := client.Complete(ctx, queuedTestPrompt)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	result := make(chan error, 1)
	go func() {
		second, err := client.Complete(ctx, queuedTestPrompt)
		if err == nil {
			_, err = io.Copy(io.Discard, second.Body)
			_ = second.Body.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("queued request ran before the previous response ended: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if leases.Load() != 1 || settlements.Load() != 0 {
		t.Fatal("retired or acquired access while a provider response was owned")
	}
	_, _ = io.Copy(io.Discard, first.Body)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if leases.Load() != 3 || settlements.Load() != 1 || calls.Load() != 2 || <-keys == <-keys {
		t.Fatalf("rotation failed: leases=%d settlements=%d inference=%d", leases.Load(), settlements.Load(), calls.Load())
	}
}

func TestRetirementRunsOnceWhenFreshOrReuseModeNeedsAnotherKey(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "reuse"}[reuse], func(t *testing.T) {
			var leases, settlements atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{}`) }))
			defer upstream.Close()
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/wallet/settle" {
					settlements.Add(1)
					w.WriteHeader(http.StatusConflict)
					// The existing wallet endpoint uses this older code when
					// its signed next state has not been recovered yet.
					_, _ = io.WriteString(w, `{"error":{"code":"pending_request"}}`)
					return
				}
				n := leases.Add(1)
				if n < 4 {
					w.WriteHeader(http.StatusConflict)
					_, _ = io.WriteString(w, `{"error":{"code":"lease_pending"}}`)
					return
				}
				writeQueuedTestLease(w, upstream.URL, n)
			}, upstream)
			client.settlementPoll = time.Millisecond
			if reuse {
				client.config.KeyReuseWindow = time.Minute
			}
			var waiting int
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctx = activity.WithReporter(ctx, func(event activity.Event) {
				if event.Kind == activity.SettlementWaiting {
					waiting++
				}
			})
			drainReuseResponse(t, client, ctx, queuedTestPrompt)
			if waiting != 1 || settlements.Load() != 1 || leases.Load() != 4 {
				t.Fatalf("waiting=%d retirements=%d leases=%d", waiting, settlements.Load(), leases.Load())
			}
		})
	}
}

func TestTenSecondReuseRetiresUnavailableKeyAfterPreviousResponseEnds(t *testing.T) {
	for _, mode := range []string{"expired_window", "different_budget"} {
		t.Run(mode, func(t *testing.T) {
			var leases, settlements, calls atomic.Int32
			keys := make(chan string, 3)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				keys <- r.Header.Get("Authorization")
				_, _ = io.WriteString(w, `{}`)
			}))
			defer upstream.Close()
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oa/v1/lease":
					n := leases.Add(1)
					var body map[string]uint64
					if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["request_limit_micro_usd"] == 0 {
						t.Error("lease request must contain only its coarse budget, never the prompt")
					}
					wantBudget := uint64(1_000_000)
					if n > 1 && mode == "different_budget" {
						wantBudget = 6_000_000
					}
					if body["request_limit_micro_usd"] != wantBudget {
						t.Errorf("lease budget=%d want=%d", body["request_limit_micro_usd"], wantBudget)
					}
					if n > 1 && settlements.Load() == 0 {
						w.WriteHeader(http.StatusConflict)
						_, _ = io.WriteString(w, `{"error":{"code":"lease_pending"}}`)
						return
					}
					writeQueuedTestLease(w, upstream.URL, n)
				case "/wallet/settle":
					body, _ := io.ReadAll(r.Body)
					if r.Method != http.MethodPost || len(body) != 0 || r.Header.Get("Origin") != "" {
						t.Error("retirement must use an authenticated prompt-free local request")
					}
					settlements.Add(1)
					_, _ = io.WriteString(w, `{"pending_request":false}`)
				default:
					t.Errorf("unexpected companion request %s", r.URL.Path)
				}
			}, upstream)
			addTestModelPolicy(client, map[string]uint64{"example/model": 1, "expensive/model": 100}, nil)
			client.config.KeyReuseWindow = 10 * time.Second
			// A successful retirement must retry immediately, without waiting
			// for this poll interval or the still-valid provider key to expire.
			client.settlementPoll = time.Hour
			clock := time.Now().Truncate(time.Second)
			var offset atomic.Int64
			client.now = func() time.Time { return clock.Add(time.Duration(offset.Load())) }
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			drainReuseResponse(t, client, ctx, queuedTestPrompt)

			offset.Store(int64(9 * time.Second))
			reused, err := client.Complete(ctx, queuedTestPrompt)
			if err != nil {
				t.Fatal(err)
			}
			defer reused.Body.Close()
			if leases.Load() != 1 || settlements.Load() != 0 || calls.Load() != 2 {
				t.Fatalf("compatible request did not reuse access: leases=%d settlements=%d inference=%d", leases.Load(), settlements.Load(), calls.Load())
			}
			firstKey, reusedKey := <-keys, <-keys
			if reusedKey != firstKey {
				t.Fatal("compatible request inside ten seconds changed keys")
			}

			nextPrompt := queuedTestPrompt
			if mode == "expired_window" {
				// The reuse at nine seconds must not extend the original window.
				offset.Store(int64(10 * time.Second))
			} else {
				nextPrompt = json.RawMessage(`{"model":"expensive/model","messages":[{"role":"user","content":"private content"}]}`)
			}
			result := make(chan error, 1)
			go func() {
				next, err := client.Complete(ctx, nextPrompt)
				if err == nil {
					_, err = io.Copy(io.Discard, next.Body)
					_ = next.Body.Close()
				}
				result <- err
			}()
			select {
			case err := <-result:
				t.Fatalf("queued request ran before the previous response ended: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if leases.Load() != 1 || settlements.Load() != 0 || calls.Load() != 2 {
				t.Fatal("retired or acquired access while the reused response was owned")
			}
			if _, err := io.Copy(io.Discard, reused.Body); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if leases.Load() != 3 || settlements.Load() != 1 || calls.Load() != 3 || <-keys == firstKey {
				t.Fatalf("rotation failed: leases=%d settlements=%d inference=%d", leases.Load(), settlements.Load(), calls.Load())
			}
		})
	}
}

func TestRetirementFailureNeverRetriesMutationOrSendsInference(t *testing.T) {
	for _, failure := range []struct {
		name   string
		status int
		body   string
	}{
		{"lost_reply", 0, ""},
		{"malformed", 200, "{"},
		{"missing_pending", 200, `{}`},
		{"unknown_conflict", 409, `{"error":{"code":"unknown"}}`},
		{"withdrawal_conflict", 409, `{"error":{"code":"withdrawal_conflict"}}`},
		{"wrong_status", 500, `{"error":{"code":"pending_settlement"}}`},
	} {
		t.Run(failure.name, func(t *testing.T) {
			var leases, settlements, calls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			defer upstream.Close()
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oa/v1/lease" {
					leases.Add(1)
					w.WriteHeader(http.StatusConflict)
					_, _ = io.WriteString(w, `{"error":{"code":"lease_pending"}}`)
					return
				}
				settlements.Add(1)
				if failure.status == 0 {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = connection.Close()
					return
				}
				w.WriteHeader(failure.status)
				_, _ = io.WriteString(w, failure.body)
			}, upstream)
			client.settlementPoll = time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := client.Complete(ctx, queuedTestPrompt)
			if err == nil || errors.Is(err, context.DeadlineExceeded) || leases.Load() != 1 || settlements.Load() != 1 || calls.Load() != 0 {
				t.Fatalf("retirement failure retried: err=%v leases=%d settlements=%d inference=%d", err, leases.Load(), settlements.Load(), calls.Load())
			}
		})
	}
}

func TestKeyActivityUsesLocalReferencesForFreshAndReusedKeys(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "reuse"}[reuse], func(t *testing.T) {
			var leases atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{}`) }))
			defer upstream.Close()
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeQueuedTestLease(w, upstream.URL, leases.Add(1)) }, upstream)
			if reuse {
				client.config.KeyReuseWindow = time.Minute
			}
			var events []activity.Event
			ctx := activity.WithReporter(context.Background(), func(event activity.Event) { events = append(events, event) })
			for range 2 {
				drainReuseResponse(t, client, ctx, queuedTestPrompt)
			}
			secondKind, secondKey := activity.KeyFresh, uint64(2)
			if reuse {
				secondKind, secondKey = activity.KeyReused, 1
			}
			want := []activity.Event{
				{Kind: activity.KeyFresh, Key: 1},
				{Kind: activity.KeyReleased, Key: 1, Complete: true, Reusable: reuse},
				{Kind: secondKind, Key: secondKey},
				{Kind: activity.KeyReleased, Key: secondKey, Complete: true, Reusable: reuse},
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("events=%+v want=%+v", events, want)
			}
			encoded, _ := json.Marshal(events)
			if strings.Contains(string(encoded), "independent-key") {
				t.Fatal("provider credential entered operational events")
			}
		})
	}
}

func TestKeyActivityReleasesOnceAfterFailureOrCancellation(t *testing.T) {
	for _, failure := range []string{"transport", "status", "body", "close", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected transport request") }))
			defer upstream.Close()
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeQueuedTestLease(w, upstream.URL, 1) }, upstream)
			client.config.KeyReuseWindow = time.Minute
			previous := client.inference.Transport
			client.inference.Transport = budgetTransport(func(r *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
					return previous.RoundTrip(r)
				}
				if failure == "transport" {
					return nil, errors.New("private provider diagnostic")
				}
				response := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}
				if failure == "status" {
					response.StatusCode = http.StatusPaymentRequired
				}
				if failure == "body" {
					response.Body = io.NopCloser(reuseErrorReader{})
				}
				return response, nil
			})
			events := make(chan activity.Event, 4)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = activity.WithReporter(ctx, func(event activity.Event) { events <- event })
			response, err := client.Complete(ctx, queuedTestPrompt)
			if failure == "transport" {
				if err == nil {
					t.Fatal("transport failure hidden")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				switch failure {
				case "cancel":
					cancel()
				case "close":
				default:
					_, _ = io.Copy(io.Discard, response.Body)
				}
				_ = response.Body.Close()
				_ = response.Body.Close()
			}
			if first := <-events; first != (activity.Event{Kind: activity.KeyFresh, Key: 1}) {
				t.Fatalf("fresh event=%+v", first)
			}
			if last := <-events; last != (activity.Event{Kind: activity.KeyReleased, Key: 1}) {
				t.Fatalf("failed release=%+v", last)
			}
			select {
			case extra := <-events:
				t.Fatalf("repeated release=%+v", extra)
			default:
			}
		})
	}
}
