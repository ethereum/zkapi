package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/OpenAnonymity/oa-chat/oa-clientd/pkg/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/lecore"
)

// recallingBackend applies opt-in local context recall to chat completions.
// The shared API sanitizes the request, then calls Complete; recall runs there,
// immediately before paid inference. The shared server package has no recall hook.
type recallingBackend struct{ server.Backend }

func (r recallingBackend) Complete(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	body, _ = lecore.Optimize(body)
	return r.Backend.Complete(ctx, body)
}

// recallingDelegator keeps strict delegation on a backend that already
// supports it. Delegation is one task, not a chat history, so its body is
// forwarded unchanged.
type recallingDelegator struct{ recallingBackend }

func (r recallingDelegator) Delegate(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	return r.Backend.(server.Delegator).Delegate(ctx, body)
}

// withLeCoreRecall wraps backend so chat completions run local leCore recall.
// A backend that does not implement delegation stays non-delegating.
func withLeCoreRecall(backend server.Backend) server.Backend {
	wrapped := recallingBackend{backend}
	if _, ok := backend.(server.Delegator); ok {
		return recallingDelegator{wrapped}
	}
	return wrapped
}
