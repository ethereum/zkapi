package zkapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

// endpoint describes one OpenRouter API reachable with a lease. Chat keeps the
// web client's model rules. Other endpoints accept only models that the
// issuer's policy lists explicitly and that OpenRouter's catalog for that
// endpoint contains, so they stay unavailable until the operator enables them.
type endpoint struct {
	path    string // below the inference base URL
	accept  string
	catalog string // public endpoint-specific model catalog; empty for chat
	fresh   bool   // never reuse or cache a key: the caller holds it for a job
}

var (
	chatEndpoint       = endpoint{path: "/chat/completions", accept: "application/json, text/event-stream"}
	embeddingsEndpoint = endpoint{path: "/embeddings", accept: "application/json", catalog: "/embeddings/models"}
	videosEndpoint     = endpoint{path: "/videos", accept: "application/json", catalog: "/videos/models", fresh: true}
)

// MediaKind names an endpoint-scoped model list.
const (
	MediaEmbeddings = "embeddings"
	MediaVideos     = "videos"
)

func mediaEndpoint(kind string) (endpoint, bool) {
	switch kind {
	case MediaEmbeddings:
		return embeddingsEndpoint, true
	case MediaVideos:
		return videosEndpoint, true
	}
	return endpoint{}, false
}

func (c *Client) endpointBudget(ctx context.Context, endpoint endpoint, body json.RawMessage) (uint64, error) {
	if endpoint.catalog == "" {
		return c.requestBudget(ctx, body)
	}
	var request struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &request) != nil || request.Model == "" || strings.TrimSpace(request.Model) != request.Model {
		return 0, &Error{http.StatusBadRequest, "invalid_model"}
	}
	enabled, err := c.enabledMediaModels(ctx, endpoint)
	if err != nil {
		return 0, err
	}
	budget, ok := enabled[request.Model]
	if !ok {
		return 0, &Error{http.StatusBadRequest, "model_not_enabled"}
	}
	return budget, nil
}

// enabledMediaModels intersects explicit, reviewed policy tiers with the
// endpoint's public catalog. There is no untiered fallback and no :online
// normalization: an endpoint-specific model needs its own policy entry.
func (c *Client) enabledMediaModels(ctx context.Context, endpoint endpoint) (map[string]uint64, error) {
	budgets, err := c.modelBudgets(ctx)
	if err != nil {
		return nil, err
	}
	catalog, err := c.catalogIDs(ctx, endpoint.catalog)
	if err != nil {
		return nil, err
	}
	enabled := make(map[string]uint64)
	for id, budget := range budgets {
		if budget > 0 && catalog[id] {
			enabled[id] = budget
		}
	}
	return enabled, nil
}

// MediaModels lists the models the issuer's policy currently enables for an
// endpoint, with their allowance. An empty list means the operator has not
// enabled any.
func (c *Client) MediaModels(ctx context.Context, kind string) (json.RawMessage, error) {
	endpoint, ok := mediaEndpoint(kind)
	if !ok {
		return nil, &Error{http.StatusNotFound, "not_found"}
	}
	if err := c.Check(ctx); err != nil {
		return nil, err
	}
	enabled, err := c.enabledMediaModels(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(enabled))
	for id := range enabled {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	models := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		provider, _, _ := strings.Cut(id, "/")
		models = append(models, map[string]any{"id": id, "object": "model", "created": 0, "owned_by": provider, "oa_request_limit_micro_usd": enabled[id]})
	}
	return json.Marshal(map[string]any{"object": "list", "data": models})
}

// Embeddings is a synchronous request with the same lease handling as chat.
// A compatible key inside the reuse window may serve both.
func (c *Client) Embeddings(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	return c.forward(ctx, embeddingsEndpoint, body)
}
