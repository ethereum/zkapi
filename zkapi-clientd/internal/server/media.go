package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MediaBackend is optional. It adds embeddings and asynchronous video jobs
// for models the issuer's policy enables for those endpoints. Without it the
// media routes return 404.
type MediaBackend interface {
	Embeddings(context.Context, json.RawMessage) (*http.Response, error)
	MediaModels(ctx context.Context, kind string) (json.RawMessage, error)
	SubmitVideo(context.Context, json.RawMessage) (*http.Response, error)
	VideoStatus(ctx context.Context, id string) (*http.Response, error)
	VideoContent(ctx context.Context, id string, index int) (*http.Response, error)
	DeleteVideo(ctx context.Context, id string) (*http.Response, error)
}

const maxVideoContentIndex = 7

// videoRoute splits /v1/videos/{id} and /v1/videos/{id}/content. The backend
// validates the exact local ID format; this only bounds what is routed.
func videoRoute(path string) (id string, content bool, ok bool) {
	rest, found := strings.CutPrefix(path, "/v1/videos/")
	if !found {
		return "", false, false
	}
	id, content = strings.CutSuffix(rest, "/content")
	if id == "" || len(id) > 64 || id == "models" {
		return "", false, false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return "", false, false
		}
	}
	return id, content, true
}

func mediaPath(path string) bool {
	switch path {
	case "/v1/embeddings", "/v1/embeddings/models", "/v1/videos", "/v1/videos/models":
		return true
	}
	_, _, ok := videoRoute(path)
	return ok
}

func (a *API) media(w http.ResponseWriter, r *http.Request) {
	backend, ok := a.backend.(MediaBackend)
	if !ok {
		writeError(w, 404, "not_found", "This endpoint is not available with the configured backend.")
		return
	}
	path, method := r.URL.Path, r.Method
	switch {
	case path == "/v1/embeddings" && method == http.MethodPost:
		a.post(w, r, sanitizeEmbeddings, backend.Embeddings)
	case path == "/v1/videos" && method == http.MethodPost:
		a.post(w, r, sanitizeVideo, backend.SubmitVideo)
	case (path == "/v1/embeddings/models" || path == "/v1/videos/models") && method == http.MethodGet:
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		defer cancel()
		kind := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/"), "/models")
		data, err := backend.MediaModels(ctx, kind)
		if err != nil {
			var safe *BackendError
			if errors.As(err, &safe) && safe.Status >= 400 && safe.Status <= 599 {
				writeError(w, safe.Status, safe.Code, safe.Message)
				return
			}
			writeError(w, 502, "models_unavailable", "Unable to load the anonymous model catalog.")
			return
		}
		writeJSON(w, 200, data)
	case path == "/v1/embeddings" || path == "/v1/videos" || path == "/v1/embeddings/models" || path == "/v1/videos/models":
		writeError(w, 405, "method_not_allowed", "Method not allowed.")
	default:
		id, content, _ := videoRoute(path)
		switch {
		case content && method == http.MethodGet:
			index := 0
			if raw := r.URL.Query().Get("index"); raw != "" {
				parsed, err := strconv.Atoi(raw)
				if err != nil || parsed < 0 || parsed > maxVideoContentIndex {
					writeError(w, 400, "invalid_request_error", "index must be an integer from 0 to 7.")
					return
				}
				index = parsed
			}
			a.get(w, r, 30*time.Minute, videoBody, func(ctx context.Context) (*http.Response, error) {
				return backend.VideoContent(ctx, id, index)
			})
		case !content && method == http.MethodGet:
			a.get(w, r, time.Minute, jsonBody, func(ctx context.Context) (*http.Response, error) {
				return backend.VideoStatus(ctx, id)
			})
		case !content && method == http.MethodDelete:
			a.get(w, r, time.Minute, jsonBody, func(ctx context.Context) (*http.Response, error) {
				return backend.DeleteVideo(ctx, id)
			})
		default:
			writeError(w, 405, "method_not_allowed", "Method not allowed.")
		}
	}
}

// get serves a bodiless job request. It shares the local queue bound but not
// the inference slots: the job already owns its lease.
func (a *API) get(w http.ResponseWriter, r *http.Request, timeout time.Duration, kind responseKind, call func(context.Context) (*http.Response, error)) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	select {
	case a.pending <- struct{}{}:
		defer func() { <-a.pending }()
	default:
		writeError(w, 429, "busy", "The local request queue is full. Retry after a running request finishes.")
		return
	}
	response, err := call(ctx)
	a.relay(ctx, w, http.NewResponseController(w), response, err, kind)
}

// Only inputs cross the boundary: user, session_id, trace, provider routing
// preferences and other account metadata do not.
var embeddingFields = map[string]bool{
	"model": true, "input": true, "dimensions": true, "encoding_format": true, "input_type": true,
}

// callback_url is dropped: job results are retrieved only through this API.
// previous_job_id would name a provider job outside this client's mapping.
var videoFields = map[string]bool{
	"model": true, "prompt": true, "duration": true, "resolution": true, "aspect_ratio": true,
	"size": true, "frame_images": true, "input_references": true, "generate_audio": true,
	"seed": true, "upscale_factor": true, "creativity": true, "provider": true,
}

func sanitizeFields(body []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(body, &values); err != nil || values == nil {
		return nil, errors.New("body must be a JSON object")
	}
	var model string
	if json.Unmarshal(values["model"], &model) != nil || strings.TrimSpace(model) == "" || len(model) > 256 {
		return nil, errors.New("model is required")
	}
	for key := range values {
		if !allowed[key] {
			delete(values, key)
		}
	}
	return values, nil
}

func sanitizeEmbeddings(body []byte) (json.RawMessage, bool, error) {
	values, err := sanitizeFields(body, embeddingFields)
	if err != nil {
		return nil, false, err
	}
	if input, ok := values["input"]; !ok || string(input) == "null" {
		return nil, false, errors.New("input is required")
	}
	clean, err := json.Marshal(values)
	return clean, false, err
}

func sanitizeVideo(body []byte) (json.RawMessage, bool, error) {
	values, err := sanitizeFields(body, videoFields)
	if err != nil {
		return nil, false, err
	}
	var prompt string
	if raw, ok := values["prompt"]; ok && json.Unmarshal(raw, &prompt) != nil {
		return nil, false, errors.New("prompt must be a string")
	}
	if prompt == "" && values["frame_images"] == nil && values["input_references"] == nil {
		return nil, false, errors.New("prompt or an image input is required")
	}
	// Keep provider-specific generation options; drop routing preferences.
	if raw, ok := values["provider"]; ok {
		delete(values, "provider")
		var provider map[string]json.RawMessage
		if json.Unmarshal(raw, &provider) == nil && provider["options"] != nil {
			options, _ := json.Marshal(map[string]json.RawMessage{"options": provider["options"]})
			values["provider"] = options
		}
	}
	clean, err := json.Marshal(values)
	return clean, false, err
}
