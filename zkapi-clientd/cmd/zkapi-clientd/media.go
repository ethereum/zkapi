package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

var _ server.MediaBackend = zkInference{}

func (z zkInference) Embeddings(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	response, err := z.Client.Embeddings(ctx, body)
	return response, mediaError(err)
}

func (z zkInference) MediaModels(ctx context.Context, kind string) (json.RawMessage, error) {
	data, err := z.Client.MediaModels(ctx, kind)
	return data, mediaError(err)
}

func (z zkInference) SubmitVideo(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	response, err := z.Client.SubmitVideo(ctx, body)
	return response, mediaError(err)
}

func (z zkInference) VideoStatus(ctx context.Context, id string) (*http.Response, error) {
	response, err := z.Client.VideoStatus(ctx, id)
	return response, mediaError(err)
}

func (z zkInference) VideoContent(ctx context.Context, id string, index int) (*http.Response, error) {
	response, err := z.Client.VideoContent(ctx, id, index)
	return response, mediaError(err)
}

func (z zkInference) DeleteVideo(ctx context.Context, id string) (*http.Response, error) {
	response, err := z.Client.DeleteVideo(ctx, id)
	return response, mediaError(err)
}

// mediaError maps endpoint and job errors to safe local responses, then the
// wallet errors shared with chat completions.
func mediaError(err error) error {
	var remote *zkapi.Error
	if !errors.As(err, &remote) {
		return err
	}
	switch remote.Code {
	case "invalid_model":
		return &server.BackendError{Status: 400, Code: "invalid_model", Message: "Select a model from /v1/embeddings/models or /v1/videos/models."}
	case "model_not_enabled":
		return &server.BackendError{Status: 400, Code: "model_not_enabled", Message: "The issuer's model policy does not enable this model for this endpoint. GET /v1/embeddings/models or /v1/videos/models lists enabled models."}
	case "models_unavailable":
		return &server.BackendError{Status: 502, Code: "models_unavailable", Message: "The provider model catalog could not be loaded. Retry when it is available."}
	case "video_job_active":
		return &server.BackendError{Status: 409, Code: "video_job_active", Message: "A video job holds the wallet's lease. Retry after it finishes, or delete it once it has finished."}
	case "lease_too_short":
		return &server.BackendError{Status: 503, Code: "lease_too_short", Message: "The issued key expires too soon for a video job. Retry later."}
	case "video_job_not_found":
		return &server.BackendError{Status: 404, Code: "video_job_not_found", Message: "Unknown video job. Jobs are kept in memory and are lost when the service restarts."}
	case "video_not_ready":
		return &server.BackendError{Status: 409, Code: "video_not_ready", Message: "The video is not available. Poll GET /v1/videos/{id} until its status is completed."}
	case "video_content_not_found":
		return &server.BackendError{Status: 404, Code: "video_content_not_found", Message: "The job has no output with this index."}
	case "video_content_expired":
		return &server.BackendError{Status: 410, Code: "video_content_expired", Message: "The job's lease has ended, so its content can no longer be downloaded."}
	case "video_job_in_progress":
		return &server.BackendError{Status: 409, Code: "video_job_in_progress", Message: "The job is still running or downloading. It can be deleted after it finishes."}
	case "invalid_upstream_response":
		return &server.BackendError{Status: 502, Code: "invalid_upstream_response", Message: "The provider returned an invalid response."}
	case "inference_transport_failed":
		return &server.BackendError{Status: 502, Code: "inference_transport_failed", Message: "The provider could not be reached. Requests are not retried automatically."}
	}
	return walletError(remote)
}

// walletError matches the chat completion mapping for wallet and policy errors.
func walletError(remote *zkapi.Error) error {
	switch remote.Code {
	case "testnet_password_required":
		return &server.BackendError{Status: 401, Code: "testnet_password_required", Message: remote.Error()}
	case "invalid_model":
		return &server.BackendError{Status: 400, Code: "invalid_model", Message: "Select a model from /v1/models."}
	case "model_budget_unavailable":
		return &server.BackendError{Status: 400, Code: "model_budget_unavailable", Message: "The model is unavailable or has no reviewed request budget. Select a model from /v1/models."}
	case "model_policy_unavailable":
		return &server.BackendError{Status: 502, Code: "model_policy_unavailable", Message: "The current model policy could not be loaded. Retry when the model service is available."}
	}
	switch remote.Status {
	case http.StatusPaymentRequired:
		return &server.BackendError{Status: 402, Code: "funding_required", Message: "The private balance needs funding. Run zkapi-clientd config to add funding."}
	case http.StatusConflict:
		if remote.Code == "withdrawal_pending" || remote.Code == "withdrawal_conflict" {
			return &server.BackendError{Status: 409, Code: "withdrawal_pending", Message: "The private balance is reserved for withdrawal. Run zkapi-clientd config --menu and choose withdraw to recover the saved destination."}
		}
		return &server.BackendError{Status: 409, Code: "wallet_conflict", Message: "The wallet could not safely prepare fresh anonymous access. Run zkapi-clientd config to check its state."}
	}
	return remote
}
