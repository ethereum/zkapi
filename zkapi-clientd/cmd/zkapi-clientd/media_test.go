package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestMediaErrorsMapToSafeActionableResponses(t *testing.T) {
	for _, test := range []struct {
		err    *zkapi.Error
		status int
		code   string
	}{
		{&zkapi.Error{Status: http.StatusPaymentRequired, Code: "companion_request_failed"}, 402, "funding_required"},
		{&zkapi.Error{Status: http.StatusBadRequest, Code: "model_not_enabled"}, 400, "model_not_enabled"},
		{&zkapi.Error{Status: http.StatusBadGateway, Code: "model_policy_unavailable"}, 502, "model_policy_unavailable"},
		{&zkapi.Error{Status: http.StatusConflict, Code: "withdrawal_pending"}, 409, "withdrawal_pending"},
		{&zkapi.Error{Status: http.StatusConflict, Code: "lease_already_used"}, 409, "wallet_conflict"},
		{&zkapi.Error{Status: http.StatusConflict, Code: "video_job_active"}, 409, "video_job_active"},
		{&zkapi.Error{Status: http.StatusNotFound, Code: "video_job_not_found"}, 404, "video_job_not_found"},
		{&zkapi.Error{Status: http.StatusGone, Code: "video_content_expired"}, 410, "video_content_expired"},
		{&zkapi.Error{Status: http.StatusConflict, Code: "video_not_ready"}, 409, "video_not_ready"},
		{&zkapi.Error{Status: http.StatusBadGateway, Code: "inference_transport_failed"}, 502, "inference_transport_failed"},
	} {
		var safe *server.BackendError
		if err := mediaError(test.err); !errors.As(err, &safe) || safe.Status != test.status || safe.Code != test.code || strings.Contains(safe.Message, "zkAPI ") {
			t.Fatalf("%s mapped to %v", test.err.Code, err)
		}
	}
	var invalid *server.BackendError
	if !errors.As(mediaError(&zkapi.Error{Status: http.StatusBadRequest, Code: "invalid_model"}), &invalid) ||
		invalid.Code != "invalid_model" || !strings.Contains(invalid.Message, "/v1/embeddings/models") || strings.Contains(invalid.Message, "Select a model from /v1/models") {
		t.Fatalf("invalid_model on a media route: %v", invalid)
	}
	if mediaError(nil) != nil {
		t.Fatal("success mapped to an error")
	}
	unknown := &zkapi.Error{Status: http.StatusBadGateway, Code: "companion_unavailable"}
	var safe *server.BackendError
	if errors.As(mediaError(unknown), &safe) {
		t.Fatal("an unreviewed error became a client-visible message")
	}
}
