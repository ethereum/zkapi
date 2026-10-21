package main

import (
	"context"
	"errors"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// Only locally-defined messages/codes may cross the API/log boundary. Never
// log err.Error(): unknown errors can contain keys, URLs or private wallet data.
func accessPreparationError(ctx context.Context, err error) error {
	var remote *zkapi.Error
	if !errors.As(err, &remote) {
		return err
	}
	var message string
	switch remote.Code {
	case "companion_unavailable":
		message = "The wallet companion could not be reached or timed out while preparing access. Key issuance may be uncertain; check the existing wallet state before retrying. Do not delete state or redeposit."
	case "companion_request_failed":
		// Preserve established funding/conflict handling in the calling adapter.
		if remote.Status == 402 || remote.Status == 409 {
			return err
		}
		message = "The wallet companion rejected an access-preparation request. Its private diagnostic response was withheld. This does not establish insufficient funds; check companion/upstream availability and wallet state before retrying."
	case "invalid_companion_response":
		message = "The wallet companion returned an unreadable, oversized or invalid response while preparing access. Key issuance may be uncertain; preserve wallet state and avoid repeated retries."
	case "invalid_verified_lease":
		message = "The returned access key failed local lease validation (verification, expiry, provider endpoint or required fields). It was not used for inference. Preserve wallet state; do not redeposit to fix this error."
	case "tor_preparation_failed":
		message = "Authenticated Tor route preparation failed before key acquisition. Check the configured Tor SOCKS listener; no direct fallback was used."
	default:
		return err
	}
	status := remote.Status
	if status < 400 || status > 599 {
		status = 502
	}
	activity.Diagnostic(ctx, "access preparation failed: code=%s status=%d (remote details withheld)", remote.Code, status)
	return &server.BackendError{Status: status, Code: remote.Code, Message: message}
}
