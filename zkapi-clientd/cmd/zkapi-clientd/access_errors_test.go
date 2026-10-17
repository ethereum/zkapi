package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestAccessErrorsExposeOnlyAllowlistedCodes(t *testing.T) {
	for _, code := range []string{"companion_unavailable", "companion_request_failed", "invalid_companion_response", "invalid_verified_lease", "tor_preparation_failed", "note_not_activated", "indexer_root_lag"} {
		var output bytes.Buffer
		ctx := activity.WithDiagnostics(context.Background(), activity.SemiVerbose, log.New(&output, "", 0))
		err := accessPreparationError(ctx, fmt.Errorf("secret raw error: %w", &zkapi.Error{Status: 502, Code: code}))
		var safe *server.BackendError
		if !errors.As(err, &safe) || safe.Code != code || !strings.Contains(output.String(), code) {
			t.Fatal("missing safe diagnostic", code, err)
		}
		if strings.Contains(output.String()+safe.Message, "secret raw error") {
			t.Fatal("private error leaked")
		}
	}
	// A recorded note the operator's batch has not activated: no key was
	// issued, and the fixed message says so and that exits are available.
	var activation *server.BackendError
	if err := accessPreparationError(context.Background(), &zkapi.Error{Status: 409, Code: "note_not_activated"}); !errors.As(err, &activation) || activation.Status != 409 || !strings.Contains(activation.Message, "not activated") || !strings.Contains(activation.Message, "Withdrawals are available") {
		t.Fatalf("note_not_activated was not explained: %v", err)
	}
	// An activated note the operator's indexer has not caught up with (503,
	// retriable): the fixed message says so and that exits are available.
	var lag *server.BackendError
	if err := accessPreparationError(context.Background(), &zkapi.Error{Status: 503, Code: "indexer_root_lag"}); !errors.As(err, &lag) || lag.Status != 503 || !strings.Contains(lag.Message, "not caught up") || !strings.Contains(lag.Message, "Withdrawals are available") {
		t.Fatalf("indexer_root_lag was not explained: %v", err)
	}
	for _, status := range []int{402, 409} {
		original := &zkapi.Error{Status: status, Code: "companion_request_failed"}
		if accessPreparationError(context.Background(), original) != original {
			t.Fatal("changed funding/conflict mapping")
		}
	}
	original := &zkapi.Error{Status: 502, Code: "unknown-secret-code"}
	var output bytes.Buffer
	ctx := activity.WithDiagnostics(context.Background(), activity.SemiVerbose, log.New(&output, "", 0))
	if accessPreparationError(ctx, original) != original || output.Len() != 0 {
		t.Fatal("unknown diagnostic disclosed")
	}
	if accessPreparationError(ctx, nil) != nil {
		t.Fatal("success changed")
	}
}
