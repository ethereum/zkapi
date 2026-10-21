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
	for _, code := range []string{"companion_unavailable", "companion_request_failed", "invalid_companion_response", "invalid_verified_lease", "tor_preparation_failed"} {
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
