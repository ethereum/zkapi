package main

import (
	"context"
	"log"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
)

type settlementRunner interface {
	RunSettlement(context.Context)
}

// Automatic settlement belongs to the daemon lifetime, independent of the
// HTTP request that opened its key window. Only local display references and
// fixed result fields enter these logs; wallet receipts report the actual cost.
func runAutomaticSettlement(ctx context.Context, logger *log.Logger, runner settlementRunner) {
	ctx = activity.WithReporter(ctx, func(event activity.Event) {
		if logger == nil || activity.DiagnosticLevel(ctx) == activity.SemiVerbose {
			return
		}
		switch event.Kind {
		case activity.SettlementStarted:
			logger.Printf("key window ended key_ref=%d; starting automatic settlement", event.Key)
		case activity.SettlementFinished:
			logger.Printf("automatic settlement result key_ref=%d ready=%t duration=%s", event.Key, event.Complete, event.Duration.Round(time.Millisecond))
		}
	})
	runner.RunSettlement(ctx)
}
