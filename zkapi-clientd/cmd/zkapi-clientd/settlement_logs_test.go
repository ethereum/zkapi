package main

import (
	"bytes"
	"context"
	"log"
	"testing"
	"time"

	"github.com/OpenAnonymity/oa-chat/oa-clientd/pkg/activity"
)

type settlementRunnerFunc func(context.Context)

func (f settlementRunnerFunc) RunSettlement(ctx context.Context) { f(ctx) }

func TestAutomaticSettlementLogsLocalKeyReferencesAndStopsWithDaemon(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	started, done := make(chan struct{}), make(chan struct{})
	runner := settlementRunnerFunc(func(life context.Context) {
		activity.Report(life, activity.Event{Kind: activity.SettlementStarted, Key: 7})
		activity.Report(life, activity.Event{Kind: activity.SettlementFinished, Key: 7, Complete: true, Duration: 17*time.Second + 125*time.Millisecond})
		activity.Report(life, activity.Event{Kind: activity.SettlementStarted, Key: 8})
		activity.Report(life, activity.Event{Kind: activity.SettlementFinished, Key: 8, Duration: 10*time.Millisecond + 100*time.Microsecond})
		// Request activity is logged only by the HTTP request logger.
		activity.Report(life, activity.Event{Kind: activity.KeyFresh, Key: 9})
		close(started)
		<-life.Done()
	})
	go func() {
		defer close(done)
		runAutomaticSettlement(ctx, log.New(&out, "", 0), runner)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("automatic settlement worker did not start")
	}
	select {
	case <-done:
		t.Fatal("automatic settlement stopped before daemon cancellation")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("automatic settlement did not stop with daemon cancellation")
	}
	want := "key window ended key_ref=7; starting automatic settlement\n" +
		"automatic settlement result key_ref=7 ready=true duration=17.125s\n" +
		"key window ended key_ref=8; starting automatic settlement\n" +
		"automatic settlement result key_ref=8 ready=false duration=10ms\n"
	if got := out.String(); got != want {
		t.Fatalf("automatic settlement logs contain unexpected data or request identity: %s", got)
	}
}
