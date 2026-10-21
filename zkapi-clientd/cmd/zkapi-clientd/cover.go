package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/cover"
)

func runCoverConfig(dir string, c config.Config, args []string, out io.Writer) error {
	f := flag.NewFlagSet("set-cover", flag.ContinueOnError)
	f.SetOutput(out)
	rate := f.Float64("rate", cover.DefaultRate, "mean requests/sec (0.01–5); continues when idle")
	concurrency := f.Int("concurrency", cover.DefaultConcurrency, "maximum in-flight requests (1–8); excess arrivals dropped")
	urls := f.String("urls", "", "space-separated HTTPS URLs you control or have permission to poll (required)")
	clear := f.Bool("clear", false, "disable cover traffic")
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected set-cover arguments")
	}
	if len(args) == 0 {
		if !c.Cover.Enabled() {
			fmt.Fprintln(out, "Cover traffic disabled.")
			return nil
		}
		fmt.Fprintf(out, "Cover enabled: mean %.3g requests/sec, maximum %d in-flight, %d destinations; active only during serve.\n", c.Cover.Rate, c.Cover.Concurrency, len(strings.Fields(c.Cover.URLs)))
		return nil
	}
	next := c
	if *clear {
		if len(args) != 1 {
			return errors.New("use --clear alone")
		}
		next.Cover = cover.Config{}
	} else {
		next.Cover = cover.Config{Rate: *rate, Concurrency: *concurrency, URLs: *urls}
	}
	if err := config.Update(dir, c, next); err != nil {
		return err
	}
	if *clear {
		fmt.Fprintln(out, "Cover traffic disabled.")
	} else {
		fmt.Fprintln(out, "Cover saved. Uses bandwidth and destination resources, not zkAPI credit. Requires tor:// and IsolateSOCKSAuth; separate cover identities, not guaranteed same exits as inference. Background noise does not guarantee anonymity. Stop/restart serve to apply. No request sent.")
	}
	return nil
}

type coverServeKey struct{}

// Only an explicit long-running serve owns cover traffic, never temporary
// funding/withdrawal runtimes. No prompt, wallet or diagnostics state is passed.
func startServeCover(ctx context.Context, c config.Config, logger *log.Logger) (func(), error) {
	enabled, _ := ctx.Value(coverServeKey{}).(bool)
	if !enabled || !c.Cover.Enabled() {
		return func() {}, nil
	}
	runner, err := cover.Start(ctx, c.Cover, c.RelayURL)
	if err != nil {
		return nil, err
	}
	logger.Printf("Cover traffic enabled: mean %.3g requests/sec, at most %d in-flight; independent Tor identities; bandwidth cost, no anonymity guarantee", c.Cover.Rate, c.Cover.Concurrency)
	done := make(chan struct{})
	finished := make(chan struct{})
	report := func() {
		s := runner.Stats()
		logger.Printf("Cover totals: attempted=%d succeeded=%d failed=%d skipped=%d response_bytes=%d", s.Attempted, s.Succeeded, s.Failed, s.Skipped, s.Bytes)
	}
	go func() {
		defer close(finished)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				report()
			}
		}
	}()
	return func() { runner.Close(); close(done); <-finished; report() }, nil
}
