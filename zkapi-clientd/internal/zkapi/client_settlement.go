package zkapi

import (
	"context"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
)

// Group metadata survives cache eviction after a failed or canceled response.
// No credential or request data is retained here. Access requires requestSlot.
type leaseGroup struct {
	serial    uint64
	until     time.Time
	attempted bool
	err       error
}

// RunSettlement retires each request group's key when its fixed window ends,
// even if no further inference arrives. The caller runs it for the daemon's
// lifetime, independently of individual request contexts. The response slot
// keeps settlement behind any active provider stream and serializes it with
// issuance, so an old timer can never retire a newly acquired key.
func (c *Client) RunSettlement(ctx context.Context) {
	var timer *time.Timer
	var expired <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.settlementWake:
		case <-expired:
		}
		select {
		case <-ctx.Done():
			return
		case c.requestSlot <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-c.requestSlot
			return
		}
		if timer != nil {
			timer.Stop()
		}
		expired = nil
		// Always read the current generation after acquiring the slot. A
		// queued request may already have retired and replaced the old group.
		if group := c.leaseGroup; group != nil && !group.attempted {
			if remaining := group.until.Sub(c.now()); remaining > 0 {
				timer = time.NewTimer(remaining)
				expired = timer.C
			} else {
				c.cachedLease = nil
				_ = c.settleGroup(ctx)
			}
		}
		<-c.requestSlot
	}
}

// settleGroup is shared by the timer and the next-request fallback. Mark the
// attempt before the RPC: a lost reply must not cause a second retirement.
// The companion reconciles pending signed state; a successful fresh issuance
// replaces this metadata. Startup recovery without a known group is bounded
// separately by waitForLease's one-attempt guard.
func (c *Client) settleGroup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	group := c.leaseGroup
	var key uint64
	if group != nil {
		if group.attempted {
			return group.err
		}
		group.attempted = true
		key = group.serial
	}
	started := time.Now()
	activity.Diagnostic(ctx, "settlement start key=%d; retiring unused access", key)
	activity.Report(ctx, activity.Event{Kind: activity.SettlementStarted, Key: key})
	err := c.retireLease(ctx)
	activity.Diagnostic(ctx, "settlement finish key=%d ready=%t elapsed=%.3fs; verified amounts follow in wallet events", key, err == nil, time.Since(started).Seconds())
	activity.Report(ctx, activity.Event{Kind: activity.SettlementFinished, Key: key, Complete: err == nil, Duration: time.Since(started)})
	if group != nil {
		group.err = err
	}
	return err
}
