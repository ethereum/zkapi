package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const relayValidUntil = 2_000_010_800

func relayDeadline(margin time.Duration) time.Time {
	return time.Unix(relayValidUntil, 0).Add(-margin)
}

func TestDecideCloseRelayFollowsTheStatusAndTheDeadline(t *testing.T) {
	margin := DefaultCloseRelaySelfSubmitMargin
	early := relayDeadline(margin).Add(-time.Minute)
	late := relayDeadline(margin)
	cases := []struct {
		name   string
		status *CloseRelayStatus
		now    time.Time
		want   CloseRelayAction
	}{
		{"queued with time left waits", &CloseRelayStatus{Status: "queued"}, early, CloseRelayWait},
		{"submitted with time left waits", &CloseRelayStatus{Status: "submitted"}, early, CloseRelayWait},
		{"queued at the deadline self-submits", &CloseRelayStatus{Status: "queued"}, late, CloseRelaySelfSubmit},
		{"submitted at the deadline self-submits", &CloseRelayStatus{Status: "submitted"}, late, CloseRelaySelfSubmit},
		{"failed self-submits at once", &CloseRelayStatus{Status: "failed", SelfSubmit: true}, early, CloseRelaySelfSubmit},
		{"expired self-submits", &CloseRelayStatus{Status: "expired", SelfSubmit: true}, early, CloseRelaySelfSubmit},
		{"landed is confirmed by the event", &CloseRelayStatus{Status: "landed"}, early, CloseRelayConfirm},
		{"closed is confirmed by the event", &CloseRelayStatus{Status: "closed"}, late, CloseRelayConfirm},
		{"unknown is handed over again", &CloseRelayStatus{Status: "unknown"}, early, CloseRelayResubmit},
		{"unknown at the deadline self-submits", &CloseRelayStatus{Status: "unknown"}, late, CloseRelaySelfSubmit},
		{"an unreadable relay waits while there is time", nil, early, CloseRelayWait},
		{"an unreadable relay at the deadline self-submits", nil, late, CloseRelaySelfSubmit},
	}
	for _, test := range cases {
		if got := DecideCloseRelay(test.status, relayValidUntil, test.now, margin); got != test.want {
			t.Errorf("%s: got %d, want %d", test.name, got, test.want)
		}
	}
}

// fakeRelay scripts the relay's statuses and the chain's MutualClose.
type fakeRelay struct {
	now         time.Time
	statuses    []CloseRelayStatus
	statusErr   error
	seenAt      int // CloseSeen is true from this call on (0: never)
	seenCalls   int
	selfSubmits int
	resubmits   int
	sleeps      int
}

func (f *fakeRelay) follower() CloseRelayFollower {
	return CloseRelayFollower{
		Status: func(context.Context) (CloseRelayStatus, error) {
			if f.statusErr != nil {
				return CloseRelayStatus{}, f.statusErr
			}
			status := f.statuses[0]
			if len(f.statuses) > 1 {
				f.statuses = f.statuses[1:]
			}
			return status, nil
		},
		Resubmit: func(context.Context) (CloseRelayStatus, error) {
			f.resubmits++
			return CloseRelayStatus{Status: "queued"}, nil
		},
		CloseSeen: func(context.Context) (bool, error) {
			f.seenCalls++
			return f.seenAt != 0 && f.seenCalls >= f.seenAt, nil
		},
		SelfSubmit: func(context.Context) error {
			f.selfSubmits++
			return nil
		},
		Now:  func() time.Time { return f.now },
		Poll: time.Minute,
		Sleep: func(context.Context, time.Duration) error {
			f.sleeps++
			f.now = f.now.Add(time.Minute)
			if f.sleeps > 1_000 {
				return errors.New("the follower never ended")
			}
			return nil
		},
	}
}

func TestCloseRelayFollowerWaitsForTheEventOrSubmitsItself(t *testing.T) {
	margin := DefaultCloseRelaySelfSubmitMargin
	start := relayDeadline(margin).Add(-10 * time.Minute)

	// Landed: done once the vault's event is seen, never self-submitted.
	relay := &fakeRelay{now: start, statuses: []CloseRelayStatus{{Status: "queued"}, {Status: "submitted"}, {Status: "landed"}}, seenAt: 5}
	outcome, err := relay.follower().Follow(context.Background(), relayValidUntil)
	if err != nil || outcome != CloseRelayLanded || relay.selfSubmits != 0 {
		t.Fatalf("landed: %v %v %d", outcome, err, relay.selfSubmits)
	}

	// Failed: submitted by the client at once.
	relay = &fakeRelay{now: start, statuses: []CloseRelayStatus{{Status: "failed", SelfSubmit: true, Detail: "payout refused"}}}
	outcome, err = relay.follower().Follow(context.Background(), relayValidUntil)
	if err != nil || outcome != CloseRelaySelfSubmitted || relay.selfSubmits != 1 || relay.sleeps != 0 {
		t.Fatalf("failed: %v %v %d %d", outcome, err, relay.selfSubmits, relay.sleeps)
	}

	// Stuck in the queue: submitted by the client at valid_until - margin,
	// not before.
	relay = &fakeRelay{now: start, statuses: []CloseRelayStatus{{Status: "submitted"}}}
	outcome, err = relay.follower().Follow(context.Background(), relayValidUntil)
	if err != nil || outcome != CloseRelaySelfSubmitted || relay.selfSubmits != 1 {
		t.Fatalf("stuck: %v %v", outcome, err)
	}
	if relay.now.Before(relayDeadline(margin)) {
		t.Fatalf("self-submitted at %v, before the deadline", relay.now)
	}

	// An unreachable relay: the client waits, then submits itself.
	relay = &fakeRelay{now: start, statusErr: errors.New("companion_unavailable")}
	if outcome, err = relay.follower().Follow(context.Background(), relayValidUntil); err != nil || outcome != CloseRelaySelfSubmitted {
		t.Fatalf("unreachable: %v %v", outcome, err)
	}

	// Lost by the relay: handed over again, then landed.
	relay = &fakeRelay{now: start, statuses: []CloseRelayStatus{{Status: "unknown"}, {Status: "queued"}, {Status: "landed"}}, seenAt: 4}
	if outcome, err = relay.follower().Follow(context.Background(), relayValidUntil); err != nil || outcome != CloseRelayLanded || relay.resubmits != 1 {
		t.Fatalf("resubmitted: %v %v %d", outcome, err, relay.resubmits)
	}

	// Reported closed, but no event by the deadline: the client submits
	// itself (a close that reverts costs gas, never the payout).
	relay = &fakeRelay{now: start, statuses: []CloseRelayStatus{{Status: "closed"}}}
	if outcome, err = relay.follower().Follow(context.Background(), relayValidUntil); err != nil || outcome != CloseRelaySelfSubmitted {
		t.Fatalf("closed without event: %v %v", outcome, err)
	}

	// The event appears just before the client would submit: nothing sent.
	relay = &fakeRelay{now: relayDeadline(margin), statuses: []CloseRelayStatus{{Status: "submitted"}}, seenAt: 2}
	if outcome, err = relay.follower().Follow(context.Background(), relayValidUntil); err != nil || outcome != CloseRelayLanded || relay.selfSubmits != 0 {
		t.Fatalf("raced: %v %v %d", outcome, err, relay.selfSubmits)
	}
}

func TestMutualCloseLogMatchesOnlyThisClose(t *testing.T) {
	vault := "0x00000000000000000000000000000000000000aa"
	destination := "0x1111111111111111111111111111111111111111"
	nullifier := "0x0101"
	// The vault's MutualClose golden log (note 7, nullifier 0x101, 900000
	// units, destination 0x11..11).
	log := CloseRelayLog{
		Address: vault,
		Topics:  []string{mutualCloseTopic, "0x0000000000000000000000000000000000000000000000000000000000000007"},
		Data:    "0x000000000000000000000000000000000000000000000000000000000000010100000000000000000000000000000000000000000000000000000000000dbba00000000000000000000000001111111111111111111111111111111111111111",
	}
	if !MutualCloseLogMatches([]CloseRelayLog{log}, vault, 7, nullifier, 900_000, destination) {
		t.Fatal("the vault's MutualClose was not recognized")
	}
	for name, mutate := range map[string]func(*CloseRelayLog){
		"another emitter":  func(l *CloseRelayLog) { l.Address = "0x00000000000000000000000000000000000000bb" },
		"another note":     func(l *CloseRelayLog) { l.Topics[1] = strings.Replace(l.Topics[1], "7", "8", 1) },
		"another event":    func(l *CloseRelayLog) { l.Topics[0] = strings.Replace(l.Topics[0], "1f43", "1f44", 1) },
		"another amount":   func(l *CloseRelayLog) { l.Data = strings.Replace(l.Data, "dbba0", "dbba1", 1) },
		"a removed log":    func(l *CloseRelayLog) { l.Removed = true },
		"another receiver": func(l *CloseRelayLog) { l.Data = strings.Replace(l.Data, "11111111", "22222222", 1) },
	} {
		copy := log
		copy.Topics = append([]string(nil), log.Topics...)
		mutate(&copy)
		if MutualCloseLogMatches([]CloseRelayLog{copy}, vault, 7, nullifier, 900_000, destination) {
			t.Errorf("%s matched", name)
		}
	}
}

func TestCloseRelayCompanionCalls(t *testing.T) {
	inference := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(inference.Close)
	var paths []string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/oa/v1/withdraw/relay/fee":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "paid", "note_id": 3, "fee_units": "250000", "ticket_hash": "0x" + strings.Repeat("ab", 32)})
		case "/oa/v1/withdraw/relay/submit":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "queued", "note_id": 3, "valid_until": relayValidUntil, "self_submit": false})
		case "/oa/v1/withdraw/relay/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "bogus"})
		}
	}, inference)
	ticket, err := client.PayCloseRelayFee(context.Background())
	if err != nil || ticket.FeeUnits != "250000" || ticket.NoteID != 3 {
		t.Fatalf("fee: %+v %v", ticket, err)
	}
	status, err := client.SubmitCloseRelay(context.Background())
	if err != nil || status.Status != "queued" || status.ValidUntil != relayValidUntil {
		t.Fatalf("submit: %+v %v", status, err)
	}
	// An unknown status is refused rather than trusted.
	if _, err := client.CloseRelayState(context.Background()); err == nil {
		t.Fatal("an unknown relay status was accepted")
	}
	want := []string{"POST /oa/v1/withdraw/relay/fee", "POST /oa/v1/withdraw/relay/submit", "GET /oa/v1/withdraw/relay/status"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths %v", paths)
	}
}
