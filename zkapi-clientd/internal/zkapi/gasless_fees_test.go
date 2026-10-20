package zkapi

import (
	"context"
	"math/big"
	"strings"
	"testing"
)

func TestGaslessBundlerPriorityHintKeepsChainAndPolicyBounds(t *testing.T) {
	for _, test := range []struct {
		name             string
		pimlico, rundler any
		wantTip          string
	}{
		{"standard instead of noisy chain median", map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "0x1", "maxFeePerGas": "0x0"}}, nil, "1"},
		{"zero tip still covers base fee", map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "0x0"}}, nil, "0"},
		{"fast fallback", map[string]any{"fast": map[string]string{"maxPriorityFeePerGas": "0x2"}}, nil, "2"},
		{"rundler fallback", nil, "0x3", "3"},
		{"invalid pimlico falls back to rundler", map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "-1"}}, "0x4", "4"},
		{"oversized hint is ignored", map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "0x1" + strings.Repeat("0", 32)}}, "0x5", "5"},
		{"large valid hint respects policy", map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "0xffffffffffffffffffffffffffffffff"}}, nil, "ceiling"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			g.pimlicoFees, g.rundlerTip = test.pimlico, test.rundler
			q, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
			if err != nil {
				t.Fatal(err)
			}
			tip, _ := new(big.Int).SetString(test.wantTip, 10)
			if test.wantTip == "ceiling" {
				tip = new(big.Int).Set(g.priorityCeiling)
			}
			base, err := feeQuantity(f.gasPrice)
			if err != nil {
				t.Fatal(err)
			}
			max := new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(2)), tip)
			if max.Cmp(g.maxFeeCeiling) > 0 {
				max.Set(g.maxFeeCeiling)
			}
			if q.MaxPriorityFeePerGas != tip.String() || q.MaxFeePerGas != max.String() || max.Cmp(new(big.Int).Add(base, tip)) < 0 {
				t.Fatalf("quote did not preserve base-fee/policy bounds: tip=%s max=%s, want %s/%s", q.MaxPriorityFeePerGas, q.MaxFeePerGas, tip, max)
			}
			if len(g.sends) != 0 {
				t.Fatal("fee lookup submitted an operation")
			}
		})
	}
}

func TestGaslessInvalidBundlerHintsUseValidatedChainFallback(t *testing.T) {
	for _, bad := range []any{"0x01", "-1", "0x", 1, "0x1" + strings.Repeat("0", 32), map[string]any{"standard": map[string]any{"maxPriorityFeePerGas": -1}}} {
		f, g := newGaslessWithdrawalFixture(t)
		baseline, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		g.pimlicoFees, g.rundlerTip = bad, bad
		f.mu.Unlock()
		q, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
		if err != nil {
			t.Fatal(err)
		}
		if q.MaxFeePerGas != baseline.MaxFeePerGas || q.MaxPriorityFeePerGas != baseline.MaxPriorityFeePerGas {
			t.Fatalf("malformed hint %v changed chain fallback fees", bad)
		}
	}
}

func TestGaslessBundlerHintCannotRepriceApprovedOperation(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	g.pimlicoFees = map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "0x1"}}
	q, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	g.pimlicoFees = map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "0x3b9aca00"}}
	f.mu.Unlock()
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), q.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	op, _ := gasfromJSON(t, g.ops[status.UserOpHash])
	if op.MaxFeePerGas.String() != q.MaxFeePerGas || op.MaxPriorityFeePerGas.String() != q.MaxPriorityFeePerGas {
		t.Fatal("changed hint repriced approved operation")
	}
	// Reopening the journal and a zero hint must not downgrade or replace the
	// operation already signed under the approved cap either.
	f.mu.Lock()
	g.pimlicoFees = map[string]any{"standard": map[string]string{"maxPriorityFeePerGas": "0x0"}}
	f.mu.Unlock()
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	resumed, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || resumed.UserOpHash != status.UserOpHash {
		t.Fatalf("resumed operation changed: %+v %v", resumed, err)
	}
}
