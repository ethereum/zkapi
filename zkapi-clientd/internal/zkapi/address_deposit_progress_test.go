package zkapi

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDepositPendingStageExplainsFeeWaitWithoutChangingSignedTransaction(t *testing.T) {
	for _, difference := range []int64{-1, 0, 1} {
		t.Run(big.NewInt(difference).String(), func(t *testing.T) {
			f := newAddressFixture(t, true)
			first, err := f.fundNative(t, 100000)
			if err != nil || first.DepositStage != "pending" {
				t.Fatalf("initial deposit: %+v %v", first, err)
			}
			tx := f.accepted[first.TransactionHash]
			f.gasPrice = "0x" + new(big.Int).Add(tx.GasFeeCap(), big.NewInt(difference)).Text(16)
			before, err := os.ReadFile(f.h.addressStatePath())
			if err != nil {
				t.Fatal(err)
			}
			progress, err := f.h.FundAddress(context.Background(), 100000)
			want := "pending"
			if difference > 0 {
				want = "fee_wait"
			}
			if err != nil || progress.Phase != "deposit_pending" || progress.DepositStage != want || progress.TransactionHash != first.TransactionHash {
				t.Fatalf("wrong pending stage: %+v %v", progress, err)
			}
			after, _ := os.ReadFile(f.h.addressStatePath())
			if string(before) != string(after) || strings.Contains(string(after), "deposit_stage") {
				t.Fatal("transient progress changed the durable journal")
			}
			if len(f.accepted) != 1 || len(f.submitted) != 2 || f.submitted[0] != f.submitted[1] || f.activated != 0 {
				t.Fatal("progress repriced/replaced the deposit or activated it before finality")
			}
			encoded, _ := json.Marshal(progress)
			if strings.Contains(string(encoded), f.submitted[0]) || strings.Contains(string(encoded), "0xabcdef") {
				t.Fatal("progress exposed signed bytes or note secrets")
			}
			// A durable phase alone cannot say whether the deposit is included.
			read, err := f.h.Address(context.Background())
			if err != nil || read.DepositStage != "" {
				t.Fatalf("saved status invented transient inclusion progress: %+v %v", read, err)
			}
		})
	}
}

func TestDepositFeeProgressUnavailableLeavesRecoveryPending(t *testing.T) {
	for _, scenario := range []string{"unavailable", "missing", "malformed", "oversized", "missing_timestamp", "malformed_timestamp", "oversized_timestamp", "stale_timestamp", "future_timestamp"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAddressFixture(t, true)
			first, err := f.fundNative(t, 100000)
			if err != nil {
				t.Fatal(err)
			}
			upstream := f.h.client.inference.Transport
			f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
				raw, err := ioReadAndRestore(r)
				if err != nil {
					return nil, err
				}
				var request struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				_ = json.Unmarshal(raw, &request)
				if request.Method != "eth_getBlockByNumber" || string(request.Params[0]) != `"latest"` {
					return upstream.RoundTrip(r)
				}
				if scenario == "unavailable" {
					return withdrawalJSONResponse(r, 503, map[string]any{"error": "sensitive-upstream-diagnostic"}), nil
				}
				// Timestamp failures must suppress fee_wait even when the
				// returned base fee exceeds the saved transaction's cap.
				fee := "0x" + new(big.Int).Add(f.accepted[first.TransactionHash].GasFeeCap(), big.NewInt(1)).Text(16)
				timestamp := "0x" + big.NewInt(time.Now().Unix()).Text(16)
				switch scenario {
				case "missing":
					fee = ""
				case "malformed":
					fee = "sensitive-upstream-diagnostic"
				case "oversized":
					fee = "0x1" + strings.Repeat("0", 64)
				case "missing_timestamp":
					timestamp = ""
				case "malformed_timestamp":
					timestamp = "sensitive-upstream-diagnostic"
				case "oversized_timestamp":
					timestamp = "0x1" + strings.Repeat("0", 64)
				case "stale_timestamp":
					timestamp = "0x" + big.NewInt(time.Now().Unix()-121).Text(16)
				case "future_timestamp":
					timestamp = "0x" + big.NewInt(time.Now().Unix()+60).Text(16)
				}
				return withdrawalJSONResponse(r, 200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]string{"baseFeePerGas": fee, "timestamp": timestamp}}), nil
			})
			progress, err := f.h.FundAddress(context.Background(), 100000)
			if err != nil || progress.DepositStage != "pending" || progress.Phase != "deposit_pending" || progress.TransactionHash != first.TransactionHash {
				t.Fatalf("optional fee read blocked saved-transaction recovery: %+v %v", progress, err)
			}
			encoded, _ := json.Marshal(progress)
			if strings.Contains(string(encoded), "sensitive-upstream") || len(f.accepted) != 1 || len(f.submitted) != 2 || f.submitted[0] != f.submitted[1] {
				t.Fatal("fee diagnostic leaked or changed the saved transaction")
			}
		})
	}
}

func TestDepositReceiptFailureLeavesDurableInclusionUnknown(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, true)
	f.finalized = "0x1"
	progress, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || progress.DepositStage != "failed_finalizing" {
		t.Fatalf("initial inclusion check: %+v %v", progress, err)
	}
	before, err := os.ReadFile(f.h.addressStatePath())
	if err != nil {
		t.Fatal(err)
	}
	upstream := f.h.client.inference.Transport
	f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		raw, err := ioReadAndRestore(r)
		if err != nil {
			return nil, err
		}
		var request struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(raw, &request)
		if request.Method == "eth_getTransactionReceipt" {
			return withdrawalJSONResponse(r, 503, map[string]any{"error": "sensitive-receipt-diagnostic"}), nil
		}
		return upstream.RoundTrip(r)
	})
	progress, err = f.h.FundAddress(context.Background(), 100000)
	if err == nil || progress.Phase != "deposit_pending" || progress.DepositStage != "" || progress.TransactionHash != first.TransactionHash {
		t.Fatalf("receipt failure invented lost inclusion: %+v %v", progress, err)
	}
	if strings.Contains(err.Error(), "sensitive-receipt") {
		t.Fatal("receipt failure exposed upstream diagnostics")
	}
	// The CLI can fall back to Address after an unavailable resume request,
	// including across a restart. Neither may invent an unmined state.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	saved, err := f.h.Address(context.Background())
	if err != nil || saved.Phase != "deposit_pending" || saved.DepositStage != "" || saved.TransactionHash != first.TransactionHash {
		t.Fatalf("durable fallback invented lost inclusion: %+v %v", saved, err)
	}
	after, _ := os.ReadFile(f.h.addressStatePath())
	if string(before) != string(after) || len(f.accepted) != 1 || len(f.submitted) != 1 || f.activated != 0 {
		t.Fatal("receipt failure changed the journal or performed a transaction")
	}
}

func TestDepositIncludedStageActivatesBeforeFinalityWithoutRebroadcast(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, false)
	f.finalized = "0x1"
	upstream := f.h.client.inference.Transport
	f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		raw, err := ioReadAndRestore(r)
		if err != nil {
			return nil, err
		}
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(raw, &request)
		if request.Method == "eth_getBlockByNumber" && string(request.Params[0]) == `"finalized"` {
			t.Error("successful mined deposit requested finality")
		}
		return upstream.RoundTrip(r)
	})
	progress, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || progress.Phase != "active" || progress.DepositStage != "awaiting_activation" || progress.TransactionHash != first.TransactionHash || f.activated != 1 || len(f.submitted) != 1 {
		t.Fatalf("mined deposit was not saved or repeated broadcast: %+v %v", progress, err)
	}

	// The operator's batch activates the recorded note.
	f.finalized = "0x20"
	f.mu.Lock()
	f.activate(1)
	f.mu.Unlock()
	active, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || active.Phase != "active" || active.DepositStage != "active" || active.Activated == nil || !*active.Activated || f.activated != 1 || len(f.accepted) != 1 {
		t.Fatalf("final deposit was not saved once, then reported activated: %+v %v", active, err)
	}
}

func TestDepositActivationFailureHasSeparateStageAndSafeRecovery(t *testing.T) {
	f := newAddressFixture(t, true)
	first, err := f.fundNative(t, 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, false)
	f.finalized = "0x1"
	upstream := f.h.client.local.Transport
	f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/funding/api/deposit/confirm" {
			return withdrawalJSONResponse(r, 503, map[string]any{"error": "sensitive-activation-diagnostic"}), nil
		}
		return upstream.RoundTrip(r)
	})
	progress, err := f.h.FundAddress(context.Background(), 100000)
	if err == nil || progress.Phase != "confirming" || progress.DepositStage != "activating" || f.activated != 0 {
		t.Fatalf("activation failure lost confirmed stage: %+v %v", progress, err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	saved, err := f.h.Address(context.Background())
	if err != nil || saved.DepositStage != "activating" || saved.TransactionHash != first.TransactionHash {
		t.Fatalf("restart lost activation progress: %+v %v", saved, err)
	}
	f.h.client.local.Transport = upstream
	active, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || active.DepositStage != "awaiting_activation" || active.TransactionHash != first.TransactionHash || f.activated != 1 || len(f.submitted) != 1 || len(f.accepted) != 1 {
		t.Fatalf("activation retry changed the transaction or initialized twice: %+v %v", active, err)
	}
}

func TestDepositBalanceRaceReturnsToFundingWithSameUnsignedNote(t *testing.T) {
	f := newAddressFixture(t, true)
	quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	// Funds were sufficient at quote time, but no longer cover network fees
	// when approval rechecks them. No signed transaction may be manufactured.
	f.eth = "0x" + quoteNumber(t, quote.PrincipalWei).Text(16)
	status, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID)
	if err != nil || status.Phase != "waiting_funds" || status.DepositStage != "" || status.TransactionHash != "" || len(f.submitted) != 0 {
		t.Fatalf("balance race did not preserve unsigned funding: %+v %v", status, err)
	}
	refreshed, err := f.h.QuoteAddressDeposit(context.Background(), quote.Amount)
	if err != nil || refreshed.Commitment != quote.Commitment || refreshed.Amount != quote.Amount || refreshed.Nonce != quote.Nonce || refreshed.ID == quote.ID || f.prepared != 1 {
		t.Fatalf("requote replaced the saved private note: %+v %v", refreshed, err)
	}
	f.eth = "0x" + quoteNumber(t, refreshed.RecommendedTotalWei).Text(16)
	status, err = f.h.ApproveAddressDeposit(context.Background(), refreshed.ID)
	if err != nil || status.Phase != "deposit_pending" || status.DepositStage != "pending" || len(f.accepted) != 1 || len(f.submitted) != 1 || f.prepared != 1 {
		t.Fatalf("funded exact note did not submit once: %+v %v", status, err)
	}
	if f.accepted[status.TransactionHash].Nonce() != quote.Nonce {
		t.Fatal("funding recovery changed the approved nonce")
	}
}
