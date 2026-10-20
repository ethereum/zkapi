package zkapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

const relayTestBatcher = "0xba7c000000000000000000000000000000000001"
const relayTestFee = 1000

// relayCompanion adds the companion's close-relay routes to a withdrawal
// fixture: the server's terms, the fee request (which moves the note to its
// successor, the fee deducted), the submission and the relay's status.
type relayCompanion struct {
	enabled               bool
	feeCalls, submissions int
	statusCalls           int
	status                string
}

func withRelay(t *testing.T, f *withdrawalFixture) *relayCompanion {
	t.Helper()
	relay := &relayCompanion{enabled: true, status: "queued"}
	upstream := f.h.client.local.Transport
	f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/oa/v1/withdraw/relay/terms":
			if !relay.enabled {
				return withdrawalJSONResponse(r, 200, map[string]any{"enabled": false}), nil
			}
			return withdrawalJSONResponse(r, 200, map[string]any{"enabled": true, "fee_units": fmt.Sprint(relayTestFee), "exit_batcher": relayTestBatcher}), nil
		case "/oa/v1/withdraw/relay/fee":
			relay.feeCalls++
			if f.reservedDestination != "" {
				t.Error("the relay fee was paid after the withdrawal was prepared")
			}
			if relay.feeCalls == 1 {
				f.walletBalance -= relayTestFee
				f.planBalance = f.walletBalance
			}
			return withdrawalJSONResponse(r, 200, map[string]any{"status": "paid", "note_id": f.noteID, "fee_units": fmt.Sprint(relayTestFee), "ticket_hash": "0x" + strings.Repeat("ab", 32)}), nil
		case "/oa/v1/withdraw/relay/submit":
			relay.submissions++
			if f.reservedDestination == "" {
				t.Error("a close was submitted before it was prepared")
			}
			return withdrawalJSONResponse(r, 202, map[string]any{"status": "queued", "note_id": f.noteID, "valid_until": 2_000_000_000, "self_submit": false}), nil
		case "/oa/v1/withdraw/relay/status":
			relay.statusCalls++
			return withdrawalJSONResponse(r, 200, map[string]any{"status": relay.status, "self_submit": relay.status == "failed" || relay.status == "expired"}), nil
		}
		return upstream.RoundTrip(r)
	})
	return relay
}

func relayContext() context.Context {
	return WithWithdrawalOptions(context.Background(), addressWithdrawalOptions{Fees: "relay"})
}

// quoteAndApproveRelay quotes a relayed close, checks the quote, and approves
// it: the fee is paid, the close prepared at the successor and handed over.
func quoteAndApproveRelay(t *testing.T, f *withdrawalFixture, relay *relayCompanion) AddressWithdrawalStatus {
	t.Helper()
	quote, err := f.h.QuoteAddressWithdrawal(relayContext(), withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if quote.FeePolicy != "relay" || quote.RelayFeeUnits != fmt.Sprint(relayTestFee) || quote.Amount != 99999-relayTestFee || quote.GasLimit != relayFallbackGas || quote.PrincipalWei != "0" {
		t.Fatalf("relay quote: %+v", quote)
	}
	// Quoting pays nothing and reserves nothing at the companion.
	if relay.feeCalls != 0 || f.prepareCalls != 0 || relay.submissions != 0 {
		t.Fatal("quoting a relayed close paid, prepared or submitted something")
	}
	status, err := f.h.ApproveAddressWithdrawal(context.Background(), quote.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != "relay_submitted" || status.FeePayer != "relay" || status.RelayFeeUnits != fmt.Sprint(relayTestFee) || relay.feeCalls != 1 || f.prepareCalls != 1 || relay.submissions != 1 {
		t.Fatalf("relay approval: %+v (fee %d, prepare %d, submit %d)", status, relay.feeCalls, f.prepareCalls, relay.submissions)
	}
	record := f.journal(t)
	if record.Pending != nil || record.Withdrawal.Amount != 99999-relayTestFee || record.Withdrawal.Relay.Fallback.Binding != record.Withdrawal.Binding || record.Withdrawal.ValidUntil == 0 {
		t.Fatalf("relay journal: %+v", record.Withdrawal)
	}
	return status
}

// landRelayedClose makes the relay's batch transaction emit the vault's
// MutualClose of the reserved close (finalized), and the vault and indexer
// show the note closed.
func landRelayedClose(f *withdrawalFixture, hash string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	log := map[string]any{"address": addressTestVault, "topics": []string{crypto.Keccak256Hash([]byte("MutualClose(uint32,uint256,uint128,address)")).Hex(), fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(withdrawalTestDestination), "transactionHash": hash, "removed": false}
	f.logs = append(f.logs, log)
	f.receipts[hash] = map[string]any{"transactionHash": hash, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": relayTestBatcher, "logs": []map[string]any{log}}
	f.closeNote(uint32(f.reservedNoteID))
}

func TestRelayedCloseLandsThroughTheBatcherWithoutSigning(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	relay := withRelay(t, f)
	quoteAndApproveRelay(t, f, relay)
	accepted := len(f.accepted)
	// The relay holds it: polls wait, nothing is signed.
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "relay_submitted" || status.RelayStatus != "queued" || !strings.Contains(status.Message, "relay") {
		t.Fatalf("relay poll: %+v %v", status, err)
	}
	if relay.statusCalls == 0 || len(f.accepted) != accepted || f.journal(t).Pending != nil {
		t.Fatal("following the relay signed or broadcast something")
	}
	// A new quote while the relay holds it is refused.
	if _, err := f.h.QuoteAddressWithdrawal(relayContext(), withdrawalTestDestination, f.noteID, "", false); err == nil {
		t.Fatal("a relayed close in flight was quoted again")
	}
	// The vault's MutualClose of this close lands, through the batcher.
	hash := "0x" + strings.Repeat("be", 32)
	landRelayedClose(f, hash)
	f.finalized = "0x1"
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase == "complete" || f.confirmCalls != 0 {
		t.Fatalf("completed before finality: %+v %v", status, err)
	}
	f.finalized = "0x20"
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.Amount != 99999-relayTestFee || f.confirmCalls != 1 || f.completedHash != hash {
		t.Fatalf("relayed close did not complete: %+v %v", status, err)
	}
	record := f.journal(t)
	if record.Pending != nil || len(f.accepted) != accepted || record.Withdrawal.SettlementHash != hash {
		t.Fatalf("relayed completion: %+v", record.Withdrawal)
	}
	// Idempotent afterwards.
	if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
		t.Fatalf("after completion: %+v %v", status, err)
	}
}

func TestRelayedCloseFallsBackToThePreApprovedWalletClose(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	relay := withRelay(t, f)
	quoteAndApproveRelay(t, f, relay)
	// The relay gives the close back: the client signs the wallet-paid close
	// under the relay quote's approval, without another quote.
	relay.status = "failed"
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "withdrawal_pending" {
		t.Fatalf("fallback: %+v %v", status, err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "withdrawal" || record.Withdrawal.FeePayer != "" || record.Withdrawal.Relay.Phase != "self_submitted" {
		t.Fatalf("fallback journal: %+v %+v", record.Pending, record.Withdrawal)
	}
	tx := f.accepted[record.Pending.Hash]
	if tx == nil || !strings.EqualFold(tx.To().Hex(), addressTestVault) || tx.Value().Sign() != 0 {
		t.Fatal("the fallback is not the wallet-paid mutualClose")
	}
	if err := validateSignedWithdrawal(tx.Data(), fundingConfig{ChainID: 1, Contract: addressTestVault}, record.Withdrawal, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The ordinary path completes it.
	f.mineWithdrawal(t, record.Pending.Hash, withdrawalTestDestination, false)
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
		t.Fatalf("fallback completion: %+v %v", status, err)
	}
}

func TestRelayedCloseFallbackNeedsAFreshQuoteOnceItsApprovalNoLongerApplies(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	relay := withRelay(t, f)
	quoteAndApproveRelay(t, f, relay)
	relay.status = "expired"
	// Another transaction took the approved nonce.
	f.nonce = "0x7"
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "quoted" || !strings.Contains(status.Message, "--fees wallet") {
		t.Fatalf("stale fallback: %+v %v", status, err)
	}
	record := f.journal(t)
	if record.Pending != nil || record.Withdrawal.FeePayer != "" || record.Withdrawal.Binding == "" {
		t.Fatalf("stale fallback journal: %+v", record.Withdrawal)
	}
}

func TestRelayModeIsRefusedWithoutARelayAndAfterPreparation(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	relay := withRelay(t, f)
	relay.enabled = false
	if _, err := f.h.QuoteAddressWithdrawal(relayContext(), withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "does not relay") {
		t.Fatalf("relay off: %v", err)
	}
	if record := f.journal(t); record.Withdrawal != nil {
		t.Fatal("a refused relay quote reserved a withdrawal")
	}
	// A wallet-paid withdrawal that was prepared cannot move to the relay.
	relay.enabled = true
	f.withdraw(t)
	if _, err := f.h.WithdrawAddress(relayContext(), withdrawalTestDestination, f.noteID); err == nil {
		t.Fatal("a prepared wallet-paid withdrawal moved to the relay")
	}
	if relay.feeCalls != 0 {
		t.Fatal("the relay fee was paid for a prepared withdrawal")
	}
}
