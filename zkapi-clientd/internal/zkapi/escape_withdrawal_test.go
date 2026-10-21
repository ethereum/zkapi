package zkapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// The shared vectors of the exit rules (design §6.4), which the companion's
// Rust wallet and the browser SDK reproduce too.
func TestEscapePayoutMatcherFollowsTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "rust", "crates", "zkapi-client", "tests", "vectors", "exit-rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Payout []struct {
			Paid           uint64   `json:"paid"`
			StateBalance   uint64   `json:"state_balance"`
			ConcededAtInit uint64   `json:"conceded_at_init"`
			Raises         []uint64 `json:"raises"`
			Bound          *uint64  `json:"bound_at_state"`
			Expected       struct {
				Result        string `json:"result"`
				ConcededFinal uint64 `json:"conceded_final"`
				Exceeded      bool   `json:"concession_exceeded_bound"`
			} `json:"expected"`
		} `json:"payout"`
		Constants map[string]uint64 `json:"constants"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors.Payout) == 0 {
		t.Fatalf("invalid vectors: %v", err)
	}
	if vectors.Constants["exit_proof_validity_seconds"] != exitProofValidity {
		t.Fatal("the exit proof lifetime differs from the shared vectors")
	}
	for i, vector := range vectors.Payout {
		got := matchEscapePayout(vector.Paid, vector.StateBalance, vector.ConcededAtInit, vector.Raises, vector.Bound)
		want := vector.Expected.Result == "matches"
		if got.Matches != want || (want && (got.ConcededFinal != vector.Expected.ConcededFinal || got.ExceededBound != vector.Expected.Exceeded)) {
			t.Errorf("vector %d: got %+v, want %+v", i, got, vector.Expected)
		}
	}
}

func testEscapePlan(conceded, stateBalance uint64, destination string) escapePlan {
	decoded, _ := hex.DecodeString(strings.TrimPrefix(destination, "0x"))
	var plan escapePlan
	plan.Status, plan.Action, plan.NoteID = "prepared", "escape", 12
	plan.StateBalance, plan.Conceded, plan.BoundAtState = fmt.Sprint(stateBalance), fmt.Sprint(conceded), "1000"
	plan.PublicInputs = withdrawalInputs{ProtocolVersion: 2, ChainID: 1, Contract: addressTestVault, ActiveRoot: "0x9", StateKeyX: "0x1", StateKeyY: "0x2", ClearanceKeyX: "0x3", ClearanceKeyY: "0x4", NoteID: 12, FinalBalance: stateBalance - conceded, Destination: decoded, Nullifier: "0x123", Kind: 0, NextNullifier: "0x456", Conceded: conceded, ValidUntil: uint64(time.Now().Unix()) + exitProofValidity}
	plan.Proof.Backend = "groth16_bn254"
	plan.Proof.Proof = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 256))
	return plan
}

// Design §6.7: the escape calldata is the 16-word tuple (836 bytes); kind
// 0; a successor nullifier that is set and differs from the nullifier;
// word 9 + word 14 equal to the companion-reported state balance; word 14
// equal to the concession the owner confirmed, at most the bound unless
// zero; valid_until in the signing window; and the binding over words[:16].
func TestEscapeCalldataChecksEveryWord(t *testing.T) {
	config := fundingConfig{ChainID: 1, Contract: addressTestVault}
	saved := func(conceded uint64) *addressWithdrawalRecord {
		return &addressWithdrawalRecord{Mode: "escape", NoteID: 12, Destination: withdrawalTestDestination, StateBalance: 99999, Conceded: conceded, Bound: 1000}
	}
	data, expected, err := escapeCalldata(testEscapePlan(700, 99999, withdrawalTestDestination), config, saved(700), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(data[2:])
	if len(raw) != 836 || hex.EncodeToString(raw[:4]) != "a38d62aa" || escapeSelector != "a38d62aa" {
		t.Fatalf("escape calldata is %d bytes with selector %x", len(raw), raw[:4])
	}
	word := func(i int) *big.Int { return new(big.Int).SetBytes(raw[4+i*32 : 4+(i+1)*32]) }
	if word(9).Uint64()+word(14).Uint64() != 99999 || word(14).Uint64() != 700 || word(12).Sign() != 0 || word(16).Uint64() != 17*32 || word(17).Uint64() != 256 {
		t.Fatal("wrong escape words")
	}
	if err := validateSignedEscape(raw, config, expected, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*escapePlan){
		"close kind":             func(p *escapePlan) { p.PublicInputs.Kind = 1 },
		"no successor":           func(p *escapePlan) { p.PublicInputs.NextNullifier = "0x0" },
		"successor is nullifier": func(p *escapePlan) { p.PublicInputs.NextNullifier = p.PublicInputs.Nullifier },
		"other concession":       func(p *escapePlan) { p.PublicInputs.Conceded = 699; p.PublicInputs.FinalBalance = 99300 },
		"payout plus concession": func(p *escapePlan) { p.PublicInputs.FinalBalance = 99000 },
		"other state balance":    func(p *escapePlan) { p.StateBalance = "100000" },
		"another state's plan":   func(p *escapePlan) { p.StateBalance = "100700"; p.PublicInputs.FinalBalance = 100000 },
		"other destination":      func(p *escapePlan) { p.PublicInputs.Destination = bytes.Repeat([]byte{7}, 20) },
		"other chain":            func(p *escapePlan) { p.PublicInputs.ChainID = 11155111 },
		"other vault":            func(p *escapePlan) { p.PublicInputs.Contract = addressTestToken },
		"other note":             func(p *escapePlan) { p.PublicInputs.NoteID = 13 },
		"expired":                func(p *escapePlan) { p.PublicInputs.ValidUntil = uint64(time.Now().Unix()) - 1 },
		"too far in the future":  func(p *escapePlan) { p.PublicInputs.ValidUntil += exitProofClockAllowance + 60 },
		"short proof":            func(p *escapePlan) { p.Proof.Proof = "AA==" },
		"not prepared":           func(p *escapePlan) { p.Status = "decision" },
	} {
		plan := testEscapePlan(700, 99999, withdrawalTestDestination)
		mutate(&plan)
		if _, _, err := escapeCalldata(plan, config, saved(700), time.Now()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// More than the bound is never conceded; zero always may be.
	if _, _, err := escapeCalldata(testEscapePlan(1001, 99999, withdrawalTestDestination), config, saved(1001), time.Now()); err == nil {
		t.Error("a concession above the bound accepted")
	}
	if _, _, err := escapeCalldata(testEscapePlan(0, 99999, withdrawalTestDestination), config, saved(0), time.Now()); err != nil {
		t.Errorf("a zero concession refused: %v", err)
	}
	// A re-proof keeps the binding unless another bound input changed.
	reproof := testEscapePlan(700, 99999, withdrawalTestDestination)
	reproof.PublicInputs.ActiveRoot, reproof.PublicInputs.ValidUntil = "0xb", reproof.PublicInputs.ValidUntil+5
	if _, again, err := escapeCalldata(reproof, config, expected, time.Now()); err != nil || again.Binding != expected.Binding {
		t.Fatalf("a re-proof at another root changed the binding: %v", err)
	}
	other := testEscapePlan(700, 99999, withdrawalTestDestination)
	other.PublicInputs.StateKeyX = "0x77"
	if _, _, err := escapeCalldata(other, config, expected, time.Now()); err == nil {
		t.Fatal("a changed signing key kept the binding")
	}
	// Signed bytes are checked against the saved confirmation alone too (a
	// resumed transaction has no plan): payout plus concession must be its
	// state balance, the concession within its bound, and the mode escape.
	for name, mutate := range map[string]func(*addressWithdrawalRecord){
		"state balance":          func(r *addressWithdrawalRecord) { r.StateBalance++ },
		"bound below concession": func(r *addressWithdrawalRecord) { r.Bound = r.Conceded - 1 },
		"mode":                   func(r *addressWithdrawalRecord) { r.Mode = "mutual" },
	} {
		record := *expected
		mutate(&record)
		if validateSignedEscape(raw, config, &record, time.Now()) == nil {
			t.Errorf("a saved escape with another %s accepted", name)
		}
	}
	// Every word of the signed bytes is checked.
	for _, index := range []int{0, 1, 2, 8, 9, 10, 11, 12, 13, 14, 16, 17, 4, 15} {
		tampered := append([]byte(nil), raw...)
		tampered[4+index*32+31] ^= 1
		if validateSignedEscape(tampered, config, expected, time.Now()) == nil {
			t.Errorf("word %d tampering accepted", index)
		}
	}
}

// escapeCompanion serves the companion's escape routes for the withdrawal
// fixture: a decision, the plan of the confirmed concession, the chain view
// and the finalization check.
type escapeCompanion struct {
	conceded, bound uint64
	plan            map[string]any
	submitted       []string
	finalized       []string
	chainPhase      string
	trusted         bool
	statuses        int
	deadline        uint64
	payout          uint64
	prepares        []map[string]any
	cancels         int
	// defeatUnread reports a reading whose defeat logs did not load.
	defeatUnread bool
}

func (e *escapeCompanion) serve(t *testing.T, r *http.Request, w *withdrawalFixture) *http.Response {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	switch r.URL.Path {
	case "/oa/v1/withdraw/escape/prepare":
		e.prepares = append(e.prepares, body)
		balance := w.planBalance
		if body["conceded"] == nil {
			return withdrawalJSONResponse(r, 200, map[string]any{"status": "decision", "action": "escape", "note_id": w.noteID, "state_balance": fmt.Sprint(balance), "conceded": fmt.Sprint(e.conceded), "bound_at_state": fmt.Sprint(e.bound), "payout": fmt.Sprint(balance - e.conceded), "reason": "mutual_refused"})
		}
		if body["conceded"] != fmt.Sprint(e.conceded) {
			return withdrawalJSONResponse(r, 409, map[string]any{"error": map[string]any{"code": "conceded_mismatch"}})
		}
		if e.plan == nil {
			plan := testEscapePlan(e.conceded, balance, fmt.Sprint(body["destination"]))
			plan.BoundAtState = fmt.Sprint(e.bound)
			encoded, _ := json.Marshal(plan)
			_ = json.Unmarshal(encoded, &e.plan)
		}
		return withdrawalJSONResponse(r, 200, e.plan)
	case "/oa/v1/withdraw/escape/submit":
		e.submitted = append(e.submitted, fmt.Sprint(body["transaction_hash"]))
		return withdrawalJSONResponse(r, 200, map[string]any{"status": "submitted"})
	case "/oa/v1/withdraw/escape/status":
		e.statuses++
		return withdrawalJSONResponse(r, 200, map[string]any{"phase": e.chainPhase, "challenge_deadline": e.deadline, "payout": fmt.Sprint(e.payout), "trusted": e.trusted, "defeat_checked": !e.defeatUnread})
	case "/oa/v1/withdraw/escape/cancel":
		e.cancels++
		return withdrawalJSONResponse(r, 200, map[string]any{"status": "cancelled"})
	case "/oa/v1/withdraw/escape/finalize":
		e.finalized = append(e.finalized, fmt.Sprint(body["transaction_hash"]))
		w.active = false
		return withdrawalJSONResponse(r, 200, map[string]any{"status": "complete"})
	}
	t.Errorf("unexpected escape route %s", r.URL.Path)
	return withdrawalJSONResponse(r, 404, map[string]any{})
}

// The escape end to end through the address-withdrawal signing path: the
// decision for review, the owner-confirmed concession, a fee quote and its
// approval for initiateEscapeWithdrawal (reported to the companion), the
// challenge period, a raise by the operator, a quoted and approved
// finalizeEscapeWithdrawal whose payout the E5 matcher follows, a credited
// payout, and a quoted and approved claimEscapePayout.
func TestTheEscapeIsSignedFinalizedMatchedAndClaimed(t *testing.T) {
	escapeEndToEnd(t, false)
}

// Design §1.2(6), §6.7: with --exit-rpc-url set, a pinned RPC that refuses
// every call blocks nothing: the decision, quotes, signing, following,
// finalization, the payout match and the claim all read and send through
// the owner's exit RPC.
func TestTheEscapeFollowsTheExitRPCWhileThePinnedRPCIsDown(t *testing.T) {
	f := escapeEndToEnd(t, true)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range []string{"eth_chainId", "eth_getTransactionCount", "eth_estimateGas", "eth_sendRawTransaction", "eth_getTransactionReceipt", "eth_getLogs"} {
		found := false
		for _, called := range f.exitCalls {
			found = found || called == method
		}
		if !found {
			t.Errorf("%s did not go through the exit RPC: %v", method, f.exitCalls)
		}
	}
}

func escapeEndToEnd(t *testing.T, pinnedDown bool) *withdrawalFixture {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 700, bound: 1000, chainPhase: "pending"}
	if pinnedDown {
		f.h.client.config.ExitRPCURL = f.exitRPC
		f.mu.Lock()
		f.pinnedDown = true
		f.mu.Unlock()
	}
	ctx := context.Background()
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_decision" || status.Conceded != 700 || status.Amount != 99999-700 || status.Mode != "escape" || !strings.Contains(status.Message, "--conceded 700") {
		t.Fatalf("no escape decision: %+v %v", status, err)
	}
	// No proof is released without an approved fee quote, nor for another
	// concession than the decision's.
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, &[]uint64{700}[0], ""); err == nil {
		t.Fatal("an escape was signed without a quote")
	}
	if _, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], ""); err == nil {
		t.Fatal("an unconfirmed concession was quoted")
	}
	for _, prepare := range f.escape.prepares {
		if prepare["conceded"] != nil {
			t.Fatal("a concession reached the companion before a quote")
		}
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{700}[0], "")
	if err != nil || quote.Kind != "escape" || quote.Amount != 99999-700 || quote.Binding == "" {
		t.Fatalf("no escape quote: %+v %v", quote, err)
	}
	before := len(f.accepted)
	status, err = f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "escape_pending" || len(f.accepted) != before+1 {
		t.Fatalf("the escape was not signed: %+v %v", status, err)
	}
	record := f.journal(t)
	initiate := f.accepted[record.Pending.Hash]
	if hex.EncodeToString(initiate.Data()[:4]) != "a38d62aa" || len(initiate.Data()) != 836 || initiate.Value().Sign() != 0 {
		t.Fatal("not an initiateEscapeWithdrawal call")
	}
	if len(f.escape.submitted) != 1 || !strings.EqualFold(f.escape.submitted[0], record.Pending.Hash) {
		t.Fatal("the companion was not told the escape transaction")
	}
	// Restart: the saved signed escape survives a reload.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	f.mine(t, record.Pending.Hash, false)
	f.escape.deadline = uint64(time.Now().Unix()) + 3600
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_initiated" || status.ChallengeDeadline != f.escape.deadline {
		t.Fatalf("the initiated escape was not followed: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, ""); err == nil {
		t.Fatal("finalization was quoted before the challenge deadline")
	}
	// The operator raises the concession to 900 (at most the bound). A raise
	// of the note at another nullifier (an escape from another state) is
	// not this escape's.
	nullifier := "0x123"
	f.mu.Lock()
	f.logs = append(f.logs, map[string]any{"address": addressTestVault, "topics": []string{escapeConcessionRaisedTopic, fmt.Sprintf("0x%064x", f.noteID)}, "data": "0x" + addressABIWord(nullifier) + fmt.Sprintf("%064x%064x", 900, 99999-900), "removed": false})
	f.logs = append(f.logs, map[string]any{"address": addressTestVault, "topics": []string{escapeConcessionRaisedTopic, fmt.Sprintf("0x%064x", f.noteID)}, "data": "0x" + addressABIWord("0x777") + fmt.Sprintf("%064x%064x", 950, 99999-950), "removed": false})
	f.mu.Unlock()
	f.escape.deadline, f.escape.payout = uint64(time.Now().Unix())-1, 99999-900
	quote, err = f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" {
		t.Fatalf("no finalize quote: %+v %v", quote, err)
	}
	status, err = f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "finalize_pending" {
		t.Fatalf("finalization was not signed: %+v %v", status, err)
	}
	record = f.journal(t)
	finalize := f.accepted[record.Pending.Hash]
	if "0x"+hex.EncodeToString(finalize.Data()) != finalizeEscapeCalldata(f.noteID) {
		t.Fatal("not a finalizeEscapeWithdrawal call")
	}
	// Finalized: the vault paid B − 900 but could not push it, so it
	// credited the destination.
	deferred := map[string]any{"address": addressTestVault, "topics": []string{escapePayoutDeferredEventTopic, fmt.Sprintf("0x%064x", f.noteID), "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": fmt.Sprintf("0x%064x", 99999-900)}
	finalized := map[string]any{"address": addressTestVault, "topics": []string{escapeFinalizedEventTopic, fmt.Sprintf("0x%064x", f.noteID)}, "data": "0x" + addressABIWord(nullifier) + fmt.Sprintf("%064x", 99999-900) + addressABIWord(withdrawalTestDestination)}
	f.mu.Lock()
	f.receipts[record.Pending.Hash] = map[string]any{"transactionHash": record.Pending.Hash, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestVault, "logs": []map[string]any{deferred, finalized}}
	f.nonce = fmt.Sprintf("0x%x", finalize.Nonce()+1)
	f.mu.Unlock()
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "complete" || status.Amount != 99999-900 || !status.PayoutCredited || status.ConcessionExceededBound || !strings.HasPrefix(status.ClaimCalldata, "0x88c10aee") {
		t.Fatalf("the finalized escape was not matched and closed: %+v %v", status, err)
	}
	if len(f.escape.finalized) != 1 || f.active {
		t.Fatal("the companion did not close the note")
	}
	// Completed through the pinned RPC (no exit RPC set), the status says to
	// check the payout through an independent source; through the owner's
	// exit RPC it does not.
	if advised := strings.Contains(status.Message, "No exit RPC was set when this escape completed") && strings.Contains(status.Message, withdrawalTestDestination); advised == pinnedDown || f.journal(t).Withdrawal.CompletedOnPinnedRPC == pinnedDown {
		t.Fatalf("payout-check advice %v with the exit RPC set %v: %s", advised, pinnedDown, status.Message)
	}
	// Deliver the credit.
	f.mu.Lock()
	f.escapeCredits = map[string]string{strings.ToLower(withdrawalTestDestination): fmt.Sprintf("0x%x", 99999-900)}
	f.mu.Unlock()
	quote, err = f.h.QuoteEscapeClaim(ctx, withdrawalTestDestination)
	if err != nil || quote.Kind != "escape_claim" {
		t.Fatalf("no claim quote: %+v %v", quote, err)
	}
	if _, err = f.h.ApproveAddressEscape(ctx, quote.ID); err != nil {
		t.Fatal(err)
	}
	record = f.journal(t)
	claim := f.accepted[record.Pending.Hash]
	if "0x"+hex.EncodeToString(claim.Data()) != strings.ToLower(claimEscapeCalldata(withdrawalTestDestination)) {
		t.Fatal("not a claimEscapePayout call")
	}
	return f
}

// E5 for a relayed escape of the reserved state (made outside this client,
// for example from an exit kit): the payout is B − c_final with the
// concession recorded at initiation and every raise; anything else is
// refused.
func TestARelayedEscapePayoutAfterARaiseIsMatched(t *testing.T) {
	for _, test := range []struct {
		name     string
		paid     uint64
		accepted bool
		// otherState records the escape at another state's balance.
		otherState uint64
	}{{"raised", 99999 - 900, true, 0}, {"unexplained", 99999 - 901, false, 0}, {"another state", 99999 + 500 - 900, false, 500}} {
		t.Run(test.name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			original := f.withdraw(t)
			f.mineWithdrawal(t, original, withdrawalTestDestination, true)
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
				t.Fatalf("revert not reported: %+v %v", status, err)
			}
			other := "0x" + strings.Repeat("c", 64)
			escapeTopic := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
			f.mu.Lock()
			f.logs = []map[string]any{
				{"address": addressTestVault, "topics": []string{escapeConcessionRecordedTopic, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord("0x999") + fmt.Sprintf("%064x%064x", f.reservedBalance+test.otherState, 100)},
				{"address": addressTestVault, "topics": []string{escapeConcessionRaisedTopic, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x%064x", 900, f.reservedBalance-900)},
			}
			f.receipts[other] = map[string]any{"transactionHash": other, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestToken, "logs": []map[string]any{{"address": addressTestVault, "topics": []string{escapeTopic, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", test.paid) + addressABIWord(withdrawalTestDestination)}}}
			f.closeNote(12)
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", other)
			if !test.accepted {
				if err == nil || f.confirmCalls != 0 {
					t.Fatal("an unexplained escape payout was accepted")
				}
				return
			}
			if err != nil || status.Phase != "complete" || f.journal(t).Withdrawal.Payout != test.paid {
				t.Fatalf("the raised escape payout was not accepted: %+v %v", status, err)
			}
		})
	}
}

// Design §6.7: with --exit-rpc-url set, the escape transaction is sent
// through the owner's exit RPC, not the pinned one, and its reads go there
// first.
func TestEscapesAreSentThroughTheExitRPC(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	f.h.client.config.ExitRPCURL = f.exitRPC
	ctx := context.Background()
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil {
		t.Fatal(err)
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rpcCalls = nil
	f.mu.Unlock()
	if _, err := f.h.ApproveAddressEscape(ctx, quote.ID); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range f.rpcCalls {
		if method == "eth_sendRawTransaction" {
			t.Fatal("the escape went through the pinned RPC")
		}
	}
	sent := false
	for _, method := range f.exitCalls {
		sent = sent || method == "eth_sendRawTransaction"
	}
	if !sent || len(f.rpcCalls) != 0 {
		t.Fatalf("the escape was not read and sent through the exit RPC: exit %v, pinned %v", f.exitCalls, f.rpcCalls)
	}
}

// Design §6.4 E4 step 5: an escape's simulation is advisory. An RPC that
// refuses to simulate it (or to estimate its gas) does not block the exit:
// the quote carries a warning and a fixed gas limit. A mutual close still
// needs its simulation.
func TestAnEscapeWhoseSimulationIsRefusedIsQuotedWithAWarning(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	ctx := context.Background()
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.refuseSimulation = true
	f.mu.Unlock()
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil {
		t.Fatal(err)
	}
	if quote.GasLimit != escapeGasLimits["escape"] || len(quote.Warnings) != 1 || !strings.Contains(quote.Warnings[0], "simulation") {
		t.Fatalf("no advisory quote: %+v", quote)
	}
	status, err := f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "escape_pending" {
		t.Fatalf("the escape was not signed: %+v %v", status, err)
	}
	if tx := f.accepted[f.journal(t).Pending.Hash]; tx.Gas() != escapeGasLimits["escape"] {
		t.Fatalf("signed with gas %d", tx.Gas())
	}
	// A mutual close is not an exit without the operator: it is refused.
	g := newWithdrawalFixture(t, true)
	g.mu.Lock()
	g.refuseSimulation = true
	g.mu.Unlock()
	if _, err := g.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, g.noteID, "", false); err == nil || !strings.Contains(err.Error(), "simulation failed") {
		t.Fatalf("a mutual close without its simulation: %v", err)
	}
}

// A mutual close mined after its valid_until reverts (ProofExpired), and so
// does one held back by an owner's pause. Once the revert is final it can
// never pay, so the escape may proceed from the same note; until then the
// signed close may still land and the escape waits for it.
func TestAnEscapeProceedsAfterAFinallyRevertedClose(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	ctx := context.Background()
	close := f.withdraw(t)
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err == nil || !strings.Contains(err.Error(), "mutual close is pending") {
		t.Fatalf("an escape beside a live close: %v", err)
	}
	f.mineWithdrawal(t, close, withdrawalTestDestination, true)
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_decision" || status.Mode != "escape" {
		t.Fatalf("no escape after the reverted close: %+v %v", status, err)
	}
	record := f.journal(t)
	if record.Pending != nil || len(record.History) == 0 || !strings.EqualFold(record.History[len(record.History)-1].Hash, close) || !record.History[len(record.History)-1].FinalizedRevert {
		t.Fatalf("the reverted close was not retired to the history: %+v", record)
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.ApproveAddressEscape(ctx, quote.ID); err != nil {
		t.Fatal(err)
	}
	if escape := f.accepted[f.journal(t).Pending.Hash]; escape.Nonce() != f.accepted[close].Nonce()+1 {
		t.Fatal("the escape did not take the next nonce")
	}
}

// Design §6.4 E6: an escape that released no exit proof (its decision was
// only shown) is cancelled: the companion drops its lock and the saved
// decision is cleared. Once an escape is signed it is not.
func TestAnEscapeDecisionIsCancelledButASignedEscapeIsNot(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	ctx := context.Background()
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil {
		t.Fatal(err)
	}
	status, err := f.h.CancelAddressEscape(ctx)
	if err != nil || status.Phase != "cancelled" || f.escape.cancels != 1 {
		t.Fatalf("not cancelled: %+v %v", status, err)
	}
	record := f.journal(t)
	if record.Withdrawal != nil || record.Phase != "active" {
		t.Fatalf("the escape decision was kept: %+v", record)
	}
	// A new escape, signed this time.
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil {
		t.Fatal(err)
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.ApproveAddressEscape(ctx, quote.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.CancelAddressEscape(ctx); err == nil || f.escape.cancels != 1 {
		t.Fatal("a signed escape was cancelled")
	}
}

// Design §1.2(6), §6.7, §2.1: with --exit-rpc-url set, an exit RPC that
// does not answer is never replaced by the pinned RPC, which the operator may
// run: the escape stops with an error naming the exit RPC, and the pinned
// RPC is asked nothing.
func TestAnEscapeAsksThePinnedRPCNothingWhenTheExitRPCFails(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	down := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	f.h.client.config.ExitRPCURL = down.URL
	f.mu.Lock()
	f.rpcCalls = nil
	f.mu.Unlock()
	if _, err := f.h.EscapeAddress(context.Background(), withdrawalTestDestination, f.noteID, nil, ""); !errors.Is(err, errExitRPCUnavailable) {
		t.Fatalf("an escape without its exit RPC: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rpcCalls) != 0 {
		t.Fatalf("the pinned RPC answered for the exit RPC: %v", f.rpcCalls)
	}
}

// exitRPCProxy serves the fixture's exit RPC through a proxy that answers
// HTTP 429 to the nth eth_getTransactionCount call (from 0) when refuse(n).
func exitRPCProxy(t *testing.T, f *withdrawalFixture, refuse func(n int) bool) string {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "eth_getTransactionCount") {
			mu.Lock()
			n := calls
			calls++
			mu.Unlock()
			if refuse(n) {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		}
		forwarded, _ := http.NewRequest(http.MethodPost, f.exitRPC, bytes.NewReader(body))
		forwarded.Header.Set("Content-Type", "application/json")
		response, err := client.Do(forwarded)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}

// The nonce an escape is signed at comes from the exit RPC alone: while it
// rate-limits the nonce reads, a pinned RPC that answers a nonce five ahead
// (which would leave the escape unmined) is never asked, and nothing is
// signed; a rate limit that passes is retried, and the escape is signed at
// the exit RPC's nonce.
func TestAnEscapeIsSignedOnlyAtTheExitRPCsNonce(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	var mu sync.Mutex
	refused := 1 << 30
	f.h.client.config.ExitRPCURL = exitRPCProxy(t, f, func(n int) bool {
		mu.Lock()
		defer mu.Unlock()
		return n < refused
	})
	f.mu.Lock()
	f.pinnedNonce, f.rpcCalls = "0x5", nil
	nonce, _ := new(big.Int).SetString(strings.TrimPrefix(f.nonce, "0x"), 16)
	f.mu.Unlock()
	ctx := context.Background()
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil {
		t.Fatal(err)
	}
	accepted := len(f.accepted)
	if _, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], ""); !errors.Is(err, errExitRPCUnavailable) {
		t.Fatalf("quoted without the exit RPC's nonce: %v", err)
	}
	// Two refusals, then answers: the first read is retried.
	mu.Lock()
	refused = 0
	mu.Unlock()
	f.h.client.config.ExitRPCURL = exitRPCProxy(t, f, func(n int) bool { return n < 2 })
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil || quote.Nonce != nonce.Uint64() {
		t.Fatalf("not quoted at the exit RPC's nonce %d: %+v %v", nonce, quote, err)
	}
	status, err := f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "escape_pending" || len(f.accepted) != accepted+1 {
		t.Fatalf("the escape was not signed: %+v %v", status, err)
	}
	if tx := f.accepted[f.journal(t).Pending.Hash]; tx.Nonce() != nonce.Uint64() {
		t.Fatalf("signed at nonce %d, not the exit RPC's %d", tx.Nonce(), nonce)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rpcCalls) != 0 {
		t.Fatalf("the pinned RPC was asked: %v", f.rpcCalls)
	}
}

// An escape transaction is never signed below its entry point's measured
// cost, whatever gas estimate an RPC answers: one that ran out of gas would
// revert and need another proof.
func TestAnEscapeIsNeverSignedBelowItsGasFloor(t *testing.T) {
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
	ctx := context.Background()
	if _, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.gas = "0x5208"
	f.mu.Unlock()
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil || quote.GasLimit != escapeGasLimits["escape"] || len(quote.Warnings) != 0 {
		t.Fatalf("an escape quoted below its gas floor: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressEscape(ctx, quote.ID); err != nil {
		t.Fatal(err)
	}
	if tx := f.accepted[f.journal(t).Pending.Hash]; tx.Gas() != escapeGasLimits["escape"] {
		t.Fatalf("signed with gas %d", tx.Gas())
	}
}

// signEscape decides, quotes and approves an escape conceding nothing, and
// returns the signed initiation.
func (f *withdrawalFixture) signEscape(t *testing.T) *types.Transaction {
	t.Helper()
	ctx := context.Background()
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_decision" {
		t.Fatalf("no escape decision: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, &[]uint64{0}[0], "")
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.h.ApproveAddressEscape(ctx, quote.ID)
	if err != nil || status.Phase != "escape_pending" {
		t.Fatalf("the escape was not signed: %+v %v", status, err)
	}
	return f.accepted[f.journal(t).Pending.Hash]
}

// follow follows the saved escape once.
func (f *withdrawalFixture) follow(t *testing.T) AddressWithdrawalStatus {
	t.Helper()
	status, err := f.h.EscapeAddress(context.Background(), withdrawalTestDestination, f.noteID, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	return status
}

// editJournal rewrites the saved payment record.
func (f *withdrawalFixture) editJournal(t *testing.T, edit func(*addressFundingRecord)) {
	t.Helper()
	record := f.journal(t)
	edit(&record)
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.h.addressStatePath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Design §6.4 E4 step 7: a signed escape that can no longer be included is
// retired unmined and signed again, never followed forever: its nonce was
// taken by another transaction in a finalized block; its nonce lies beyond
// the account's pending nonce (signed at a nonce some RPC answered wrongly)
// past a grace period; or its proof expired while it waited in a mempool,
// where the new escape replaces it at its nonce with higher fees. One mined
// while this was checked is followed, never retired.
func TestAStuckEscapeIsRetiredAndSignedAgain(t *testing.T) {
	retired := func(t *testing.T, f *withdrawalFixture, stuck *types.Transaction) {
		t.Helper()
		status := f.follow(t)
		record := f.journal(t)
		last := record.History[len(record.History)-1]
		if status.Phase != "escape_expired" || record.Pending != nil || !last.Unmined || last.Hash != stuck.Hash().Hex() || !strings.Contains(status.Message, "retired unmined") {
			t.Fatalf("the stuck escape was not retired: %+v %+v", status, record)
		}
	}
	t.Run("nonce gap", func(t *testing.T) {
		f := newWithdrawalFixture(t, true)
		f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
		f.mu.Lock()
		f.nonce = "0x5"
		f.mu.Unlock()
		stuck := f.signEscape(t)
		f.mu.Lock()
		f.nonce = "0x1"
		f.mu.Unlock()
		// Within the grace period the gap may still fill.
		if status := f.follow(t); status.Phase != "escape_pending" {
			t.Fatalf("retired within the grace period: %+v", status)
		}
		f.editJournal(t, func(record *addressFundingRecord) { record.Pending.SignedAt -= 3600 })
		retired(t, f, stuck)
		if again := f.signEscape(t); again.Nonce() != 1 || !bytes.Equal(again.Data(), stuck.Data()) {
			t.Fatalf("the escape was signed again at nonce %d", again.Nonce())
		}
	})
	t.Run("nonce taken", func(t *testing.T) {
		f := newWithdrawalFixture(t, true)
		f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
		stuck := f.signEscape(t)
		f.mu.Lock()
		f.nonce, f.finalizedNonce = fmt.Sprintf("0x%x", stuck.Nonce()+1), fmt.Sprintf("0x%x", stuck.Nonce()+1)
		f.mu.Unlock()
		retired(t, f, stuck)
		if again := f.signEscape(t); again.Nonce() != stuck.Nonce()+1 {
			t.Fatalf("the escape was signed again at nonce %d", again.Nonce())
		}
	})
	t.Run("mined meanwhile", func(t *testing.T) {
		f := newWithdrawalFixture(t, true)
		f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
		landed := f.signEscape(t)
		f.mine(t, landed.Hash().Hex(), false)
		f.mu.Lock()
		f.nonce, f.finalizedNonce = fmt.Sprintf("0x%x", landed.Nonce()+1), fmt.Sprintf("0x%x", landed.Nonce()+1)
		f.hideReceipts = 1
		f.mu.Unlock()
		if status := f.follow(t); status.Phase != "escape_pending" {
			t.Fatalf("a mined escape was retired: %+v", status)
		}
		f.escape.deadline = uint64(time.Now().Unix()) + 3600
		if status := f.follow(t); status.Phase != "escape_initiated" {
			t.Fatalf("the mined escape was not followed: %+v", status)
		}
		for _, entry := range f.journal(t).History {
			if entry.Unmined {
				t.Fatal("a mined escape was recorded as unmined")
			}
		}
	})
	t.Run("expired in a mempool", func(t *testing.T) {
		f := newWithdrawalFixture(t, true)
		f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
		// A proof that expires in five seconds.
		plan := testEscapePlan(0, f.planBalance, withdrawalTestDestination)
		plan.BoundAtState = "0"
		plan.PublicInputs.ValidUntil = uint64(time.Now().Unix()) + 5
		encoded, _ := json.Marshal(plan)
		_ = json.Unmarshal(encoded, &f.escape.plan)
		stuck := f.signEscape(t)
		f.mu.Lock()
		// It waits in the mempool (pending nonce one higher) while the
		// chain moves past its valid_until.
		f.pendingNonce = fmt.Sprintf("0x%x", stuck.Nonce()+1)
		f.mu.Unlock()
		if status := f.follow(t); status.Phase != "escape_pending" {
			t.Fatalf("retired while its proof is valid: %+v", status)
		}
		f.mu.Lock()
		f.latestTime = time.Now().Unix() + 10
		f.mu.Unlock()
		retired(t, f, stuck)
		// A fresh proof, signed at the same nonce with higher fees.
		f.escape.plan = nil
		prepares := len(f.escape.prepares)
		again := f.signEscape(t)
		raised := func(fee *big.Int) *big.Int {
			return new(big.Int).Add(new(big.Int).Add(fee, new(big.Int).Quo(fee, big.NewInt(8))), big.NewInt(1))
		}
		if again.Nonce() != stuck.Nonce() || again.GasFeeCap().Cmp(raised(stuck.GasFeeCap())) < 0 || again.GasTipCap().Cmp(raised(stuck.GasTipCap())) < 0 {
			t.Fatalf("no replacement: nonce %d, fees %s/%s after %s/%s", again.Nonce(), again.GasFeeCap(), again.GasTipCap(), stuck.GasFeeCap(), stuck.GasTipCap())
		}
		if bytes.Equal(again.Data(), stuck.Data()) || len(f.escape.prepares) <= prepares {
			t.Fatal("the expired proof was signed again")
		}
	})
}

// Design §6.4 E6: cancel releases only an escape that released no exit
// proof. An escape on chain is refused and kept, even with no transaction
// pending: a complete one whose payout the vault credited (dropping it would
// lose the credit's claim, which only retiring the record keeps), and a
// defeated one the chain (read again) shows pending after all.
func TestAnEscapeOnChainIsNeverCancelled(t *testing.T) {
	ctx := context.Background()
	refused := func(t *testing.T, f *withdrawalFixture) {
		t.Helper()
		before, _ := json.Marshal(f.journal(t))
		if _, err := f.h.CancelAddressEscape(ctx); err == nil || !strings.Contains(err.Error(), "on chain") {
			t.Fatalf("an escape on chain was cancelled: %v", err)
		}
		after, _ := json.Marshal(f.journal(t))
		if !bytes.Equal(before, after) || f.escape.cancels != 0 {
			t.Fatal("a refused cancel changed the escape")
		}
	}
	t.Run("complete and credited", func(t *testing.T) {
		f := escapeEndToEnd(t, false)
		claim := f.journal(t).Pending.Hash
		f.mu.Lock()
		f.receipts[claim] = map[string]any{"transactionHash": claim, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": addressTestVault, "logs": []map[string]any{}}
		f.nonce = fmt.Sprintf("0x%x", f.accepted[claim].Nonce()+1)
		f.mu.Unlock()
		if _, err := f.h.ClaimEscapePayout(ctx, withdrawalTestDestination); err != nil {
			t.Fatal(err)
		}
		record := f.journal(t)
		if record.Pending != nil || record.Withdrawal == nil || record.Withdrawal.Phase != "complete" || !record.Withdrawal.PayoutCredited {
			t.Fatalf("not a complete credited escape: %+v", record)
		}
		refused(t, f)
	})
	t.Run("defeated", func(t *testing.T) {
		f := newWithdrawalFixture(t, true)
		f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "defeated"}
		initiate := f.signEscape(t)
		f.mine(t, initiate.Hash().Hex(), false)
		status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
		if err == nil || status.Phase != "defeated" || f.journal(t).Pending != nil {
			t.Fatalf("not a defeated escape: %+v %v", status, err)
		}
		// The defeat was one reading; the chain read again shows the
		// escape pending, so it is on chain and kept.
		f.escape.chainPhase = "pending"
		refused(t, f)
	})
}

// Design §6.4 E5 and E6, §2.1: one reading that an escape was defeated
// (without an exit RPC, the pinned RPC's, which the operator may run) is
// never final. Every rerun asks the companion again; once the chain, read
// through the owner's exit RPC configured afterwards, shows the escape
// pending, clientd follows it and finalizes it. A defeat the chain keeps
// showing stays a device_not_newest record the owner can clear.
func TestADefeatIsReadAgainAndNeverFinalOnOneReading(t *testing.T) {
	ctx := context.Background()
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "defeated"}
	initiate := f.signEscape(t)
	f.mine(t, initiate.Hash().Hex(), false)
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if !isDeviceNotNewest(err) || status.Phase != "defeated" || !strings.Contains(status.Message, "pinned RPC") || !strings.Contains(status.Message, "exit-kit escape") {
		t.Fatalf("no untrusted defeat: %+v %v", status, err)
	}
	asked := f.escape.statuses
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if !isDeviceNotNewest(err) || f.escape.statuses != asked+1 {
		t.Fatalf("a saved defeat was not read again: %+v %v (%d readings)", status, err, f.escape.statuses)
	}
	// The truth, through the owner's own RPC: the escape is pending.
	f.h.client.config.ExitRPCURL = f.exitRPC
	f.escape.chainPhase, f.escape.trusted, f.escape.deadline, f.escape.payout = "pending", true, uint64(time.Now().Unix())-1, 99999
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_initiated" || f.journal(t).Withdrawal.Phase != "escape_initiated" {
		t.Fatalf("the pending escape was not followed: %+v %v", status, err)
	}
	quote, err := f.h.QuoteAddressEscape(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || quote.Kind != "escape_finalize" {
		t.Fatalf("no finalization quote: %+v %v", quote, err)
	}

	// A defeat the chain keeps showing, through the exit RPC: kept until the
	// owner clears it, which the chain then allows.
	f = newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "defeated", trusted: true}
	f.h.client.config.ExitRPCURL = f.exitRPC
	initiate = f.signEscape(t)
	f.mine(t, initiate.Hash().Hex(), false)
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if !isDeviceNotNewest(err) || status.Phase != "defeated" || strings.Contains(status.Message, "pinned RPC") {
		t.Fatalf("no trusted defeat: %+v %v", status, err)
	}
	if status, err := f.h.CancelAddressEscape(ctx); err != nil || status.Phase != "cancelled" || f.escape.cancels != 1 {
		t.Fatalf("a defeated escape was not cleared: %+v %v", status, err)
	}
	if record := f.journal(t); record.Withdrawal != nil || record.Phase != "active" {
		t.Fatalf("the defeated record was kept: %+v", record)
	}
}

// An escape whose initiation receipt Go followed but which the chain, read
// through the owner's exit RPC, shows never landed (the companion released
// its dead lock: "expired") is decided and proved again; the same reading
// through the pinned RPC changes nothing.
func TestAnEscapeTheExitRPCShowsNeverLandedIsDecidedAgain(t *testing.T) {
	ctx := context.Background()
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "expired"}
	initiate := f.signEscape(t)
	f.mine(t, initiate.Hash().Hex(), false)
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_initiated" || !strings.Contains(status.Message, "No exit RPC is set") {
		t.Fatalf("a pinned-RPC reading moved the escape: %+v %v", status, err)
	}
	f.h.client.config.ExitRPCURL = f.exitRPC
	f.escape.trusted = true
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_expired" || strings.Contains(status.Message, "No exit RPC is set") {
		t.Fatalf("the escape was not decided again: %+v %v", status, err)
	}
	prepares := len(f.escape.prepares)
	if status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); err != nil || status.Phase != "escape_decision" || len(f.escape.prepares) != prepares+1 {
		t.Fatalf("no fresh decision: %+v %v", status, err)
	}
}

// E6 with failing defeat logs: a reading that could not read whether the
// escape was defeated decides nothing, even through the owner's exit RPC.
// Neither "unknown" nor an "expired" without its defeat logs retires the
// escape or clears a saved defeat; logs that load decide again.
func TestAnEscapeReadingWithoutItsDefeatLogsDecidesNothing(t *testing.T) {
	ctx := context.Background()
	f := newWithdrawalFixture(t, true)
	f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "unknown"}
	f.h.client.config.ExitRPCURL = f.exitRPC
	initiate := f.signEscape(t)
	f.mine(t, initiate.Hash().Hex(), false)
	status, err := f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_initiated" || f.journal(t).Withdrawal.Phase != "escape_initiated" || !strings.Contains(status.Message, escapeUnreadNote) {
		t.Fatalf("an unread defeat moved the escape: %+v %v", status, err)
	}
	f.escape.chainPhase, f.escape.trusted, f.escape.defeatUnread = "expired", true, true
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_initiated" || f.journal(t).Withdrawal.Phase != "escape_initiated" {
		t.Fatalf("an expiry without its defeat logs retired the escape: %+v %v", status, err)
	}
	// A saved defeat is kept through a reading without the logs.
	f.escape.chainPhase, f.escape.defeatUnread = "defeated", false
	if status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, ""); !isDeviceNotNewest(err) || status.Phase != "defeated" {
		t.Fatalf("no defeat: %+v %v", status, err)
	}
	f.escape.chainPhase, f.escape.trusted, f.escape.defeatUnread = "unknown", false, true
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "defeated" || f.journal(t).Withdrawal.Phase != "defeated" || !strings.Contains(status.Message, escapeUnreadNote) {
		t.Fatalf("an unread defeat changed the saved defeat: %+v %v", status, err)
	}
	// Logs that load decide: the escape never landed.
	f.escape.chainPhase, f.escape.trusted, f.escape.defeatUnread = "expired", true, false
	status, err = f.h.EscapeAddress(ctx, withdrawalTestDestination, f.noteID, nil, "")
	if err != nil || status.Phase != "escape_expired" || f.journal(t).Withdrawal.Phase != "escape_expired" {
		t.Fatalf("a checked expiry was not followed: %+v %v", status, err)
	}
}

func isDeviceNotNewest(err error) bool {
	var coded *Error
	return errors.As(err, &coded) && coded.Code == "device_not_newest"
}

// httptestTLS serves JSON-RPC answers from answer(method) over the test TLS
// certificate the fixtures' clients trust.
func httptestTLS(t *testing.T, answer func(method string) any) string {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": answer(request.Method)})
	}))
	t.Cleanup(server.Close)
	return server.URL
}
