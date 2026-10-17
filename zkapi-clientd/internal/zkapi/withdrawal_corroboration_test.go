package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestWithdrawalRequiresClearanceOwnershipCapability(t *testing.T) {
	t.Run("the concession deployment requires the capability", func(t *testing.T) {
		f := newWithdrawalFixture(t)
		f.withdraw(t) // The companion reports clearance_ownership_proof_version 1.
		if f.prepareCalls != 1 {
			t.Fatal("a capable companion could not withdraw")
		}
	})
	for _, capability := range []deploymentCapabilities{{VaultRevision: 3, ClearanceOwnershipProof: "required"}, {VaultRevision: 2}, {ClearanceOwnershipProof: "optional"}} {
		t.Run(fmt.Sprintf("%+v", capability), func(t *testing.T) {
			f := newWithdrawalFixture(t)
			f.ownershipProofVersion = 0
			f.h.client.capabilities = &capability
			before := f.journal(t)
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err == nil || !strings.Contains(err.Error(), "ownership proofs") {
				t.Fatalf("outdated companion was allowed to reserve the note: %v", err)
			}
			after := f.journal(t)
			if f.prepareCalls != 0 || f.reservedDestination != "" || after.Withdrawal != nil || after.Phase != before.Phase {
				t.Fatal("refused withdrawal reserved the note or saved intent")
			}
			if _, err := f.h.AddressWithdrawal(context.Background()); err != nil {
				t.Fatalf("status reads require the clearance capability: %v", err)
			}
			// A saved withdrawal without a proof plan is gated at prepare.
			f.ownershipProofVersion, f.pending = 1, true
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "waiting_settlement" {
				t.Fatalf("capable companion could not save the withdrawal: %+v %v", status, err)
			}
			f.ownershipProofVersion, f.pending = 0, false
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err == nil || f.prepareCalls != 0 {
				t.Fatal("a downgraded companion reached prepare for an unplanned withdrawal")
			}
			f.ownershipProofVersion = 1
			hash := f.withdraw(t)
			// Finishing an already signed withdrawal never needs the gate.
			f.ownershipProofVersion = 0
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.prepareCalls != 1 {
				t.Fatalf("the gate blocked finality bookkeeping: %+v %v", status, err)
			}
		})
	}
}

// Review root cause on the withdrawal side: a receipt alone must not decide
// that the note closed. A forged MutualClose receipt never deletes the
// companion's note state or archives the deposit recovery file while the
// vault, read at the receipt's canonical block, shows the note open.
func TestForgedMutualCloseReceiptNeverClosesNote(t *testing.T) {
	for _, vault := range []string{"active", "pending withdrawal"} {
		t.Run(vault, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			hash := f.withdraw(t)
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			f.mu.Lock()
			note := f.vaultNotes[12]
			note.status = noteActive
			if vault == "pending withdrawal" {
				note.status = notePendingWithdrawal
			}
			f.vaultNotes[12] = note
			f.mu.Unlock()
			for range 2 {
				status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
				if err != nil || status.Phase != "withdrawal_pending" || status.Message != withdrawalVerifyingMessage {
					t.Fatalf("forged close was not held pending: %+v %v", status, err)
				}
			}
			if f.confirmCalls != 0 || !f.active || f.journal(t).Pending == nil || f.journal(t).Withdrawal.Phase != "withdrawal_pending" {
				t.Fatal("forged close reached the companion or retired the signed withdrawal")
			}
			if _, err := os.Stat(f.h.statePath); err != nil {
				t.Fatal("forged close archived the deposit recovery file")
			}
			f.mu.Lock()
			f.closeNote(12)
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
				t.Fatalf("corroborated close did not complete: %+v %v", status, err)
			}
		})
	}
}

// A close changes no tree leaf, so the vault's Closed status at the payout
// block is the closing evidence and the indexer's tree is not read. A note
// closed after its activation keeps its leaf in the tree, and one closed
// before it is inserted later by its batch; neither waits for an operator.
func TestClosedNoteCompletesWhateverItsTreeLeaf(t *testing.T) {
	for name, activated := range map[string]bool{"activated": true, "recorded only": false} {
		t.Run(name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			if activated {
				f.mu.Lock()
				f.activate(1)
				f.mu.Unlock()
			}
			hash := f.withdraw(t)
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			f.mu.Lock()
			inTree, snapshots := f.treeLeaves()[12].Sign() != 0, f.snapshotReads
			f.mu.Unlock()
			if inTree != activated {
				t.Fatal("the fixture's tree does not match the note's activation")
			}
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
				t.Fatalf("the closed note did not complete: %+v %v", status, err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.snapshotReads != snapshots {
				t.Fatal("completing the withdrawal read the indexer's tree")
			}
		})
	}
}

// Review finding (clientd-flows 1): with an exit RPC configured, the
// payment RPC alone never completes a withdrawal. The owner's exit RPC must
// also show the same final payout receipt and the note closed at its block.
func TestWithdrawalCompletionNeedsTheExitRPCsAgreement(t *testing.T) {
	for name, disagree := range map[string]func(f *withdrawalFixture){
		"exit vault shows the note open": func(f *withdrawalFixture) {
			f.exitVaultNotes = maps.Clone(f.vaultNotes)
			note := f.exitVaultNotes[12]
			note.status = notePendingWithdrawal
			f.exitVaultNotes[12] = note
		},
		"exit RPC has no receipt": func(f *withdrawalFixture) { f.exitHidesReceipts = true },
		"exit RPC not final":      func(f *withdrawalFixture) { f.exitFinalized = "0xf" },
		// The exit RPC's receipt must be the payment RPC's: the same block,
		// by number and by hash, the same status and the same logs.
		"exit receipt in another block": func(f *withdrawalFixture) {
			f.exitReceipt = func(receipt map[string]any) { receipt["blockNumber"] = "0x11" }
		},
		"exit RPC on another fork": func(f *withdrawalFixture) {
			// Its vault state at the payment RPC's block is refused, but at
			// its own finalized block it shows the note closed.
			fork := "0x" + strings.Repeat("f", 64)
			f.exitCanonical = fork
			f.exitReceipt = func(receipt map[string]any) { receipt["blockHash"] = fork }
		},
		"exit receipt reverted": func(f *withdrawalFixture) {
			f.exitReceipt = func(receipt map[string]any) { receipt["status"] = "0x0" }
		},
		"exit receipt pays another destination": func(f *withdrawalFixture) {
			data := "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(addressTestToken)
			f.exitReceipt = func(receipt map[string]any) {
				log := maps.Clone(receipt["logs"].([]map[string]any)[0])
				log["data"] = data
				receipt["logs"] = []map[string]any{log}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			f.h.client.config.ExitRPCURL = f.exitRPC
			hash := f.withdraw(t)
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			f.mu.Lock()
			disagree(f)
			f.mu.Unlock()
			for range 2 {
				status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
				if err != nil || status.Phase != "withdrawal_pending" || status.Message != withdrawalVerifyingMessage || status.ExitRPCUnusable {
					t.Fatalf("the payment RPC alone completed the withdrawal: %+v %v", status, err)
				}
			}
			if f.confirmCalls != 0 || !f.active || f.journal(t).Pending == nil {
				t.Fatal("an uncorroborated close reached the companion or retired the signed withdrawal")
			}
			if _, err := os.Stat(f.h.statePath); err != nil {
				t.Fatal("an uncorroborated close archived the deposit recovery file")
			}
			f.mu.Lock()
			f.exitVaultNotes, f.exitHidesReceipts, f.exitFinalized = nil, false, ""
			f.exitReceipt, f.exitCanonical = nil, ""
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
				t.Fatalf("the close both RPCs show did not complete: %+v %v", status, err)
			}
		})
	}
}

// Two receipts of one payout carry the same logs only when every field of
// every log agrees; hex case alone may differ between RPCs.
func TestSameReceiptLogsComparesEveryLogField(t *testing.T) {
	receipt := func(edit func(log map[string]any), extra ...map[string]any) *addressReceipt {
		log := map[string]any{"address": addressTestVault, "topics": []string{"0x" + strings.Repeat("ab", 32), fmt.Sprintf("0x%064x", 12)}, "data": "0x" + strings.Repeat("cd", 32), "removed": false}
		if edit != nil {
			edit(log)
		}
		raw, _ := json.Marshal(map[string]any{"logs": append([]map[string]any{log}, extra...)})
		var decoded addressReceipt
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		return &decoded
	}
	upper := func(hex string) string { return "0x" + strings.ToUpper(hex[2:]) }
	base := receipt(nil)
	if !sameReceiptLogs(base, receipt(func(log map[string]any) {
		log["address"], log["data"] = upper(addressTestVault), upper(log["data"].(string))
		log["topics"] = []string{upper(log["topics"].([]string)[0]), log["topics"].([]string)[1]}
	})) {
		t.Fatal("logs differing only in hex case were not the same")
	}
	for name, other := range map[string]*addressReceipt{
		"another log count": receipt(nil, map[string]any{"address": addressTestVault, "topics": []string{}, "data": "0x"}),
		"removed":           receipt(func(log map[string]any) { log["removed"] = true }),
		"another emitter":   receipt(func(log map[string]any) { log["address"] = addressTestToken }),
		"other data":        receipt(func(log map[string]any) { log["data"] = "0x" + strings.Repeat("ce", 32) }),
		"another topic": receipt(func(log map[string]any) {
			log["topics"] = []string{"0x" + strings.Repeat("ab", 32), fmt.Sprintf("0x%064x", 13)}
		}),
		"fewer topics": receipt(func(log map[string]any) { log["topics"] = []string{"0x" + strings.Repeat("ab", 32)} }),
	} {
		if sameReceiptLogs(base, other) || sameReceiptLogs(other, base) {
			t.Errorf("%s: the logs were the same", name)
		}
	}
}

// Review finding (clientd-flows 1, follow-up): an exit RPC that cannot check
// the close at all (it does not answer, serves another network, or refuses
// reads at a block hash, EIP-1898) is named in the status, so the owner can
// fix the configuration instead of waiting for a vault state that never
// comes. The withdrawal still waits, and completes once the exit RPC works.
func TestWithdrawalNamesAnExitRPCThatCannotCheckTheClose(t *testing.T) {
	down := httptest.NewTLSServer(http.NotFoundHandler())
	down.Close()
	for name, broken := range map[string]func(f *withdrawalFixture){
		"unreachable":              func(f *withdrawalFixture) { f.h.client.config.ExitRPCURL = down.URL },
		"another network":          func(f *withdrawalFixture) { f.exitChain = "0xaa36a7" },
		"refuses block-hash reads": func(f *withdrawalFixture) { f.exitRefusesBlockHash = true },
		"rate-limits receipts": func(f *withdrawalFixture) {
			f.exitUnavailable = map[string]bool{"eth_getTransactionReceipt": true}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			f.h.client.config.ExitRPCURL = f.exitRPC
			hash := f.withdraw(t)
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			f.mu.Lock()
			broken(f)
			f.mu.Unlock()
			for range 2 {
				status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
				if err != nil || status.Phase != "withdrawal_pending" || status.Message != withdrawalExitRPCUnusableMessage || !status.ExitRPCUnusable {
					t.Fatalf("the unusable exit RPC was not named: %+v %v", status, err)
				}
			}
			if f.confirmCalls != 0 || !f.active || f.journal(t).Pending == nil {
				t.Fatal("a close the exit RPC could not check reached the companion or retired the signed withdrawal")
			}
			f.mu.Lock()
			f.exitChain, f.exitRefusesBlockHash, f.exitUnavailable = "", false, nil
			f.mu.Unlock()
			f.h.client.config.ExitRPCURL = f.exitRPC
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
				t.Fatalf("the close did not complete once the exit RPC worked: %+v %v", status, err)
			}
		})
	}
}

// Review finding (clientd-fixes, sponsored close): a gasless close reads the
// payout and the vault through the exit RPC alone (exitOnly). An exit RPC
// that cannot read the vault once the payout is final there (it refuses
// reads at a block hash, EIP-1898, or does not answer them) is named the
// same way, not left at the plain wait for the vault state.
func TestSponsoredWithdrawalNamesAnExitRPCThatCannotCheckTheClose(t *testing.T) {
	for name, broken := range map[string]func(f *withdrawalFixture){
		"refuses block-hash reads": func(f *withdrawalFixture) { f.exitRefusesBlockHash = true },
		"rate-limits vault reads":  func(f *withdrawalFixture) { f.exitUnavailable = map[string]bool{"eth_call": true} },
	} {
		t.Run(name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			f.h.client.config.ExitRPCURL = f.exitRPC
			ctx := payoutContext(payoutFees)
			hash := f.sponsoredClose(t)
			charged := big.NewInt(2_000_000_000_000_000)
			bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
			f.mu.Lock()
			f.finalized, f.rpcCalls, f.exitCalls = "0x20", nil, nil
			broken(f)
			f.mu.Unlock()
			for range 2 {
				status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
				if err != nil || status.Phase != "withdrawal_pending" || status.TransactionHash != bundle || status.Message != withdrawalExitRPCUnusableMessage || !status.ExitRPCUnusable {
					t.Fatalf("the unusable exit RPC was not named for the sponsored close: %+v %v", status, err)
				}
			}
			f.mu.Lock()
			pinned, exit := len(f.rpcCalls), strings.Join(f.exitCalls, " ")
			f.exitRefusesBlockHash, f.exitUnavailable = false, nil
			f.mu.Unlock()
			if pinned != 0 || !strings.Contains(exit, "eth_call") || f.confirmCalls != 0 || !f.active {
				t.Fatalf("the close was not checked through the exit RPC alone, or completed unchecked: pinned %d, exit %s", pinned, exit)
			}
			status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || status.ExitRPCUnusable || f.confirmCalls != 1 {
				t.Fatalf("the sponsored close did not complete once the exit RPC worked: %+v %v", status, err)
			}
		})
	}
}

// The exit RPC as the only source cannot check a close either when it does
// not answer or serves another network.
func TestExitOnlyCloseCheckNamesAnUnusableExitRPC(t *testing.T) {
	down := httptest.NewTLSServer(http.NotFoundHandler())
	down.Close()
	for name, broken := range map[string]func(f *withdrawalFixture){
		"unreachable":     func(f *withdrawalFixture) { f.h.client.config.ExitRPCURL = down.URL },
		"another network": func(f *withdrawalFixture) { f.exitChain = "0xaa36a7" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			f.h.client.config.ExitRPCURL = f.exitRPC
			f.mu.Lock()
			broken(f)
			f.mu.Unlock()
			config, err := f.h.config(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = f.h.corroborateWithdrawalClosed(context.Background(), config.exitConfig(), f.noteID, &addressReceipt{BlockNumber: "0x10", BlockHash: addressTestBlock})
			if !errors.Is(err, errWithdrawalVerificationPending) || !errors.Is(err, errExitRPCCloseCheckUnusable) {
				t.Fatalf("the unusable exit RPC was not named: %v", err)
			}
		})
	}
}

// Review finding (clientd-fixes5, test gaps): the exit RPC as the only
// source, not answering a vault read after its retries, is named even when
// its finalized block reads below the payout's (a node behind a load
// balancer can lag the one that served the payout as final). A vault read
// it refuses before the payout is final there stays the plain wait: that is
// the chain, not the RPC.
func TestExitOnlyCloseCheckNamesAVaultReadFailureByWhetherThePayoutIsFinal(t *testing.T) {
	for name, test := range map[string]struct {
		broken   func(f *withdrawalFixture)
		unusable bool
	}{
		"vault read unanswered":              {func(f *withdrawalFixture) { f.exitUnavailable = map[string]bool{"eth_call": true} }, true},
		"vault read refused before finality": {func(f *withdrawalFixture) { f.exitRefusesBlockHash = true }, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			f.h.client.config.ExitRPCURL = f.exitRPC
			f.mu.Lock()
			f.exitFinalized = "0x5"
			test.broken(f)
			f.mu.Unlock()
			config, err := f.h.config(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = f.h.corroborateWithdrawalClosed(context.Background(), config.exitConfig(), f.noteID, &addressReceipt{BlockNumber: "0x10", BlockHash: addressTestBlock})
			if !errors.Is(err, errWithdrawalVerificationPending) || errors.Is(err, errExitRPCCloseCheckUnusable) != test.unusable {
				t.Fatalf("the vault read failure was reported as unusable %v, want %v: %v", errors.Is(err, errExitRPCCloseCheckUnusable), test.unusable, err)
			}
		})
	}
}

// Review finding (clientd-fixes5, low): an exit RPC that does not answer or
// serves another network while a sponsored withdrawal is followed through
// it alone fails before its close check. It is named as the exit RPC, never
// as the payment RPC, and its management refusal carries exit_rpc_unusable,
// for which the guided session shows its fixed label. Nothing completes.
func TestSponsoredWithdrawalNamesAnUnusableExitRPCBeforeItsCloseCheck(t *testing.T) {
	down := httptest.NewTLSServer(http.NotFoundHandler())
	down.Close()
	for name, broken := range map[string]func(f *withdrawalFixture){
		"another network": func(f *withdrawalFixture) { f.exitChain = "0xaa36a7" },
		"unreachable":     func(f *withdrawalFixture) { f.h.client.config.ExitRPCURL = down.URL },
	} {
		t.Run(name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			f.h.client.config.ExitRPCURL = f.exitRPC
			ctx := payoutContext(payoutFees)
			hash := f.sponsoredClose(t)
			charged := big.NewInt(2_000_000_000_000_000)
			g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
			f.mu.Lock()
			f.finalized = "0x20"
			broken(f)
			f.mu.Unlock()
			_, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
			if !exitRPCUnusable(err) || !strings.Contains(err.Error(), "exit RPC (--exit-rpc-url)") || strings.Contains(err.Error(), "payment RPC") {
				t.Fatalf("the unusable exit RPC was not named: %v", err)
			}
			for _, method := range []string{"GET", "POST"} {
				r := httptest.NewRequest(method, "http://127.0.0.1:8787/admin/withdrawal", strings.NewReader(fmt.Sprintf(`{"destination":%q,"note_id":%d}`, withdrawalTestDestination, f.noteID)))
				r.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				f.h.ServeAdminHTTP(recorder, r)
				var failure struct{ Error, Code string }
				if json.Unmarshal(recorder.Body.Bytes(), &failure) != nil || failure.Code != "exit_rpc_unusable" || !strings.Contains(failure.Error, "exit RPC (--exit-rpc-url)") {
					t.Fatalf("%s: the management refusal does not name the exit RPC: %d %s", method, recorder.Code, recorder.Body.String())
				}
			}
			if f.confirmCalls != 0 || !f.active || f.journal(t).Withdrawal.Phase == "complete" {
				t.Fatal("the close completed while the exit RPC could not be used")
			}
		})
	}
}

// Review finding (clientd-fixes5, privacy): a deposit after a completed
// sponsored withdrawal is no exit. Its quote and its approval, and funding
// without a quote, read and simulate it through the payment RPC: the owner's
// exit RPC is never asked for the funding address's balance or nonce, nor
// to estimate or send the deposit. While the withdrawal is still under way,
// funding is refused after reading through the exit RPC as before.
func TestADepositAfterASponsoredWithdrawalIsNotNamedToTheExitRPC(t *testing.T) {
	deposit := map[string]bool{"eth_getBalance": true, "eth_getTransactionCount": true, "eth_estimateGas": true, "eth_feeHistory": true, "eth_sendRawTransaction": true}
	named := func(calls []string) (found []string) {
		for _, call := range calls {
			if deposit[call] {
				found = append(found, call)
			}
		}
		return found
	}
	for _, quoted := range []bool{true, false} {
		t.Run(map[bool]string{true: "quote and approval", false: "funding without a quote"}[quoted], func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			f.h.client.config.ExitRPCURL = f.exitRPC
			hash := f.sponsoredClose(t)
			f.mu.Lock()
			f.exitCalls, f.rpcCalls = nil, nil
			f.mu.Unlock()
			if _, err := f.h.FundAddress(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "a withdrawal is saved") {
				t.Fatalf("funding was not refused while the withdrawal is under way: %v", err)
			}
			f.mu.Lock()
			exit, pinned := named(f.exitCalls), named(f.rpcCalls)
			f.mu.Unlock()
			if len(exit) == 0 || len(pinned) != 0 {
				t.Fatalf("funding under way was not read through the exit RPC alone: exit %v, pinned %v", exit, pinned)
			}
			charged := big.NewInt(2_000_000_000_000_000)
			g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
			f.mu.Lock()
			f.finalized = "0x20"
			f.mu.Unlock()
			if status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
				t.Fatalf("the sponsored withdrawal did not complete: %+v %v", status, err)
			}
			f.mu.Lock()
			f.exitCalls, f.rpcCalls = nil, nil
			f.mu.Unlock()
			if quoted {
				quote, err := f.h.QuoteAddressDeposit(context.Background(), 100000)
				if err != nil {
					t.Fatal(err)
				}
				if status, err := f.h.ApproveAddressDeposit(context.Background(), quote.ID); err != nil || status.Phase != "deposit_pending" {
					t.Fatalf("the deposit was not sent: %+v %v", status, err)
				}
			} else if _, err := f.h.FundAddress(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "approve a current payment quote") {
				t.Fatalf("funding without a quote was not refused at signing: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			exit, pinned = named(f.exitCalls), named(f.rpcCalls)
			if len(exit) != 0 || !slices.Contains(pinned, "eth_getBalance") || !slices.Contains(pinned, "eth_getTransactionCount") {
				t.Fatalf("the deposit was named to the exit RPC: exit %v, pinned %v", exit, pinned)
			}
			if quoted && (!slices.Contains(pinned, "eth_estimateGas") || !slices.Contains(pinned, "eth_sendRawTransaction")) {
				t.Fatalf("the deposit was not simulated and sent through the payment RPC: %v", pinned)
			}
		})
	}
}

// A complete exit that is not done yet keeps funding on the exit RPC: a
// sponsored withdrawal whose payout the paymaster credited, and an escape
// whose payout claim is pending (with the pinned RPC down). Funding is
// refused as before, after reading through the exit RPC alone.
func TestFundingIsRefusedThroughTheExitRPCWhileACompleteExitIsNotDone(t *testing.T) {
	t.Run("paymaster credit", func(t *testing.T) {
		f, g := newGaslessWithdrawalFixture(t)
		f.h.client.config.ExitRPCURL = f.exitRPC
		hash := f.sponsoredClose(t)
		charged := big.NewInt(11)
		g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, Credited: new(big.Int).Sub(gaslessPayoutWei, charged)})
		f.mu.Lock()
		f.finalized = "0x20"
		f.mu.Unlock()
		if status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" || !status.PaymasterCredited {
			t.Fatalf("the credited withdrawal did not complete: %+v %v", status, err)
		}
		f.mu.Lock()
		f.exitCalls, f.rpcCalls = nil, nil
		f.mu.Unlock()
		if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); !errors.Is(err, errWithdrawalPayoutWaiting) {
			t.Fatalf("a deposit was quoted while the credit waits: %v", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if !slices.Contains(f.exitCalls, "eth_getBalance") || slices.Contains(f.rpcCalls, "eth_getBalance") {
			t.Fatalf("the refused quote was not read through the exit RPC: exit %v, pinned %v", f.exitCalls, f.rpcCalls)
		}
	})
	t.Run("escape claim pending", func(t *testing.T) {
		f := escapeEndToEnd(t, true)
		if record := f.journal(t); record.Pending == nil || record.Pending.Kind != "escape_claim" || record.Withdrawal.Phase != "complete" {
			t.Fatalf("no pending claim: %+v", record)
		}
		if _, err := f.h.FundAddress(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "a different public transaction is saved") {
			t.Fatalf("funding was not refused through the exit RPC while the claim is pending: %v", err)
		}
	})
}

// An ownership proof sent for clearance is a valid escape proof. If anyone
// escapes the reserved note with it, the finalized escape of exactly this
// reservation is payout evidence, but only as an independently relayed one.
func TestAddressWithdrawalAcceptsFinalizedEscapeOfSameReservation(t *testing.T) {
	escape := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
	for _, destination := range []string{withdrawalTestDestination, addressTestToken} {
		t.Run(destination, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			original := f.withdraw(t)
			f.mineWithdrawal(t, original, withdrawalTestDestination, true)
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
				t.Fatalf("revert not reported: %+v %v", status, err)
			}
			other := "0x" + strings.Repeat("c", 64)
			f.mu.Lock()
			logs := []map[string]any{{"address": addressTestVault, "topics": []string{escape, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(destination)}}
			f.receipts[other] = map[string]any{"transactionHash": other, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestToken, "logs": logs}
			f.closeNote(12)
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", other)
			if destination != withdrawalTestDestination {
				if err == nil || f.confirmCalls != 0 {
					t.Fatal("an escape to another destination was accepted")
				}
				return
			}
			if err != nil || status.Phase != "complete" || f.journal(t).Withdrawal.SettlementHash != other {
				t.Fatalf("finalized escape of the reservation was not accepted: %+v %v", status, err)
			}
			// Our own signed transaction can only be evidenced by MutualClose.
			receipt := &addressReceipt{Status: "0x1", To: addressTestVault}
			raw, _ := json.Marshal(logs)
			_ = json.Unmarshal(raw, &receipt.Logs)
			if _, err := validateWithdrawalReceipt(receipt, fundingConfig{Contract: addressTestVault}, f.journal(t).Withdrawal, false); err == nil {
				t.Fatal("an escape event was accepted as our own mutual close")
			}
		})
	}
}

// On a vault_revision 2 vault a finalized escape whose push to the
// destination failed (the address rejected ETH or needed more than 100,000
// gas) still closes the note, but the vault only credits the balance to
// escapePayoutCredits(destination) and emits EscapePayoutDeferred before
// EscapeWithdrawalFinalized. Such an escape is never reported as paid: the
// withdrawal completes its bookkeeping with a credited state that names the
// claimEscapePayout(destination) call that delivers the credit.
func TestAddressWithdrawalReportsCreditedEscapePayoutWithItsClaim(t *testing.T) {
	deferredTopic := crypto.Keccak256Hash([]byte("EscapePayoutDeferred(uint32,address,uint128)")).Hex()
	if deferredTopic != "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942" {
		t.Fatal("EscapePayoutDeferred topic drifted from the vault's")
	}
	if hex.EncodeToString(crypto.Keccak256([]byte("claimEscapePayout(address)"))[:4]) != claimEscapePayoutSelector {
		t.Fatal("claimEscapePayout selector drifted from the vault's")
	}
	escape := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
	other := "0x" + strings.Repeat("c", 64)
	destinationWord := "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))
	type mutation func(log map[string]any, f *withdrawalFixture)
	for _, test := range []struct {
		name     string
		deferral mutation
		// companion reports escape_payout_credited for the receipt.
		companion bool
		credited  bool
	}{
		{"deferred for this note and destination", func(map[string]any, *withdrawalFixture) {}, false, true},
		{"only the companion saw the deferral", nil, true, true},
		{"no deferral", nil, false, false},
		{"deferral for another note", func(log map[string]any, f *withdrawalFixture) {
			log["topics"].([]string)[1] = fmt.Sprintf("0x%064x", f.reservedNoteID+1)
		}, false, false},
		{"deferral for another destination", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"].([]string)[2] = "0x" + addressABIWord(addressTestToken)
		}, false, false},
		{"deferral from another emitter", func(log map[string]any, _ *withdrawalFixture) {
			log["address"] = addressTestToken
		}, false, false},
		{"removed deferral", func(log map[string]any, _ *withdrawalFixture) {
			log["removed"] = true
		}, false, false},
		// Exactly the deferral's three topics, under its own topic0.
		{"deferral without its destination topic", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"] = log["topics"].([]string)[:2]
		}, false, false},
		{"deferral with a fourth topic", func(log map[string]any, _ *withdrawalFixture) {
			topics := log["topics"].([]string)
			log["topics"] = append(append([]string{}, topics...), topics[2])
		}, false, false},
		{"a claimed payout instead of a deferral", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"].([]string)[0] = crypto.Keccak256Hash([]byte("EscapePayoutClaimed(address,uint128)")).Hex()
		}, false, false},
		{"deferral with one topic", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"] = log["topics"].([]string)[:1]
		}, false, false},
		{"deferral without topics", func(log map[string]any, _ *withdrawalFixture) {
			log["topics"] = []string{}
		}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			original := f.withdraw(t)
			f.mineWithdrawal(t, original, withdrawalTestDestination, true)
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
				t.Fatalf("revert not reported: %+v %v", status, err)
			}
			f.mu.Lock()
			finalized := map[string]any{"address": addressTestVault, "topics": []string{escape, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(withdrawalTestDestination)}
			logs := []map[string]any{finalized}
			if test.deferral != nil {
				deferred := map[string]any{"address": addressTestVault, "topics": []string{deferredTopic, fmt.Sprintf("0x%064x", f.reservedNoteID), destinationWord}, "data": fmt.Sprintf("0x%064x", f.reservedBalance)}
				test.deferral(deferred, f)
				logs = []map[string]any{deferred, finalized}
			}
			f.receipts[other] = map[string]any{"transactionHash": other, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestVault, "logs": logs}
			f.closeNote(12)
			f.companionCredited = test.companion
			// The first confirmation reply is lost after the credit was saved.
			f.confirmFailure = true
			f.mu.Unlock()
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", other); err == nil {
				t.Fatal("a failed companion confirmation completed the withdrawal")
			}
			if saved := f.journal(t).Withdrawal; saved.Phase != "confirming" || saved.PayoutCredited != (test.credited && !test.companion) {
				t.Fatalf("the receipt's credit was not saved before confirmation: %+v", saved)
			}
			f.confirmFailure = false
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" {
				t.Fatalf("the finalized escape did not complete the withdrawal: %+v %v", status, err)
			}
			read, err := f.h.AddressWithdrawal(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, reported := range []AddressWithdrawalStatus{status, read} {
				if reported.PayoutCredited != test.credited || f.journal(t).Withdrawal.PayoutCredited != test.credited {
					t.Fatalf("credited = %v, want %v: %+v", reported.PayoutCredited, test.credited, reported)
				}
				if !test.credited {
					if reported.ClaimCalldata != "" || strings.Contains(reported.Message, "claimEscapePayout") {
						t.Fatalf("a paid escape was reported as credited: %+v", reported)
					}
					continue
				}
				claim := "0x88c10aee" + addressABIWord(strings.ToLower(withdrawalTestDestination))
				if reported.ClaimCalldata != claim || !strings.EqualFold(reported.VaultAddress, addressTestVault) {
					t.Fatalf("the claim call is missing: %+v", reported)
				}
				for _, part := range []string{"claimEscapePayout(" + withdrawalTestDestination + ")", "0x88c10aee", reported.VaultAddress, claim, "nothing has arrived"} {
					if !strings.Contains(reported.Message, part) {
						t.Fatalf("the credited message lacks %q: %s", part, reported.Message)
					}
				}
				if strings.Contains(reported.Message, "was withdrawn") || reported.Message == "The remaining private balance was withdrawn and the private note is closed." {
					t.Fatalf("a credited escape was reported as paid: %s", reported.Message)
				}
			}
		})
	}
}

// completeCreditedEscape completes the fixture's withdrawal through a relayed
// escape whose payout the vault credited, and returns its transaction hash.
func completeCreditedEscape(t *testing.T, f *withdrawalFixture) string {
	t.Helper()
	original := f.withdraw(t)
	f.mineWithdrawal(t, original, withdrawalTestDestination, true)
	if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
		t.Fatalf("revert not reported: %+v %v", status, err)
	}
	settlement := "0x" + strings.Repeat("c", 64)
	escape := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
	f.mu.Lock()
	finalized := map[string]any{"address": addressTestVault, "topics": []string{escape, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(withdrawalTestDestination)}
	deferred := map[string]any{"address": addressTestVault, "topics": []string{escapePayoutDeferredEventTopic, fmt.Sprintf("0x%064x", f.reservedNoteID), "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": fmt.Sprintf("0x%064x", f.reservedBalance)}
	f.receipts[settlement] = map[string]any{"transactionHash": settlement, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestVault, "logs": []map[string]any{deferred, finalized}}
	f.closeNote(12)
	f.mu.Unlock()
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", settlement)
	if err != nil || status.Phase != "complete" || !status.PayoutCredited {
		t.Fatalf("the credited escape did not complete: %+v %v", status, err)
	}
	return settlement
}

// A credited escape payout outlives its withdrawal record. A later deposit
// (a new funding request, a native deposit quote, adopting a note deposited
// elsewhere, or repairing such a deposit's note binding) replaces that
// record, but the funding and withdrawal statuses keep listing the credit
// with its claimEscapePayout call while the vault still holds it, also after
// a restart, and stop once it reads zero.
func TestCreditedEscapePayoutStaysReportedAfterTheNextDeposit(t *testing.T) {
	ctx := context.Background()
	for _, replace := range []string{"refill", "quote", "adoption", "rebind"} {
		t.Run(replace, func(t *testing.T) {
			f := newWithdrawalFixture(t, replace == "quote")
			settlement := completeCreditedEscape(t, f)
			destination := strings.ToLower(withdrawalTestDestination)
			f.mu.Lock()
			f.escapeCredits = map[string]string{destination: fmt.Sprintf("0x%x", f.reservedBalance)}
			f.mu.Unlock()
			if before, err := f.h.Address(ctx); err != nil || len(before.EscapePayoutCredits) != 0 {
				t.Fatalf("the current withdrawal's credit was listed twice: %+v %v", before, err)
			}
			switch replace {
			case "refill":
				refill, err := f.h.FundAddress(ctx, 50000)
				if err != nil || len(refill.EscapePayoutCredits) != 1 {
					t.Fatalf("the refill does not report the credit: %+v %v", refill, err)
				}
			case "quote":
				if _, err := f.h.QuoteAddressDeposit(ctx, 50000); err != nil {
					t.Fatal(err)
				}
			case "adoption":
				config, err := f.h.config(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.h.adoptPostWithdrawalDeposit(config, depositRecord{Amount: 50000, Commitment: "0x1234"}, 13); err != nil {
					t.Fatal(err)
				}
			case "rebind":
				// A deposit through the legacy funding API whose activation
				// never ran (say its receipt was misreported) is repaired to
				// the note the vault and the indexer agree on.
				if _, err := f.h.prepare(ctx, 50000); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				f.registerDeposit(13, "0x5678", 50000, bucketedExpiry())
				f.mu.Unlock()
				note := uint64(13)
				repaired, err := f.h.RebindDeposit(ctx, &note, nil)
				if err != nil || repaired.Phase != "active" || f.activated != 2 || f.noteID != 13 || len(repaired.EscapePayoutCredits) != 1 {
					t.Fatalf("the repair did not activate note 13 and report the credit: %+v %v", repaired, err)
				}
			}
			record := f.journal(t)
			want := addressCreditedPayout{NoteID: f.reservedNoteID, Destination: withdrawalTestDestination, Amount: f.reservedBalance, SettlementHash: settlement}
			if record.Withdrawal != nil || len(record.CreditedPayouts) != 1 || record.CreditedPayouts[0] != want {
				t.Fatalf("the credited payout was not kept: %+v", record)
			}
			claim := "0x88c10aee" + addressABIWord(destination)
			check := func(label string, credits []EscapePayoutCredit) {
				t.Helper()
				if len(credits) != 1 {
					t.Fatalf("%s: credits %+v", label, credits)
				}
				c := credits[0]
				if !strings.EqualFold(c.Destination, withdrawalTestDestination) || c.ClaimCalldata != claim || !strings.EqualFold(c.VaultAddress, addressTestVault) || c.CreditedAmount != fmt.Sprint(f.reservedBalance) || len(c.NoteIDs) != 1 || c.NoteIDs[0] != f.reservedNoteID || len(c.TransactionHashes) != 1 || c.TransactionHashes[0] != settlement {
					t.Fatalf("%s: credit %+v", label, c)
				}
				unit := "token units"
				if replace == "quote" {
					unit = "gwei"
				}
				for _, part := range []string{"claimEscapePayout(" + c.Destination + ")", "0x88c10aee", claim, c.VaultAddress, "nothing has arrived", fmt.Sprintf("a credit of %d %s", f.reservedBalance, unit), fmt.Sprintf("(note %d)", f.reservedNoteID)} {
					if !strings.Contains(c.Message, part) {
						t.Fatalf("%s: the message lacks %q: %s", label, part, c.Message)
					}
				}
			}
			for restarted := range 2 {
				if restarted == 1 {
					f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
				}
				funding, err := f.h.Address(ctx)
				if err != nil {
					t.Fatal(err)
				}
				check("funding", funding.EscapePayoutCredits)
				withdrawal, err := f.h.AddressWithdrawal(ctx)
				if err != nil {
					t.Fatal(err)
				}
				check("withdrawal", withdrawal.EscapePayoutCredits)
			}
			// Claimed: the vault holds nothing for the destination any more.
			f.mu.Lock()
			f.escapeCredits = nil
			f.mu.Unlock()
			funding, err := f.h.Address(ctx)
			if err != nil || len(funding.EscapePayoutCredits) != 0 {
				t.Fatalf("a claimed credit is still reported: %+v %v", funding, err)
			}
			if len(f.journal(t).CreditedPayouts) != 1 {
				t.Fatal("a zero read removed the saved credit")
			}
			// A damaged saved credit is refused, not silently dropped.
			raw, err := os.ReadFile(f.h.addressStatePath())
			if err != nil {
				t.Fatal(err)
			}
			for field, value := range map[string]any{"destination": "0x0000000000000000000000000000000000000000", "note_id": uint64(1) << 32, "settlement_hash": "0x12"} {
				var saved map[string]any
				if err := json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				saved["credited_payouts"].([]any)[0].(map[string]any)[field] = value
				damaged, _ := json.Marshal(saved)
				if err := os.WriteFile(f.h.addressStatePath(), damaged, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := f.h.Address(ctx); err == nil || !strings.Contains(err.Error(), "credited escape payout recovery data is invalid") {
					t.Fatalf("%s: a damaged credit was accepted: %v", field, err)
				}
			}
		})
	}
}

// Retiring keeps only a complete credited withdrawal, once.
func TestRetireWithdrawalKeepsOnlyCreditedPayoutsOnce(t *testing.T) {
	credited := &addressWithdrawalRecord{NoteID: 7, Destination: withdrawalTestDestination, Amount: 5, Phase: "complete", SettlementHash: "0x" + strings.Repeat("AB", 32), PayoutCredited: true}
	record := &addressFundingRecord{Withdrawal: credited}
	retireWithdrawal(record)
	again := *credited
	record.Withdrawal = &again
	retireWithdrawal(record)
	if record.Withdrawal != nil || len(record.CreditedPayouts) != 1 || record.CreditedPayouts[0].SettlementHash != "0x"+strings.Repeat("ab", 32) {
		t.Fatalf("credited payout: %+v", record.CreditedPayouts)
	}
	for _, w := range []addressWithdrawalRecord{{Phase: "complete", SettlementHash: "0x" + strings.Repeat("cd", 32)}, {Phase: "confirming", PayoutCredited: true, SettlementHash: "0x" + strings.Repeat("ef", 32)}} {
		record.Withdrawal = &w
		retireWithdrawal(record)
		if record.Withdrawal != nil || len(record.CreditedPayouts) != 1 {
			t.Fatalf("an uncredited or unfinished withdrawal was kept: %+v", record.CreditedPayouts)
		}
	}
}

// Our own signed mutual close pays in full or reverts; a deferral log in its
// receipt, or a companion claiming one, never marks it credited, and the
// saved record stays loadable.
func TestOwnMutualCloseIsNeverReportedAsCredited(t *testing.T) {
	f := newWithdrawalFixture(t)
	hash := f.withdraw(t)
	f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
	f.mu.Lock()
	receipt := f.receipts[hash]
	deferred := map[string]any{"address": addressTestVault, "topics": []string{escapePayoutDeferredEventTopic, fmt.Sprintf("0x%064x", f.reservedNoteID), "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": fmt.Sprintf("0x%064x", f.reservedBalance)}
	receipt["logs"] = append([]map[string]any{deferred}, receipt["logs"].([]map[string]any)...)
	f.companionCredited = true
	f.mu.Unlock()
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.PayoutCredited {
		t.Fatalf("own mutual close was not completed as paid: %+v %v", status, err)
	}
	if read, err := f.h.AddressWithdrawal(context.Background()); err != nil || read.PayoutCredited || f.journal(t).Withdrawal.PayoutCredited {
		t.Fatalf("own mutual close was saved as credited: %+v %v", read, err)
	}
}
