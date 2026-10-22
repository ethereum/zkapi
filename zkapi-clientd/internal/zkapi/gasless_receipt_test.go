package zkapi

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The receipt-first follow of a sponsored operation (root review): an RPC
// that refuses multi-block eth_getLogs (the bundled Sepolia RPC does) must
// not keep a bundler receipt the chain confirms from settling the record,
// and a failed log search is never taken for the operation's absence: the
// EntryPoint's nonce decides whether following may go on.

// consumeOperationNonce moves the EntryPoint's nonce of the journaled
// operation's key past it, as an inclusion this RPC cannot locate does.
func (g *gaslessFixture) consumeOperationNonce(t *testing.T, f *withdrawalFixture) {
	t.Helper()
	u := f.journal(t).Withdrawal.UserOp
	nonce, ok := new(big.Int).SetString(u.Nonce, 10)
	if !ok {
		t.Fatalf("journaled nonce %q", u.Nonce)
	}
	sender := strings.ToLower(f.journal(t).Withdrawal.Transit.Account)
	g.f.mu.Lock()
	defer g.f.mu.Unlock()
	g.sequences[sender+"|"+new(big.Int).Rsh(nonce, 64).String()]++
}

func (g *gaslessFixture) setLogsDown(down bool) {
	g.f.mu.Lock()
	defer g.f.mu.Unlock()
	g.logsDown = down
}

// A mined operation is settled from the bundler's receipt once the chain's
// own receipt of the transaction it names carries the operation's exact
// event: the refused log search is not even needed, before or after a
// restart.
func TestGaslessFollowAdoptsAConfirmedBundlerReceiptWhileLogsFail(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "same process", true: "after a restart"}[restart], func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			f.eth = "0x0"
			hash := f.sponsoredClose(t)
			charged := big.NewInt(3_000_000_000_000_000)
			bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
			g.setLogsDown(true)
			if restart {
				f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
			}
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || status.TransactionHash != bundle || status.ChargedWei != charged.String() || status.ReceivedWei != new(big.Int).Sub(gaslessPayoutWei, charged).String() || f.confirmCalls != 1 {
				t.Fatalf("the confirmed receipt was not adopted: %+v %v", status, err)
			}
			if len(g.sends) != 1 || len(f.submitted) != 1 {
				t.Fatalf("something was re-sent or a wallet transaction signed: %v %d", g.sends, len(f.submitted))
			}
		})
	}
}

// A receipt that names the operation's hash is adopted only with the exact
// event: another hash, another sender, another paymaster or another nonce
// in the transaction's receipt is refused, even with a vault log that would
// otherwise settle the close. The operation's nonce is unconsumed, so the
// follow goes on as usual and nothing is re-sent before its time.
func TestGaslessFollowRefusesAMismatchedBundlerReceiptWhileLogsFail(t *testing.T) {
	other := common.HexToAddress("0x00000000000000000000000000000000000c0ffe")
	for name, forge := range map[string]func(topics []string, data string, nonce *big.Int) ([]string, string){
		"another hash": func(topics []string, data string, _ *big.Int) ([]string, string) {
			topics[1] = "0x" + strings.Repeat("ab", 32)
			return topics, data
		},
		"another sender": func(topics []string, data string, _ *big.Int) ([]string, string) {
			topics[2] = "0x" + addressWord(other)
			return topics, data
		},
		"another paymaster": func(topics []string, data string, _ *big.Int) ([]string, string) {
			topics[3] = "0x" + addressWord(other)
			return topics, data
		},
		"another nonce": func(topics []string, data string, nonce *big.Int) ([]string, string) {
			return topics, "0x" + wordHex(new(big.Int).Add(nonce, big.NewInt(1))) + data[2+64:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			hash := f.sponsoredClose(t)
			w := f.journal(t).Withdrawal
			nonce, _ := new(big.Int).SetString(w.UserOp.Nonce, 10)
			transit := common.HexToAddress(w.Transit.Account)
			topics := []string{userOperationEventTopic, hash, "0x" + addressWord(transit), "0x" + addressWord(g.paymaster)}
			data := "0x" + wordHex(nonce) + wordHex(big.NewInt(1)) + wordHex(big.NewInt(5)) + uintWord(400_000)
			topics, data = forge(topics, data, nonce)
			forged := "0x" + strings.Repeat("e", 64)
			nullifier := new(big.Int).SetBytes(common.FromHex(w.Nullifier))
			f.mu.Lock()
			f.receipts[forged] = map[string]any{"transactionHash": forged, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": g.entryPoint.Hex(), "logs": []map[string]any{
				{"address": g.entryPoint.Hex(), "topics": topics, "data": data},
				{"address": g.vault.Hex(), "topics": []string{withdrawalEventTopic, "0x" + uintWord(f.noteID)}, "data": "0x" + wordHex(nullifier) + uintWord(w.Amount) + addressWord(transit)},
			}}
			g.forgedReceiptTransaction = forged
			g.logsDown = true
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "op_submitted" || status.TransactionHash != "" || f.confirmCalls != 0 {
				t.Fatalf("a mismatched receipt was adopted: %+v %v", status, err)
			}
			if u := f.journal(t).Withdrawal.UserOp; u.TransactionHash != "" || u.IncludedHash != "" || len(g.sends) != 1 {
				t.Fatalf("the journal or the bundler changed: %+v %v", u, g.sends)
			}
		})
	}
}

// Logs refused, the nonce consumed and no confirmed receipt: the operation
// was included where this RPC cannot find it. The record stays pending with
// a clear error, before the resend window and after it, whether the
// operation was sent or only built: nothing is re-sent, re-signed or
// released, and no wallet transaction is signed.
func TestGaslessFollowStaysPendingWhenLogsFailAndTheNonceIsConsumed(t *testing.T) {
	for _, built := range []bool{false, true} {
		t.Run(map[bool]string{false: "submitted", true: "built, never sent"}[built], func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			var hash string
			if built {
				quote, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
				if err != nil {
					t.Fatal(err)
				}
				g.sendDown = true
				status, err := f.h.ApproveAddressWithdrawal(context.Background(), quote.ID)
				if err != nil || status.Phase != "op_built" {
					t.Fatalf("not left built: %+v %v", status, err)
				}
				hash = status.UserOpHash
				g.sendDown = false
			} else {
				hash = f.sponsoredClose(t)
			}
			g.consumeOperationNonce(t, f)
			g.setLogsDown(true)
			before := f.journal(t).Withdrawal
			for _, aged := range []bool{false, true} {
				if aged {
					ageInFlightOperation(t, f)
					g.known[hash] = false
					before = f.journal(t).Withdrawal
				}
				calls := len(g.bundlerCalls)
				status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
				if err == nil || !strings.Contains(err.Error(), "cannot be located") || !strings.Contains(err.Error(), "--exit-rpc-url") {
					t.Fatalf("aged %v: no clear error: %+v %v", aged, status, err)
				}
				if status.Phase != before.Phase || status.UserOpHash != hash {
					t.Fatalf("aged %v: the status changed: %+v", aged, status)
				}
				for _, method := range g.bundlerCalls[calls:] {
					if method == "eth_sendUserOperation" {
						t.Fatalf("aged %v: something was sent to the bundler", aged)
					}
				}
				after := f.journal(t).Withdrawal
				if after.Phase != before.Phase || after.UserOp.Hash != before.UserOp.Hash || len(after.UserOp.Hashes) != len(before.UserOp.Hashes) || after.UserOp.SubmittedAt != before.UserOp.SubmittedAt || after.GaslessRefusal != "" {
					t.Fatalf("aged %v: the journal changed: %+v", aged, after.UserOp)
				}
			}
			if len(f.submitted) != 1 {
				t.Fatal("a wallet transaction was signed")
			}
			// Once the RPC serves logs again, the inclusion is found and
			// followed (here, the fixture's receipt of the mined copy).
			g.setLogsDown(false)
			f.mu.Lock()
			g.sequences = map[string]uint64{}
			f.mu.Unlock()
			if built {
				// The copy the bundler never acknowledged was included.
				var op gaslessUserOpJSON
				if err := json.Unmarshal(before.UserOp.JSON, &op); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				g.ops[hash] = op
				f.mu.Unlock()
			}
			bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
			g.setLogsDown(true)
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || status.TransactionHash != bundle {
				t.Fatalf("the inclusion was not followed: %+v %v", status, err)
			}
		})
	}
}

// Logs refused and the nonce unconsumed: no copy was included, which the
// EntryPoint's state establishes, so the follow goes on as usual: an
// operation never sent is sent as its identical journaled bytes, and one the
// bundler forgot is re-sent identically.
func TestGaslessFollowGoesOnWhenLogsFailAndTheNonceIsUnconsumed(t *testing.T) {
	t.Run("built, never sent", func(t *testing.T) {
		f, g := newGaslessWithdrawalFixture(t)
		quote, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
		if err != nil {
			t.Fatal(err)
		}
		g.sendDown = true
		status, err := f.h.ApproveAddressWithdrawal(context.Background(), quote.ID)
		if err != nil || status.Phase != "op_built" {
			t.Fatalf("not left built: %+v %v", status, err)
		}
		g.sendDown = false
		g.setLogsDown(true)
		status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
		u := f.journal(t).Withdrawal.UserOp
		if err != nil || status.Phase != "op_submitted" || len(g.sends) != 1 || g.sends[0] != u.Hash || u.Hash != status.UserOpHash {
			t.Fatalf("the journaled bytes were not sent: %+v %v %v", status, err, g.sends)
		}
	})
	t.Run("forgotten by the bundler", func(t *testing.T) {
		f, g := newGaslessWithdrawalFixture(t)
		hash := f.sponsoredClose(t)
		ageInFlightOperation(t, f)
		g.known[hash] = false
		g.setLogsDown(true)
		status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
		if err != nil || status.Phase != "op_submitted" || status.UserOpHash != hash || len(g.sends) != 2 || g.sends[1] != hash {
			t.Fatalf("the identical operation was not re-sent: %+v %v %v", status, err, g.sends)
		}
	})
}

// The look for a late inclusion before a wallet-paid fallback follows the
// same rule: a confirmed bundler receipt is followed though logs fail; a
// consumed nonce without one stops the fallback with nothing changed; an
// unconsumed nonce lets the fallback proceed.
func TestGaslessLateLookFollowsTheReceiptAndTheNonceWhileLogsFail(t *testing.T) {
	refused := func(t *testing.T) (*withdrawalFixture, *gaslessFixture, string) {
		t.Helper()
		f, g := newGaslessWithdrawalFixture(t)
		first := f.sponsoredClose(t)
		ageInFlightOperation(t, f)
		g.known[first], g.refuse, g.refuseMessage = false, true, "AA23 reverted: account validation failed"
		status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
		if err != nil || status.Phase != "gasless_refused" || status.GaslessRetryable {
			t.Fatalf("no stop: %+v %v", status, err)
		}
		g.refuse = false
		return f, g, first
	}
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	t.Run("receipt", func(t *testing.T) {
		f, g, first := refused(t)
		bundle := g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
		g.setLogsDown(true)
		status, err := f.h.WithdrawAddress(wallet, withdrawalTestDestination, f.noteID)
		if err != nil || status.Phase != "complete" || status.TransactionHash != bundle || f.journal(t).Withdrawal.FeePayer != "payout" {
			t.Fatalf("the late operation was not followed: %+v %v", status, err)
		}
	})
	t.Run("nonce consumed", func(t *testing.T) {
		f, g, _ := refused(t)
		g.consumeOperationNonce(t, f)
		g.setLogsDown(true)
		prepares := len(f.prepareBodies)
		if _, err := f.h.QuoteAddressWithdrawal(wallet, withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "cannot be located") {
			t.Fatalf("the fallback went on: %v", err)
		}
		if w := f.journal(t).Withdrawal; w.FeePayer != "payout" || w.UserOp == nil || w.Phase != "gasless_refused" || len(f.prepareBodies) != prepares || f.journal(t).Quote != nil {
			t.Fatalf("the fallback changed the record: %+v", w)
		}
	})
	t.Run("nonce unconsumed", func(t *testing.T) {
		f, g, _ := refused(t)
		g.setLogsDown(true)
		quote, err := f.h.QuoteAddressWithdrawal(wallet, withdrawalTestDestination, f.noteID, "", false)
		if err != nil || quote.FeePolicy != "low" {
			t.Fatalf("the fallback was refused: %+v %v", quote, err)
		}
		if w := f.journal(t).Withdrawal; w.FeePayer != "wallet" || w.UserOp != nil {
			t.Fatalf("the fallback did not proceed: %+v", w)
		}
	})
}
