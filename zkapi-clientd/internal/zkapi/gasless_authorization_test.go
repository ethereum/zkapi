package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// setBaseFee sets the fixture chain's base fee (and gas price) in wei.
func (f *withdrawalFixture) setBaseFee(wei int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gasPrice = fmt.Sprintf("0x%x", wei)
}

// authorizedQuote is an authorize-once payout quote of the fixture close.
func authorizedQuote(t *testing.T, f *withdrawalFixture, options addressWithdrawalOptions) AddressPaymentQuote {
	t.Helper()
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(options), withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.MaxTotalFeeWei == "" || quote.MinNetPayoutWei == "" || !quote.FeeMayChange {
		t.Fatalf("no authorize-once quote: %+v %v", quote, err)
	}
	return quote
}

func signedOp(t *testing.T, g *gaslessFixture, hash string) *gaslessUserOp {
	t.Helper()
	g.f.mu.Lock()
	encoded, ok := g.ops[hash]
	g.f.mu.Unlock()
	if !ok {
		t.Fatalf("the bundler never saw %s", hash)
	}
	op, err := gaslessUserOpFromJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func weiOf(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("not wei: %q", value)
	}
	return n
}

// One approval carries the close at the fees of the moment it is signed,
// whichever way they moved since the quote: down, up within the maximum, or
// up past the 2 × base headroom (the maximum fee is lowered to fit, the
// operation still paying the base fee and its tip). The maximum, the floor
// and the scope are journaled with it, and one operation is sent.
func TestGaslessAuthorizationFollowsFeeDriftWithoutANewApproval(t *testing.T) {
	for name, base := range map[string]int64{"down": 250_000_000, "up within the maximum": 5_000_000_000, "up past the headroom": 10_000_000_000} {
		t.Run(name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			quote := authorizedQuote(t, f, payoutFees)
			maximum := weiOf(t, quote.MaxTotalFeeWei)
			if maximum.Cmp(new(big.Int).Quo(gaslessPayoutWei, big.NewInt(4))) != 0 || weiOf(t, quote.MinNetPayoutWei).Cmp(new(big.Int).Sub(gaslessPayoutWei, maximum)) != 0 {
				t.Fatalf("the default maximum is not a quarter of the payout: %+v", quote)
			}
			f.setBaseFee(base)
			accepted := len(f.accepted)
			status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
			if err != nil || status.Phase != "op_submitted" || len(g.sends) != 1 || len(f.accepted) != accepted {
				t.Fatalf("approval: %+v %v %v", status, err, g.sends)
			}
			op := signedOp(t, g, status.UserOpHash)
			quoted := weiOf(t, quote.MaxFeePerGas)
			if (base < 1_000_000_000) != (op.MaxFeePerGas.Cmp(quoted) < 0) {
				t.Fatalf("the operation was not priced at approval: %s (quoted %s)", op.MaxFeePerGas, quoted)
			}
			if loss := payoutLoss(op, g.flatFee, g.profile.GasPolicy, false); loss.Cmp(maximum) > 0 {
				t.Fatalf("the payout may lose %s, above the authorized %s", loss, maximum)
			}
			if new(big.Int).Add(big.NewInt(base), op.MaxPriorityFeePerGas).Cmp(op.MaxFeePerGas) > 0 {
				t.Fatal("the operation does not pay the current base fee and its tip")
			}
			w := f.journal(t).Withdrawal
			a := w.Authorization
			if a == nil || a.MaxTotalFeeWei != quote.MaxTotalFeeWei || a.Nonce != w.UserOp.Nonce || w.UserOp.FeeCapWei != quote.MaxTotalFeeWei || !strings.EqualFold(a.TransitAccount, w.Transit.Account) || a.Destination != withdrawalTestDestination {
				t.Fatalf("the authorization was not journaled: %+v %+v", a, w.UserOp)
			}
			if status.AuthorizedMaxFeeWei != quote.MaxTotalFeeWei || status.AuthorizedMinNetPayoutWei != quote.MinNetPayoutWei || status.NewWithdrawalFees != "payout" {
				t.Fatalf("the status does not show the authorization: %+v", status)
			}
		})
	}
}

// Fees above the maximum for now are a state, not a failure: nothing is
// signed and no wallet transaction is made, the authorization holds, and a
// plain resume signs once fees fall, with no new quote or approval.
func TestGaslessAuthorizationWaitsAboveItsMaximumAndRetriesWithoutApproval(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	quote := authorizedQuote(t, f, payoutFees)
	f.setBaseFee(20_000_000_000)
	accepted := len(f.accepted)
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if err != nil || status.Phase != "gasless_refused" || !status.GaslessRetryable || !strings.HasPrefix(status.GaslessRefusal, CodeFeeAboveAuthorization) || len(g.sends) != 0 || len(f.accepted) != accepted {
		t.Fatalf("above the maximum: %+v %v %v", status, err, g.sends)
	}
	if strings.Contains(status.Message, "--fees wallet") || status.AuthorizedMaxFeeWei != quote.MaxTotalFeeWei {
		t.Fatalf("the waiting status: %s", status.Message)
	}
	// Still above: the resume waits again, signing nothing.
	if status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "gasless_refused" || !status.GaslessRetryable || len(g.sends) != 0 {
		t.Fatalf("a resume above the maximum: %+v %v", status, err)
	}
	f.setBaseFee(1_000_000_000)
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || len(g.sends) != 1 || len(f.accepted) != accepted {
		t.Fatalf("not signed once fees fell: %+v %v", status, err)
	}
	if a := f.journal(t).Withdrawal.Authorization; a == nil || a.QuoteID != quote.ID || a.Rebuilds != 1 || a.Revoked != "" {
		t.Fatalf("the resume did not use the approval: %+v", a)
	}
}

// A bundler that is down when the owner approves: the authorization is
// journaled first, nothing is signed, no wallet transaction is made and no
// wallet path is offered; a fresh process resumes it once the bundler is
// back.
func TestGaslessAuthorizationSurvivesABundlerOutageAndARestart(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	quote := authorizedQuote(t, f, payoutFees)
	g.f.mu.Lock()
	g.down = true
	g.f.mu.Unlock()
	accepted := len(f.accepted)
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if err != nil || status.Phase != "gasless_refused" || !status.GaslessRetryable || !strings.HasPrefix(status.GaslessRefusal, "bundler_unavailable") || len(f.accepted) != accepted {
		t.Fatalf("bundler down at approval: %+v %v", status, err)
	}
	if strings.Contains(status.Message, "--fees wallet") || f.journal(t).Withdrawal.Authorization == nil {
		t.Fatalf("a wallet path was offered or the approval lost: %s", status.Message)
	}
	// The wallet is refused while the approval holds.
	if _, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Fees: "wallet"}), withdrawalTestDestination, f.noteID, "", false); GaslessRefusalCode(err) != CodeWalletFeesUnavailable {
		t.Fatalf("a wallet fallback while the approval holds: %v", err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	g.f.mu.Lock()
	g.down = false
	g.f.mu.Unlock()
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || len(g.sends) != 1 || len(f.accepted) != accepted {
		t.Fatalf("not resumed after the restart: %+v %v", status, err)
	}
}

// The authorization covers its destination, note and identity only:
// another destination or note is refused before anything is signed, and a
// journal whose authorization names another payout address, transit
// account, vault or bound is refused on load.
func TestGaslessAuthorizationIsBoundToItsDestinationNoteAndIdentity(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	quote := authorizedQuote(t, f, payoutFees)
	f.setBaseFee(20_000_000_000)
	if status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID); err != nil || !status.GaslessRetryable {
		t.Fatalf("approval: %+v %v", status, err)
	}
	f.setBaseFee(1_000_000_000)
	other := common.HexToAddress("0x" + strings.Repeat("44", 20)).Hex()
	if _, err := f.h.WithdrawAddress(context.Background(), other, f.noteID); err == nil {
		t.Fatal("another destination was accepted")
	}
	if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID+1); err == nil {
		t.Fatal("another note was accepted")
	}
	if len(g.sends) != 0 {
		t.Fatal("something was signed for another destination or note")
	}
	for name, tamper := range map[string]func(*gaslessAuthorization){
		"destination": func(a *gaslessAuthorization) { a.Destination = other },
		"transit":     func(a *gaslessAuthorization) { a.TransitAccount = other },
		"vault":       func(a *gaslessAuthorization) { a.Contract = other },
		"note":        func(a *gaslessAuthorization) { a.NoteID++ },
		"bound": func(a *gaslessAuthorization) {
			a.MaxTotalFeeWei = new(big.Int).Add(weiOf(t, a.MaxTotalFeeWei), big.NewInt(1)).String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			saved := f.journal(t)
			tampered := saved
			w := *saved.Withdrawal
			a := *w.Authorization
			tamper(&a)
			w.Authorization = &a
			tampered.Withdrawal = &w
			if err := f.h.saveAddress(&tampered); err == nil {
				if _, err := f.h.AddressWithdrawal(context.Background()); err == nil {
					t.Fatal("a tampered authorization was loaded")
				}
			}
			if err := f.h.saveAddress(&saved); err != nil {
				t.Fatal(err)
			}
		})
	}
	if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "op_submitted" {
		t.Fatalf("the untampered approval no longer resumes: %+v %v", status, err)
	}
}

// One charged inclusion per approval: copies share the first one's nonce.
// A nonce that moved (an operation of the transit account was included) ends
// the approval; nothing is ever signed at the next nonce under it.
func TestGaslessAuthorizationNeverMovesToANewNonce(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	first := f.sponsoredClose(t)
	pinned := f.journal(t).Withdrawal.Authorization.Nonce
	if pinned == "" || pinned != f.journal(t).Withdrawal.UserOp.Nonce {
		t.Fatalf("the nonce was not pinned: %q", pinned)
	}
	// A refusal for now, then the nonce moves without a copy found.
	f.editJournal(t, func(record *addressFundingRecord) {
		record.Withdrawal.Phase, record.Withdrawal.GaslessRefusal = "gasless_refused", "bundler_unavailable: test"
	})
	g.consumeOperationNonce(t, f)
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if GaslessRefusalCode(err) != "nonce_consumed" || status.Phase != "gasless_refused" || status.GaslessRetryable || !strings.HasPrefix(status.GaslessRefusal, "nonce_consumed") || len(g.sends) != 1 || g.sends[0] != first {
		t.Fatalf("a copy at a new nonce: %+v %v %v", status, err, g.sends)
	}
	if a := f.journal(t).Withdrawal.Authorization; a == nil || a.Revoked == "" || a.Nonce != pinned {
		t.Fatalf("the approval was not ended: %+v", a)
	}
	if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); len(g.sends) != 1 {
		t.Fatalf("a later resume signed under the ended approval: %+v %v", status, err)
	}
}

// A copy signed before an automatic rebuild stays journaled with the next
// one: a bundler that includes the earlier copy late still settles the
// withdrawal, found by its hash, and nothing is proved or sent again.
func TestGaslessAuthorizationKeepsEarlierCopiesAcrossRebuilds(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	first := f.sponsoredClose(t)
	f.editJournal(t, func(record *addressFundingRecord) {
		record.Withdrawal.Phase, record.Withdrawal.GaslessRefusal = "gasless_refused", "bundler_unavailable: test"
	})
	f.setBaseFee(1_100_000_000)
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash == first || len(g.sends) != 2 {
		t.Fatalf("no rebuild: %+v %v %v", status, err, g.sends)
	}
	second := status.UserOpHash
	u := f.journal(t).Withdrawal.UserOp
	if len(u.Hashes) < 2 || u.Hashes[0] != first || u.Hash != second || u.Nonce != signedOp(t, g, first).Nonce.String() {
		t.Fatalf("the earlier copy was dropped from the journal: %+v", u)
	}
	prepares := len(f.prepareBodies)
	bundle := g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.TransactionHash != bundle || status.ReceivedWei == "" {
		t.Fatalf("the late earlier copy did not settle the withdrawal: %+v %v", status, err)
	}
	if w := f.journal(t).Withdrawal; w.UserOp.IncludedHash != first || len(f.prepareBodies) != prepares || len(g.sends) != 2 {
		t.Fatalf("the late copy was not adopted: %+v", w.UserOp)
	}
}

// Every rebuild before signing goes through the same pricing and checks:
// a close whose fee was lowered to fit the approval is rebuilt after a
// stale nonce (AA25) or a transit account created meanwhile (AA10) within
// the approval again, never at the unclamped fee.
func TestGaslessAuthorizationDryRunRebuildKeepsTheBound(t *testing.T) {
	for _, failure := range []string{"AA25 invalid account nonce", "AA10 sender already constructed"} {
		t.Run(failure[:4], func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			quote := authorizedQuote(t, f, payoutFees)
			f.setBaseFee(10_000_000_000)
			g.f.mu.Lock()
			g.dryRunRevertOnce = common.FromHex(fixtureFailedOp(failure))
			g.f.mu.Unlock()
			status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
			if err != nil || status.Phase != "op_submitted" || len(g.sends) != 1 {
				t.Fatalf("approval: %+v %v", status, err)
			}
			op := signedOp(t, g, status.UserOpHash)
			if loss := payoutLoss(op, g.flatFee, g.profile.GasPolicy, false); loss.Cmp(weiOf(t, quote.MaxTotalFeeWei)) > 0 || op.MaxFeePerGas.Cmp(big.NewInt(20_000_000_000)) >= 0 {
				t.Fatalf("the rebuilt copy left the approval: maxFee %s, loss %s", op.MaxFeePerGas, loss)
			}
			if (failure[:4] == "AA10") != (len(op.InitCode) == 0) {
				t.Fatal("the rebuild did not follow the dry run")
			}
		})
	}
}

// A re-signed copy counts the payout address as it is now: one that gained
// code after the quote (EIP-7702) owes the credit surcharge, which must fit
// the approval too, so a bump that would not is not signed.
func TestGaslessAuthorizationReplacementCountsAPayeeThatGainedCode(t *testing.T) {
	for _, gainsCode := range []bool{false, true} {
		t.Run(fmt.Sprint(gainsCode), func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			first := f.sponsoredClose(t)
			op := signedOp(t, g, first)
			raise := func(fee *big.Int) *big.Int {
				return new(big.Int).Add(new(big.Int).Add(fee, new(big.Int).Quo(fee, big.NewInt(8))), big.NewInt(1))
			}
			bumped := *op
			bumped.MaxFeePerGas, bumped.MaxPriorityFeePerGas = raise(op.MaxFeePerGas), raise(op.MaxPriorityFeePerGas)
			// An approval that fits the raised copy, but not its surcharge.
			loss := payoutLoss(&bumped, g.flatFee, g.profile.GasPolicy, false)
			surcharge := new(big.Int).Mul(new(big.Int).SetUint64(g.profile.GasPolicy.CreditGas), bumped.MaxFeePerGas)
			maximum := new(big.Int).Add(loss, new(big.Int).Quo(surcharge, big.NewInt(2)))
			f.editJournal(t, func(record *addressFundingRecord) {
				a := record.Withdrawal.Authorization
				a.MaxTotalFeeWei, a.MinNetPayoutWei = maximum.String(), new(big.Int).Sub(gaslessPayoutWei, maximum).String()
				record.Withdrawal.UserOp.FeeCapWei = maximum.String()
				record.Withdrawal.UserOp.SubmittedAt -= 400
			})
			if gainsCode {
				g.f.mu.Lock()
				g.codes[strings.ToLower(withdrawalTestDestination)] = "0xef0100" + strings.Repeat("ab", 20)
				g.f.mu.Unlock()
			}
			g.known[first], g.refuseResend = false, true
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil {
				t.Fatal(err)
			}
			hashes := f.journal(t).Withdrawal.UserOp.Hashes
			if gainsCode {
				if status.Phase != "gasless_refused" || !strings.HasPrefix(status.GaslessRefusal, CodeFeeAboveAuthorization) || len(hashes) != 1 || len(g.sends) != 1 {
					t.Fatalf("a copy whose surcharge leaves the approval: %+v %v", status, hashes)
				}
				return
			}
			if status.Phase != "op_submitted" || len(hashes) != 2 || len(g.sends) != 2 {
				t.Fatalf("the raised copy that fits was not signed: %+v %v", status, hashes)
			}
		})
	}
}

// A funding address without any ETH withdraws: nothing is asked of it, the
// payout pays the fee, and the status shows what arrived and what the fee
// took.
func TestGaslessZeroETHSignerCompletesTheWithdrawal(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	f.mu.Lock()
	f.eth = "0x0"
	f.mu.Unlock()
	accepted := len(f.accepted)
	quote := authorizedQuote(t, f, payoutFees)
	if quote.ShortfallWei != "0" || quote.RecommendedTopUpWei != "0" {
		t.Fatalf("the payout quote asked for ETH: %+v", quote)
	}
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if err != nil || status.Phase != "op_submitted" || status.ETHBalance != "0" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	g.mineUserOp(t, status.UserOpHash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(7), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(7))})
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.ChargedWei != "7" || status.ReceivedWei != new(big.Int).Sub(gaslessPayoutWei, big.NewInt(7)).String() {
		t.Fatalf("not complete: %+v %v", status, err)
	}
	if len(f.accepted) != accepted {
		t.Fatal("the funding address signed a transaction")
	}
}

// The management API: a new withdrawal is quoted payout-paid without naming
// a fee mode, a wallet-paid one is refused by code with nothing reserved,
// the status names the policy, and an approval answers with the
// authorization; an expired quote and an invalid payee are named by code.
func TestGaslessManagementAPIOffersOnlyThePayoutWithdrawal(t *testing.T) {
	f, _ := newGaslessWithdrawalFixture(t)
	call := func(method, path, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, "http://127.0.0.1:8787"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.h.ServeAdminHTTP(recorder, r)
		var answer map[string]any
		_ = json.Unmarshal(recorder.Body.Bytes(), &answer)
		return recorder.Code, answer
	}
	code, answer := call("GET", "/admin/withdrawal", "")
	if code != http.StatusOK || answer["new_withdrawal_fees"] != "payout" {
		t.Fatalf("status: %d %+v", code, answer)
	}
	code, answer = call("POST", "/admin/withdrawal/quote", fmt.Sprintf(`{"destination":%q,"note_id":%d,"fees":"wallet"}`, withdrawalTestDestination, f.noteID))
	if code == http.StatusOK || answer["code"] != CodeWalletFeesUnavailable || f.journal(t).Withdrawal != nil || f.prepareCalls != 0 {
		t.Fatalf("a wallet-paid withdrawal: %d %+v", code, answer)
	}
	code, answer = call("POST", "/admin/withdrawal", fmt.Sprintf(`{"destination":%q,"note_id":%d}`, withdrawalTestDestination, f.noteID))
	if code == http.StatusOK || f.journal(t).Withdrawal != nil {
		t.Fatalf("an unquoted withdrawal reserved the note: %d %+v", code, answer)
	}
	code, answer = call("POST", "/admin/withdrawal/quote", fmt.Sprintf(`{"destination":%q,"note_id":%d}`, "0x0000000000000000000000000000000000000009", f.noteID))
	if code == http.StatusOK || answer["code"] != CodeInvalidPayee {
		t.Fatalf("an invalid payee: %d %+v", code, answer)
	}
	code, answer = call("POST", "/admin/withdrawal/quote", fmt.Sprintf(`{"destination":%q,"note_id":%d}`, withdrawalTestDestination, f.noteID))
	if code != http.StatusOK || answer["fee_policy"] != "payout" || answer["max_total_fee_wei"] == nil || answer["fee_may_change"] != true {
		t.Fatalf("no payout quote: %d %+v", code, answer)
	}
	id := answer["id"].(string)
	code, answer = call("POST", "/admin/withdrawal/approve", `{"quote_id":"`+strings.Repeat("0", 64)+`"}`)
	if code == http.StatusOK || answer["code"] != CodeQuoteChanged {
		t.Fatalf("another quote approved: %d %+v", code, answer)
	}
	code, answer = call("POST", "/admin/withdrawal/approve", `{"quote_id":"`+id+`"}`)
	if code != http.StatusOK || answer["phase"] != "op_submitted" || answer["authorized_max_fee_wei"] == nil || answer["authorized_min_net_payout_wei"] == nil {
		t.Fatalf("approval: %d %+v", code, answer)
	}
}

// A rebuilt copy whose send lands but whose answer is lost is still looked
// for by its own hash: every signed copy is journaled before it is sent.
func TestGaslessAuthorizationFindsARebuiltCopyWhoseSendAnswerWasLost(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	first := f.sponsoredClose(t)
	f.editJournal(t, func(record *addressFundingRecord) {
		record.Withdrawal.Phase, record.Withdrawal.GaslessRefusal = "gasless_refused", "bundler_unavailable: test"
	})
	f.setBaseFee(1_100_000_000)
	g.f.mu.Lock()
	g.sendDown = true
	g.f.mu.Unlock()
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_built" {
		t.Fatalf("the rebuilt copy: %+v %v", status, err)
	}
	u := f.journal(t).Withdrawal.UserOp
	second := u.Hash
	listed := false
	for _, hash := range u.Hashes {
		listed = listed || hash == second
	}
	if second == first || !listed || u.Hashes[0] != first {
		t.Fatalf("the rebuilt copy is not journaled before its send: %+v", u)
	}
	// The bundler answers again: the journaled copy is sent as it is and,
	// once included, settles the withdrawal; the earlier copy is still
	// looked for beside it.
	g.f.mu.Lock()
	g.sendDown = false
	g.f.mu.Unlock()
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || g.sends[len(g.sends)-1] != second {
		t.Fatalf("the journaled copy was not sent: %+v %v %v", status, err, g.sends)
	}
	bundle := g.mineUserOp(t, second, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.TransactionHash != bundle {
		t.Fatalf("the rebuilt copy did not settle the withdrawal: %+v %v", status, err)
	}
}

// realProofHex is the fixture's exit proof (256 bytes of 0x5a), as it
// would appear in any request that carried it.
var realProofHex = strings.Repeat("5a", 256)

// A quote publishes nothing executable: no request it makes carries the
// real exit proof (the vault's close is permissionless) or a signature the
// transit account's owner made; the approval then signs and sends the real
// operation.
func TestGaslessQuotePublishesNoExecutableClose(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	var dryRuns []*gaslessUserOp
	g.f.mu.Lock()
	g.dryRunHook = func(op *gaslessUserOp) { dryRuns = append(dryRuns, op) }
	f.outbound = nil
	g.f.mu.Unlock()
	quote := authorizedQuote(t, f, payoutFees)
	owner := f.journal(t).Withdrawal.Transit.Owner
	g.f.mu.Lock()
	outbound := append([]string{}, f.outbound...)
	quoteDryRuns := append([]*gaslessUserOp{}, dryRuns...)
	g.f.mu.Unlock()
	if len(outbound) == 0 || len(quoteDryRuns) != 0 {
		t.Fatalf("the quote simulated the operation (%d dry runs) or made no requests", len(quoteDryRuns))
	}
	for _, request := range outbound {
		if strings.Contains(strings.ToLower(request), realProofHex) {
			t.Fatalf("a quote request carried the exit proof: %.120s", request)
		}
	}
	for _, op := range quoteDryRuns {
		if signer, err := recoverUserOpSigner(op.hash(g.entryPoint, 1), op.Signature); err == nil && strings.EqualFold(signer.Hex(), owner) {
			t.Fatal("the quote's dry run carried the owner's signature")
		}
	}
	if len(g.sends) != 0 {
		t.Fatal("the quote sent an operation")
	}
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	sent := signedOp(t, g, status.UserOpHash)
	if signer, err := recoverUserOpSigner(sent.hash(g.entryPoint, 1), sent.Signature); err != nil || !strings.EqualFold(signer.Hex(), owner) || !strings.Contains(hex.EncodeToString(sent.CallData), realProofHex) {
		t.Fatal("the approved operation is not the owner's signed close")
	}
}

// An approved copy is journaled (bytes, hash, nonce) before its signed dry
// run shows it to the RPC; a dry run whose answer is lost leaves that copy,
// which a fresh process sends as it is, with no new approval or proof.
func TestGaslessApprovedCopyIsJournaledBeforeItsDryRun(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	quote := authorizedQuote(t, f, payoutFees)
	journaledFirst := false
	g.f.mu.Lock()
	g.dryRunHook = func(op *gaslessUserOp) {
		u := f.journal(t).Withdrawal.UserOp
		journaledFirst = u != nil && strings.EqualFold(u.Hash, op.hash(g.entryPoint, 1).Hex()) && u.Nonce == op.Nonce.String()
	}
	g.dropDryRunOnce = true
	g.f.mu.Unlock()
	if _, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID); err == nil {
		t.Fatal("a lost dry run answer was taken for success")
	}
	w := f.journal(t).Withdrawal
	if w.UserOp == nil || w.Phase != "op_built" || w.Authorization == nil || w.Authorization.Nonce != w.UserOp.Nonce || len(g.sends) != 0 {
		t.Fatalf("the signed copy was not journaled: %+v", w)
	}
	saved := w.UserOp.Hash
	g.f.mu.Lock()
	g.dryRunHook = nil
	g.f.mu.Unlock()
	prepares := len(f.prepareBodies)
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || len(g.sends) != 1 || g.sends[0] != saved || len(f.prepareBodies) != prepares {
		t.Fatalf("the journaled copy was not recovered: %+v %v %v", status, err, g.sends)
	}
	// The journal check ran on a later dry run too (none here: the
	// recovered copy is sent as it was journaled).
	_ = journaledFirst
	f2, g2 := newGaslessWithdrawalFixture(t)
	quote = authorizedQuote(t, f2, payoutFees)
	g2.f.mu.Lock()
	g2.dryRunHook = func(op *gaslessUserOp) {
		u := f2.journal(t).Withdrawal.UserOp
		journaledFirst = u != nil && strings.EqualFold(u.Hash, op.hash(g2.entryPoint, 1).Hex())
	}
	g2.f.mu.Unlock()
	if status, err := f2.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID); err != nil || status.Phase != "op_submitted" || !journaledFirst {
		t.Fatalf("the dry run saw a copy the journal did not hold: %+v %v", status, err)
	}
}

// A stale nonce at the signed dry run never moves the approval: the copy
// at the pinned nonce stays journaled, nothing is signed at the next nonce.
func TestGaslessApprovalDryRunAtAConsumedNonceSignsNothingNew(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	quote := authorizedQuote(t, f, payoutFees)
	g.f.mu.Lock()
	g.dryRunHook = func(op *gaslessUserOp) {
		// Another operation of the transit account takes the nonce.
		g.sequences[strings.ToLower(op.Sender.Hex())+"|"+new(big.Int).Rsh(op.Nonce, 64).String()]++
		g.dryRunHook = nil
	}
	g.dryRunRevertOnce = common.FromHex(fixtureFailedOp("AA25 invalid account nonce"))
	g.f.mu.Unlock()
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if GaslessRefusalCode(err) != "nonce_consumed" || status.Phase != "gasless_refused" || len(g.sends) != 0 {
		t.Fatalf("a copy at a new nonce: %+v %v %v", status, err, g.sends)
	}
	w := f.journal(t).Withdrawal
	if w.UserOp == nil || w.UserOp.Nonce != w.Authorization.Nonce || len(w.UserOp.Hashes) != 1 || w.Authorization.Revoked == "" {
		t.Fatalf("the pinned copy was not kept, or the approval moved: %+v %+v", w.UserOp, w.Authorization)
	}
}
