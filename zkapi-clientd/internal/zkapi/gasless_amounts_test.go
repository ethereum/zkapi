package zkapi

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// ERC-7562 LIM-070: a bundler refuses an operation whose preVerificationGas
// is below the calldata cost of the packed operation plus
// PRE_VERIFICATION_OVERHEAD_GAS (50,000). The client signs at least that
// (with a 65-byte non-zero signature, so the real one never costs more) for
// every shape of the vectors, above the eth-infinitism reference formula as
// well, and within the paymaster's cap.
func TestGaslessPreVerificationGasCoversLIM070(t *testing.T) {
	_, g := newGaslessWithdrawalFixture(t)
	policy := g.profile.GasPolicy
	v := loadTransitVectors(t)
	closeWithInit := vectorOp(t, v)
	closeWithout := vectorOp(t, v)
	closeWithout.InitCode, closeWithout.VerificationGasLimit = nil, policy.VerificationDefault
	finalize := vectorOp(t, v)
	finalize.InitCode, finalize.CallData = nil, transitCallData(common.FromHex(finalizeEscapeCalldata(0)))
	forward := vectorOp(t, v)
	forward.InitCode, forward.CallData = nil, transitCallData(nil)
	for name, op := range map[string]*gaslessUserOp{"close with initCode": closeWithInit, "close": closeWithout, "finalize": finalize, "forward": forward} {
		required := op.requiredPreVerificationGas(policy)
		probe := *op
		probe.Signature = bytes.Repeat([]byte{0xff}, 65)
		probe.PreVerificationGas = required
		packed := probe.abiTuple()
		minimum := calldataCost(packed) + 50_000
		reference := 21_000 + 18_300 + calldataCost(packed) + 4*uint64((len(packed)+31)/32)
		if required < minimum || required < reference || required > policy.PVGCap || required < policy.PVGFloor {
			t.Fatalf("%s: preVerificationGas %d, LIM-070 minimum %d, reference %d, cap %d", name, required, minimum, reference, policy.PVGCap)
		}
		// A re-sign with higher fees never needs more.
		bumped := probe
		bumped.MaxFeePerGas, bumped.MaxPriorityFeePerGas = new(big.Int).Lsh(big.NewInt(1), 127), new(big.Int).Lsh(big.NewInt(1), 127)
		if calldataCost(bumped.abiTuple())+50_000 > required {
			t.Fatalf("%s: a fee bump outgrows the signed preVerificationGas", name)
		}
	}
	// The shape a quote prices before the proof exists covers the real one.
	shape := gaslessShapeOp(policy, gaslessKindClose, true, g.paymaster, g.flatFee, 0)
	if shape.PreVerificationGas < closeWithInit.requiredPreVerificationGas(policy) {
		t.Fatalf("the pre-proof shape's preVerificationGas %d is below the real operation's", shape.PreVerificationGas)
	}
}

// The preVerificationGas rule the SDK shares, PVG = clamp(max(A,
// ceil(1.1 × B), C), pvg_floor, pvg_cap), on the vectors' close operation
// (unsigned, as built) with and without its initCode, a FORWARD of the same
// sender and a FINALIZE. The expected numbers were computed independently
// (not by either client) and are asserted, the same, by the SDK's
// "preVerificationGas follows the rule zkapi-clientd shares" test in
// sdk/test/zkapi-gasless.test.mjs.
func TestGaslessPreVerificationGasParity(t *testing.T) {
	v := loadTransitVectors(t)
	var policy gaslessGasPolicy
	if err := json.Unmarshal(v.GasPolicy, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.PVGFloor != 40_000 || policy.PVGCap != 150_000 {
		t.Fatalf("the vectors' pvg floor and cap moved: %d, %d", policy.PVGFloor, policy.PVGCap)
	}
	closeWithInit := vectorOp(t, v)
	closeWithInit.Signature = nil
	closeWithout := *closeWithInit
	closeWithout.InitCode = nil
	forward := closeWithout
	forward.CallData, forward.CallGasLimit = transitCallData(nil), 97_500
	forward.Nonce = new(big.Int).Lsh(gaslessForwardNonceKey, 64)
	finalize := closeWithout
	finalize.CallData, finalize.CallGasLimit = transitCallData(common.FromHex(finalizeEscapeCalldata(vectorUint(t, v.Close.NoteID).Uint64()))), 295_000
	finalize.Nonce = new(big.Int).Or(new(big.Int).Lsh(vectorUint(t, v.Close.NonceKey), 64), big.NewInt(1))
	for _, test := range []struct {
		name                   string
		op                     *gaslessUserOp
		lim070, reference, pvg uint64
		handleOpsBytes         int
	}{
		// A (LIM-070 term), B (reference minimum), PVG, handleOps bytes (C = 21,000 + 16 × bytes + 10,000)
		{"close with initCode", closeWithInit, 66_316, 52_668, 66_316, 1_764},
		{"close without initCode", &closeWithout, 65_356, 51_696, 65_356, 1_668},
		{"forward", &forward, 57_904, 44_136, 57_904, 804},
		{"finalize", &finalize, 57_956, 44_196, 57_956, 868},
	} {
		if got := test.op.lim070PreVerificationGas(policy); got != test.lim070 {
			t.Errorf("%s: A %d, want %d", test.name, got, test.lim070)
		}
		if got := test.op.referencePreVerificationGas(policy); got != test.reference {
			t.Errorf("%s: B %d, want %d", test.name, got, test.reference)
		}
		if got := test.op.handleOpsCalldataBytes(policy); got != test.handleOpsBytes {
			t.Errorf("%s: handleOps bytes %d, want %d", test.name, got, test.handleOpsBytes)
		}
		if got := test.op.requiredPreVerificationGas(policy); got != test.pvg {
			t.Errorf("%s: preVerificationGas %d, want %d", test.name, got, test.pvg)
		}
		// The op's own preVerificationGas does not move the figure.
		moved := *test.op
		moved.PreVerificationGas = 1
		if got := moved.requiredPreVerificationGas(policy); got != test.pvg {
			t.Errorf("%s: preVerificationGas %d with another signed value", test.name, got)
		}
	}
	// The clamp: a floor above every term, a cap below them.
	floored, capped := policy, policy
	floored.PVGFloor, capped.PVGCap = 70_000, 60_000
	if got := closeWithInit.requiredPreVerificationGas(floored); got != 70_000 {
		t.Errorf("a floor of 70,000: %d", got)
	}
	if got := closeWithInit.requiredPreVerificationGas(capped); got != 60_000 {
		t.Errorf("a cap of 60,000: %d", got)
	}
}

// The bundler's preVerificationGas estimate above the client's own (within
// the cap) is what that bundler requires: it is adopted in the quote's
// amounts and in the signed operation, which the approval binds; one above
// the cap is refused; one below the client's own is ignored.
func TestGaslessQuoteAdoptsTheBundlersPreVerificationGas(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	policy := g.profile.GasPolicy
	estimate := func(pvg uint64) map[string]string {
		return map[string]string{"preVerificationGas": hexQuantityUint(pvg), "verificationGasLimit": hexQuantityUint(policy.VerificationFloorInit), "callGasLimit": hexQuantityUint(policy.CallFloor[gaslessKindClose-1]), "paymasterVerificationGasLimit": hexQuantityUint(policy.PMVerificationFloor), "paymasterPostOpGasLimit": hexQuantityUint(policy.PostOpFloor)}
	}
	const wanted = 120_000
	f.mu.Lock()
	g.estimate = estimate(wanted)
	f.mu.Unlock()
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	maxFee, _ := new(big.Int).SetString(quote.MaxFeePerGas, 10)
	gas := quote.UserOpGas
	maxCost := new(big.Int).Mul(new(big.Int).SetUint64(gas.PreVerificationGas+gas.VerificationGasLimit+gas.CallGasLimit+gas.PaymasterVerificationGasLimit+gas.PaymasterPostOpGasLimit), maxFee)
	if gas.PreVerificationGas != wanted || quote.FeeCapWei != new(big.Int).Add(maxCost, g.flatFee).String() {
		t.Fatalf("the bundler's preVerificationGas was not adopted: %+v", quote)
	}
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	if sent, _ := gasfromJSON(t, g.ops[status.UserOpHash]); sent.PreVerificationGas != wanted {
		t.Fatalf("the signed operation carries preVerificationGas %d", sent.PreVerificationGas)
	}
	// Above the cap: the bundler is suspect.
	f2, g2 := newGaslessWithdrawalFixture(t)
	f2.mu.Lock()
	g2.estimate = estimate(policy.PVGCap + 1)
	f2.mu.Unlock()
	if _, err := f2.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f2.noteID, "", false); GaslessRefusalCode(err) != "gasless_estimate_above_cap" {
		t.Fatalf("an estimate above the cap: %v", err)
	}
	// Below the client's own: ignored, the shared rule's figure is quoted
	// and signed.
	f3, g3 := newGaslessWithdrawalFixture(t)
	f3.mu.Lock()
	g3.estimate = estimate(policy.PVGFloor)
	f3.mu.Unlock()
	lower, err := f3.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f3.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if lower.UserOpGas.PreVerificationGas <= policy.PVGFloor {
		t.Fatalf("a lower estimate was adopted: %d", lower.UserOpGas.PreVerificationGas)
	}
	status, err = f3.h.ApproveAddressWithdrawal(payoutContext(payoutFees), lower.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	sent, _ := gasfromJSON(t, g3.ops[status.UserOpHash])
	unsigned := *sent
	unsigned.Signature = nil
	if sent.PreVerificationGas != lower.UserOpGas.PreVerificationGas || sent.PreVerificationGas != unsigned.requiredPreVerificationGas(policy) {
		t.Fatalf("signed preVerificationGas %d, quoted %d, the rule's %d", sent.PreVerificationGas, lower.UserOpGas.PreVerificationGas, unsigned.requiredPreVerificationGas(policy))
	}
}

// --fee-cap-gwei bounds what the payout may lose: for a contract payout
// address that includes the paymaster's credit surcharge, taken beyond the
// operation's maximum when the push fails, so a cap between the maximum and
// the maximum plus the surcharge is refused (on the quote, and so on every
// fee bump checked the same way).
func TestGaslessFeeCapIncludesTheCreditSurchargeOfAContractPayee(t *testing.T) {
	_, g := newGaslessWithdrawalFixture(t)
	policy := g.profile.GasPolicy
	op := vectorOp(t, loadTransitVectors(t))
	payout := new(big.Int).Mul(big.NewInt(2), big.NewInt(100_000_000_000_000_000))
	live := gaslessLive{FlatFee: g.flatFee, Owed: new(big.Int), MaxSponsoredCost: g.maxSponsoredCost, MinEscapeNet: g.minEscapeNet, BaseFee: big.NewInt(10_000_000_000)}
	a := gaslessAmountsFor(gaslessKindClose, payout, op, live, policy, true, false)
	if a.CreditSurcharge.Sign() == 0 {
		t.Fatal("no credit surcharge for a contract payee")
	}
	ceilGwei := func(wei *big.Int) uint64 {
		q, r := new(big.Int).QuoRem(wei, big.NewInt(1_000_000_000), new(big.Int))
		if r.Sign() != 0 {
			q.Add(q, big.NewInt(1))
		}
		return q.Uint64()
	}
	justAboveMaximum := addressWithdrawalOptions{FeeCapGwei: ceilGwei(a.FeeCap), AllowExpensiveGas: true}
	err := checkGaslessAmounts(a, gaslessKindClose, live, 100, justAboveMaximum)
	if GaslessRefusalCode(err) != "fee_above_cap" || !strings.Contains(err.Error(), "credit surcharge") {
		t.Fatalf("a cap below the maximum plus the surcharge: %v", err)
	}
	enough := addressWithdrawalOptions{FeeCapGwei: ceilGwei(new(big.Int).Add(a.FeeCap, a.CreditSurcharge)), AllowExpensiveGas: true}
	if err := checkGaslessAmounts(a, gaslessKindClose, live, 100, enough); err != nil {
		t.Fatalf("a cap covering the surcharge: %v", err)
	}
	// An address without code pays no surcharge: the maximum alone counts.
	plain := gaslessAmountsFor(gaslessKindClose, payout, op, live, policy, false, false)
	if err := checkGaslessAmounts(plain, gaslessKindClose, live, 100, justAboveMaximum); err != nil {
		t.Fatalf("an address without code: %v", err)
	}
}

// Only an explicit duplicate answer counts as "the bundler holds it": a
// validation failure whose text says "already" (AA10 sender already
// constructed) is not one, and AA10 is recognised in the data or the text.
func TestGaslessBundlerRefusalsAreClassified(t *testing.T) {
	failed := []byte(`"0x` + fixtureFailedOp("AA10 sender already constructed") + `"`)
	for _, test := range []struct {
		refusal     rpcError
		holds, aa10 bool
	}{
		{rpcError{Message: "already known"}, true, false},
		{rpcError{Message: "UserOperation already in mempool"}, true, false},
		{rpcError{Message: "AA10 sender already constructed"}, false, true},
		{rpcError{Message: "validation reverted", Data: failed}, false, true},
		{rpcError{Message: "replacement op must increase maxFeePerGas and maxPriorityFeePerGas"}, false, false},
		{rpcError{Message: "the sender is already being processed"}, false, false},
	} {
		if bundlerHoldsOperation(&test.refusal) != test.holds || bundlerRefusedAA10(&test.refusal) != test.aa10 {
			t.Fatalf("%q classified wrongly", test.refusal.Message)
		}
	}
}
