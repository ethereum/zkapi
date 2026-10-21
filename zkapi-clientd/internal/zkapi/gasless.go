package zkapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Gasless withdrawals over ERC-4337 (EntryPoint v0.7.0): the shared client
// logic of design section 3.1, byte-checked against the cross-language
// vectors in protocol/contracts/test/fixtures/transit-vectors.json. A vault
// exit whose destination is a transit account S (the CREATE2 of a fresh owner
// key and the payout address Y) is carried by a user operation the
// ZkApiWithdrawalPaymaster sponsors: the payout address needs no ETH, the
// paymaster keeps a measured gas charge out of what S forwards, and the rest
// reaches Y. This file holds the profile, the derivations, the packing and
// hashing, the ABI of the EntryPoint and the paymaster, the bundler JSON-RPC
// client and the deployment checks; gasless_flow.go drives a withdrawal.

// Operation kinds, as the paymaster numbers them.
const (
	gaslessKindClose    uint8 = 1
	gaslessKindEscape   uint8 = 2
	gaslessKindFinalize uint8 = 3
	gaslessKindForward  uint8 = 4
)

// gaslessKindNames name the kinds in records, quotes and status.
var gaslessKindNames = map[uint8]string{gaslessKindClose: "close", gaslessKindEscape: "escape", gaslessKindFinalize: "finalize", gaslessKindForward: "forward"}

// gaslessKindOf is the inverse of gaslessKindNames; 0 for an unknown name.
func gaslessKindOf(name string) uint8 {
	for kind, known := range gaslessKindNames {
		if known == name {
			return kind
		}
	}
	return 0
}

// The paymaster's and the EntryPoint's errors are bounded: an op must not
// stay in flight longer than the proof it carries; the bundler is asked
// again after this long without inclusion; a stop this long before
// valid_until leaves no room for a late inclusion to pay.
const (
	gaslessResendAfter   = 5 * time.Minute
	gaslessExpiryMargin  = 60 * time.Second
	gaslessFeeBumpEighth = 8 // +12.5%: fee + fee/8
)

// Canonical EntryPoint v0.7.0 and its SenderCreator, pinned by runtime
// codehash on every chain (design section 0).
const (
	gaslessEntryPointCodehash    = "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58"
	gaslessSenderCreatorCodehash = "0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689"
)

// selectorOf is the 4-byte selector of a function signature, as 8 hex
// characters (the style of withdrawalSelector).
func selectorOf(signature string) string {
	return hex.EncodeToString(crypto.Keccak256([]byte(signature))[:4])
}

func topicOf(signature string) string {
	return crypto.Keccak256Hash([]byte(signature)).Hex()
}

// The ABI of the gasless contracts, derived from their signatures.
const packedUserOperationTuple = "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)"

var (
	// EntryPoint v0.7.0.
	selectorGetNonce          = selectorOf("getNonce(address,uint192)")
	selectorGetUserOpHash     = selectorOf("getUserOpHash(" + packedUserOperationTuple + ")")
	selectorHandleOps         = selectorOf("handleOps(" + packedUserOperationTuple + "[],address)")
	selectorEntryPointBalance = selectorOf("balanceOf(address)")
	// ZkApiWithdrawalAccount.
	selectorTransitWithdraw = selectorOf("withdraw(bytes)")
	selectorTransitSweep    = selectorOf("sweep()")
	// ZkApiWithdrawalAccountFactory.
	selectorCreateAccount           = selectorOf("createAccount(address,address)")
	selectorFactoryGetAddress       = selectorOf("getAddress(address,address)")
	selectorAccountCreationCodeHash = selectorOf("accountCreationCodeHash()")
	selectorFactoryPaymaster        = selectorOf("paymaster()")
	selectorFactoryImplementation   = selectorOf("implementation()")
	// ZkApiWithdrawalPaymaster.
	selectorPaymasterEntryPoint = selectorOf("entryPoint()")
	selectorPaymasterVault      = selectorOf("vault()")
	selectorPaymasterFactory    = selectorOf("factory()")
	selectorWeiPerUnit          = selectorOf("WEI_PER_UNIT()")
	selectorGasPolicy           = selectorOf("gasPolicy()")
	selectorPaymasterPolicy     = selectorOf("policy()")
	selectorMaxFeeCeiling       = selectorOf("maxFeeCeiling()")
	selectorPriorityFeeCeiling  = selectorOf("priorityFeeCeiling()")
	selectorCallCap             = selectorOf("callCap(uint8)")
	selectorAttempts            = selectorOf("attempts(bytes32)")
	selectorOwed                = selectorOf("owed(address)")
	selectorStranded            = selectorOf("stranded(address)")
	selectorEscapeNotePlusOne   = selectorOf("escapeNotePlusOne(address)")
	selectorCredits             = selectorOf("credits(address)")
	selectorPaymasterQuote      = selectorOf("quote(uint8,address,uint32,uint256,uint256,uint256)")
	selectorClaimCredit         = selectorOf("claimCredit(address)")
	// ZkApiVault getters the gasless path reads.
	selectorPendingWithdrawals = selectorOf("pendingWithdrawals(uint32)")
	selectorVaultPaused        = selectorOf("paused()")
	selectorVaultPausedAt      = selectorOf("pausedAt()")
)

var (
	userOperationEventTopic         = topicOf("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)")
	userOperationRevertReasonTopic  = topicOf("UserOperationRevertReason(bytes32,address,uint256,bytes)")
	accountDeployedTopic            = topicOf("AccountDeployed(bytes32,address,address,address)")
	paymasterSettledTopic           = topicOf("Settled(bytes32,address,address,uint8,uint32,uint256,uint256,uint256,uint256)")
	paymasterSponsorshipFailedTopic = topicOf("SponsorshipFailed(bytes32,address,uint8,uint32,uint256)")
	paymasterPayoutCreditedTopic    = topicOf("PayoutCredited(address,uint256)")
	paymasterCreditClaimedTopic     = topicOf("CreditClaimed(address,uint256)")
	paymasterCollectedTopic         = topicOf("Collected(address,address,uint256,uint256,uint256)")
	paymasterStrandedTopic          = topicOf("Stranded(address)")
	paymasterEscapeOwedTopic        = topicOf("EscapeInitiationOwed(address,uint32,uint256)")
)

// gaslessForwardNonceKey is the nonce key of a FORWARD operation:
// uint192(uint256(keccak256("zkapi.gasless.forward"))).
var gaslessForwardNonceKey = new(big.Int).SetBytes(crypto.Keccak256([]byte("zkapi.gasless.forward"))[8:])

// gaslessErrorNames map the custom error selectors of the paymaster, the
// account, the factory, the proof adapter and the vault to their names, so a
// refusal from a dry run or a reverted operation is reported by name.
var gaslessErrorNames = func() map[string]string {
	names := map[string]string{}
	for _, signature := range []string{
		// ZkApiWithdrawalPaymaster
		"NotEntryPoint()", "SponsorshipPaused()", "SponsorshipInFlight(bytes32)", "BadPaymasterData()", "FeeAboveCap(uint256,uint256)", "FeeAboveCeiling()",
		"GasLimitOutOfRange(uint8,uint256,uint256,uint256)", "MaxCostAbovePolicy(uint256,uint256)", "NotTransitAccount()", "UnsupportedCall()", "WrongNonceKey()",
		"AttemptsExhausted(bytes32)", "BindingMismatch()", "DestinationNotSender()", "InvalidValidUntil()", "UnknownRoot()", "NoteNotActive()", "NullifierUsed()",
		"InvalidFelt()", "WrongKind()", "InvalidBalance()", "BadSuccessor()", "ChallengedNullifier()", "SupersededState()", "EscapesDisabled()",
		"EscapeAlreadySponsored(uint32)", "EscapeEvidencePending(uint32)", "PayoutBelowCost(uint256,uint256)", "ExitsPaused(uint64)", "NotPendingEscape()",
		"NotStranded()", "NotRepayable()", "ZeroAmount()", "NativeTransferFailed()", "CreditsReserved()", "InvalidKind()",
		// ZkApiWithdrawalAccount and the factory
		"NotProxy()", "VaultCallFailed(bytes)", "NothingToSweep()", "UnknownCall()", "NotPaymasterOwner()", "StakeTermsLocked()", "InvalidPayee()", "CreateFailed()",
		// The proof adapter and the vault
		"InvalidProof()", "InvalidNativeValue()", "StaleRoot()", "ReplayedNullifier()", "InvalidDestination()", "NotePendingWithdrawal()", "NoteExpired()",
		"NoteNotExpired()", "InsufficientDeposit()", "InvalidCommitment()", "ChallengeExpired()", "ChallengeNotExpired()", "NotPendingWithdrawal()",
		"InvalidDeploymentBinding()", "InvalidSiblings()", "Paused()", "NotPaused()", "Unauthorized()", "WrongWithdrawalKind()", "NotSuccessorEvidence()",
		"NotStateEvidence()", "NotARaise()", "ProofExpired()", "PauseCooldown()", "NoteNotClosed()",
	} {
		names[selectorOf(signature)] = signature[:strings.Index(signature, "(")]
	}
	return names
}()

var (
	selectorFailedOp           = selectorOf("FailedOp(uint256,string)")
	selectorFailedOpWithRevert = selectorOf("FailedOpWithRevert(uint256,string,bytes)")
	selectorVaultCallFailed    = selectorOf("VaultCallFailed(bytes)")
	selectorErrorString        = selectorOf("Error(string)")
)

// ------------------------------------------------------------------------- profile

// gaslessProfile is the profile's gasless object (design 4.3): the pinned
// gasless contracts of a deployment, the operator's bundler and the gas
// policy the paymaster enforces, which the client mirrors. Absent or null,
// the option is hidden and the wallet-paid path is exactly as before.
type gaslessProfile struct {
	EntryPoint        string `json:"entry_point_address"`
	EntryPointCode    string `json:"entry_point_runtime_codehash"`
	SenderCreator     string `json:"sender_creator_address"`
	SenderCreatorCode string `json:"sender_creator_runtime_codehash"`
	Paymaster         string `json:"withdrawal_paymaster_address"`
	PaymasterCode     string `json:"withdrawal_paymaster_runtime_codehash"`
	Factory           string `json:"withdrawal_account_factory_address"`
	FactoryCode       string `json:"withdrawal_account_factory_runtime_codehash"`
	// The transit accounts' logic: every transit account is a proxy that
	// delegatecalls it, so its code decides where the account's balance
	// goes. The factory's constructor creates it; nothing but its runtime
	// codehash pins it.
	Implementation            string                `json:"withdrawal_account_implementation_address"`
	ImplementationCode        string                `json:"withdrawal_account_implementation_runtime_codehash"`
	AccountCreationCode       string                `json:"account_creation_code"`
	AccountCreationCodeHash   string                `json:"account_creation_code_keccak256"`
	BundlerURL                string                `json:"bundler_url"`
	GasPolicy                 gaslessGasPolicy      `json:"gas_policy"`
	Policy                    gaslessPolicySnapshot `json:"policy"`
	FeeCeilings               gaslessFeeCeilings    `json:"fee_ceilings"`
	UneconomicFractionPercent profileUint           `json:"uneconomic_fraction_percent"`
}

// gaslessPolicySnapshot is the policy at deployment time; clients read the
// live one from the paymaster.
type gaslessPolicySnapshot struct {
	MaxSponsoredCostWei profileBig `json:"max_sponsored_cost_wei"`
	FlatFeeWei          profileBig `json:"flat_fee_wei"`
	MinEscapeNetWei     profileBig `json:"min_escape_net_wei"`
	EscapesEnabled      bool       `json:"escapes_enabled"`
}

type gaslessFeeCeilings struct {
	MaxFeeWei      profileBig `json:"max_fee_wei"`
	PriorityFeeWei profileBig `json:"priority_fee_wei"`
}

// profileUint is a profile number: a JSON number or a decimal string (every
// number of a profile is a safe integer or a decimal string).
type profileUint uint64

func (n *profileUint) UnmarshalJSON(raw []byte) error {
	value, err := parseProfileBig(raw)
	if err != nil {
		return err
	}
	if !value.IsUint64() {
		return errors.New("profile number out of range")
	}
	*n = profileUint(value.Uint64())
	return nil
}

// profileBig is a profile wei amount: a JSON number or a decimal string.
type profileBig struct{ *big.Int }

func (n *profileBig) UnmarshalJSON(raw []byte) error {
	value, err := parseProfileBig(raw)
	if err != nil {
		return err
	}
	n.Int = value
	return nil
}

func (n profileBig) value() *big.Int {
	if n.Int == nil {
		return new(big.Int)
	}
	return n.Int
}

func parseProfileBig(raw []byte) (*big.Int, error) {
	text := strings.TrimSpace(string(raw))
	if text == "null" {
		return new(big.Int), nil
	}
	var quoted string
	if json.Unmarshal(raw, &quoted) == nil {
		text = strings.TrimSpace(quoted)
	}
	value, ok := new(big.Int).SetString(text, 10)
	if !ok || value.Sign() < 0 || value.BitLen() > 256 {
		return nil, errors.New("invalid profile number")
	}
	return value, nil
}

// gaslessGasPolicy mirrors the paymaster's immutable gas policy (its
// gasPolicy() view) and carries the client's default limits. The profile
// names its fields in snake_case (design 4.3); the vectors and the manifest
// spell a few of them differently (post_op_floor, postOpFloor), so keys are
// matched with their case and underscores removed. A default the profile
// does not carry is derived from the floors and caps the way the contract's
// own tests pick their limits.
type gaslessGasPolicy struct {
	CallFloor, CallCap, CallDefault                                                     [4]uint64
	PostOpFloor, PostOpCap, PostOpDefault                                               uint64
	VerificationFloor, VerificationFloorInit, VerificationCap                           uint64
	VerificationDefault, VerificationDefaultInit                                        uint64
	PVGFloor, PVGCap                                                                    uint64
	PMVerificationFloor, PMVerificationCap, PMVerificationDefault                       uint64
	PostOpBaseGas, PostOpEscapeGas, PostOpFinalizeExtraGas, PostOpEscapeForwardGas      uint64
	EOAPushGas, NewAccountGas, PayoutPushGas, CreditGas                                 uint64
	AccountCallOverheadGas, AccountCallOverheadEscapeGas, MarginGas, FinalizeReserveGas uint64
	MaxAttempts                                                                         uint64
}

func normalizePolicyKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", ""))
}

func (g *gaslessGasPolicy) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	scalar := func(target *uint64) func(json.RawMessage) error {
		return func(value json.RawMessage) error {
			var n profileUint
			if err := n.UnmarshalJSON(value); err != nil {
				return err
			}
			*target = uint64(n)
			return nil
		}
	}
	array := func(target *[4]uint64) func(json.RawMessage) error {
		return func(value json.RawMessage) error {
			var items []json.RawMessage
			if err := json.Unmarshal(value, &items); err != nil || len(items) != 4 {
				return errors.New("a per-kind gas policy entry needs four values")
			}
			for i, item := range items {
				var n profileUint
				if err := n.UnmarshalJSON(item); err != nil {
					return err
				}
				target[i] = uint64(n)
			}
			return nil
		}
	}
	setters := map[string]func(json.RawMessage) error{
		"callfloor": array(&g.CallFloor), "callcap": array(&g.CallCap), "callhardcap": array(&g.CallCap), "calldefault": array(&g.CallDefault),
		"postopfloor": scalar(&g.PostOpFloor), "postopcap": scalar(&g.PostOpCap), "postopdefault": scalar(&g.PostOpDefault),
		"verificationfloor": scalar(&g.VerificationFloor), "verificationfloorinit": scalar(&g.VerificationFloorInit), "verificationcap": scalar(&g.VerificationCap),
		"verificationdefault": scalar(&g.VerificationDefault), "verificationdefaultinit": scalar(&g.VerificationDefaultInit),
		"pvgfloor": scalar(&g.PVGFloor), "pvgcap": scalar(&g.PVGCap),
		"pmverificationfloor": scalar(&g.PMVerificationFloor), "pmverificationcap": scalar(&g.PMVerificationCap), "pmverificationdefault": scalar(&g.PMVerificationDefault),
		"postopbasegas": scalar(&g.PostOpBaseGas), "postopescapegas": scalar(&g.PostOpEscapeGas), "postopfinalizeextragas": scalar(&g.PostOpFinalizeExtraGas), "postopescapeforwardgas": scalar(&g.PostOpEscapeForwardGas),
		"eoapushgas": scalar(&g.EOAPushGas), "newaccountgas": scalar(&g.NewAccountGas), "payoutpushgas": scalar(&g.PayoutPushGas), "creditgas": scalar(&g.CreditGas),
		"accountcalloverheadgas": scalar(&g.AccountCallOverheadGas), "accountcalloverheadescapegas": scalar(&g.AccountCallOverheadEscapeGas),
		"margingas": scalar(&g.MarginGas), "finalizereservegas": scalar(&g.FinalizeReserveGas), "maxattempts": scalar(&g.MaxAttempts),
	}
	for key, value := range fields {
		if set, known := setters[normalizePolicyKey(key)]; known {
			if err := set(value); err != nil {
				return fmt.Errorf("gas policy %s: %w", key, err)
			}
		}
	}
	return nil
}

// MarshalJSON writes the design's snake_case names, so a saved copy of a
// policy reads back the same way.
func (g gaslessGasPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"call_floor": g.CallFloor, "call_cap": g.CallCap, "call_default": g.CallDefault,
		"postop_floor": g.PostOpFloor, "postop_cap": g.PostOpCap, "postop_default": g.PostOpDefault,
		"verification_floor": g.VerificationFloor, "verification_floor_init": g.VerificationFloorInit, "verification_cap": g.VerificationCap,
		"verification_default": g.VerificationDefault, "verification_default_init": g.VerificationDefaultInit,
		"pvg_floor": g.PVGFloor, "pvg_cap": g.PVGCap,
		"pm_verification_floor": g.PMVerificationFloor, "pm_verification_cap": g.PMVerificationCap, "pm_verification_default": g.PMVerificationDefault,
		"postop_base_gas": g.PostOpBaseGas, "postop_escape_gas": g.PostOpEscapeGas, "postop_finalize_extra_gas": g.PostOpFinalizeExtraGas, "postop_escape_forward_gas": g.PostOpEscapeForwardGas,
		"eoa_push_gas": g.EOAPushGas, "new_account_gas": g.NewAccountGas, "payout_push_gas": g.PayoutPushGas, "credit_gas": g.CreditGas,
		"account_call_overhead_gas": g.AccountCallOverheadGas, "account_call_overhead_escape_gas": g.AccountCallOverheadEscapeGas,
		"margin_gas": g.MarginGas, "finalize_reserve_gas": g.FinalizeReserveGas, "max_attempts": g.MaxAttempts,
	})
}

// withDefaults fills the client's default limits the profile left out, the
// way the contract's tests pick theirs: a call limit a quarter of the way
// from its floor to its cap, postOp 20,000 above its floor, verification
// 20,000 (40,000 with initCode) and paymaster verification 30,000 above
// theirs. Every default must sit within [floor, cap].
func (g gaslessGasPolicy) withDefaults() (gaslessGasPolicy, error) {
	for k := range g.CallDefault {
		if g.CallDefault[k] == 0 {
			if g.CallCap[k] < g.CallFloor[k] {
				return g, errors.New("a call gas cap below its floor")
			}
			g.CallDefault[k] = g.CallFloor[k] + (g.CallCap[k]-g.CallFloor[k])/4
		}
		if g.CallDefault[k] < g.CallFloor[k] || g.CallDefault[k] > g.CallCap[k] {
			return g, errors.New("a default call gas limit outside its floor and cap")
		}
	}
	fill := func(target *uint64, floor, add, capValue uint64, label string) error {
		if *target == 0 {
			*target = floor + add
			if *target > capValue {
				*target = capValue
			}
		}
		if *target < floor || *target > capValue {
			return fmt.Errorf("the default %s gas limit is outside its floor and cap", label)
		}
		return nil
	}
	for _, f := range []struct {
		target            *uint64
		floor, add, limit uint64
		label             string
	}{
		{&g.PostOpDefault, g.PostOpFloor, 20_000, g.PostOpCap, "postOp"},
		{&g.VerificationDefault, g.VerificationFloor, 20_000, g.VerificationCap, "verification"},
		{&g.VerificationDefaultInit, g.VerificationFloorInit, 40_000, g.VerificationCap, "first-use verification"},
		{&g.PMVerificationDefault, g.PMVerificationFloor, 30_000, g.PMVerificationCap, "paymaster verification"},
	} {
		if err := fill(f.target, f.floor, f.add, f.limit, f.label); err != nil {
			return g, err
		}
	}
	if g.PVGFloor > g.PVGCap || g.MaxAttempts == 0 || g.FinalizeReserveGas == 0 {
		return g, errors.New("an incomplete gas policy")
	}
	return g, nil
}

// words is the policy as the paymaster's gasPolicy() returns it: 30 words,
// the two per-kind arrays first.
func (g gaslessGasPolicy) words() []uint64 {
	out := append(append([]uint64{}, g.CallFloor[:]...), g.CallCap[:]...)
	return append(out, g.PostOpFloor, g.PostOpCap, g.VerificationFloor, g.VerificationFloorInit, g.VerificationCap, g.PVGFloor, g.PVGCap,
		g.PMVerificationFloor, g.PMVerificationCap, g.PostOpBaseGas, g.PostOpEscapeGas, g.PostOpFinalizeExtraGas, g.PostOpEscapeForwardGas,
		g.EOAPushGas, g.NewAccountGas, g.PayoutPushGas, g.CreditGas, g.AccountCallOverheadGas, g.AccountCallOverheadEscapeGas, g.MarginGas,
		g.FinalizeReserveGas, g.MaxAttempts)
}

// callLimits are the floor, cap and default of a kind's callGasLimit.
func (g gaslessGasPolicy) callLimits(kind uint8) (floor, capValue, byDefault uint64) {
	if kind < 1 || kind > 4 {
		return 0, 0, 0
	}
	return g.CallFloor[kind-1], g.CallCap[kind-1], g.CallDefault[kind-1]
}

// errGaslessUnavailable prefixes every reason the gasless path is unusable
// for a deployment: it never refuses deposits or wallet-paid exits.
var errGaslessUnavailable = errors.New("gasless_unavailable")

// validate checks the gasless profile's shape and fills the defaults; it is
// run before any gasless use, never when the deployment is parsed, so a bad
// gasless object disables only --fees payout.
func (g *gaslessProfile) validate() (gaslessProfile, error) {
	invalid := func(what string) error {
		return fmt.Errorf("%w: the packaged profile's gasless object %s", errGaslessUnavailable, what)
	}
	if g == nil {
		return gaslessProfile{}, fmt.Errorf("%w: this deployment publishes no gasless paymaster", errGaslessUnavailable)
	}
	profile := *g
	for _, address := range []string{profile.EntryPoint, profile.SenderCreator, profile.Paymaster, profile.Factory, profile.Implementation} {
		if !isHex(address, 20) || common.HexToAddress(address) == (common.Address{}) {
			return profile, invalid("names an invalid contract address")
		}
	}
	for _, code := range []string{profile.EntryPointCode, profile.SenderCreatorCode, profile.PaymasterCode, profile.FactoryCode, profile.ImplementationCode, profile.AccountCreationCodeHash} {
		if !isHex(code, 32) {
			return profile, invalid("names an invalid code hash")
		}
	}
	creation, err := hex.DecodeString(strings.TrimPrefix(profile.AccountCreationCode, "0x"))
	if err != nil || !strings.HasPrefix(profile.AccountCreationCode, "0x") || len(creation) == 0 || !strings.EqualFold(crypto.Keccak256Hash(creation).Hex(), profile.AccountCreationCodeHash) {
		return profile, invalid("carries an account creation code that does not hash to its pin")
	}
	// The proxy creation code embeds the logic every transit account
	// delegatecalls: the pinned implementation.
	if !bytes.Contains(creation, common.HexToAddress(profile.Implementation).Bytes()) {
		return profile, invalid("carries an account creation code for another account implementation")
	}
	if !strings.EqualFold(profile.EntryPointCode, gaslessEntryPointCodehash) || !strings.EqualFold(profile.SenderCreatorCode, gaslessSenderCreatorCodehash) {
		return profile, invalid("pins an EntryPoint other than the canonical v0.7.0")
	}
	if profile.BundlerURL != "" {
		if err := ValidateBundlerURL(profile.BundlerURL); err != nil {
			return profile, invalid("names an invalid bundler URL")
		}
	}
	if profile.GasPolicy, err = profile.GasPolicy.withDefaults(); err != nil {
		return profile, invalid(err.Error())
	}
	if profile.UneconomicFractionPercent == 0 || profile.UneconomicFractionPercent > 100 {
		profile.UneconomicFractionPercent = 25
	}
	return profile, nil
}

// ValidateBundlerURL accepts a bundler URL under the exit RPC's rules:
// HTTPS, or plain HTTP to a node on this machine; no credentials, query or
// fragment.
func ValidateBundlerURL(raw string) error {
	if err := ValidateExitRPCURL(raw); err != nil {
		return errors.New("the bundler URL must be an HTTPS URL, or plain HTTP to a bundler on this machine, without credentials, query or fragment")
	}
	return nil
}

// --------------------------------------------------------------------- derivations

// transitInitCodeHash is keccak(creationCode ‖ abi.encode(entryPoint, vault,
// paymaster, owner, payee)): the init code hash of the transit account.
func transitInitCodeHash(creationCode []byte, entryPoint, vault, paymaster, owner, payee common.Address) common.Hash {
	init := append([]byte{}, creationCode...)
	for _, address := range []common.Address{entryPoint, vault, paymaster, owner, payee} {
		init = append(init, common.LeftPadBytes(address.Bytes(), 32)...)
	}
	return crypto.Keccak256Hash(init)
}

// transitAccountAddress is S = CREATE2(factory, salt 0, initCodeHash).
func transitAccountAddress(factory common.Address, creationCode []byte, entryPoint, vault, paymaster, owner, payee common.Address) common.Address {
	return crypto.CreateAddress2(factory, [32]byte{}, transitInitCodeHash(creationCode, entryPoint, vault, paymaster, owner, payee).Bytes())
}

// transitInitCode is the op's initCode on first use: factory ‖
// createAccount(owner, payee).
func transitInitCode(factory, owner, payee common.Address) []byte {
	data, _ := hex.DecodeString(selectorCreateAccount + addressABIWord(strings.ToLower(owner.Hex())) + addressABIWord(strings.ToLower(payee.Hex())))
	return append(append([]byte{}, factory.Bytes()...), data...)
}

// transitCallData is S.withdraw(vaultCall): the selector, the offset word,
// the length word and the call padded to a word.
func transitCallData(vaultCall []byte) []byte {
	data, _ := hex.DecodeString(selectorTransitWithdraw)
	data = append(data, common.LeftPadBytes([]byte{0x20}, 32)...)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(uint64(len(vaultCall))).Bytes(), 32)...)
	data = append(data, vaultCall...)
	if padding := (32 - len(vaultCall)%32) % 32; padding != 0 {
		data = append(data, make([]byte, padding)...)
	}
	return data
}

// vaultCallOfTransitCallData is the inverse of transitCallData, strictly: the
// vault call inside S.withdraw(bytes) calldata, or an error for any other
// layout (the paymaster accepts exactly this one).
func vaultCallOfTransitCallData(callData []byte) ([]byte, error) {
	invalid := errors.New("invalid transit account calldata")
	if len(callData) < 68 || hex.EncodeToString(callData[:4]) != selectorTransitWithdraw || new(big.Int).SetBytes(callData[4:36]).Cmp(big.NewInt(0x20)) != 0 {
		return nil, invalid
	}
	length := new(big.Int).SetBytes(callData[36:68])
	if !length.IsUint64() || length.Uint64() > uint64(len(callData)-68) {
		return nil, invalid
	}
	n := int(length.Uint64())
	if len(callData) != 68+(n+31)/32*32 {
		return nil, invalid
	}
	for _, b := range callData[68+n:] {
		if b != 0 {
			return nil, invalid
		}
	}
	return append([]byte{}, callData[68:68+n]...), nil
}

// gaslessKey is the paymaster's attempt key of an operation (keyFor).
func gaslessKey(kind uint8, nullifier *big.Int, noteID uint32, sender common.Address) common.Hash {
	var label string
	var value []byte
	switch kind {
	case gaslessKindClose:
		label, value = "close", common.LeftPadBytes(nullifier.Bytes(), 32)
	case gaslessKindEscape:
		label, value = "escape", common.LeftPadBytes(new(big.Int).SetUint64(uint64(noteID)).Bytes(), 32)
	case gaslessKindFinalize:
		label, value = "finalize", common.LeftPadBytes(new(big.Int).SetUint64(uint64(noteID)).Bytes(), 32)
	default:
		label, value = "forward", common.LeftPadBytes(sender.Bytes(), 32)
	}
	// abi.encode(string, word): the string's offset, the word, the string's
	// length and its bytes padded to a word.
	encoded := append(common.LeftPadBytes([]byte{0x40}, 32), value...)
	encoded = append(encoded, common.LeftPadBytes([]byte{byte(len(label))}, 32)...)
	encoded = append(encoded, common.RightPadBytes([]byte(label), 32)...)
	return crypto.Keccak256Hash(encoded)
}

// gaslessNonceKey is the 192-bit nonce key of a kind: the withdrawal
// nullifier (close, escape and finalize) or the FORWARD key.
func gaslessNonceKey(kind uint8, nullifier *big.Int) *big.Int {
	if kind == gaslessKindForward {
		return new(big.Int).Set(gaslessForwardNonceKey)
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(1))
	return new(big.Int).And(nullifier, mask)
}

// ----------------------------------------------------------------- the operation

// gaslessUserOp is a v0.7 user operation in its unpacked form; packing is
// done for hashing and for the EntryPoint's ABI.
type gaslessUserOp struct {
	Sender                        common.Address
	Nonce                         *big.Int
	InitCode                      []byte
	CallData                      []byte
	CallGasLimit                  uint64
	VerificationGasLimit          uint64
	PreVerificationGas            uint64
	MaxFeePerGas                  *big.Int
	MaxPriorityFeePerGas          *big.Int
	Paymaster                     common.Address
	PaymasterVerificationGasLimit uint64
	PaymasterPostOpGasLimit       uint64
	FeeCapWei                     *big.Int // the 12-byte paymasterData
	Signature                     []byte
}

func uint128Word(high, low uint64) []byte {
	word := make([]byte, 32)
	copy(word[8:16], common.LeftPadBytes(new(big.Int).SetUint64(high).Bytes(), 8))
	copy(word[24:32], common.LeftPadBytes(new(big.Int).SetUint64(low).Bytes(), 8))
	return word
}

// accountGasLimits is verificationGasLimit << 128 | callGasLimit.
func (op *gaslessUserOp) accountGasLimits() []byte {
	return uint128Word(op.VerificationGasLimit, op.CallGasLimit)
}

// gasFees is maxPriorityFeePerGas << 128 | maxFeePerGas.
func (op *gaslessUserOp) gasFees() []byte {
	word := make([]byte, 32)
	copy(word[:16], common.LeftPadBytes(op.MaxPriorityFeePerGas.Bytes(), 16))
	copy(word[16:], common.LeftPadBytes(op.MaxFeePerGas.Bytes(), 16))
	return word
}

// paymasterAndData is P (20) ‖ paymasterVerificationGasLimit (16) ‖
// paymasterPostOpGasLimit (16) ‖ feeCapWei (12).
func (op *gaslessUserOp) paymasterAndData() []byte {
	data := append([]byte{}, op.Paymaster.Bytes()...)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(op.PaymasterVerificationGasLimit).Bytes(), 16)...)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(op.PaymasterPostOpGasLimit).Bytes(), 16)...)
	return append(data, common.LeftPadBytes(op.FeeCapWei.Bytes(), 12)...)
}

// maxCost is the prefund the EntryPoint charges the paymaster: the five
// limits times maxFeePerGas.
func (op *gaslessUserOp) maxCost() *big.Int {
	gas := new(big.Int).SetUint64(op.PreVerificationGas + op.VerificationGasLimit + op.CallGasLimit + op.PaymasterVerificationGasLimit + op.PaymasterPostOpGasLimit)
	return gas.Mul(gas, op.MaxFeePerGas)
}

// hash is the EntryPoint v0.7.0 userOpHash:
// keccak(abi.encode(keccak(abi.encode(sender, nonce, keccak(initCode),
// keccak(callData), accountGasLimits, preVerificationGas, gasFees,
// keccak(paymasterAndData))), entryPoint, chainId)).
func (op *gaslessUserOp) hash(entryPoint common.Address, chainID uint64) common.Hash {
	inner := append([]byte{}, common.LeftPadBytes(op.Sender.Bytes(), 32)...)
	inner = append(inner, common.LeftPadBytes(op.Nonce.Bytes(), 32)...)
	inner = append(inner, crypto.Keccak256(op.InitCode)...)
	inner = append(inner, crypto.Keccak256(op.CallData)...)
	inner = append(inner, op.accountGasLimits()...)
	inner = append(inner, common.LeftPadBytes(new(big.Int).SetUint64(op.PreVerificationGas).Bytes(), 32)...)
	inner = append(inner, op.gasFees()...)
	inner = append(inner, crypto.Keccak256(op.paymasterAndData())...)
	outer := append(crypto.Keccak256(inner), common.LeftPadBytes(entryPoint.Bytes(), 32)...)
	outer = append(outer, common.LeftPadBytes(new(big.Int).SetUint64(chainID).Bytes(), 32)...)
	return crypto.Keccak256Hash(outer)
}

// eip191Digest is what the owner signs: personal_sign of the 32 raw bytes
// of the userOpHash.
func eip191Digest(userOpHash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("\x19Ethereum Signed Message:\n32"), userOpHash.Bytes()...))
}

// secp256k1HalfN bounds s: the account refuses a higher one.
var secp256k1HalfN, _ = new(big.Int).SetString("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16)

// signUserOpHash signs the EIP-191 digest of hash with the owner key: 65
// bytes r ‖ s ‖ v, v in {27, 28}, low s.
func signUserOpHash(userOpHash common.Hash, key *ecdsa.PrivateKey) ([]byte, error) {
	signature, err := crypto.Sign(eip191Digest(userOpHash).Bytes(), key)
	if err != nil || len(signature) != 65 {
		return nil, errors.New("cannot sign the user operation")
	}
	if new(big.Int).SetBytes(signature[32:64]).Cmp(secp256k1HalfN) > 0 {
		return nil, errors.New("the signature is not canonical")
	}
	signature[64] += 27
	return signature, nil
}

// recoverUserOpSigner is the signer of a 65-byte op signature over hash.
func recoverUserOpSigner(userOpHash common.Hash, signature []byte) (common.Address, error) {
	if len(signature) != 65 || (signature[64] != 27 && signature[64] != 28) {
		return common.Address{}, errors.New("invalid user operation signature")
	}
	raw := append([]byte{}, signature...)
	raw[64] -= 27
	public, err := crypto.SigToPub(eip191Digest(userOpHash).Bytes(), raw)
	if err != nil {
		return common.Address{}, errors.New("invalid user operation signature")
	}
	return crypto.PubkeyToAddress(*public), nil
}

// abiTuple is the ABI encoding of the packed operation as one dynamic
// tuple (9 head words, then the four bytes fields).
func (op *gaslessUserOp) abiTuple() []byte {
	dynamic := [][]byte{op.InitCode, op.CallData, op.paymasterAndData(), op.Signature}
	head := make([][]byte, 9)
	head[0] = common.LeftPadBytes(op.Sender.Bytes(), 32)
	head[1] = common.LeftPadBytes(op.Nonce.Bytes(), 32)
	head[4] = op.accountGasLimits()
	head[5] = common.LeftPadBytes(new(big.Int).SetUint64(op.PreVerificationGas).Bytes(), 32)
	head[6] = op.gasFees()
	var tail []byte
	for i, slot := range []int{2, 3, 7, 8} {
		head[slot] = common.LeftPadBytes(new(big.Int).SetUint64(uint64(9*32+len(tail))).Bytes(), 32)
		tail = append(tail, common.LeftPadBytes(new(big.Int).SetUint64(uint64(len(dynamic[i]))).Bytes(), 32)...)
		tail = append(tail, dynamic[i]...)
		if padding := (32 - len(dynamic[i])%32) % 32; padding != 0 {
			tail = append(tail, make([]byte, padding)...)
		}
	}
	encoded := bytes.Join(head, nil)
	return append(encoded, tail...)
}

// The preVerificationGas rule both clients apply (the SDK's
// preVerificationGasFor in sdk/services/zkapiGasless.mjs computes the same
// numbers): PVG = clamp(max(A, ceil(1.1 × B), C), pvg_floor, pvg_cap).
const (
	// gaslessPVGOverheadGas is ERC-7562 LIM-070's
	// PRE_VERIFICATION_OVERHEAD_GAS: a bundler that enforces LIM-070 refuses
	// an operation whose preVerificationGas is below the calldata cost of
	// the operation plus this.
	gaslessPVGOverheadGas = 50_000
	// gaslessPVGMarginGas covers what bundlers add beyond LIM-070's minimum
	// (per-word costs, the bundle's own words) and the zero bytes of a proof
	// generated again between a quote and its approval.
	gaslessPVGMarginGas = 2_000
	// The eth-infinitism reference bundler's calcPreVerificationGas (the
	// DefaultGasOverheads of v0.7): fixed, per operation and per word of
	// the encoded operation, reserved with a 10% margin.
	gaslessPVGReferenceFixedGas   = 21_000
	gaslessPVGReferencePerOpGas   = 18_300
	gaslessPVGReferencePerWordGas = 4
	gaslessPVGReferenceMarginPct  = 10
	// The calldata reserve: the intrinsic transaction gas, 16 per byte of
	// handleOps calldata and an overhead.
	gaslessPVGBaseGas         = 21_000
	gaslessPVGCalldataByteGas = 16
	gaslessPVGCalldataExtra   = 10_000
)

// calldataCost is the EVM's calldata gas: 4 per zero byte, 16 per other.
func calldataCost(data []byte) uint64 {
	var cost uint64
	for _, b := range data {
		if b == 0 {
			cost += 4
		} else {
			cost += 16
		}
	}
	return cost
}

// pvgProbe is a copy of op for sizing its preVerificationGas: the word at
// pvg_cap (so the client's own choice never changes its size), an absent
// nonce, fee or fee cap counted as 0.
func (op *gaslessUserOp) pvgProbe(g gaslessGasPolicy) gaslessUserOp {
	probe := *op
	for _, field := range []**big.Int{&probe.Nonce, &probe.MaxFeePerGas, &probe.MaxPriorityFeePerGas, &probe.FeeCapWei} {
		if *field == nil {
			*field = new(big.Int)
		}
	}
	probe.PreVerificationGas = g.PVGCap
	return probe
}

// lim070PreVerificationGas is term A of the rule: the calldata cost of
// handleOps([op], 0xff…ff) at its worst (a 65-byte 0xff signature, both fee
// fields 2^128 − 1, preVerificationGas at pvg_cap, so a re-sign with higher
// fees never needs more) plus LIM-070's overhead and a margin.
func (op *gaslessUserOp) lim070PreVerificationGas(g gaslessGasPolicy) uint64 {
	probe := op.pvgProbe(g)
	probe.Signature = bytes.Repeat([]byte{0xff}, 65)
	allOnes := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	probe.MaxFeePerGas, probe.MaxPriorityFeePerGas = allOnes, allOnes
	data := common.FromHex(probe.handleOpsCalldata(common.BytesToAddress(bytes.Repeat([]byte{0xff}, 20))))
	return calldataCost(data) + gaslessPVGOverheadGas + gaslessPVGMarginGas
}

// referencePreVerificationGas is term B of the rule, before its margin: the
// reference bundler's minimum, 21,000 + 18,300 + 4 per word + 4 / 16 per
// zero / non-zero byte of the ABI-encoded packed operation, with
// preVerificationGas at pvg_cap, the fees as they are and, unsigned, a
// 65-byte signature of 0x01 bytes (the SDK's referencePreVerificationGas).
func (op *gaslessUserOp) referencePreVerificationGas(g gaslessGasPolicy) uint64 {
	probe := op.pvgProbe(g)
	if len(probe.Signature) != 65 {
		probe.Signature = bytes.Repeat([]byte{0x01}, 65)
	}
	encoded := probe.abiTuple()
	return gaslessPVGReferenceFixedGas + gaslessPVGReferencePerOpGas + gaslessPVGReferencePerWordGas*uint64((len(encoded)+31)/32) + calldataCost(encoded)
}

// handleOpsCalldataBytes is the byte length of handleOps([op], beneficiary)
// with a 65-byte signature, whatever the beneficiary (the SDK's
// handleOpsCalldataBytes): what term C of the rule counts.
func (op *gaslessUserOp) handleOpsCalldataBytes(g gaslessGasPolicy) int {
	probe := op.pvgProbe(g)
	probe.Signature = make([]byte, 65)
	return len(common.FromHex(probe.handleOpsCalldata(common.Address{})))
}

// requiredPreVerificationGas is the preVerificationGas op is signed with,
// the rule both clients share:
//
//	PVG = clamp(max(A, ceil(1.1 × B), C), pvg_floor, pvg_cap)
//
// with A the LIM-070 term (lim070PreVerificationGas), B the reference
// bundler's minimum (referencePreVerificationGas) and C = 21,000 + 16 ×
// handleOpsCalldataBytes + 10,000, all computed on op as it is built (its
// nonce, initCode, callData, limits, fees and fee cap). preVerificationGas
// is the bundler's compensation, not a limit the paymaster measures: below A
// a bundler enforcing LIM-070 refuses the operation, and every retry with
// it; a bundler that asks for more within pvg_cap through
// eth_estimateUserOperationGas gets its figure (submitUserOperation).
func (op *gaslessUserOp) requiredPreVerificationGas(g gaslessGasPolicy) uint64 {
	required := op.lim070PreVerificationGas(g)
	reference := op.referencePreVerificationGas(g)
	if withMargin := (reference*(100+gaslessPVGReferenceMarginPct) + 99) / 100; withMargin > required {
		required = withMargin
	}
	if size := gaslessPVGBaseGas + gaslessPVGCalldataByteGas*uint64(op.handleOpsCalldataBytes(g)) + gaslessPVGCalldataExtra; size > required {
		required = size
	}
	if required < g.PVGFloor {
		required = g.PVGFloor
	}
	if required > g.PVGCap {
		required = g.PVGCap
	}
	return required
}

// gaslessShapeOp is an operation of kind as the client builds it (its
// pinned default limits, initCode when the transit account is new) with
// every variable byte non-zero: what a quote prices before the real
// operation exists (the pre-proof check, an escape's later finalization).
func gaslessShapeOp(g gaslessGasPolicy, kind uint8, initCode bool, paymaster common.Address, flatFee *big.Int, callCap uint64) *gaslessUserOp {
	ones := func(n int) []byte { return bytes.Repeat([]byte{0xff}, n) }
	op := &gaslessUserOp{Sender: common.BytesToAddress(ones(20)), Nonce: new(big.Int).SetBytes(ones(32)), Paymaster: paymaster, FeeCapWei: new(big.Int).Set(flatFee), MaxFeePerGas: new(big.Int), MaxPriorityFeePerGas: new(big.Int)}
	switch kind {
	case gaslessKindClose, gaslessKindEscape:
		op.CallData = transitCallData(ones(withdrawalCalldataLength))
	case gaslessKindFinalize:
		op.CallData = transitCallData(common.FromHex(finalizeEscapeCalldata(0xffffffff)))
	default:
		op.CallData = transitCallData(nil)
	}
	if initCode {
		op.InitCode = transitInitCode(common.BytesToAddress(ones(20)), common.BytesToAddress(ones(20)), common.BytesToAddress(ones(20)))
	}
	_, _, op.CallGasLimit = g.callLimits(kind)
	if callCap != 0 && op.CallGasLimit > callCap {
		op.CallGasLimit = callCap
	}
	op.VerificationGasLimit = g.VerificationDefault
	if initCode {
		op.VerificationGasLimit = g.VerificationDefaultInit
	}
	op.PaymasterVerificationGasLimit, op.PaymasterPostOpGasLimit = g.PMVerificationDefault, g.PostOpDefault
	op.PreVerificationGas = op.requiredPreVerificationGas(g)
	return op
}

// getUserOpHashCalldata is entryPoint.getUserOpHash(op).
func (op *gaslessUserOp) getUserOpHashCalldata() string {
	return "0x" + selectorGetUserOpHash + hex.EncodeToString(common.LeftPadBytes([]byte{0x20}, 32)) + hex.EncodeToString(op.abiTuple())
}

// handleOpsCalldata is entryPoint.handleOps([op], beneficiary).
func (op *gaslessUserOp) handleOpsCalldata(beneficiary common.Address) string {
	data := hex.EncodeToString(common.LeftPadBytes([]byte{0x40}, 32)) + addressABIWord(strings.ToLower(beneficiary.Hex()))
	data += hex.EncodeToString(common.LeftPadBytes([]byte{0x01}, 32)) + hex.EncodeToString(common.LeftPadBytes([]byte{0x20}, 32))
	return "0x" + selectorHandleOps + data + hex.EncodeToString(op.abiTuple())
}

// gaslessUserOpJSON is the unpacked v0.7 shape of the bundler RPC and the
// journal: the field names of eth_sendUserOperation, quantities as 0x-hex.
type gaslessUserOpJSON struct {
	Sender                        string `json:"sender"`
	Nonce                         string `json:"nonce"`
	Factory                       string `json:"factory,omitempty"`
	FactoryData                   string `json:"factoryData,omitempty"`
	CallData                      string `json:"callData"`
	CallGasLimit                  string `json:"callGasLimit"`
	VerificationGasLimit          string `json:"verificationGasLimit"`
	PreVerificationGas            string `json:"preVerificationGas"`
	MaxFeePerGas                  string `json:"maxFeePerGas"`
	MaxPriorityFeePerGas          string `json:"maxPriorityFeePerGas"`
	Paymaster                     string `json:"paymaster"`
	PaymasterVerificationGasLimit string `json:"paymasterVerificationGasLimit"`
	PaymasterPostOpGasLimit       string `json:"paymasterPostOpGasLimit"`
	PaymasterData                 string `json:"paymasterData"`
	Signature                     string `json:"signature"`
}

func hexQuantity(value *big.Int) string {
	return "0x" + value.Text(16)
}

func hexQuantityUint(value uint64) string {
	return hexQuantity(new(big.Int).SetUint64(value))
}

func (op *gaslessUserOp) toJSON() gaslessUserOpJSON {
	encoded := gaslessUserOpJSON{
		Sender: op.Sender.Hex(), Nonce: hexQuantity(op.Nonce), CallData: "0x" + hex.EncodeToString(op.CallData),
		CallGasLimit: hexQuantityUint(op.CallGasLimit), VerificationGasLimit: hexQuantityUint(op.VerificationGasLimit), PreVerificationGas: hexQuantityUint(op.PreVerificationGas),
		MaxFeePerGas: hexQuantity(op.MaxFeePerGas), MaxPriorityFeePerGas: hexQuantity(op.MaxPriorityFeePerGas),
		Paymaster: op.Paymaster.Hex(), PaymasterVerificationGasLimit: hexQuantityUint(op.PaymasterVerificationGasLimit), PaymasterPostOpGasLimit: hexQuantityUint(op.PaymasterPostOpGasLimit),
		PaymasterData: "0x" + hex.EncodeToString(common.LeftPadBytes(op.FeeCapWei.Bytes(), 12)), Signature: "0x" + hex.EncodeToString(op.Signature),
	}
	if len(op.InitCode) >= 20 {
		encoded.Factory = common.BytesToAddress(op.InitCode[:20]).Hex()
		encoded.FactoryData = "0x" + hex.EncodeToString(op.InitCode[20:])
	}
	return encoded
}

// gaslessUserOpFromJSON parses the unpacked form strictly.
func gaslessUserOpFromJSON(encoded gaslessUserOpJSON) (*gaslessUserOp, error) {
	invalid := errors.New("invalid saved user operation")
	quantity := func(value string) (*big.Int, error) {
		n, err := feeQuantity(value)
		if err != nil {
			return nil, invalid
		}
		return n, nil
	}
	small := func(value string) (uint64, error) {
		n, err := quantity(value)
		if err != nil || !n.IsUint64() {
			return 0, invalid
		}
		return n.Uint64(), nil
	}
	bytesOf := func(value string) ([]byte, error) {
		if !strings.HasPrefix(value, "0x") {
			return nil, invalid
		}
		raw, err := hex.DecodeString(value[2:])
		if err != nil {
			return nil, invalid
		}
		return raw, nil
	}
	if !isHex(encoded.Sender, 20) || !isHex(encoded.Paymaster, 20) {
		return nil, invalid
	}
	op := &gaslessUserOp{Sender: common.HexToAddress(encoded.Sender), Paymaster: common.HexToAddress(encoded.Paymaster)}
	var err error
	if op.Nonce, err = quantity(encoded.Nonce); err != nil {
		return nil, err
	}
	if op.CallData, err = bytesOf(encoded.CallData); err != nil {
		return nil, err
	}
	if encoded.Factory != "" || encoded.FactoryData != "" {
		if !isHex(encoded.Factory, 20) {
			return nil, invalid
		}
		data, err := bytesOf(encoded.FactoryData)
		if err != nil {
			return nil, err
		}
		op.InitCode = append(common.HexToAddress(encoded.Factory).Bytes(), data...)
	}
	for _, field := range []struct {
		target *uint64
		value  string
	}{{&op.CallGasLimit, encoded.CallGasLimit}, {&op.VerificationGasLimit, encoded.VerificationGasLimit}, {&op.PreVerificationGas, encoded.PreVerificationGas}, {&op.PaymasterVerificationGasLimit, encoded.PaymasterVerificationGasLimit}, {&op.PaymasterPostOpGasLimit, encoded.PaymasterPostOpGasLimit}} {
		if *field.target, err = small(field.value); err != nil {
			return nil, err
		}
	}
	if op.MaxFeePerGas, err = quantity(encoded.MaxFeePerGas); err != nil {
		return nil, err
	}
	if op.MaxPriorityFeePerGas, err = quantity(encoded.MaxPriorityFeePerGas); err != nil {
		return nil, err
	}
	paymasterData, err := bytesOf(encoded.PaymasterData)
	if err != nil || len(paymasterData) != 12 {
		return nil, invalid
	}
	op.FeeCapWei = new(big.Int).SetBytes(paymasterData)
	if op.Signature, err = bytesOf(encoded.Signature); err != nil {
		return nil, err
	}
	if op.MaxFeePerGas.BitLen() > 128 || op.MaxPriorityFeePerGas.BitLen() > 128 || op.Nonce.BitLen() > 256 {
		return nil, invalid
	}
	return op, nil
}

// --------------------------------------------------------------------- the charge

// gaslessChargeFor mirrors the paymaster's chargeFor: the EntryPoint's gas
// so far, the pinned postOp and push gas of the kind and payee, the 10%
// penalty on the unused call and postOp limits, and the margin, times
// feePerGas (before the flat fee and the cap at maxCost).
func gaslessChargeFor(g gaslessGasPolicy, kind uint8, actualGas, executionGasUsed, callGasLimit, postOpGasLimit uint64, payeeHasCode, payeeIsEmpty bool, feePerGas *big.Int) *big.Int {
	var postOpGas, overhead uint64
	if kind == gaslessKindEscape {
		postOpGas, overhead = g.PostOpEscapeGas, g.AccountCallOverheadEscapeGas
	} else {
		postOpGas = g.PostOpBaseGas + g.EOAPushGas
		if payeeHasCode {
			postOpGas += g.PayoutPushGas
		} else if payeeIsEmpty {
			postOpGas += g.NewAccountGas
		}
		if kind == gaslessKindFinalize {
			postOpGas += g.PostOpFinalizeExtraGas
		}
		overhead = g.AccountCallOverheadGas
	}
	if executionGasUsed > callGasLimit {
		executionGasUsed = callGasLimit
	}
	usedOfLimit := executionGasUsed + overhead + postOpGas
	limit := callGasLimit + postOpGasLimit
	var penalty uint64
	if limit > usedOfLimit {
		penalty = (limit - usedOfLimit) / 10
	}
	gas := new(big.Int).SetUint64(actualGas + postOpGas + penalty + g.MarginGas)
	return gas.Mul(gas, feePerGas)
}

// ------------------------------------------------------------ JSON-RPC envelopes

// rpcError is a JSON-RPC error object: a refusal the node or bundler
// answered, as opposed to a transport failure.
type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// revertData is the revert bytes an eth_call error carries, in the shapes
// nodes use (a hex string, or an object with a data field), or nil.
func (e *rpcError) revertData() []byte {
	if e == nil || len(e.Data) == 0 {
		return nil
	}
	var text string
	if json.Unmarshal(e.Data, &text) != nil {
		var nested struct {
			Data string `json:"data"`
		}
		if json.Unmarshal(e.Data, &nested) != nil {
			return nil
		}
		text = nested.Data
	}
	if !strings.HasPrefix(text, "0x") {
		return nil
	}
	raw, err := hex.DecodeString(text[2:])
	if err != nil {
		return nil
	}
	return raw
}

var errBundlerUnavailable = errors.New("bundler_unavailable: the bundler did not answer")

// bundlerCall is one JSON-RPC call to the bundler through the configured
// transport. A JSON-RPC error is returned as rpcError; a transport failure
// as errBundlerUnavailable.
func (h *FundingHandler) bundlerCall(ctx context.Context, url, method string, params []any) (json.RawMessage, *rpcError, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, errBundlerUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := h.client.inference.Do(req)
	if err != nil {
		return nil, nil, errBundlerUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != http.StatusOK {
		return nil, nil, errBundlerUnavailable
	}
	var envelope struct {
		Version string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   *rpcError       `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != "2.0" {
		return nil, nil, fmt.Errorf("%w: invalid answer", errBundlerUnavailable)
	}
	if envelope.Error != nil {
		return nil, envelope.Error, nil
	}
	return envelope.Result, nil, nil
}

// aaFailure is a decoded FailedOp / FailedOpWithRevert of the EntryPoint:
// the AA code and text, and the inner revert's error name when there is one.
type aaFailure struct {
	Reason string // for example "AA33 reverted"
	Code   string // for example "AA33"
	Inner  string // the paymaster's error name, "" without inner bytes
	Raw    []byte
}

func (f aaFailure) String() string {
	if f.Inner != "" {
		return f.Reason + " (" + f.Inner + ")"
	}
	return f.Reason
}

// decodeAAFailure decodes the revert data of a failed handleOps.
func decodeAAFailure(data []byte) (aaFailure, bool) {
	if len(data) < 4 {
		return aaFailure{}, false
	}
	selector := hex.EncodeToString(data[:4])
	if selector != selectorFailedOp && selector != selectorFailedOpWithRevert {
		return aaFailure{}, false
	}
	body := data[4:]
	reason, ok := abiStringAt(body, 1)
	if !ok {
		return aaFailure{}, false
	}
	failure := aaFailure{Reason: reason, Raw: data}
	if len(reason) >= 4 {
		failure.Code = reason[:4]
	}
	if selector == selectorFailedOpWithRevert {
		if inner, ok := abiBytesAt(body, 2); ok {
			failure.Inner = gaslessErrorName(inner)
		}
	}
	return failure, true
}

// gaslessErrorName names revert bytes: a known custom error (with the
// VaultCallFailed wrapper unwrapped), Error(string), or the selector.
func gaslessErrorName(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	selector := hex.EncodeToString(data[:4])
	if selector == selectorVaultCallFailed {
		if inner, ok := abiBytesAt(data[4:], 0); ok {
			return "VaultCallFailed:" + gaslessErrorName(inner)
		}
	}
	if selector == selectorErrorString {
		if text, ok := abiStringAt(data[4:], 0); ok {
			return "Error:" + text
		}
	}
	if name, known := gaslessErrorNames[selector]; known {
		return name
	}
	return "0x" + selector
}

// abiBytesAt reads a dynamic bytes argument whose offset is head word
// index of an ABI-encoded argument list.
func abiBytesAt(body []byte, index int) ([]byte, bool) {
	if len(body) < (index+1)*32 {
		return nil, false
	}
	offset := new(big.Int).SetBytes(body[index*32 : (index+1)*32])
	if !offset.IsUint64() || offset.Uint64()+32 > uint64(len(body)) {
		return nil, false
	}
	start := offset.Uint64()
	length := new(big.Int).SetBytes(body[start : start+32])
	if !length.IsUint64() || start+32+length.Uint64() > uint64(len(body)) {
		return nil, false
	}
	return body[start+32 : start+32+length.Uint64()], true
}

func abiStringAt(body []byte, index int) (string, bool) {
	raw, ok := abiBytesAt(body, index)
	return string(raw), ok
}

// ----------------------------------------------------------- deployment checks

// callData is an eth_call returning any ABI payload (rpcCaller.word reads
// one word).
func (r rpcCaller) callData(ctx context.Context, to, data string) (string, error) {
	var result string
	if err := r.call(ctx, "eth_call", []any{map[string]string{"to": to, "data": data}, "latest"}, &result); err != nil {
		return "", err
	}
	if !strings.HasPrefix(result, "0x") || len(result)%2 != 0 || (len(result) > 2 && !isHex(result, (len(result)-2)/2)) {
		return "", fmt.Errorf("invalid eth_call answer from the RPC %s", r.url)
	}
	return strings.ToLower(result[2:]), nil
}

// verifyGaslessCode runs the gasless deployment checks of design 4.4 through
// rpcURL: the runtime code of the EntryPoint, its SenderCreator, the
// paymaster, the factory and the transit accounts' implementation hash to
// the profile's pins; the paymaster names the vault, the factory and the
// EntryPoint and reads the vault's unit; the factory names the paymaster,
// the implementation and the creation code; the paymaster's gas
// policy is the profile's; and the factory derives the same transit account
// as this client for a sample pair. A mismatch is gasless_unavailable, which
// never refuses deposits or wallet-paid exits.
func verifyGaslessCode(ctx context.Context, client *http.Client, rpcURL string, d deploymentIdentity) error {
	profile, err := d.Gasless.validate()
	if err != nil {
		return err
	}
	rpc := rpcCaller{url: rpcURL, client: client}
	mismatch := func(what string) error {
		return fmt.Errorf("%w: %s through %s does not match this release's pin; --fees payout is unavailable (deposits and wallet-paid exits are unaffected)", errGaslessUnavailable, what, rpcURL)
	}
	pins := []struct{ label, address, pin, evidence string }{
		{"the EntryPoint's runtime code", profile.EntryPoint, profile.EntryPointCode, d.Evidence.EntryPointCode},
		{"the SenderCreator's runtime code", profile.SenderCreator, profile.SenderCreatorCode, d.Evidence.SenderCreatorCode},
		{"the withdrawal paymaster's runtime code", profile.Paymaster, profile.PaymasterCode, d.Evidence.PaymasterCode},
		{"the account factory's runtime code", profile.Factory, profile.FactoryCode, d.Evidence.FactoryCode},
		// A paymaster whose creation code differs from the source could have
		// its factory create other account logic while every runtime above
		// still matches: only this pin catches it.
		{"the transit account implementation's runtime code", profile.Implementation, profile.ImplementationCode, d.Evidence.ImplementationCode},
	}
	for _, code := range pins {
		if code.evidence != "" && !strings.EqualFold(code.evidence, code.pin) {
			return fmt.Errorf("%w: the profile's evidence and gasless pins disagree about %s", errGaslessUnavailable, code.label)
		}
		hash, err := rpc.codeHash(ctx, code.address)
		if err != nil {
			return err
		}
		if !strings.EqualFold(hash, code.pin) {
			return mismatch(code.label)
		}
	}
	for _, getter := range []struct{ label, contract, selector, want string }{
		{"the paymaster's vault()", profile.Paymaster, "0x" + selectorPaymasterVault, addressABIWord(strings.ToLower(d.Contract))},
		{"the paymaster's factory()", profile.Paymaster, "0x" + selectorPaymasterFactory, addressABIWord(strings.ToLower(profile.Factory))},
		{"the paymaster's entryPoint()", profile.Paymaster, "0x" + selectorPaymasterEntryPoint, addressABIWord(strings.ToLower(profile.EntryPoint))},
		{"the paymaster's WEI_PER_UNIT()", profile.Paymaster, "0x" + selectorWeiPerUnit, uintWord(1_000_000_000)},
		{"the factory's paymaster()", profile.Factory, "0x" + selectorFactoryPaymaster, addressABIWord(strings.ToLower(profile.Paymaster))},
		{"the factory's implementation()", profile.Factory, "0x" + selectorFactoryImplementation, addressABIWord(strings.ToLower(profile.Implementation))},
		{"the factory's accountCreationCodeHash()", profile.Factory, "0x" + selectorAccountCreationCodeHash, addressABIWord(strings.ToLower(profile.AccountCreationCodeHash))},
	} {
		got, err := rpc.word(ctx, getter.contract, getter.selector)
		if err != nil {
			return err
		}
		if got != strings.ToLower(getter.want) {
			return mismatch(getter.label)
		}
	}
	policy, err := rpc.callData(ctx, profile.Paymaster, "0x"+selectorGasPolicy)
	if err != nil {
		return err
	}
	expected := ""
	for _, word := range profile.GasPolicy.words() {
		expected += uintWord(word)
	}
	if policy != expected {
		return fmt.Errorf("%w: the paymaster's gasPolicy() through %s is not the profile's gas policy (gasless_policy_mismatch); --fees payout is unavailable", errGaslessUnavailable, rpcURL)
	}
	creation, _ := hex.DecodeString(strings.TrimPrefix(profile.AccountCreationCode, "0x"))
	sampleOwner, samplePayee := common.HexToAddress("0x0000000000000000000000000000000000000001"), common.HexToAddress("0x0000000000000000000000000000000000000002")
	local := transitAccountAddress(common.HexToAddress(profile.Factory), creation, common.HexToAddress(profile.EntryPoint), common.HexToAddress(d.Contract), common.HexToAddress(profile.Paymaster), sampleOwner, samplePayee)
	derived, err := rpc.word(ctx, profile.Factory, "0x"+selectorFactoryGetAddress+addressABIWord(strings.ToLower(sampleOwner.Hex()))+addressABIWord(strings.ToLower(samplePayee.Hex())))
	if err != nil {
		return err
	}
	if derived != addressABIWord(strings.ToLower(local.Hex())) {
		return fmt.Errorf("%w: the factory's getAddress through %s differs from the local transit account derivation (gasless_deployment_mismatch); --fees payout is unavailable", errGaslessUnavailable, rpcURL)
	}
	return nil
}

// CheckGaslessDeployment runs the gasless deployment checks through the
// pinned RPC and, when one is configured, the user's exit RPC. A failure
// disables --fees payout only.
func (c *Client) CheckGaslessDeployment(ctx context.Context) error {
	deployment, _, err := deployedDeployment(c.config.Network)
	if err != nil {
		return err
	}
	endpoints, err := c.packagedEndpoints()
	if err != nil {
		return err
	}
	if err := verifyGaslessCode(ctx, c.inference, endpoints.RPC, deployment); err != nil {
		return err
	}
	if c.config.ExitRPCURL != "" {
		if err := ValidateExitRPCURL(c.config.ExitRPCURL); err != nil {
			return err
		}
		if err := verifyGaslessCode(ctx, c.inference, c.config.ExitRPCURL, deployment); err != nil {
			return err
		}
	}
	return nil
}
