package zkapi

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The gasless withdrawal flow of design section 3.3: a withdrawal whose
// network fee is paid from the payout. The proof binds a transit account S
// (a fresh owner key per withdrawal and the payout address Y); the exit is
// carried by a user operation the paymaster sponsors; the record journals
// the owner key and every operation before it is sent, and a resume follows
// the operation on the bundler and, authoritatively, on chain.

// addressWithdrawalOptions are the per-request choices of a withdrawal
// command (the CLI's --fees, --fee-cap-gwei, --bundler-url,
// --allow-expensive-gas, --collect, --sweep and --claim-credit), carried in
// the context like the quote mode.
type addressWithdrawalOptions struct {
	// Fees is "payout" for a gasless withdrawal, "wallet" or "" for the
	// wallet-paid path.
	Fees string
	// FeeCapGwei bounds what the payout may lose to the network fee and the
	// paymaster's flat fee, and for a contract payout address the credit
	// surcharge of a failed push (0: no bound).
	FeeCapGwei uint64
	BundlerURL string
	// AllowExpensiveGas accepts a fee above the profile's uneconomic
	// fraction of the payout.
	AllowExpensiveGas bool
	// Collect forwards a balance that sits in the transit account with a
	// sponsored FORWARD operation; Sweep does it wallet-paid (S.sweep(),
	// createAccount first); ClaimCredit delivers a payout the paymaster
	// credited (claimCredit(Y), wallet-paid).
	Collect, Sweep, ClaimCredit bool
}

type addressWithdrawalOptionsKey struct{}

func withdrawalOptions(ctx context.Context) addressWithdrawalOptions {
	options, _ := ctx.Value(addressWithdrawalOptionsKey{}).(addressWithdrawalOptions)
	return options
}

// WithWithdrawalOptions carries options to WithdrawAddress, EscapeAddress
// and their quotes.
func WithWithdrawalOptions(ctx context.Context, options addressWithdrawalOptions) context.Context {
	return context.WithValue(ctx, addressWithdrawalOptionsKey{}, options)
}

// addressTransit is the transit account S of a gasless withdrawal: the
// pinned contracts it was derived from, its owner key (fresh per
// withdrawal, never the funding key) and the payout address it binds.
type addressTransit struct {
	Factory            string `json:"factory"`
	Paymaster          string `json:"paymaster"`
	EntryPoint         string `json:"entry_point"`
	Account            string `json:"account"`
	Owner              string `json:"owner"`
	OwnerKey           string `json:"owner_key"`
	CreationCodeKeccak string `json:"creation_code_keccak256"`
}

// addressUserOp is the user operation in flight for a withdrawal, journaled
// before it is sent so that a crash re-sends identical bytes.
type addressUserOp struct {
	Kind             string          `json:"kind"`
	JSON             json.RawMessage `json:"json"`
	Hash             string          `json:"hash"`
	Hashes           []string        `json:"hashes,omitempty"`
	Nonce            string          `json:"nonce"`
	InitCode         bool            `json:"init_code"`
	BundlerURL       string          `json:"bundler_url"`
	BuiltAt          int64           `json:"built_at"`
	SubmittedAt      int64           `json:"submitted_at,omitempty"`
	SubmittedAtBlock uint64          `json:"submitted_at_block,omitempty"`
	Ambiguous        bool            `json:"ambiguous,omitempty"`
	// ValidUntil is the proof's lifetime a CLOSE or ESCAPE operation carries
	// (0 for FINALIZE and FORWARD): the operation is abandoned 60 s before.
	ValidUntil uint64 `json:"valid_until,omitempty"`
	// TransactionHash is the bundle transaction once the operation's
	// UserOperationEvent was found on chain, and IncludedHash the hash that
	// event names: one of Hashes, which may be an earlier copy than JSON
	// (a bundler may include an operation after it was re-signed with
	// higher fees). Hash always stays the hash of JSON, so the journal
	// validates whichever copy landed.
	TransactionHash string `json:"transaction_hash,omitempty"`
	IncludedHash    string `json:"included_hash,omitempty"`
	// Revert names the reason of a reverted operation.
	Revert string `json:"revert,omitempty"`
	// The approval's bounds on a re-signed copy (an operation the bundler
	// dropped for its fees is re-signed an eighth higher only within them):
	// FeeCapWei is the most the fee may take from the payout (the user's
	// --fee-cap-gwei in wei when one was given with the quote, else the
	// approved maximum), FeeCapGwei that flag and AllowExpensiveGas the
	// acceptance of a fee above the uneconomic fraction.
	FeeCapWei         string `json:"fee_cap_wei,omitempty"`
	FeeCapGwei        uint64 `json:"fee_cap_gwei,omitempty"`
	AllowExpensiveGas bool   `json:"allow_expensive_gas,omitempty"`
}

// listHash journals hash among the operation's hashes once.
func (u *addressUserOp) listHash(hash string) {
	for _, listed := range u.Hashes {
		if strings.EqualFold(listed, hash) {
			return
		}
	}
	u.Hashes = append(u.Hashes, hash)
}

// shownHash is the hash the status reports: the included copy once the
// operation landed, else the one in flight.
func (u *addressUserOp) shownHash() string {
	if u.IncludedHash != "" {
		return u.IncludedHash
	}
	return u.Hash
}

// transitKinds are the wallet-paid transactions of the gasless path: the
// transit account's creation and sweep, and the paymaster credit claim.
var transitKinds = map[string]bool{"transit_create": true, "transit_sweep": true, "gasless_claim": true}

// TransitKind reports a wallet-paid transit transaction kind.
func TransitKind(kind string) bool { return transitKinds[kind] }

// GaslessPhase reports a phase of the gasless path: an operation built or
// sent, reverted, or a refusal of the sponsored path.
func GaslessPhase(phase string) bool {
	switch phase {
	case "op_built", "op_submitted", "op_reverted", "gasless_refused", "finalize_op_built", "finalize_op_submitted", "forward_op_built", "forward_op_submitted":
		return true
	}
	return false
}

// GaslessPendingPhase reports a phase during which an operation is in
// flight and a resume keeps following it.
func GaslessPendingPhase(phase string) bool {
	switch phase {
	case "op_built", "op_submitted", "finalize_op_built", "finalize_op_submitted", "forward_op_built", "forward_op_submitted":
		return true
	}
	return false
}

// gaslessRefusal is a reason the gasless path cannot carry a withdrawal
// now; the wallet-paid path stays available.
type gaslessRefusal struct {
	Code    string
	Message string
}

func (e *gaslessRefusal) Error() string { return e.Code + ": " + e.Message }

func refuse(code, format string, args ...any) error {
	return &gaslessRefusal{Code: code, Message: fmt.Sprintf(format, args...)}
}

// GaslessRefusalCode is the machine-readable code of a gasless refusal, ""
// for any other error.
func GaslessRefusalCode(err error) string {
	var refusal *gaslessRefusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	if errors.Is(err, errGaslessUnavailable) {
		return "gasless_unavailable"
	}
	if errors.Is(err, errBundlerUnavailable) {
		return "bundler_unavailable"
	}
	return ""
}

// gaslessEnvironment is what a withdrawal's gasless operations need: the
// validated profile, the chain config (the exit RPC when one is set), the
// bundler and the transit account with its key.
type gaslessEnvironment struct {
	profile                                                      gaslessProfile
	deployment                                                   deploymentIdentity
	config                                                       fundingConfig
	bundler                                                      string
	bundlerErr                                                   error
	entryPoint, paymaster, factory, vault, account, owner, payee common.Address
	key                                                          *ecdsa.PrivateKey
	// journaled marks an environment of the contracts journaled with the
	// record that the current profile does not pin (followEnvironment): an
	// operation already sent is looked for on chain and settled from its
	// inclusion, but nothing is sent, re-sent or re-signed through it.
	journaled bool
}

func (h *FundingHandler) gaslessProfile() (gaslessProfile, deploymentIdentity, error) {
	deployment, _, err := deployedDeployment(h.client.config.Network)
	if err != nil {
		return gaslessProfile{}, deployment, err
	}
	profile, err := deployment.Gasless.validate()
	return profile, deployment, err
}

// resolveBundlerURL is the bundler: the request's, then the configuration's,
// then the profile's.
func (h *FundingHandler) resolveBundlerURL(options addressWithdrawalOptions, profile gaslessProfile) (string, error) {
	for _, candidate := range []string{options.BundlerURL, h.client.config.BundlerURL, profile.BundlerURL} {
		if candidate == "" {
			continue
		}
		if err := ValidateBundlerURL(candidate); err != nil {
			return "", err
		}
		return candidate, nil
	}
	return "", refuse("bundler_unavailable", "no bundler is configured for this deployment: pass --bundler-url URL or set zkapi.bundler_url")
}

// ensureGaslessChecked runs the gasless deployment checks (design 4.4)
// through the pinned RPC and the exit RPC once per process.
func (h *FundingHandler) ensureGaslessChecked(ctx context.Context) error {
	key := h.client.config.Network + "|" + h.client.config.ExitRPCURL
	if h.gaslessChecked[key] {
		return nil
	}
	if err := h.client.CheckGaslessDeployment(ctx); err != nil {
		return err
	}
	if h.gaslessChecked == nil {
		h.gaslessChecked = map[string]bool{}
	}
	h.gaslessChecked[key] = true
	return nil
}

// errGaslessPayee refuses a payout address the transit account's factory
// never accepts as a payee.
var errGaslessPayee = errors.New("invalid_payee")

// checkGaslessPayee applies the factory's InvalidPayee rule
// (ZkApiWithdrawalAccountFactory.createAccount reverts for the zero
// address, the vault, the paymaster, the EntryPoint and the factory
// itself): getAddress is pure and derives a transit account for such a
// payee too, but that account can never be created, so a proof bound to it
// would strand the payout (no sponsored operation, no sweep). The payout
// address is refused before anything is reserved.
func checkGaslessPayee(profile gaslessProfile, vault, payee string) error {
	address := common.HexToAddress(payee)
	names := []struct {
		address common.Address
		name    string
	}{
		{common.Address{}, "the zero address"},
		{common.HexToAddress(vault), "the vault"},
		{common.HexToAddress(profile.EntryPoint), "the EntryPoint"},
		{common.HexToAddress(profile.Paymaster), "the withdrawal paymaster"},
		{common.HexToAddress(profile.Factory), "the withdrawal account factory"},
	}
	for _, reserved := range names {
		if address == reserved.address {
			return fmt.Errorf("%w: the payout address %s is %s of this deployment, which the transit account's factory never accepts as a payee; withdraw to another address", errGaslessPayee, address.Hex(), reserved.name)
		}
	}
	return nil
}

// newTransit derives a transit account for the payout address: a fresh
// owner key, S by CREATE2 from the profile's creation code, cross-checked
// with the factory's getAddress through the read RPC.
func (h *FundingHandler) newTransit(ctx context.Context, config fundingConfig, profile gaslessProfile, payee string) (*addressTransit, error) {
	if err := checkGaslessPayee(profile, config.Contract, payee); err != nil {
		return nil, err
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, errors.New("cannot generate the transit account's owner key")
	}
	owner := crypto.PubkeyToAddress(key.PublicKey)
	creation, _ := hex.DecodeString(strings.TrimPrefix(profile.AccountCreationCode, "0x"))
	account := transitAccountAddress(common.HexToAddress(profile.Factory), creation, common.HexToAddress(profile.EntryPoint), common.HexToAddress(config.Contract), common.HexToAddress(profile.Paymaster), owner, common.HexToAddress(payee))
	var derived string
	if err := h.addressRPC(ctx, config.exitConfig(), "eth_call", []any{map[string]string{"to": profile.Factory, "data": "0x" + selectorFactoryGetAddress + addressABIWord(strings.ToLower(owner.Hex())) + addressABIWord(strings.ToLower(payee))}, "latest"}, &derived); err != nil {
		return nil, err
	}
	if !isHex(derived, 32) || !strings.EqualFold(derived[2:], addressABIWord(strings.ToLower(account.Hex()))) {
		return nil, fmt.Errorf("%w: the factory derives another transit account than this client (gasless_deployment_mismatch)", errGaslessUnavailable)
	}
	return &addressTransit{Factory: common.HexToAddress(profile.Factory).Hex(), Paymaster: common.HexToAddress(profile.Paymaster).Hex(), EntryPoint: common.HexToAddress(profile.EntryPoint).Hex(), Account: account.Hex(), Owner: owner.Hex(), OwnerKey: hex.EncodeToString(crypto.FromECDSA(key)), CreationCodeKeccak: profile.AccountCreationCodeHash}, nil
}

// GaslessRecordNotPinned is the refusal of a sponsored operation (a
// FORWARD, a FINALIZE, a new, re-sent or re-signed operation of a sponsored
// close or escape) for an existing gasless record whose paymaster and
// factory the current profile does not pin: the profile publishes no
// gasless contracts any more (gasless: null, the paymaster's retirement) or
// pins others. The record's wallet-paid recovery (--sweep, --claim-credit,
// --escape --fees wallet) uses the contracts journaled with it and keeps
// working, and an operation already sent is still followed on chain and
// released if it was not included (followEnvironment, followUserOperation);
// the code is also the reason journaled with such a release.
const GaslessRecordNotPinned = "gasless_record_not_pinned"

// sameGaslessContracts reports whether the transit account t was made under
// the profile's contracts.
func sameGaslessContracts(t *addressTransit, profile gaslessProfile) bool {
	return strings.EqualFold(t.Factory, profile.Factory) && strings.EqualFold(t.Paymaster, profile.Paymaster) && strings.EqualFold(t.EntryPoint, profile.EntryPoint) && strings.EqualFold(t.CreationCodeKeccak, profile.AccountCreationCodeHash)
}

// recordProfile is the current gasless profile when it pins the contracts
// the record's transit account was made under, which a sponsored operation
// for that record needs; otherwise the gasless_record_not_pinned refusal,
// which names the wallet-paid alternatives.
func (h *FundingHandler) recordProfile(w *addressWithdrawalRecord) (gaslessProfile, deploymentIdentity, error) {
	deployment, _, err := deployedDeployment(h.client.config.Network)
	if err != nil {
		return gaslessProfile{}, deployment, err
	}
	t := w.Transit
	alternatives := walletRecoveryAlternatives(w)
	if w.UserOp != nil && GaslessPendingPhase(w.Phase) {
		// The wallet-paid actions wait for the operation in flight: the
		// resume follows it through the journaled contracts and releases it
		// if it was not included.
		command := "zkapi-clientd withdraw --to " + w.Destination
		if w.Mode == "escape" {
			command = "zkapi-clientd withdraw --escape --to " + w.Destination
		}
		alternatives = "the operation already sent is followed on chain by resuming with " + command + " (without --fees): if it was not included it is released, and then " + alternatives
	}
	if deployment.Gasless == nil {
		return gaslessProfile{}, deployment, refuse(GaslessRecordNotPinned, "this withdrawal's transit account %s was made under paymaster %s and factory %s, and this release's deployment profile publishes no gasless paymaster any more, so nothing of it is sponsored; %s", t.Account, t.Paymaster, t.Factory, alternatives)
	}
	profile, err := deployment.Gasless.validate()
	if err != nil {
		return profile, deployment, err
	}
	if !sameGaslessContracts(t, profile) {
		return gaslessProfile{}, deployment, refuse(GaslessRecordNotPinned, "this withdrawal's transit account %s was made under paymaster %s and factory %s, but this release's deployment profile pins paymaster %s and factory %s, so nothing of it is sponsored; %s", t.Account, t.Paymaster, t.Factory, profile.Paymaster, profile.Factory, alternatives)
	}
	return profile, deployment, nil
}

// walletRecoveryAlternatives names the wallet-paid recovery of a gasless
// record, which uses the contracts journaled with it. While the record's
// exit is not on chain yet, the wallet-paid close or escape initiation
// (--fees wallet) comes first: it is the only way forward for an open note.
func walletRecoveryAlternatives(w *addressWithdrawalRecord) string {
	recovery := "deliver a payout waiting in the transit account with zkapi-clientd withdraw --sweep --to " + w.Destination + " and a credited payout with --claim-credit (both paid by the local signing address), and finalize a pending escape with zkapi-clientd withdraw --escape --to " + w.Destination + " --fees wallet"
	if !gaslessExitNotOnChain(w) {
		return recovery
	}
	if w.Mode == "escape" {
		return "initiate the escape from the local signing address with zkapi-clientd withdraw --escape --to " + w.Destination + " --fees wallet (the payout then reaches the transit account); later, " + recovery
	}
	return "close the note from the local signing address with zkapi-clientd withdraw --to " + w.Destination + " --fees wallet (the payout then reaches the transit account); later, " + recovery
}

// gaslessExitNotOnChain reports whether a gasless record's exit (its close,
// or its escape's initiation) is not known on chain yet, so the note is
// still open as far as the record knows.
func gaslessExitNotOnChain(w *addressWithdrawalRecord) bool {
	if w.FundsWaitingInTransit || w.PaymasterCredited || w.PayoutCredited || w.SettlementHash != "" {
		return false
	}
	if w.Mode == "escape" {
		return w.InitiateHash == "" && w.Phase != "complete" && w.Phase != "defeated"
	}
	switch w.Phase {
	case "complete", "confirming", "forward_op_built", "forward_op_submitted":
		return false
	case "op_reverted":
		// The bundle transaction of a reverted close is not the note's exit.
		return true
	}
	return w.TransactionHash == ""
}

// releasedOperationReason is the refusal journaled when followUserOperation
// releases an operation the current profile no longer sponsors.
func releasedOperationReason(w *addressWithdrawalRecord) string {
	next := "close the note again with zkapi-clientd withdraw --to " + w.Destination + " --fees wallet"
	switch {
	case w.UserOp != nil && gaslessKindOf(w.UserOp.Kind) == gaslessKindForward:
		next = "deliver the payout waiting in the transit account with zkapi-clientd withdraw --sweep --to " + w.Destination
	case w.Mode == "escape" && w.InitiateHash != "":
		next = "finalize the escape with zkapi-clientd withdraw --escape --to " + w.Destination + " --fees wallet"
	case w.Mode == "escape":
		next = "initiate the escape again with zkapi-clientd withdraw --escape --to " + w.Destination + " --fees wallet"
	}
	return "this release's deployment profile no longer pins the paymaster and factory this withdrawal's transit account was made under, so the sponsored operation it sent, not included by now, was released without being re-sent; " + next + " (a late inclusion of the released operation is looked for first and otherwise fails harmlessly)"
}

// transitOwnerKey is the record's transit owner key, checked against its
// journaled owner and the proof's destination.
func transitOwnerKey(w *addressWithdrawalRecord) (*ecdsa.PrivateKey, error) {
	key, err := crypto.HexToECDSA(w.Transit.OwnerKey)
	if err != nil || !strings.EqualFold(crypto.PubkeyToAddress(key.PublicKey).Hex(), w.Transit.Owner) {
		return nil, errors.New("the saved transit owner key is invalid; preserve the recovery file")
	}
	if !strings.EqualFold(w.ProofDestination, w.Transit.Account) {
		return nil, errors.New("the saved transit account is not the one derived from its owner and payout address; preserve the recovery file")
	}
	return key, nil
}

// journaledEnvironment is the environment of a wallet-paid action on an
// existing gasless record (--sweep, --claim-credit, and the look for a late
// inclusion before --fees wallet finalizes or closes): the contracts
// journaled with the record (transit account, factory, paymaster,
// EntryPoint, owner, payout address), never the current profile's, so these
// keep working once the profile retires its gasless pins or names another
// paymaster. The journaled factory's getAddress(owner, payee) must name the
// journaled account through the read RPC; while the profile still pins the
// same contracts, the account is also derived locally as for a sponsored
// operation. No bundler is resolved: none of these contacts one.
func (h *FundingHandler) journaledEnvironment(ctx context.Context, config fundingConfig, record *addressFundingRecord) (*gaslessEnvironment, error) {
	w := record.Withdrawal
	if w == nil || w.Transit == nil {
		return nil, errors.New("the saved withdrawal has no transit account")
	}
	t := w.Transit
	for _, address := range []string{t.Factory, t.Paymaster, t.EntryPoint, t.Account, t.Owner, w.Destination} {
		if !isHex(address, 20) || common.HexToAddress(address) == (common.Address{}) {
			return nil, errors.New("the saved transit account names an invalid contract or account address; preserve the recovery file")
		}
	}
	key, err := transitOwnerKey(w)
	if err != nil {
		return nil, err
	}
	deployment, _, err := deployedDeployment(h.client.config.Network)
	if err != nil {
		return nil, err
	}
	env := &gaslessEnvironment{
		deployment: deployment, config: config.exitConfig(),
		entryPoint: common.HexToAddress(t.EntryPoint), paymaster: common.HexToAddress(t.Paymaster), factory: common.HexToAddress(t.Factory),
		vault: common.HexToAddress(config.Contract), account: common.HexToAddress(t.Account), owner: common.HexToAddress(t.Owner), payee: common.HexToAddress(w.Destination), key: key,
	}
	if deployment.Gasless != nil {
		if profile, err := deployment.Gasless.validate(); err == nil && sameGaslessContracts(t, profile) {
			creation, _ := hex.DecodeString(strings.TrimPrefix(profile.AccountCreationCode, "0x"))
			if transitAccountAddress(env.factory, creation, env.entryPoint, env.vault, env.paymaster, env.owner, env.payee) != env.account {
				return nil, errors.New("the saved transit account is not the one derived from its owner and payout address; preserve the recovery file")
			}
			env.profile = profile
		}
	}
	var derived string
	if err := h.addressRPC(ctx, env.config, "eth_call", []any{map[string]string{"to": env.factory.Hex(), "data": "0x" + selectorFactoryGetAddress + addressABIWord(strings.ToLower(env.owner.Hex())) + addressABIWord(strings.ToLower(env.payee.Hex()))}, "latest"}, &derived); err != nil {
		return nil, err
	}
	if !isHex(derived, 32) || !strings.EqualFold(derived[2:], addressABIWord(strings.ToLower(env.account.Hex()))) {
		return nil, errors.New("the saved transit account's factory derives another account for its owner and payout address; nothing was signed, preserve the recovery file")
	}
	return env, nil
}

// followEnvironment is the environment that follows an operation the
// record already sent, and reads the settlement of its inclusion: the
// sponsored one (gaslessEnvironment) while the current profile pins the
// record's contracts; otherwise (gasless: null, or pins naming another
// paymaster) the journaled one, marked journaled, with the bundler the
// operation was sent to (else the request's or the configuration's) for
// read-only lookups. Following needs no sponsorship from the current
// profile: an operation already sent either lands or is released
// (followUserOperation), so a record in flight when the profile retired
// its pins is never left without a path forward.
func (h *FundingHandler) followEnvironment(ctx context.Context, config fundingConfig, record *addressFundingRecord) (*gaslessEnvironment, error) {
	options := withdrawalOptions(ctx)
	env, err := h.gaslessEnvironment(ctx, config, record, options)
	if GaslessRefusalCode(err) != GaslessRecordNotPinned {
		return env, err
	}
	if env, err = h.journaledEnvironment(ctx, config, record); err != nil {
		return nil, err
	}
	env.journaled = true
	candidates := []string{options.BundlerURL, h.client.config.BundlerURL}
	if u := record.Withdrawal.UserOp; u != nil && options.BundlerURL == "" {
		candidates = append([]string{u.BundlerURL}, candidates...)
	}
	for _, candidate := range candidates {
		if candidate != "" && ValidateBundlerURL(candidate) == nil {
			env.bundler = candidate
			break
		}
	}
	return env, nil
}

// gaslessEnvironment loads the saved transit account of record for a
// sponsored operation: the current profile must pin the contracts it was
// made under (recordProfile).
func (h *FundingHandler) gaslessEnvironment(ctx context.Context, config fundingConfig, record *addressFundingRecord, options addressWithdrawalOptions) (*gaslessEnvironment, error) {
	w := record.Withdrawal
	if w == nil || w.Transit == nil {
		return nil, errors.New("the saved withdrawal has no transit account")
	}
	profile, deployment, err := h.recordProfile(w)
	if err != nil {
		return nil, err
	}
	key, err := transitOwnerKey(w)
	if err != nil {
		return nil, err
	}
	// The saved account must be the CREATE2 of the saved owner and the payout
	// address under the pinned contracts: a lying RPC or an edited journal
	// cannot substitute the account the proof binds.
	creation, _ := hex.DecodeString(strings.TrimPrefix(profile.AccountCreationCode, "0x"))
	derived := transitAccountAddress(common.HexToAddress(profile.Factory), creation, common.HexToAddress(profile.EntryPoint), common.HexToAddress(config.Contract), common.HexToAddress(profile.Paymaster), common.HexToAddress(w.Transit.Owner), common.HexToAddress(w.Destination))
	if !strings.EqualFold(derived.Hex(), w.Transit.Account) {
		return nil, errors.New("the saved transit account is not the one derived from its owner and payout address; preserve the recovery file")
	}
	// The bundler is resolved here but required only where it is used
	// (submitUserOperation, followUserOperation): the wallet-paid sweep and
	// credit claim, and the chain-side look for a late inclusion, never
	// contact it.
	bundler := ""
	var bundlerErr error
	if w.UserOp != nil && options.BundlerURL == "" {
		bundler = w.UserOp.BundlerURL
	}
	if bundler == "" {
		bundler, bundlerErr = h.resolveBundlerURL(options, profile)
	}
	return &gaslessEnvironment{
		profile: profile, deployment: deployment, config: config.exitConfig(), bundler: bundler, bundlerErr: bundlerErr,
		entryPoint: common.HexToAddress(profile.EntryPoint), paymaster: common.HexToAddress(profile.Paymaster), factory: common.HexToAddress(profile.Factory),
		vault: common.HexToAddress(config.Contract), account: common.HexToAddress(w.Transit.Account), owner: common.HexToAddress(w.Transit.Owner), payee: common.HexToAddress(w.Destination), key: key,
	}, nil
}

// needBundler is the bundler's resolution error when no bundler resolved.
func (env *gaslessEnvironment) needBundler() error {
	if env.bundler == "" {
		if env.bundlerErr != nil {
			return env.bundlerErr
		}
		return refuse("bundler_unavailable", "no bundler is configured for this deployment: pass --bundler-url URL or set zkapi.bundler_url")
	}
	return nil
}

// ----------------------------------------------------------------- chain reads

func (h *FundingHandler) gaslessWords(ctx context.Context, env *gaslessEnvironment, to common.Address, data string, count int) ([]*big.Int, error) {
	var encoded string
	if err := h.addressRPC(ctx, env.config, "eth_call", []any{map[string]string{"to": to.Hex(), "data": data}, "latest"}, &encoded); err != nil {
		return nil, err
	}
	if !isHex(encoded, 32*count) {
		return nil, errors.New("invalid answer from the paymaster or the EntryPoint")
	}
	words := make([]*big.Int, count)
	for i := range words {
		words[i] = new(big.Int).SetBytes(common.FromHex(encoded[2+i*64 : 2+(i+1)*64]))
	}
	return words, nil
}

func (h *FundingHandler) gaslessWord(ctx context.Context, env *gaslessEnvironment, to common.Address, data string) (*big.Int, error) {
	words, err := h.gaslessWords(ctx, env, to, data, 1)
	if err != nil {
		return nil, err
	}
	return words[0], nil
}

// gaslessLive is the paymaster's and the vault's live state the pre-flight
// reads (design 3.1): the policy, the ceilings, the kind's call cap, the
// deposit, the attempts under the operation's key and what S owes.
type gaslessLive struct {
	MaxSponsoredCost, FlatFee, MinEscapeNet *big.Int
	EscapesEnabled, SponsorshipPaused       bool
	MaxFeeCeiling, PriorityFeeCeiling       *big.Int
	CallCap                                 uint64
	Deposit, Owed                           *big.Int
	Attempts                                uint64
	VaultPaused                             bool
	ReopenAt                                uint64
	// BaseFee is the latest block's base fee: the fee an operation would pay
	// now (base plus tip, at most its maxFeePerGas) prices the expected
	// charge of a quote.
	BaseFee *big.Int
}

func (h *FundingHandler) gaslessLive(ctx context.Context, env *gaslessEnvironment, kind uint8, key common.Hash) (gaslessLive, error) {
	var live gaslessLive
	policy, err := h.gaslessWords(ctx, env, env.paymaster, "0x"+selectorPaymasterPolicy, 5)
	if err != nil {
		return live, err
	}
	live.MaxSponsoredCost, live.FlatFee, live.MinEscapeNet = policy[0], policy[1], policy[2]
	live.EscapesEnabled, live.SponsorshipPaused = policy[3].Sign() != 0, policy[4].Sign() != 0
	if live.MaxFeeCeiling, err = h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorMaxFeeCeiling); err != nil {
		return live, err
	}
	if live.PriorityFeeCeiling, err = h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorPriorityFeeCeiling); err != nil {
		return live, err
	}
	callCap, err := h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorCallCap+uintWord(uint64(kind)))
	if err != nil {
		return live, err
	}
	if !callCap.IsUint64() {
		return live, errors.New("invalid call gas cap from the paymaster")
	}
	live.CallCap = callCap.Uint64()
	if live.Deposit, err = h.gaslessWord(ctx, env, env.entryPoint, "0x"+selectorEntryPointBalance+addressABIWord(strings.ToLower(env.paymaster.Hex()))); err != nil {
		return live, err
	}
	attempts, err := h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorAttempts+strings.TrimPrefix(key.Hex(), "0x"))
	if err != nil {
		return live, err
	}
	live.Attempts = attempts.Uint64()
	if live.Owed, err = h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorOwed+addressABIWord(strings.ToLower(env.account.Hex()))); err != nil {
		return live, err
	}
	var block struct {
		Base string `json:"baseFeePerGas"`
	}
	if err := h.addressRPC(ctx, env.config, "eth_getBlockByNumber", []any{"latest", false}, &block); err != nil {
		return live, err
	}
	if live.BaseFee, err = feeQuantity(block.Base); err != nil {
		return live, errAddressFeeData
	}
	if kind == gaslessKindClose || kind == gaslessKindEscape {
		paused, err := h.gaslessWord(ctx, env, env.vault, "0x"+selectorVaultPaused)
		if err != nil {
			return live, err
		}
		if live.VaultPaused = paused.Sign() != 0; live.VaultPaused {
			pausedAt, err := h.gaslessWord(ctx, env, env.vault, "0x"+selectorVaultPausedAt)
			if err != nil {
				return live, err
			}
			live.ReopenAt = pausedAt.Uint64() + env.deployment.MaxPauseDuration
		}
	}
	return live, nil
}

// checkGaslessLive turns the live state into the refusals of design 3.1.
func checkGaslessLive(live gaslessLive, kind uint8, g gaslessGasPolicy) error {
	if live.SponsorshipPaused {
		return refuse("sponsorship_paused", "the paymaster has paused sponsorship; use --fees wallet")
	}
	if kind == gaslessKindEscape && !live.EscapesEnabled {
		return refuse("escapes_disabled", "the paymaster does not sponsor escape initiations; initiate the escape with --fees wallet, then rerun with --fees payout once it is on chain to finalize it sponsored")
	}
	if live.VaultPaused {
		return refuse("exits_paused", "the vault is paused; exits reopen at Unix %d", live.ReopenAt)
	}
	if live.Attempts >= g.MaxAttempts {
		return refuse("gasless_attempts_exhausted", "this state used its %d sponsored attempts; use --fees wallet", g.MaxAttempts)
	}
	return nil
}

// checkBundler asks the bundler its chain (when it answers that method) and
// its EntryPoints, which must include the pinned one.
func (h *FundingHandler) checkBundler(ctx context.Context, env *gaslessEnvironment) error {
	result, refused, err := h.bundlerCall(ctx, env.bundler, "eth_chainId", []any{})
	if err != nil {
		return refuse("bundler_unavailable", "the bundler %s did not answer; use --fees wallet or another --bundler-url", env.bundler)
	}
	if refused == nil {
		var chain string
		if json.Unmarshal(result, &chain) != nil {
			return refuse("bundler_unavailable", "the bundler %s answered an invalid chain ID", env.bundler)
		}
		id, ok := new(big.Int).SetString(strings.TrimPrefix(chain, "0x"), 16)
		if !ok || !id.IsUint64() || id.Uint64() != env.config.ChainID {
			return refuse("bundler_wrong_chain", "the bundler %s serves another chain", env.bundler)
		}
	}
	result, refused, err = h.bundlerCall(ctx, env.bundler, "eth_supportedEntryPoints", []any{})
	if err != nil || refused != nil {
		return refuse("bundler_unavailable", "the bundler %s did not list its EntryPoints", env.bundler)
	}
	var supported []string
	if json.Unmarshal(result, &supported) != nil {
		return refuse("bundler_unavailable", "the bundler %s answered an invalid EntryPoint list", env.bundler)
	}
	for _, entryPoint := range supported {
		if strings.EqualFold(entryPoint, env.entryPoint.Hex()) {
			return nil
		}
	}
	return refuse("bundler_unsupported_entry_point", "the bundler %s does not serve EntryPoint v0.7.0 at %s", env.bundler, env.entryPoint.Hex())
}

// ----------------------------------------------------------------- fees and gas

// gaslessFees picks the operation's fees from the latest base fee and the
// chain's median tip by selectGaslessFees.
func (h *FundingHandler) gaslessFees(ctx context.Context, env *gaslessEnvironment, live gaslessLive) (maxFee, priority *big.Int, err error) {
	var block struct {
		Number string `json:"number"`
		Base   string `json:"baseFeePerGas"`
	}
	if err := h.addressRPC(ctx, env.config, "eth_getBlockByNumber", []any{"latest", false}, &block); err != nil {
		return nil, nil, err
	}
	number, e1 := feeQuantity(block.Number)
	base, e2 := feeQuantity(block.Base)
	if e1 != nil || e2 != nil || !number.IsUint64() {
		return nil, nil, errAddressFeeData
	}
	var history addressFeeHistory
	if h.addressRPC(ctx, env.config, "eth_feeHistory", []any{"0x14", block.Number, []int{50}}, &history) != nil {
		return nil, nil, errAddressFeeData
	}
	tip, err := lowPriorityFee(history, number.Uint64(), base)
	if err != nil {
		return nil, nil, err
	}
	return selectGaslessFees(base, tip, live.MaxFeeCeiling, live.PriorityFeeCeiling)
}

// selectGaslessFees is the fee rule both clients share (the SDK's
// selectFees; testdata/gasless-fee-parity.json is the table both assert):
// maxPriorityFeePerGas = min(tip, priority ceiling) and maxFeePerGas =
// min(2 × base + priority, max-fee ceiling), refused
// (gas_above_paymaster_ceiling) only when base + priority is above the
// max-fee ceiling. An operation at maxFeePerGas = ceiling still lands while
// base + priority fits under it; a base fee that rises past it is handled by
// the fee bump (within the ceilings) and the stop before validUntil.
func selectGaslessFees(base, tip, maxFeeCeiling, priorityFeeCeiling *big.Int) (maxFee, priority *big.Int, err error) {
	priority = new(big.Int).Set(tip)
	if priority.Cmp(priorityFeeCeiling) > 0 {
		priority.Set(priorityFeeCeiling)
	}
	if new(big.Int).Add(base, priority).Cmp(maxFeeCeiling) > 0 {
		return nil, nil, refuse("gas_above_paymaster_ceiling", "the network fee (base %s wei plus tip %s wei per gas) is above the paymaster's ceiling of %s wei; sponsorship is refused during this fee spike, use --fees wallet or retry later", base, priority, maxFeeCeiling)
	}
	maxFee = new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(2)), priority)
	if maxFee.Cmp(maxFeeCeiling) > 0 {
		maxFee.Set(maxFeeCeiling)
	}
	return maxFee, priority, nil
}

// gaslessGasFields are the five limits and the fees an operation is built
// with: the pinned defaults, or the fields a quote bound.
type gaslessGasFields struct {
	Call, Verification, PVG, PMVerification, PostOp uint64
	MaxFee, Priority, FeeCap                        *big.Int
	InitCode                                        bool
}

// GaslessQuoteGas is the gas of a payout quote, bound at approval.
type GaslessQuoteGas struct {
	CallGasLimit                  uint64 `json:"call_gas_limit"`
	VerificationGasLimit          uint64 `json:"verification_gas_limit"`
	PreVerificationGas            uint64 `json:"pre_verification_gas"`
	PaymasterVerificationGasLimit uint64 `json:"paymaster_verification_gas_limit"`
	PaymasterPostOpGasLimit       uint64 `json:"paymaster_post_op_gas_limit"`
	InitCode                      bool   `json:"init_code"`
}

// buildGaslessOp assembles the operation of kind for vaultCall: the nonce
// under the kind's key, initCode on first use, the pinned limits (or the
// quoted ones) and the fees.
func (h *FundingHandler) buildGaslessOp(ctx context.Context, env *gaslessEnvironment, kind uint8, vaultCall []byte, nullifier *big.Int, live gaslessLive, fixed *gaslessGasFields) (*gaslessUserOp, error) {
	key := gaslessNonceKey(kind, nullifier)
	nonce, err := h.gaslessWord(ctx, env, env.entryPoint, "0x"+selectorGetNonce+addressABIWord(strings.ToLower(env.account.Hex()))+addressABIWord(key.Text(16)))
	if err != nil {
		return nil, err
	}
	if new(big.Int).Rsh(nonce, 64).Cmp(key) != 0 {
		return nil, errors.New("the EntryPoint answered a nonce under another key")
	}
	var code string
	if err := h.addressRPC(ctx, env.config, "eth_getCode", []any{env.account.Hex(), "latest"}, &code); err != nil {
		return nil, err
	}
	g := env.profile.GasPolicy
	op := &gaslessUserOp{Sender: env.account, Nonce: nonce, CallData: transitCallData(vaultCall), Paymaster: env.paymaster}
	if code == "0x" || code == "" {
		op.InitCode = transitInitCode(env.factory, env.owner, env.payee)
	}
	if fixed != nil {
		if fixed.InitCode != (len(op.InitCode) != 0) {
			return nil, errAddressQuoteChanged
		}
		op.CallGasLimit, op.VerificationGasLimit, op.PreVerificationGas, op.PaymasterVerificationGasLimit, op.PaymasterPostOpGasLimit = fixed.Call, fixed.Verification, fixed.PVG, fixed.PMVerification, fixed.PostOp
		op.MaxFeePerGas, op.MaxPriorityFeePerGas, op.FeeCapWei = fixed.MaxFee, fixed.Priority, fixed.FeeCap
		return op, nil
	}
	_, _, op.CallGasLimit = g.callLimits(kind)
	if op.CallGasLimit > live.CallCap {
		op.CallGasLimit = live.CallCap
	}
	op.VerificationGasLimit = g.VerificationDefault
	if len(op.InitCode) != 0 {
		op.VerificationGasLimit = g.VerificationDefaultInit
	}
	op.PaymasterVerificationGasLimit, op.PaymasterPostOpGasLimit = g.PMVerificationDefault, g.PostOpDefault
	op.FeeCapWei = new(big.Int).Set(live.FlatFee)
	// ERC-7562 LIM-070: the operation's calldata cost plus the bundler's
	// overhead, which a bundler enforcing it requires; above the paymaster's
	// cap no bundler enforcing it carries the operation. The term does not
	// depend on the fees (it counts them at their widest).
	if op.lim070PreVerificationGas(g) > g.PVGCap {
		return nil, refuse("gasless_unavailable", "the operation's calldata exceeds the paymaster's preVerificationGas cap")
	}
	if op.MaxFeePerGas, op.MaxPriorityFeePerGas, err = h.gaslessFees(ctx, env, live); err != nil {
		return nil, err
	}
	// The shared rule, on the operation as it is signed (its fees included).
	op.PreVerificationGas = op.requiredPreVerificationGas(g)
	return op, nil
}

// gaslessAmounts are the wei figures of a quote (design 3.1): the payout,
// the most the operation can charge (maxCost plus the flat fee), what S
// owes, the finalization reserve of an escape and what Y receives at least.
// For an escape initiation MinimumReceived is the paymaster's floor (the
// reserve is the finalize shape's floors at this operation's fee), not what
// Y receives: the finalization is a later operation at its own fees, so
// FinalizeEstimate (the finalization's expected charge at the current fee)
// and EstimatedReceived (the payout less both expected charges and the
// debt) are what the quote shows, as estimates.
type gaslessAmounts struct {
	Payout, MaxCost, FlatFee, FeeCap, Owed, FinalizeReserve, MinimumReceived, ExpectedFee *big.Int
	FinalizeEstimate, EstimatedReceived                                                   *big.Int
	// PayeeHasCode: the payout address is a contract. The paymaster pushes
	// it the payout with 100,000 gas and, when that fails, credits the
	// payout less a CREDIT_GAS surcharge taken beyond the cap, so the floor
	// (MinimumReceived) already deducts CreditSurcharge for such a payee.
	PayeeHasCode    bool
	CreditSurcharge *big.Int
}

// gaslessFeeNow is the fee per gas the operation would pay if included
// now: the base fee plus its tip, at most its maxFeePerGas (the
// EntryPoint's min(maxFee, base + priority)); the ceiling when the base
// fee is unknown.
func gaslessFeeNow(op *gaslessUserOp, live gaslessLive) *big.Int {
	if live.BaseFee == nil {
		return new(big.Int).Set(op.MaxFeePerGas)
	}
	now := new(big.Int).Add(live.BaseFee, op.MaxPriorityFeePerGas)
	if now.Cmp(op.MaxFeePerGas) > 0 {
		now.Set(op.MaxFeePerGas)
	}
	return now
}

func gaslessAmountsFor(kind uint8, payout *big.Int, op *gaslessUserOp, live gaslessLive, g gaslessGasPolicy, payeeHasCode, payeeIsEmpty bool) gaslessAmounts {
	a := gaslessAmounts{Payout: payout, MaxCost: op.maxCost(), FlatFee: live.FlatFee, Owed: live.Owed, FinalizeReserve: new(big.Int), PayeeHasCode: payeeHasCode, CreditSurcharge: new(big.Int)}
	a.FeeCap = new(big.Int).Add(a.MaxCost, a.FlatFee)
	deducted := new(big.Int).Add(a.FeeCap, a.Owed)
	feeNow := gaslessFeeNow(op, live)
	if payeeHasCode && kind != gaslessKindEscape {
		// The paymaster's worst case for a contract payee whose push fails:
		// the credit's bookkeeping is charged beyond the cap, at the fee
		// paid (at most maxFeePerGas), before the rest is credited.
		a.CreditSurcharge = new(big.Int).Mul(new(big.Int).SetUint64(g.CreditGas), op.MaxFeePerGas)
		deducted.Add(deducted, a.CreditSurcharge)
	}
	// The expected charge (an estimate, not a bound): the paymaster's
	// chargeFor at the gas an operation of this shape uses and at the fee
	// it would pay now, plus the flat fee, capped at the maximum.
	a.ExpectedFee = gaslessExpectedCharge(g, kind, op, feeNow, a.FlatFee, payeeHasCode, payeeIsEmpty)
	if kind == gaslessKindEscape {
		a.FinalizeReserve = new(big.Int).Mul(new(big.Int).SetUint64(g.FinalizeReserveGas), op.MaxFeePerGas)
		deducted.Add(deducted, a.FinalizeReserve)
		deducted.Add(deducted, a.FlatFee)
		// What the payout address would receive, estimated the way the
		// expected charge is: the initiation's expected charge (recorded as
		// the transit account's debt), what it owes already, and the
		// finalization's expected charge (the finalize shape the client
		// builds, its validation floors and measured execution, at the fee
		// an operation would pay now). The maxima stay separate bounds.
		finalize := gaslessShapeOp(g, gaslessKindFinalize, false, op.Paymaster, a.FlatFee, 0)
		finalize.MaxFeePerGas, finalize.MaxPriorityFeePerGas = op.MaxFeePerGas, op.MaxPriorityFeePerGas
		a.FinalizeEstimate = gaslessExpectedCharge(g, gaslessKindFinalize, finalize, feeNow, a.FlatFee, payeeHasCode, payeeIsEmpty)
		a.EstimatedReceived = new(big.Int).Sub(payout, new(big.Int).Add(a.ExpectedFee, a.Owed))
		a.EstimatedReceived.Sub(a.EstimatedReceived, a.FinalizeEstimate)
		if a.EstimatedReceived.Sign() < 0 {
			a.EstimatedReceived = new(big.Int)
		}
	}
	a.MinimumReceived = new(big.Int).Sub(payout, deducted)
	return a
}

// gaslessExpectedCharge is the paymaster's chargeFor for op at the gas an
// operation of its shape uses (its preVerificationGas in full, the
// validation floors rather than the signed limits, the kind's measured
// execution and the pinned postOp constants) and at feeNow, plus the flat
// fee, capped at the operation's maximum (maxCost plus the flat fee).
func gaslessExpectedCharge(g gaslessGasPolicy, kind uint8, op *gaslessUserOp, feeNow, flatFee *big.Int, payeeHasCode, payeeIsEmpty bool) *big.Int {
	floor, _, _ := g.callLimits(kind)
	overhead := g.AccountCallOverheadGas
	if kind == gaslessKindEscape {
		overhead = g.AccountCallOverheadEscapeGas
	}
	execution := uint64(0)
	if floor > 20_000+overhead {
		execution = floor - 20_000 - overhead
	}
	verification := g.VerificationFloor
	if len(op.InitCode) != 0 {
		verification = g.VerificationFloorInit
	}
	if verification > op.VerificationGasLimit {
		verification = op.VerificationGasLimit
	}
	pmVerification := g.PMVerificationFloor
	if pmVerification > op.PaymasterVerificationGasLimit {
		pmVerification = op.PaymasterVerificationGasLimit
	}
	actual := op.PreVerificationGas + verification + pmVerification + execution + overhead
	expected := gaslessChargeFor(g, kind, actual, execution, op.CallGasLimit, op.PaymasterPostOpGasLimit, payeeHasCode, payeeIsEmpty, feeNow)
	expected.Add(expected, flatFee)
	if maximum := new(big.Int).Add(op.maxCost(), flatFee); expected.Cmp(maximum) > 0 {
		expected = maximum
	}
	return expected
}

// gaslessPayeeAdvisory is design 3.1's advisory for a payout address with
// code, shown before proving and with the quote.
const gaslessPayeeAdvisory = "the payout address is a contract; it must accept ETH within 100,000 gas or the payout is credited in the paymaster for a later claim (withdraw --claim-credit), less the credit's gas"

// feeBumpBound is the most the fee may take from the payout after a
// re-sign of a dropped operation: the user's --fee-cap-gwei when one was
// given, else the quoted maximum (an approval without a cap never re-signs
// above what it approved).
func feeBumpBound(a gaslessAmounts, options addressWithdrawalOptions) *big.Int {
	if options.FeeCapGwei != 0 {
		return new(big.Int).Mul(new(big.Int).SetUint64(options.FeeCapGwei), big.NewInt(1_000_000_000))
	}
	return new(big.Int).Set(a.FeeCap)
}

// checkGaslessAmounts refuses a payout the fee would eat (payout_below_gas),
// or lose an uneconomic fraction of (gasless_uneconomic), and a fee above
// the user's cap.
func checkGaslessAmounts(a gaslessAmounts, kind uint8, live gaslessLive, percent uint64, options addressWithdrawalOptions) error {
	minimum := new(big.Int)
	if kind == gaslessKindEscape {
		minimum = live.MinEscapeNet
	}
	if a.MinimumReceived.Cmp(minimum) <= 0 || a.Payout.Sign() == 0 {
		return refuse("payout_below_gas", "the payout (%s wei) does not cover the sponsored fee (at most %s wei, plus %s wei owed); use --fees wallet", a.Payout, a.FeeCap, a.Owed)
	}
	if a.MaxCost.Cmp(live.MaxSponsoredCost) > 0 {
		return refuse("gasless_refused", "the operation's maximum cost %s wei is above the paymaster's policy of %s wei; use --fees wallet", a.MaxCost, live.MaxSponsoredCost)
	}
	if options.FeeCapGwei != 0 {
		// The cap bounds what the payout may lose: for a contract payout
		// address that includes the credit surcharge the paymaster takes
		// beyond the operation's maximum when the push fails.
		userCap := new(big.Int).Mul(new(big.Int).SetUint64(options.FeeCapGwei), big.NewInt(1_000_000_000))
		loss := new(big.Int).Set(a.FeeCap)
		if a.PayeeHasCode && a.CreditSurcharge != nil {
			loss.Add(loss, a.CreditSurcharge)
		}
		if loss.Cmp(userCap) > 0 {
			if loss.Cmp(a.FeeCap) > 0 {
				return refuse("fee_above_cap", "the payout may lose %s wei (the sponsored fee of at most %s wei and the %s wei credit surcharge of a contract payout address), above your --fee-cap-gwei of %d gwei", loss, a.FeeCap, a.CreditSurcharge, options.FeeCapGwei)
			}
			return refuse("fee_above_cap", "the sponsored fee may reach %s wei, above your --fee-cap-gwei of %d gwei", a.FeeCap, options.FeeCapGwei)
		}
	}
	if !options.AllowExpensiveGas && new(big.Int).Mul(a.FeeCap, big.NewInt(100)).Cmp(new(big.Int).Mul(a.Payout, new(big.Int).SetUint64(percent))) > 0 {
		return refuse("gasless_uneconomic", "the sponsored fee may reach %s wei, more than %d%% of the %s wei payout; pass --allow-expensive-gas to accept it, or use --fees wallet", a.FeeCap, percent, a.Payout)
	}
	return nil
}

// crossCheckQuote compares the local figures with the paymaster's quote()
// view: a disagreement disables the gasless path (gasless_policy_mismatch).
func (h *FundingHandler) crossCheckQuote(ctx context.Context, env *gaslessEnvironment, kind uint8, noteID uint32, nullifier *big.Int, op *gaslessUserOp, a gaslessAmounts, live gaslessLive) error {
	data := "0x" + selectorPaymasterQuote + uintWord(uint64(kind)) + addressABIWord(strings.ToLower(env.account.Hex())) + uintWord(uint64(noteID)) + addressABIWord(nullifier.Text(16)) + addressABIWord(a.MaxCost.Text(16)) + addressABIWord(op.MaxFeePerGas.Text(16))
	words, err := h.gaslessWords(ctx, env, env.paymaster, data, 6)
	if err != nil {
		return err
	}
	required := new(big.Int).Add(new(big.Int).Add(a.MaxCost, a.FlatFee), a.Owed)
	if kind == gaslessKindEscape {
		required.Add(required, a.FinalizeReserve)
		required.Add(required, live.MinEscapeNet)
		required.Add(required, a.FlatFee)
	}
	if words[0].Cmp(required) != 0 || words[1].Cmp(a.Owed) != 0 || words[2].Cmp(a.FlatFee) != 0 || words[3].Cmp(a.FinalizeReserve) != 0 {
		return refuse("gasless_policy_mismatch", "the paymaster's quote disagrees with the profile's gas policy; --fees payout is disabled until the profile is updated")
	}
	if words[4].Sign() == 0 {
		return refuse("gasless_attempts_exhausted", "this state used its sponsored attempts; use --fees wallet")
	}
	if kind == gaslessKindEscape && words[5].Sign() == 0 {
		return refuse("escapes_disabled", "the paymaster will not sponsor this escape (escapes disabled, the note already sponsored, or an open sponsored escape of this transit account); use --fees wallet")
	}
	return nil
}

// payeeState reads whether Y has code (the push forwards 100,000 gas and
// credits on failure) and whether it is empty (the push pays the new-account
// surcharge).
func (h *FundingHandler) payeeState(ctx context.Context, env *gaslessEnvironment) (hasCode, isEmpty bool, err error) {
	var code string
	if err := h.addressRPC(ctx, env.config, "eth_getCode", []any{env.payee.Hex(), "latest"}, &code); err != nil {
		return false, false, err
	}
	hasCode = code != "0x" && code != ""
	if hasCode {
		return true, false, nil
	}
	balance, err := h.addressQuantity(ctx, env.config, "eth_getBalance", []any{env.payee.Hex(), "latest"})
	if err != nil {
		return false, false, err
	}
	count, err := h.addressQuantity(ctx, env.config, "eth_getTransactionCount", []any{env.payee.Hex(), "latest"})
	if err != nil {
		return false, false, err
	}
	return false, balance.Sign() == 0 && count.Sign() == 0, nil
}

// --------------------------------------------------------------------- dry run

// dryRunGaslessOp simulates handleOps([op], owner) through the read RPC. A
// clean run returns nil; a FailedOp is returned decoded; another revert or
// a refusal to simulate is an error.
func (h *FundingHandler) dryRunGaslessOp(ctx context.Context, env *gaslessEnvironment, op *gaslessUserOp) (*aaFailure, error) {
	call := map[string]string{"from": env.owner.Hex(), "to": env.entryPoint.Hex(), "data": op.handleOpsCalldata(env.owner)}
	_, refused, err := h.addressRPCRaw(ctx, env.config, "eth_call", []any{call, "latest"})
	if err != nil {
		return nil, err
	}
	if refused == nil {
		return nil, nil
	}
	if failure, ok := decodeAAFailure(refused.revertData()); ok {
		return &failure, nil
	}
	return nil, refuse("gasless_refused", "the dry run of the sponsored operation was refused by the RPC (%s); use --fees wallet or retry", strings.TrimSpace(refused.Message))
}

// refusalOfFailure maps a dry run's FailedOp to a refusal (design 3.1).
func refusalOfFailure(f aaFailure) error {
	switch f.Code {
	case "AA31":
		return refuse("paymaster_underfunded", "the paymaster's deposit cannot cover this operation; retry later or use --fees wallet")
	case "AA32":
		return refuse("op_window", "the operation is outside its time window (a finalization before the challenge deadline, or an expired proof); rerun later")
	case "AA24":
		return refuse("wrong_owner_account", "the transit account refuses the saved owner key's signature; preserve the recovery file")
	}
	switch f.Inner {
	case "SponsorshipPaused":
		return refuse("sponsorship_paused", "the paymaster has paused sponsorship; use --fees wallet")
	case "AttemptsExhausted":
		return refuse("gasless_attempts_exhausted", "this state used its sponsored attempts; use --fees wallet")
	case "PayoutBelowCost":
		return refuse("payout_below_gas", "the paymaster finds the payout too small for the sponsored fee; use --fees wallet")
	case "ExitsPaused":
		return refuse("exits_paused", "the vault is paused; rerun once exits reopen")
	case "FeeAboveCeiling":
		return refuse("gas_above_paymaster_ceiling", "the operation's fees are above the paymaster's ceilings; request a fresh quote")
	case "EscapesDisabled", "EscapeAlreadySponsored", "EscapeEvidencePending":
		return refuse("escapes_disabled", "the paymaster will not sponsor this escape (%s); initiate it with --fees wallet", f.Inner)
	case "NoteNotActive", "NullifierUsed", "NotPendingEscape":
		return refuse("note_closed", "the vault no longer accepts this exit (%s): the note may have been closed by another transaction, with the payout in the transit account; run withdraw --collect", f.Inner)
	}
	return refuse("gasless_refused", "the sponsored operation would fail: %s; use --fees wallet", f.String())
}

// ----------------------------------------------------------- quote and submit

// gaslessPayout is the wei the operation of kind delivers to S: the
// close's or escape's final balance, the pending escape's payout, or what S
// holds (FORWARD).
func (h *FundingHandler) gaslessPayout(ctx context.Context, env *gaslessEnvironment, record *addressFundingRecord, kind uint8) (*big.Int, error) {
	w := record.Withdrawal
	switch kind {
	case gaslessKindClose, gaslessKindEscape:
		return new(big.Int).Mul(new(big.Int).SetUint64(w.Amount), big.NewInt(1_000_000_000)), nil
	case gaslessKindFinalize:
		pending, err := h.gaslessWords(ctx, env, env.vault, "0x"+selectorPendingWithdrawals+uintWord(w.NoteID), 6)
		if err != nil {
			return nil, err
		}
		if pending[0].Sign() == 0 || !strings.EqualFold(common.BigToAddress(pending[4]).Hex(), env.account.Hex()) {
			return nil, refuse("note_closed", "the vault shows no pending escape of this note paying the transit account; it may have been finalized by someone else (run withdraw --escape --to %s again to collect)", w.Destination)
		}
		return new(big.Int).Mul(pending[3], big.NewInt(1_000_000_000)), nil
	}
	return h.addressQuantity(ctx, env.config, "eth_getBalance", []any{env.account.Hex(), "latest"})
}

func gaslessBuiltPhase(kind uint8) string {
	switch kind {
	case gaslessKindFinalize:
		return "finalize_op_built"
	case gaslessKindForward:
		return "forward_op_built"
	}
	return "op_built"
}

func gaslessSubmittedPhase(kind uint8) string {
	switch kind {
	case gaslessKindFinalize:
		return "finalize_op_submitted"
	case gaslessKindForward:
		return "forward_op_submitted"
	}
	return "op_submitted"
}

// gaslessPendingPhase is the existing phase once the bundle transaction is
// known.
func gaslessPendingPhase(kind uint8) string {
	switch kind {
	case gaslessKindEscape:
		return "escape_pending"
	case gaslessKindFinalize:
		return "finalize_pending"
	case gaslessKindForward:
		return "forward_op_submitted"
	}
	return "withdrawal_pending"
}

// gaslessQuoteKind is the quote kind a record's operation is approved under.
func gaslessQuoteKind(w *addressWithdrawalRecord, kind uint8) string {
	if w.Mode == "escape" && kind != gaslessKindForward {
		if kind == gaslessKindEscape {
			return "escape"
		}
		return "escape_finalize"
	}
	return "withdrawal"
}

// submitUserOperation is the gasless counterpart of signAddressTransaction
// for an exit of kind with vaultCall (design 3.3): under a quote it builds
// the operation and quotes its figures; under an approval it rebuilds it
// with the approved fields, signs it, dry-runs it, journals it (op_built),
// sends it and journals the submission (op_submitted). It never signs a
// wallet transaction and never reports waiting_funds.
func (h *FundingHandler) submitUserOperation(ctx context.Context, config fundingConfig, record *addressFundingRecord, kind uint8, vaultCall []byte) error {
	w := record.Withdrawal
	mode := quoteMode(ctx)
	if mode == nil || (mode.Capture == nil && mode.Approval == nil) {
		return errors.New("review and approve a current payment quote before signing")
	}
	options := withdrawalOptions(ctx)
	if mode.Approval != nil {
		// The approval binds the choices the quote was made with (the
		// CLI's --approve carries no flags): the bundler the quote was
		// checked against, the fee cap and the acceptance of a fee above
		// the uneconomic fraction. Design 3.3: flag, then configuration,
		// then the profile, resolved once, at the quote.
		// An approval naming another bundler is not this quote's, and is
		// refused before that bundler is contacted.
		if options.BundlerURL != "" && options.BundlerURL != mode.Approval.BundlerURL {
			return errAddressQuoteChanged
		}
		if options.BundlerURL == "" && mode.Approval.BundlerURL != "" {
			if err := ValidateBundlerURL(mode.Approval.BundlerURL); err != nil {
				return errAddressQuoteChanged
			}
			options.BundlerURL = mode.Approval.BundlerURL
		}
		if options.FeeCapGwei == 0 {
			options.FeeCapGwei = mode.Approval.FeeCapGwei
		}
		options.AllowExpensiveGas = options.AllowExpensiveGas || mode.Approval.AllowExpensiveGas
	}
	env, err := h.gaslessEnvironment(ctx, config, record, options)
	if err != nil {
		return err
	}
	if err := env.needBundler(); err != nil {
		return err
	}
	if err := h.ensureGaslessChecked(ctx); err != nil {
		return err
	}
	if err := h.checkBundler(ctx, env); err != nil {
		return err
	}
	nullifier := new(big.Int)
	if kind != gaslessKindForward {
		if !isHex(w.Nullifier, 32) {
			return errors.New("the withdrawal has no nullifier yet")
		}
		nullifier.SetBytes(common.FromHex(w.Nullifier))
	}
	noteID := uint32(w.NoteID)
	key := gaslessKey(kind, nullifier, noteID, env.account)
	live, err := h.gaslessLive(ctx, env, kind, key)
	if err != nil {
		return err
	}
	if err := checkGaslessLive(live, kind, env.profile.GasPolicy); err != nil {
		return err
	}
	payout, err := h.gaslessPayout(ctx, env, record, kind)
	if err != nil {
		return err
	}
	var fixed *gaslessGasFields
	quoteKind := gaslessQuoteKind(w, kind)
	if mode.Approval != nil {
		if fixed, err = validateGaslessApproval(record, mode.Approval, quoteKind, kind, env.account.Hex(), env.bundler); err != nil {
			return err
		}
	}
	op, err := h.buildGaslessOp(ctx, env, kind, vaultCall, nullifier, live, fixed)
	if err != nil {
		return err
	}
	// The bundler's estimate is a cross-check of the limits, which never
	// follow it; its preVerificationGas, though, is what that bundler
	// requires to carry the operation (pure compensation, which the
	// paymaster does not measure), so a higher one within the cap is
	// adopted before the amounts are quoted, and bound at approval.
	adoptedPVG := uint64(0)
	if mode.Capture != nil {
		if estimate, err := h.estimateUserOperation(ctx, env, op); err != nil {
			return err
		} else if estimate != nil {
			if err := checkGaslessEstimate(*estimate, env.profile.GasPolicy, kind, live.CallCap); err != nil {
				return err
			}
			if estimate.PreVerificationGas > op.PreVerificationGas {
				adoptedPVG = estimate.PreVerificationGas
				op.PreVerificationGas = adoptedPVG
			}
		}
	}
	if live.Deposit.Cmp(op.maxCost()) < 0 {
		return refuse("paymaster_underfunded", "the paymaster's deposit (%s wei) cannot cover this operation's maximum cost (%s wei); retry later or use --fees wallet", live.Deposit, op.maxCost())
	}
	hasCode, isEmpty, err := h.payeeState(ctx, env)
	if err != nil {
		return err
	}
	amounts := gaslessAmountsFor(kind, payout, op, live, env.profile.GasPolicy, hasCode, isEmpty)
	if err := checkGaslessAmounts(amounts, kind, live, uint64(env.profile.UneconomicFractionPercent), options); err != nil {
		return err
	}
	if err := h.crossCheckQuote(ctx, env, kind, noteID, nullifier, op, amounts, live); err != nil {
		return err
	}
	hash := op.hash(env.entryPoint, env.config.ChainID)
	if remote, err := h.gaslessWord(ctx, env, env.entryPoint, op.getUserOpHashCalldata()); err != nil {
		return err
	} else if common.BigToHash(remote) != hash {
		return refuse("entry_point_hash_mismatch", "the EntryPoint hashes the operation differently than this client; nothing was signed")
	}
	if op.Signature, err = signUserOpHash(hash, env.key); err != nil {
		return err
	}
	// The dry run, with one rebuild for a stale nonce (AA25) or an account
	// another transaction created meanwhile (AA10).
	for attempt := 0; ; attempt++ {
		failure, err := h.dryRunGaslessOp(ctx, env, op)
		if err != nil {
			return err
		}
		if failure == nil {
			break
		}
		if attempt == 0 && (failure.Code == "AA25" || failure.Code == "AA10") {
			if fixed != nil {
				fixed.InitCode = fixed.InitCode && failure.Code != "AA10"
			}
			if op, err = h.buildGaslessOp(ctx, env, kind, vaultCall, nullifier, live, fixed); err != nil {
				return err
			}
			if failure.Code == "AA10" {
				op.InitCode = nil
			}
			if op.PreVerificationGas < adoptedPVG {
				op.PreVerificationGas = adoptedPVG
			}
			hash = op.hash(env.entryPoint, env.config.ChainID)
			if op.Signature, err = signUserOpHash(hash, env.key); err != nil {
				return err
			}
			continue
		}
		return refusalOfFailure(*failure)
	}
	if mode.Capture != nil {
		quote, err := h.saveGaslessQuote(record, quoteKind, kind, op, amounts, env, options)
		if err != nil {
			return err
		}
		*mode.Capture = quote
		return nil
	}
	encoded, err := json.Marshal(op.toJSON())
	if err != nil {
		return errors.New("cannot encode the user operation")
	}
	// The bound a re-signed copy must respect is journaled with the
	// operation, so a resume from a fresh process enforces it: the one the
	// approved quote showed, tightened by a cap given with the approval.
	bound := feeBumpBound(amounts, options)
	if approved, ok := new(big.Int).SetString(mode.Approval.FeeBumpCapWei, 10); ok && approved.Sign() > 0 && approved.Cmp(bound) < 0 {
		bound = approved
	}
	w.UserOp = &addressUserOp{Kind: gaslessKindNames[kind], JSON: encoded, Hash: hash.Hex(), Nonce: op.Nonce.String(), InitCode: len(op.InitCode) != 0, BundlerURL: env.bundler, BuiltAt: time.Now().Unix(), FeeCapWei: bound.String(), FeeCapGwei: options.FeeCapGwei, AllowExpensiveGas: options.AllowExpensiveGas}
	if kind == gaslessKindClose || kind == gaslessKindEscape {
		w.UserOp.ValidUntil = validUntilOfVaultCall(vaultCall)
	}
	w.Phase, w.GaslessRefusal = gaslessBuiltPhase(kind), ""
	if w.StartBlock == 0 {
		w.StartBlock = h.latestBlock(ctx, env.config)
	}
	record.Quote = nil
	if err := h.saveAddress(record); err != nil {
		return err
	}
	return h.sendUserOperation(ctx, env, record)
}

// validUntilOfVaultCall is word 15 of an 836-byte exit call, 0 otherwise.
func validUntilOfVaultCall(vaultCall []byte) uint64 {
	if len(vaultCall) != withdrawalCalldataLength {
		return 0
	}
	value := new(big.Int).SetBytes(vaultCall[4+15*32 : 4+16*32])
	if !value.IsUint64() {
		return 0
	}
	return value.Uint64()
}

// estimateUserOperation asks the bundler's estimate with maxFeePerGas 0
// (the paymaster's estimation convention); nil when the bundler declines.
func (h *FundingHandler) estimateUserOperation(ctx context.Context, env *gaslessEnvironment, op *gaslessUserOp) (*GaslessQuoteGas, error) {
	probe := *op
	probe.MaxFeePerGas, probe.MaxPriorityFeePerGas, probe.Signature = new(big.Int), new(big.Int), make([]byte, 65)
	result, refused, err := h.bundlerCall(ctx, env.bundler, "eth_estimateUserOperationGas", []any{probe.toJSON(), env.entryPoint.Hex()})
	if err != nil {
		return nil, refuse("bundler_unavailable", "the bundler %s did not answer the gas estimate", env.bundler)
	}
	if refused != nil {
		return nil, nil
	}
	var estimate struct {
		PreVerificationGas            string `json:"preVerificationGas"`
		VerificationGasLimit          string `json:"verificationGasLimit"`
		CallGasLimit                  string `json:"callGasLimit"`
		PaymasterVerificationGasLimit string `json:"paymasterVerificationGasLimit"`
		PaymasterPostOpGasLimit       string `json:"paymasterPostOpGasLimit"`
	}
	if json.Unmarshal(result, &estimate) != nil {
		return nil, nil
	}
	parse := func(value string) uint64 {
		n, err := feeQuantity(value)
		if err != nil || !n.IsUint64() {
			return 0
		}
		return n.Uint64()
	}
	return &GaslessQuoteGas{PreVerificationGas: parse(estimate.PreVerificationGas), VerificationGasLimit: parse(estimate.VerificationGasLimit), CallGasLimit: parse(estimate.CallGasLimit), PaymasterVerificationGasLimit: parse(estimate.PaymasterVerificationGasLimit), PaymasterPostOpGasLimit: parse(estimate.PaymasterPostOpGasLimit)}, nil
}

// checkGaslessEstimate refuses a bundler whose estimate exceeds a cap: the
// signed limits never follow an estimate, so one above a cap means the
// bundler is suspect (gasless_estimate_above_cap).
func checkGaslessEstimate(estimate GaslessQuoteGas, g gaslessGasPolicy, kind uint8, callCap uint64) error {
	if estimate.CallGasLimit > callCap || estimate.VerificationGasLimit > g.VerificationCap || estimate.PreVerificationGas > g.PVGCap || estimate.PaymasterVerificationGasLimit > g.PMVerificationCap || estimate.PaymasterPostOpGasLimit > g.PostOpCap {
		return refuse("gasless_estimate_above_cap", "the bundler estimates gas above the paymaster's caps; it cannot be trusted, use another --bundler-url or --fees wallet")
	}
	return nil
}

// saveGaslessQuote journals a payout quote: the figures of design 3.3, the
// operation's gas fields and the choices the quote was made with (the fee
// cap, the bound on a re-signed copy, the expensive-gas acceptance), bound
// at approval.
func (h *FundingHandler) saveGaslessQuote(record *addressFundingRecord, quoteKind string, kind uint8, op *gaslessUserOp, a gaslessAmounts, env *gaslessEnvironment, options addressWithdrawalOptions) (AddressPaymentQuote, error) {
	w := record.Withdrawal
	id, err := quoteID()
	if err != nil {
		return AddressPaymentQuote{}, err
	}
	total := op.PreVerificationGas + op.VerificationGasLimit + op.CallGasLimit + op.PaymasterVerificationGasLimit + op.PaymasterPostOpGasLimit
	q := AddressPaymentQuote{
		ID: id, Kind: quoteKind, Address: record.Address, ChainID: record.ChainID, Contract: record.Contract, DeploymentID: record.DeploymentID,
		Amount: w.Amount, Destination: w.Destination, NoteID: w.NoteID, Binding: w.Binding,
		PrincipalWei: "0", BalanceWei: "0", ExpectedFeeWei: a.ExpectedFee.String(), RequiredFeeWei: a.FeeCap.String(), FeeReserveWei: a.FeeCap.String(), FeeBufferWei: "0",
		RequiredTotalWei: "0", RecommendedTotalWei: "0", ShortfallWei: "0", RecommendedTopUpWei: "0", EstimatedGas: total, GasLimit: total,
		MaxFeePerGas: op.MaxFeePerGas.String(), MaxPriorityFeePerGas: op.MaxPriorityFeePerGas.String(), FeePolicy: "payout", ExpiresAt: time.Now().Add(gaslessQuoteLifetime).UnixMilli(),
		UserOpKind: gaslessKindNames[kind], UserOpNonce: op.Nonce.String(), TransitAccount: env.account.Hex(), BundlerURL: env.bundler,
		FeeCapWei: a.FeeCap.String(), FlatFeeWei: a.FlatFee.String(), PayoutWei: a.Payout.String(), MinimumReceivedWei: a.MinimumReceived.String(), OwedWei: a.Owed.String(), FinalizeReserveWei: a.FinalizeReserve.String(),
		FeeBumpCapWei: feeBumpBound(a, options).String(), FeeCapGwei: options.FeeCapGwei, AllowExpensiveGas: options.AllowExpensiveGas,
		UserOpGas: &GaslessQuoteGas{CallGasLimit: op.CallGasLimit, VerificationGasLimit: op.VerificationGasLimit, PreVerificationGas: op.PreVerificationGas, PaymasterVerificationGasLimit: op.PaymasterVerificationGasLimit, PaymasterPostOpGasLimit: op.PaymasterPostOpGasLimit, InitCode: len(op.InitCode) != 0},
	}
	if a.PayeeHasCode {
		q.PayeeHasCode, q.CreditSurchargeWei = true, a.CreditSurcharge.String()
		q.Warnings = append(q.Warnings, gaslessPayeeAdvisory)
	}
	if kind == gaslessKindEscape {
		// No floor is promised for the payout of an escape initiation: its
		// finalization is quoted later at its own fees.
		q.MinimumReceivedWei = ""
		q.FinalizeEstimateWei, q.EstimatedReceivedWei = a.FinalizeEstimate.String(), a.EstimatedReceived.String()
	}
	if w.Mode == "escape" {
		q.Amount = w.Amount
		if w.Payout != 0 {
			q.Amount = w.Payout
		}
	}
	record.Quote = &q
	if err := h.saveAddress(record); err != nil {
		return AddressPaymentQuote{}, err
	}
	return q, nil
}

// gaslessQuoteLifetime is a payout quote's validity: the fees it binds are
// the operation's own, so it may live longer than a wallet quote.
const gaslessQuoteLifetime = 2 * time.Minute

// validateGaslessApproval binds an approval to the saved payout quote the
// way validatePaymentApproval binds a wallet quote: the same note, amount,
// binding, payout address, transit account, operation kind and bundler
// (the one the quote was checked against is the one the signed operation
// goes to); the gas fields and fees it carries are the ones signed.
func validateGaslessApproval(record *addressFundingRecord, q *AddressPaymentQuote, quoteKind string, kind uint8, transit, bundler string) (*gaslessGasFields, error) {
	w := record.Withdrawal
	if q == nil || record.Quote == nil || record.Quote.ID != q.ID || q.FeePolicy != "payout" || q.Kind != quoteKind || q.ExpiresAt <= time.Now().UnixMilli() || q.DeploymentID != record.DeploymentID || q.ChainID != record.ChainID || !strings.EqualFold(q.Address, record.Address) || !strings.EqualFold(q.Contract, record.Contract) {
		return nil, errAddressQuoteChanged
	}
	if q.BundlerURL == "" || q.BundlerURL != bundler {
		return nil, errAddressQuoteChanged
	}
	if w == nil || q.NoteID != w.NoteID || q.Binding != w.Binding || !strings.EqualFold(q.Destination, w.Destination) || !strings.EqualFold(q.TransitAccount, transit) || q.UserOpKind != gaslessKindNames[kind] || q.UserOpGas == nil {
		return nil, errAddressQuoteChanged
	}
	if kind != gaslessKindForward && q.Amount != w.Amount && q.Amount != w.Payout {
		return nil, errAddressQuoteChanged
	}
	maxFee, ok1 := new(big.Int).SetString(q.MaxFeePerGas, 10)
	priority, ok2 := new(big.Int).SetString(q.MaxPriorityFeePerGas, 10)
	flatFee, ok3 := new(big.Int).SetString(q.FlatFeeWei, 10)
	if !ok1 || !ok2 || !ok3 || maxFee.Sign() <= 0 || priority.Sign() < 0 || flatFee.Sign() < 0 || maxFee.BitLen() > 128 || flatFee.BitLen() > 96 {
		return nil, errAddressQuoteChanged
	}
	g := q.UserOpGas
	return &gaslessGasFields{Call: g.CallGasLimit, Verification: g.VerificationGasLimit, PVG: g.PreVerificationGas, PMVerification: g.PaymasterVerificationGasLimit, PostOp: g.PaymasterPostOpGasLimit, MaxFee: maxFee, Priority: priority, FeeCap: flatFee, InitCode: g.InitCode}, nil
}

// sendUserOperation sends the journaled operation to the bundler and
// journals the submission. A bundler that answers another hash is noted
// (ambiguous: recovery continues by chain logs under the local hash); a
// bundler that refuses the operation leaves the record gasless_refused with
// the reason (a FORWARD's leaves it complete with the payout waiting, see
// stopUserOperation); one that does not answer leaves the operation
// op_built, to be re-sent on the next resume.
func (h *FundingHandler) sendUserOperation(ctx context.Context, env *gaslessEnvironment, record *addressFundingRecord) error {
	w := record.Withdrawal
	u := w.UserOp
	kind := gaslessKindOf(u.Kind)
	result, refused, err := h.bundlerCall(ctx, env.bundler, "eth_sendUserOperation", []any{json.RawMessage(u.JSON), env.entryPoint.Hex()})
	if err != nil {
		return nil
	}
	if refused != nil {
		message := strings.TrimSpace(refused.Message)
		switch {
		case bundlerHoldsOperation(refused):
			// The bundler holds it already (a re-send after a lost answer).
			result, _ = json.Marshal(u.Hash)
		case bundlerRefusedAA10(refused) && u.InitCode:
			// Someone created the transit account meanwhile (its factory is
			// permissionless): the operation is rebuilt without initCode,
			// as the dry run does, and sent once more.
			sent := u.Hash
			if err := h.resignUserOperation(ctx, env, record, func(op *gaslessUserOp) { op.InitCode = nil }); err != nil {
				return err
			}
			if u.Hash == sent {
				// Stopped with its reason, or the nonce is gone: journaled.
				return nil
			}
			return h.sendUserOperation(ctx, env, record)
		default:
			reason := "bundler_refused: " + message
			if failure, ok := decodeAAFailure(refused.revertData()); ok {
				reason = GaslessRefusalCode(refusalOfFailure(failure)) + ": " + failure.String()
			}
			stopUserOperation(w, reason)
			return h.saveAddress(record)
		}
	}
	var returned string
	if json.Unmarshal(result, &returned) != nil || !isHex(returned, 32) || !strings.EqualFold(returned, u.Hash) {
		u.Ambiguous = true
	}
	listed := false
	for _, hash := range u.Hashes {
		listed = listed || strings.EqualFold(hash, u.Hash)
	}
	if !listed {
		u.Hashes = append(u.Hashes, u.Hash)
	}
	u.SubmittedAt = time.Now().Unix()
	if u.SubmittedAtBlock == 0 {
		u.SubmittedAtBlock = h.latestBlock(ctx, env.config)
	}
	w.Phase = gaslessSubmittedPhase(kind)
	return h.saveAddress(record)
}

// bundlerHoldsOperation reports a refusal of eth_sendUserOperation that
// says the bundler holds the operation already: only an explicit duplicate
// answer, never a validation failure (an EntryPoint FailedOp in the data,
// or an AA code in the message, such as "AA10 sender already constructed").
func bundlerHoldsOperation(refused *rpcError) bool {
	if _, ok := decodeAAFailure(refused.revertData()); ok {
		return false
	}
	message := strings.ToLower(refused.Message)
	if aaCodeInMessage.MatchString(message) {
		return false
	}
	for _, phrase := range []string{"already known", "already in mempool", "already in the mempool"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

// bundlerRefusedAA10 reports a refusal for an initCode whose sender exists.
func bundlerRefusedAA10(refused *rpcError) bool {
	if failure, ok := decodeAAFailure(refused.revertData()); ok {
		return failure.Code == "AA10"
	}
	return strings.Contains(strings.ToLower(refused.Message), "aa10")
}

var aaCodeInMessage = regexp.MustCompile(`\baa[0-9]{2}\b`)

// stopUserOperation stops the journaled operation with its reason (a
// refused send, a refused re-signed copy, a re-sign the approval does not
// allow, a consumed nonce, an expired proof). A close, an escape or a
// finalization leaves the record gasless_refused. A FORWARD delivers the
// payout of a note that is closed already: its record stays complete with
// the payout waiting in the transit account (--collect again, or --sweep),
// never gasless_refused, which would treat the closed note as one to prove
// again. Either way the operation and its hashes stay journaled, so a late
// inclusion is still found (lateUserOperation).
func stopUserOperation(w *addressWithdrawalRecord, reason string) {
	w.Phase, w.GaslessRefusal = "gasless_refused", reason
	if w.UserOp != nil && gaslessKindOf(w.UserOp.Kind) == gaslessKindForward {
		w.Phase, w.FundsWaitingInTransit = "complete", true
	}
}

// resignUserOperation re-signs the journaled operation after change (higher
// fees, initCode dropped), dry-runs it and journals it (the new hash beside
// the earlier ones, not yet sent) before anyone sends it. A dry run that
// finds the transit account created meanwhile (AA10) drops initCode first;
// one that finds the nonce consumed (AA25: an earlier copy, or another
// operation, was included) leaves the journal to the nonce check of the
// next resume; any other failure stops the record with its reason, as a
// refused send does.
func (h *FundingHandler) resignUserOperation(ctx context.Context, env *gaslessEnvironment, record *addressFundingRecord, change func(*gaslessUserOp)) error {
	w := record.Withdrawal
	u := w.UserOp
	var encoded gaslessUserOpJSON
	if json.Unmarshal(u.JSON, &encoded) != nil {
		return errors.New("the saved user operation is invalid; preserve the recovery file")
	}
	op, err := gaslessUserOpFromJSON(encoded)
	if err != nil {
		return err
	}
	change(op)
	for attempt := 0; ; attempt++ {
		hash := op.hash(env.entryPoint, env.config.ChainID)
		if op.Signature, err = signUserOpHash(hash, env.key); err != nil {
			return err
		}
		failure, err := h.dryRunGaslessOp(ctx, env, op)
		if err != nil {
			return err
		}
		if failure == nil {
			break
		}
		if attempt == 0 && failure.Code == "AA10" && len(op.InitCode) != 0 {
			op.InitCode = nil
			continue
		}
		if failure.Code == "AA25" {
			// The nonce is gone: nothing is re-signed; the resume looks for
			// the operation that took it.
			u.SubmittedAt = 0
			return h.saveAddress(record)
		}
		stopUserOperation(w, GaslessRefusalCode(refusalOfFailure(*failure))+": "+failure.String())
		return h.saveAddress(record)
	}
	reencoded, err := json.Marshal(op.toJSON())
	if err != nil {
		return errors.New("cannot encode the user operation")
	}
	hash := op.hash(env.entryPoint, env.config.ChainID)
	u.JSON, u.Hash, u.InitCode = reencoded, hash.Hex(), len(op.InitCode) != 0
	u.listHash(hash.Hex())
	u.SubmittedAt = 0
	return h.saveAddress(record)
}

// ---------------------------------------------------------------------- follow

// gaslessOutcome is what a follow found: the operation's bundle
// transaction once final, with its success and its receipt.
type gaslessOutcome struct {
	Included bool
	Success  bool
	Hash     string
	Receipt  *addressReceipt
	Revert   string
}

// userOperationLog is a UserOperationEvent read through eth_getLogs.
type userOperationLog struct {
	TransactionHash string   `json:"transactionHash"`
	Topics          []string `json:"topics"`
	Data            string   `json:"data"`
	Removed         bool     `json:"removed"`
}

// findUserOperationEvent looks for the EntryPoint's UserOperationEvent of
// one of hashes from block; "" when none is on chain yet.
func (h *FundingHandler) findUserOperationEvent(ctx context.Context, env *gaslessEnvironment, hashes []string, from uint64) (string, error) {
	var logs []userOperationLog
	for _, hash := range hashes {
		filter := map[string]any{"address": env.entryPoint.Hex(), "fromBlock": fmt.Sprintf("0x%x", from), "toBlock": "latest", "topics": []any{userOperationEventTopic, hash}}
		if err := h.addressRPC(ctx, env.config, "eth_getLogs", []any{filter}, &logs); err != nil {
			return "", err
		}
		for _, log := range logs {
			if !log.Removed && isHex(log.TransactionHash, 32) && len(log.Topics) == 4 && strings.EqualFold(log.Topics[1], hash) {
				return log.TransactionHash, nil
			}
		}
	}
	return "", nil
}

// findUserOperationByNonce looks for a UserOperationEvent of the transit
// account under the paymaster with the operation's nonce (an ambiguous
// submission whose hash the bundler answered differently).
func (h *FundingHandler) findUserOperationByNonce(ctx context.Context, env *gaslessEnvironment, nonce *big.Int, from uint64) (string, string, error) {
	var logs []userOperationLog
	filter := map[string]any{"address": env.entryPoint.Hex(), "fromBlock": fmt.Sprintf("0x%x", from), "toBlock": "latest", "topics": []any{userOperationEventTopic, nil, "0x" + addressABIWord(strings.ToLower(env.account.Hex())), "0x" + addressABIWord(strings.ToLower(env.paymaster.Hex()))}}
	if err := h.addressRPC(ctx, env.config, "eth_getLogs", []any{filter}, &logs); err != nil {
		return "", "", err
	}
	for _, log := range logs {
		if log.Removed || !isHex(log.TransactionHash, 32) || len(log.Topics) != 4 || !isHex(log.Data, 128) {
			continue
		}
		if new(big.Int).SetBytes(common.FromHex(log.Data[2:66])).Cmp(nonce) == 0 {
			return log.TransactionHash, log.Topics[1], nil
		}
	}
	return "", "", nil
}

// parseUserOperationEvent finds the UserOperationEvent of one of hashes in
// receipt: the hash, whether it succeeded and its actual gas cost.
func parseUserOperationEvent(receipt *addressReceipt, entryPoint common.Address, hashes []string) (hash string, success bool, actualGasCost *big.Int, found bool) {
	for _, log := range receipt.Logs {
		if log.Removed || !strings.EqualFold(log.Address, entryPoint.Hex()) || len(log.Topics) != 4 || !strings.EqualFold(log.Topics[0], userOperationEventTopic) || !isHex(log.Data, 128) {
			continue
		}
		for _, candidate := range hashes {
			if strings.EqualFold(log.Topics[1], candidate) {
				data := log.Data[2:]
				return log.Topics[1], new(big.Int).SetBytes(common.FromHex(data[64:128])).Sign() != 0, new(big.Int).SetBytes(common.FromHex(data[128:192])), true
			}
		}
	}
	return "", false, nil, false
}

// parseUserOperationRevertReason names the revert of hash in receipt.
func parseUserOperationRevertReason(receipt *addressReceipt, entryPoint common.Address, hash string) string {
	for _, log := range receipt.Logs {
		if log.Removed || !strings.EqualFold(log.Address, entryPoint.Hex()) || len(log.Topics) != 3 || !strings.EqualFold(log.Topics[0], userOperationRevertReasonTopic) || !strings.EqualFold(log.Topics[1], hash) {
			continue
		}
		data := common.FromHex(log.Data)
		if reason, ok := abiBytesAt(data, 1); ok {
			return gaslessErrorName(reason)
		}
	}
	return "reverted"
}

// paymasterSettlement is what the paymaster's logs in a receipt say about
// the transit account: Settled (received, charged, owedPaid, paidOut),
// PayoutCredited for the payee, or SponsorshipFailed.
type paymasterSettlement struct {
	Found                                bool
	Kind                                 uint8
	Received, Charged, OwedPaid, PaidOut *big.Int
	Credited                             *big.Int
	Failed                               bool
}

func parsePaymasterSettlement(receipt *addressReceipt, paymaster, sender, payee common.Address) paymasterSettlement {
	s := paymasterSettlement{Received: new(big.Int), Charged: new(big.Int), OwedPaid: new(big.Int), PaidOut: new(big.Int)}
	senderTopic, payeeTopic := "0x"+addressABIWord(strings.ToLower(sender.Hex())), "0x"+addressABIWord(strings.ToLower(payee.Hex()))
	word := func(data string, i int) *big.Int {
		return new(big.Int).SetBytes(common.FromHex(data[2+i*64 : 2+(i+1)*64]))
	}
	for _, log := range receipt.Logs {
		if log.Removed || !strings.EqualFold(log.Address, paymaster.Hex()) || len(log.Topics) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(log.Topics[0], paymasterSettledTopic) && len(log.Topics) == 4 && strings.EqualFold(log.Topics[2], senderTopic) && isHex(log.Data, 192):
			s.Found, s.Kind = true, uint8(word(log.Data, 0).Uint64())
			s.Received, s.Charged, s.OwedPaid, s.PaidOut = word(log.Data, 2), word(log.Data, 3), word(log.Data, 4), word(log.Data, 5)
		case strings.EqualFold(log.Topics[0], paymasterPayoutCreditedTopic) && len(log.Topics) == 2 && strings.EqualFold(log.Topics[1], payeeTopic) && isHex(log.Data, 32):
			s.Credited = word(log.Data, 0)
		case strings.EqualFold(log.Topics[0], paymasterSponsorshipFailedTopic) && len(log.Topics) == 3 && strings.EqualFold(log.Topics[2], senderTopic):
			s.Failed = true
		}
	}
	return s
}

// parseCollected reads the paymaster's Collected of the transit account in
// a sweep receipt: received, owedPaid, paidOut.
func parseCollected(receipt *addressReceipt, paymaster, sender common.Address) (received, owedPaid, paidOut *big.Int, found bool) {
	senderTopic := "0x" + addressABIWord(strings.ToLower(sender.Hex()))
	for _, log := range receipt.Logs {
		if log.Removed || !strings.EqualFold(log.Address, paymaster.Hex()) || len(log.Topics) != 3 || !strings.EqualFold(log.Topics[0], paymasterCollectedTopic) || !strings.EqualFold(log.Topics[1], senderTopic) || !isHex(log.Data, 96) {
			continue
		}
		data := log.Data[2:]
		return new(big.Int).SetBytes(common.FromHex(data[:64])), new(big.Int).SetBytes(common.FromHex(data[64:128])), new(big.Int).SetBytes(common.FromHex(data[128:])), true
	}
	return nil, nil, nil, false
}

// followUserOperation follows the saved operation (design 3.3), mirroring
// followEscapeTransaction: the bundle transaction is looked for on chain by
// the operation's hashes (authoritative) and through the bundler's receipt
// (a hint whose transaction must carry the event), the real receipt comes
// from eth_getTransactionReceipt and needs finality, an operation never
// sent (op_built) is re-sent as identical bytes, one the bundler forgot is
// re-sent or re-signed with fees raised an eighth, every hash journaled,
// and one whose proof is about to expire is abandoned 60 s before.
func (h *FundingHandler) followUserOperation(ctx context.Context, config fundingConfig, record *addressFundingRecord) (*gaslessOutcome, error) {
	w := record.Withdrawal
	u := w.UserOp
	if u == nil {
		return nil, errors.New("no user operation is saved")
	}
	env, err := h.followEnvironment(ctx, config, record)
	if err != nil {
		return nil, err
	}
	if !env.journaled {
		if err := env.needBundler(); err != nil {
			return nil, err
		}
	}
	var encoded gaslessUserOpJSON
	if json.Unmarshal(u.JSON, &encoded) != nil {
		return nil, errors.New("the saved user operation is invalid; preserve the recovery file")
	}
	op, err := gaslessUserOpFromJSON(encoded)
	if err != nil {
		return nil, err
	}
	kind := gaslessKindOf(u.Kind)
	hashes := append([]string{}, u.Hashes...)
	if len(hashes) == 0 {
		hashes = []string{u.Hash}
	}
	from := u.SubmittedAtBlock
	if from == 0 {
		from = w.StartBlock
	}
	if from == 0 {
		from = env.deployment.DeployBlock
	}
	tx := u.TransactionHash
	if tx == "" {
		if tx, err = h.findUserOperationEvent(ctx, env, hashes, from); err != nil {
			return nil, err
		}
	}
	if tx == "" && u.SubmittedAt != 0 && env.bundler != "" {
		// The bundler's receipt names a transaction; only the chain decides.
		for _, hash := range hashes {
			result, refused, err := h.bundlerCall(ctx, env.bundler, "eth_getUserOperationReceipt", []any{hash})
			if err != nil || refused != nil {
				continue
			}
			var receipt struct {
				Receipt struct {
					TransactionHash string `json:"transactionHash"`
				} `json:"receipt"`
			}
			if json.Unmarshal(result, &receipt) == nil && isHex(receipt.Receipt.TransactionHash, 32) {
				if candidate, _, err := h.addressFinalReceipt(ctx, env.config, receipt.Receipt.TransactionHash, false); err == nil && candidate != nil {
					if _, _, _, found := parseUserOperationEvent(candidate, env.entryPoint, hashes); found {
						tx = receipt.Receipt.TransactionHash
					}
				}
			}
		}
	}
	if tx == "" && u.Ambiguous {
		candidate, included, err := h.findUserOperationByNonce(ctx, env, op.Nonce, from)
		if err != nil {
			return nil, err
		}
		if candidate != "" {
			tx, hashes = candidate, append(hashes, included)
			u.listHash(included)
		}
	}
	if tx != "" {
		receipt, final, err := h.addressFinalReceipt(ctx, env.config, tx, true)
		if err != nil {
			return nil, err
		}
		if receipt == nil {
			// Reorganized away: look again next time.
			u.TransactionHash, u.IncludedHash = "", ""
			return &gaslessOutcome{}, h.saveAddress(record)
		}
		hash, success, _, found := parseUserOperationEvent(receipt, env.entryPoint, hashes)
		if !found {
			u.TransactionHash, u.IncludedHash = "", ""
			return &gaslessOutcome{}, h.saveAddress(record)
		}
		if u.TransactionHash == "" {
			u.TransactionHash, u.IncludedHash = strings.ToLower(tx), hash
			u.listHash(hash)
			w.Phase = gaslessPendingPhase(kind)
			if kind != gaslessKindForward {
				// A forward delivers a closed note's payout: the record's
				// transaction stays the exit's (the forward's is the
				// operation's own, and CollectHashes once settled).
				w.TransactionHash = strings.ToLower(tx)
			}
			if err := h.saveAddress(record); err != nil {
				return nil, err
			}
		}
		if !final {
			return &gaslessOutcome{Hash: tx}, nil
		}
		if success {
			return &gaslessOutcome{Included: true, Success: true, Hash: tx, Receipt: receipt}, nil
		}
		u.Revert = parseUserOperationRevertReason(receipt, env.entryPoint, hash)
		w.Phase = "op_reverted"
		if settlement := parsePaymasterSettlement(receipt, env.paymaster, env.account, env.payee); settlement.Credited != nil {
			w.PayoutCredited, w.PaymasterCredited = true, true
		}
		return &gaslessOutcome{Included: true, Hash: tx, Receipt: receipt, Revert: u.Revert}, h.saveAddress(record)
	}
	now := time.Now().Unix()
	if u.ValidUntil != 0 && now >= int64(u.ValidUntil)-int64(gaslessExpiryMargin/time.Second) {
		stopUserOperation(w, "op_expired: the proof's lifetime ran out before the operation was included; rerun --to to prove again (a late inclusion fails harmlessly)")
		return &gaslessOutcome{}, h.saveAddress(record)
	}
	if env.journaled {
		// The current profile no longer sponsors this record: the operation
		// is not re-sent nor re-signed. It is given the time a bundler
		// takes to include it, then released, so the wallet-paid recovery
		// can proceed; a later inclusion is still looked for before a
		// wallet-paid step (lateUserOperation) and otherwise fails
		// harmlessly (the note's nullifier, or the escape's finalization,
		// is spent once).
		last := u.SubmittedAt
		if u.BuiltAt > last {
			last = u.BuiltAt
		}
		if now-last < int64(gaslessResendAfter/time.Second) {
			return &gaslessOutcome{}, nil
		}
		stopUserOperation(w, GaslessRecordNotPinned+": "+releasedOperationReason(w))
		return &gaslessOutcome{}, h.saveAddress(record)
	}
	if u.SubmittedAt == 0 {
		// Never sent, or the answer was lost: unless its nonce was consumed,
		// the identical bytes are re-sent.
		nonce, err := h.gaslessWord(ctx, env, env.entryPoint, "0x"+selectorGetNonce+addressABIWord(strings.ToLower(env.account.Hex()))+addressABIWord(new(big.Int).Rsh(op.Nonce, 64).Text(16)))
		if err != nil {
			return nil, err
		}
		if nonce.Cmp(op.Nonce) > 0 {
			candidate, included, err := h.findUserOperationByNonce(ctx, env, op.Nonce, from)
			if err != nil {
				return nil, err
			}
			if candidate == "" {
				stopUserOperation(w, "nonce_consumed: another operation of the transit account took this nonce; rerun --to")
				return &gaslessOutcome{}, h.saveAddress(record)
			}
			u.listHash(included)
			u.Ambiguous = true
			return &gaslessOutcome{}, h.saveAddress(record)
		}
		return &gaslessOutcome{}, h.sendUserOperation(ctx, env, record)
	}
	if now-u.SubmittedAt < int64(gaslessResendAfter/time.Second) {
		return &gaslessOutcome{}, nil
	}
	// Five minutes without inclusion: ask the bundler; a forgotten operation
	// is re-sent; a refused re-send is re-signed with higher fees.
	result, refused, err := h.bundlerCall(ctx, env.bundler, "eth_getUserOperationByHash", []any{u.Hash})
	if err == nil && refused == nil && string(result) != "null" && len(result) != 0 {
		u.SubmittedAt = now
		return &gaslessOutcome{}, h.saveAddress(record)
	}
	_, refused, err = h.bundlerCall(ctx, env.bundler, "eth_sendUserOperation", []any{json.RawMessage(u.JSON), env.entryPoint.Hex()})
	if err != nil {
		return &gaslessOutcome{}, nil
	}
	if refused == nil {
		u.SubmittedAt = now
		return &gaslessOutcome{}, h.saveAddress(record)
	}
	if bundlerHoldsOperation(refused) {
		u.SubmittedAt = now
		return &gaslessOutcome{}, h.saveAddress(record)
	}
	if bundlerRefusedAA10(refused) && u.InitCode {
		// The transit account was created meanwhile: the same operation
		// without initCode, dry-run first, at the same fees.
		sent := u.Hash
		if err := h.resignUserOperation(ctx, env, record, func(op *gaslessUserOp) { op.InitCode = nil }); err != nil {
			return nil, err
		}
		if u.Hash == sent {
			return &gaslessOutcome{}, nil
		}
		return &gaslessOutcome{}, h.sendUserOperation(ctx, env, record)
	}
	return &gaslessOutcome{}, h.bumpUserOperationFees(ctx, env, record, op)
}

// bumpUserOperationFees re-signs an operation the bundler dropped for its
// fees with both fee fields raised an eighth, journals the new hash beside
// the old ones and sends it. The raise stays within the paymaster's
// ceilings (at them it waits) and within what the approval allowed (design
// 3.3: the approval binds the fees): the journaled bound on the fee (the
// user's --fee-cap-gwei, else the approved maximum), the payout's floor,
// the uneconomic fraction, and the paymaster's policy and deposit. A raise
// beyond them is not signed: the record stops as gasless_refused
// (fee_bump_needs_quote) and the next run quotes again at the current
// fees; a forward keeps its complete record, with the payout waiting.
func (h *FundingHandler) bumpUserOperationFees(ctx context.Context, env *gaslessEnvironment, record *addressFundingRecord, op *gaslessUserOp) error {
	w := record.Withdrawal
	u := w.UserOp
	kind := gaslessKindOf(u.Kind)
	live, err := h.gaslessLive(ctx, env, kind, common.Hash{})
	if err != nil {
		return err
	}
	raise := func(fee, ceiling *big.Int) *big.Int {
		raised := new(big.Int).Add(fee, new(big.Int).Quo(fee, big.NewInt(gaslessFeeBumpEighth)))
		raised.Add(raised, big.NewInt(1))
		if raised.Cmp(ceiling) > 0 {
			raised.Set(ceiling)
		}
		return raised
	}
	maxFee, priority := raise(op.MaxFeePerGas, live.MaxFeeCeiling), raise(op.MaxPriorityFeePerGas, live.PriorityFeeCeiling)
	if maxFee.Cmp(op.MaxFeePerGas) <= 0 && priority.Cmp(op.MaxPriorityFeePerGas) <= 0 {
		return nil
	}
	bumped := *op
	bumped.MaxFeePerGas, bumped.MaxPriorityFeePerGas = maxFee, priority
	stop := func(reason string) error {
		stopUserOperation(w, fmt.Sprintf("fee_bump_needs_quote: the bundler dropped the operation %s for its fees, and re-signing it an eighth higher is not allowed: %s; rerun the command for a fresh quote at the current fees (a late inclusion of the dropped operation is harmless), or use --fees wallet", u.Hash, reason))
		return h.saveAddress(record)
	}
	bound, ok := new(big.Int).SetString(u.FeeCapWei, 10)
	if !ok || bound.Sign() <= 0 {
		bound = new(big.Int).Add(op.maxCost(), live.FlatFee)
	}
	if feeCap := new(big.Int).Add(bumped.maxCost(), live.FlatFee); feeCap.Cmp(bound) > 0 {
		limit := fmt.Sprintf("the approved maximum of %s wei (a quote made with --fee-cap-gwei allows re-signing up to that cap)", bound)
		if u.FeeCapGwei != 0 {
			limit = fmt.Sprintf("your --fee-cap-gwei of %d gwei", u.FeeCapGwei)
		}
		return stop(fmt.Sprintf("the fee could reach %s wei, above %s", feeCap, limit))
	}
	if bumped.maxCost().Cmp(live.MaxSponsoredCost) > 0 {
		return stop(fmt.Sprintf("its maximum cost %s wei would be above the paymaster's policy of %s wei", bumped.maxCost(), live.MaxSponsoredCost))
	}
	if bumped.maxCost().Cmp(live.Deposit) > 0 {
		return stop(fmt.Sprintf("the paymaster's deposit (%s wei) cannot cover its maximum cost (%s wei)", live.Deposit, bumped.maxCost()))
	}
	payout, err := h.gaslessPayout(ctx, env, record, kind)
	if err != nil {
		if GaslessRefusalCode(err) != "" {
			return stop(err.Error())
		}
		return err
	}
	hasCode, isEmpty, err := h.payeeState(ctx, env)
	if err != nil {
		return err
	}
	amounts := gaslessAmountsFor(kind, payout, &bumped, live, env.profile.GasPolicy, hasCode, isEmpty)
	if err := checkGaslessAmounts(amounts, kind, live, uint64(env.profile.UneconomicFractionPercent), addressWithdrawalOptions{FeeCapGwei: u.FeeCapGwei, AllowExpensiveGas: u.AllowExpensiveGas}); err != nil {
		return stop(err.Error())
	}
	// The raised copy is dry-run before it is journaled: an account
	// created meanwhile drops initCode (a bundler would refuse the copy as
	// AA10), and a consumed nonce or another failure signs nothing.
	sent := u.Hash
	if err := h.resignUserOperation(ctx, env, record, func(op *gaslessUserOp) {
		op.MaxFeePerGas, op.MaxPriorityFeePerGas = maxFee, priority
	}); err != nil {
		return err
	}
	if u.Hash == sent {
		return nil
	}
	return h.sendUserOperation(ctx, env, record)
}

// lateUserOperation looks once for the inclusion of an operation the record
// gave up on (a re-sign the approval does not allow, a refused re-signed
// copy, an expired proof): a bundler may include a dropped operation after
// all. Every journaled copy is looked for, whatever the last send did (a
// re-signed copy the bundler refused leaves an earlier copy that it took).
// Found, the record returns to the submitted phase of the operation's
// kind, so the resume follows its bundle transaction instead of proving
// again or falling back to the wallet. An operation already found on chain
// (TransactionHash set) was not dropped and is not looked for.
func (h *FundingHandler) lateUserOperation(ctx context.Context, config fundingConfig, record *addressFundingRecord) (bool, error) {
	w := record.Withdrawal
	u := w.UserOp
	if u == nil || (u.Hash == "" && len(u.Hashes) == 0) {
		return false, nil
	}
	if u.TransactionHash != "" {
		// Found on chain and followed already (an escape's initiation,
		// whose finalization was then refused, say): it was not dropped,
		// and its inclusion is not a step to take again.
		return false, nil
	}
	// A look on chain only: the journaled contracts, so the wallet-paid
	// fallback it guards works without the current profile's pins.
	env, err := h.journaledEnvironment(ctx, config, record)
	if err != nil {
		return false, err
	}
	hashes := append([]string{}, u.Hashes...)
	listed := false
	for _, hash := range hashes {
		listed = listed || strings.EqualFold(hash, u.Hash)
	}
	if !listed && u.Hash != "" {
		hashes = append(hashes, u.Hash)
	}
	from := u.SubmittedAtBlock
	if from == 0 {
		from = w.StartBlock
	}
	if from == 0 {
		from = env.deployment.DeployBlock
	}
	tx, err := h.findUserOperationEvent(ctx, env, hashes, from)
	if err != nil || tx == "" {
		return false, err
	}
	w.Phase, w.GaslessRefusal = gaslessSubmittedPhase(gaslessKindOf(u.Kind)), ""
	return true, h.saveAddress(record)
}

// lateGaslessOperation is lateUserOperation before a --fees wallet fallback
// discards the record's operation: only a record stopped as gasless_refused
// can hold one a bundler may still include. Under a quote request the
// operation found is not followed (a quote never completes a withdrawal):
// the request is refused with the resume command.
func (h *FundingHandler) lateGaslessOperation(ctx context.Context, config fundingConfig, record *addressFundingRecord) (bool, error) {
	w := record.Withdrawal
	if w.Phase != "gasless_refused" || w.UserOp == nil {
		return false, nil
	}
	late, err := h.lateUserOperation(ctx, config, record)
	if err != nil || !late {
		return late, err
	}
	if mode := quoteMode(ctx); mode != nil && mode.Capture != nil {
		command := "zkapi-clientd withdraw --to " + w.Destination
		if w.Mode == "escape" {
			command = "zkapi-clientd withdraw --escape --to " + w.Destination
		}
		return true, errors.New("the sponsored operation the bundler dropped was included after all; follow it with " + command + " (no wallet-paid transaction is needed)")
	}
	return true, nil
}

// ------------------------------------------------------------------ completion

// recordSettlement copies the paymaster's figures into the record.
func recordSettlement(w *addressWithdrawalRecord, s paymasterSettlement) {
	w.ChargedWei, w.OwedPaidWei, w.ReceivedWei = s.Charged.String(), s.OwedPaid.String(), s.PaidOut.String()
	if s.Credited != nil {
		w.ReceivedWei = "0"
		w.PayoutCredited, w.PaymasterCredited = true, true
	}
	w.FundsWaitingInTransit = !s.Found
}

// completeGaslessWithdrawal closes a mutual close carried by a sponsored
// operation whose receipt was checked: the companion is told the bundle
// transaction, the deposit archived and the record completed.
func (h *FundingHandler) completeGaslessWithdrawal(ctx context.Context, config fundingConfig, record *addressFundingRecord, hash string, settlement paymasterSettlement, relayed bool) error {
	w := record.Withdrawal
	w.Phase = "confirming"
	if relayed {
		w.SettlementHash = strings.ToLower(hash)
	} else {
		w.TransactionHash = strings.ToLower(hash)
	}
	recordSettlement(w, settlement)
	if err := h.saveAddress(record); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"transaction_hash": hash})
	raw, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/confirm", body)
	if err != nil {
		return err
	}
	var confirmed withdrawalBridgeStatus
	if json.Unmarshal(raw, &confirmed) != nil || !withdrawalStatusMatches(confirmed, w) || confirmed.Phase != "complete" || !strings.EqualFold(confirmed.TransactionHash, hash) {
		return errors.New("invalid withdrawal confirmation; preserve the saved operation")
	}
	if err := h.archiveWithdrawnDepositForEscape(config, record, hash); err != nil {
		return err
	}
	record.Amount, record.Commitment, record.Phase = 0, "", "ready"
	w.Phase = "complete"
	w.CompletedOnPinnedRPC = config.ExitRPC == ""
	return h.saveAddress(record)
}

// findVaultExitTransaction finds the transaction that closed the note:
// its MutualClose or EscapeWithdrawalFinalized log, from block.
func (h *FundingHandler) findVaultExitTransaction(ctx context.Context, config fundingConfig, w *addressWithdrawalRecord, from uint64) (string, error) {
	for _, topic := range []string{withdrawalEventTopic, escapeFinalizedEventTopic} {
		var logs []userOperationLog
		filter := map[string]any{"address": config.Contract, "fromBlock": fmt.Sprintf("0x%x", from), "toBlock": "finalized", "topics": []string{topic, fmt.Sprintf("0x%064x", w.NoteID)}}
		if err := h.addressRPC(ctx, config, "eth_getLogs", []any{filter}, &logs); err != nil {
			return "", err
		}
		for _, log := range logs {
			if !log.Removed && isHex(log.TransactionHash, 32) {
				return log.TransactionHash, nil
			}
		}
	}
	return "", nil
}

// ------------------------------------------------------- collect, sweep, claim

// transitBalance is what S holds, and whether the paymaster holds evidence
// that a sponsored FORWARD may collect it.
func (h *FundingHandler) transitBalance(ctx context.Context, env *gaslessEnvironment, noteID uint64) (balance *big.Int, evidence bool, err error) {
	if balance, err = h.addressQuantity(ctx, env.config, "eth_getBalance", []any{env.account.Hex(), "latest"}); err != nil {
		return nil, false, err
	}
	stranded, err := h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorStranded+addressABIWord(strings.ToLower(env.account.Hex())))
	if err != nil {
		return nil, false, err
	}
	if stranded.Sign() != 0 {
		return balance, true, nil
	}
	recorded, err := h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorEscapeNotePlusOne+addressABIWord(strings.ToLower(env.account.Hex())))
	if err != nil {
		return nil, false, err
	}
	if recorded.Sign() == 0 {
		return balance, false, nil
	}
	note, err := h.vaultNote(ctx, env.config, uint32(recorded.Uint64()-1), "latest")
	if err != nil {
		return nil, false, err
	}
	return balance, note.Status == noteClosed, nil
}

// errTransitEmpty is the --sweep of a transit account that holds nothing.
var errTransitEmpty = errors.New("the transit account holds nothing to sweep")

// transitSweepIntent is the wallet-paid transaction --sweep signs next: the
// account's creation when S has no code, else its sweep.
func (h *FundingHandler) transitSweepIntent(ctx context.Context, env *gaslessEnvironment) (kind, to, data string, err error) {
	var code string
	if err := h.addressRPC(ctx, env.config, "eth_getCode", []any{env.account.Hex(), "latest"}, &code); err != nil {
		return "", "", "", err
	}
	if code == "0x" || code == "" {
		return "transit_create", env.factory.Hex(), "0x" + hex.EncodeToString(transitInitCode(env.factory, env.owner, env.payee)[20:]), nil
	}
	balance, err := h.addressQuantity(ctx, env.config, "eth_getBalance", []any{env.account.Hex(), "latest"})
	if err != nil {
		return "", "", "", err
	}
	if balance.Sign() == 0 {
		return "", "", "", errTransitEmpty
	}
	return "transit_sweep", env.account.Hex(), "0x" + selectorTransitSweep, nil
}

// transitTransactionData is the exact call a wallet-paid transit kind
// carries, for the journal's validation.
func transitTransactionData(kind string, w *addressWithdrawalRecord) (to, data string) {
	t := w.Transit
	switch kind {
	case "transit_create":
		return t.Factory, "0x" + hex.EncodeToString(transitInitCode(common.HexToAddress(t.Factory), common.HexToAddress(t.Owner), common.HexToAddress(w.Destination))[20:])
	case "transit_sweep":
		return t.Account, "0x" + selectorTransitSweep
	case "gasless_claim":
		return t.Paymaster, "0x" + selectorClaimCredit + addressABIWord(strings.ToLower(w.Destination))
	}
	return "", ""
}

// followTransitTransaction follows a pending wallet-paid transit
// transaction to finality and records what it did.
func (h *FundingHandler) followTransitTransaction(ctx context.Context, config fundingConfig, record *addressFundingRecord) error {
	w, pending := record.Withdrawal, record.Pending
	gcfg := config.exitConfig()
	receipt, final, err := h.addressFinalReceipt(ctx, gcfg, pending.Hash, true)
	if err != nil {
		return err
	}
	if !final {
		if receipt == nil {
			h.broadcastAddress(ctx, gcfg, pending)
		}
		return nil
	}
	if err := recordAddressActualFee(pending, receipt); err != nil {
		return err
	}
	retired := *pending
	retired.FinalizedRevert = receipt.Status == "0x0"
	record.History = append(record.History, retired)
	record.Pending = nil
	if receipt.Status == "0x1" && w.Transit != nil {
		switch pending.Kind {
		case "transit_sweep":
			if received, owedPaid, paidOut, found := parseCollected(receipt, common.HexToAddress(w.Transit.Paymaster), common.HexToAddress(w.Transit.Account)); found {
				w.SweepHash, w.OwedPaidWei, w.ReceivedWei = strings.ToLower(pending.Hash), owedPaid.String(), paidOut.String()
				w.ChargedWei = new(big.Int).Sub(new(big.Int).Sub(received, owedPaid), paidOut).String()
				w.FundsWaitingInTransit = false
				if credited := parsePaymasterSettlement(receipt, common.HexToAddress(w.Transit.Paymaster), common.HexToAddress(w.Transit.Account), common.HexToAddress(w.Destination)).Credited; credited != nil {
					w.ReceivedWei, w.PayoutCredited, w.PaymasterCredited = "0", true, true
				}
			}
		case "gasless_claim":
			w.ClaimHash = strings.ToLower(pending.Hash)
			payee := "0x" + addressABIWord(strings.ToLower(w.Destination))
			for _, log := range receipt.Logs {
				if !log.Removed && strings.EqualFold(log.Address, w.Transit.Paymaster) && len(log.Topics) == 2 && strings.EqualFold(log.Topics[0], paymasterCreditClaimedTopic) && strings.EqualFold(log.Topics[1], payee) && isHex(log.Data, 32) {
					// The credit reached Y: nothing waits in the paymaster
					// any more, so new deposits are no longer held back.
					w.ReceivedWei = new(big.Int).SetBytes(common.FromHex(log.Data)).String()
					w.PaymasterCredited, w.PayoutCredited = false, false
				}
			}
		}
	}
	return h.saveAddress(record)
}

// GaslessAvailability is whether --fees payout can carry the next
// withdrawal (design 3.1 pre-flight), and why not.
type GaslessAvailability struct {
	Available           bool   `json:"available"`
	Reason              string `json:"reason,omitempty"`
	Message             string `json:"message,omitempty"`
	BundlerURL          string `json:"bundler_url,omitempty"`
	PaymasterDepositWei string `json:"paymaster_deposit_wei,omitempty"`
	FlatFeeWei          string `json:"flat_fee_wei,omitempty"`
	MaxFeeCeilingWei    string `json:"max_fee_ceiling_wei,omitempty"`
	EscapesEnabled      bool   `json:"escapes_enabled,omitempty"`
}

// GaslessAvailability runs the gasless pre-flight that needs no record: the
// deployment checks, the bundler and the paymaster's live policy.
func (h *FundingHandler) GaslessAvailability(ctx context.Context) (GaslessAvailability, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	config, err := h.config(ctx)
	if err != nil {
		return GaslessAvailability{}, err
	}
	live, env, err := h.gaslessPreflight(ctx, config, withdrawalOptions(ctx), gaslessKindClose)
	if err != nil {
		code := GaslessRefusalCode(err)
		if code == "" {
			return GaslessAvailability{}, err
		}
		return GaslessAvailability{Reason: code, Message: err.Error()}, nil
	}
	return GaslessAvailability{Available: true, BundlerURL: env.bundler, PaymasterDepositWei: live.Deposit.String(), FlatFeeWei: live.FlatFee.String(), MaxFeeCeilingWei: live.MaxFeeCeiling.String(), EscapesEnabled: live.EscapesEnabled}, nil
}

// gaslessPreflight is the availability check before a transit account is
// derived: the profile, the deployment checks, the bundler and the live
// policy (without a key: attempts are not read).
func (h *FundingHandler) gaslessPreflight(ctx context.Context, config fundingConfig, options addressWithdrawalOptions, kind uint8) (gaslessLive, *gaslessEnvironment, error) {
	profile, deployment, err := h.gaslessProfile()
	if err != nil {
		return gaslessLive{}, nil, err
	}
	bundler, err := h.resolveBundlerURL(options, profile)
	if err != nil {
		return gaslessLive{}, nil, err
	}
	if err := h.ensureGaslessChecked(ctx); err != nil {
		return gaslessLive{}, nil, err
	}
	env := &gaslessEnvironment{profile: profile, deployment: deployment, config: config.exitConfig(), bundler: bundler, entryPoint: common.HexToAddress(profile.EntryPoint), paymaster: common.HexToAddress(profile.Paymaster), factory: common.HexToAddress(profile.Factory), vault: common.HexToAddress(config.Contract)}
	if err := h.checkBundler(ctx, env); err != nil {
		return gaslessLive{}, nil, err
	}
	live, err := h.gaslessLive(ctx, env, kind, common.Hash{})
	if err != nil {
		return gaslessLive{}, nil, err
	}
	live.Attempts = 0
	if err := checkGaslessLive(live, kind, profile.GasPolicy); err != nil {
		return gaslessLive{}, nil, err
	}
	return live, env, nil
}

// gaslessPrepareCheck is the pre-proof amount check: the current private
// balance must cover the sponsored fee at the current fees, so nothing is
// reserved for a payout the fee would eat. It reports whether the payout
// address has code (design 3.1's advisory: the push may fail and the
// payout be credited), read before the transit account is derived.
func (h *FundingHandler) gaslessPrepareCheck(ctx context.Context, config fundingConfig, options addressWithdrawalOptions, kind uint8, balanceUnits uint64, payee string) (payeeHasCode bool, err error) {
	profile, _, err := h.gaslessProfile()
	if err != nil {
		return false, err
	}
	if err := checkGaslessPayee(profile, config.Contract, payee); err != nil {
		return false, err
	}
	live, env, err := h.gaslessPreflight(ctx, config, options, kind)
	if err != nil {
		return false, err
	}
	env.payee = common.HexToAddress(payee)
	maxFee, priority, err := h.gaslessFees(ctx, env, live)
	if err != nil {
		return false, err
	}
	g := env.profile.GasPolicy
	// The operation the proof will be carried by, as the client builds it
	// (a new transit account, so initCode), its preVerificationGas the
	// shared rule's on its worst-case calldata.
	op := gaslessShapeOp(g, kind, true, env.paymaster, live.FlatFee, live.CallCap)
	op.MaxFeePerGas, op.MaxPriorityFeePerGas = maxFee, priority
	payout := new(big.Int).Mul(new(big.Int).SetUint64(balanceUnits), big.NewInt(1_000_000_000))
	hasCode, isEmpty, err := h.payeeState(ctx, env)
	if err != nil {
		return false, err
	}
	live.Owed = new(big.Int)
	return hasCode, checkGaslessAmounts(gaslessAmountsFor(kind, payout, op, live, g, hasCode, isEmpty), kind, live, uint64(env.profile.UneconomicFractionPercent), options)
}

// ------------------------------------------------------- resumes and actions

// resumeGaslessClose follows the close operation and completes the
// withdrawal once its bundle transaction is final and successful: the vault
// log is checked with the proof destination (S), the note's closure
// corroborated, and the companion told the bundle transaction.
func (h *FundingHandler) resumeGaslessClose(ctx context.Context, config fundingConfig, record *addressFundingRecord, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	outcome, err := h.followUserOperation(ctx, config, record)
	if err != nil {
		return update(), err
	}
	if !outcome.Included || !outcome.Success {
		return update(), nil
	}
	env, err := h.followEnvironment(ctx, config, record)
	if err != nil {
		return update(), err
	}
	if _, err := validateWithdrawalReceipt(outcome.Receipt, config, w, true); err != nil {
		return update(), err
	}
	if err := h.corroborateWithdrawalClosed(ctx, config, w.NoteID, outcome.Receipt); err != nil {
		if errors.Is(err, errWithdrawalVerificationPending) {
			next := update()
			next.Message = withdrawalVerifyingMessage
			return next, nil
		}
		return update(), err
	}
	settlement := parsePaymasterSettlement(outcome.Receipt, env.paymaster, env.account, env.payee)
	if err := h.completeGaslessWithdrawal(ctx, config, record, outcome.Hash, settlement, false); err != nil {
		return update(), err
	}
	return update(), nil
}

// resumeForward follows a FORWARD operation: on success the paymaster's
// Settled figures close the record; on failure the payout stays in the
// transit account for a wallet-paid sweep.
func (h *FundingHandler) resumeForward(ctx context.Context, config fundingConfig, record *addressFundingRecord, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	outcome, err := h.followUserOperation(ctx, config, record)
	if err != nil {
		return update(), err
	}
	if !outcome.Included {
		return update(), nil
	}
	if !outcome.Success {
		// The note is closed and the record complete; only the payout's
		// delivery failed, so the record stays complete with the payout
		// waiting and the reason shown (a new --collect or --sweep follows).
		w.Phase, w.GaslessRefusal, w.FundsWaitingInTransit = "complete", "forward_reverted: the sponsored forward reverted ("+outcome.Revert+"); the payout stays in the transit account, deliver it with --collect again or --sweep", true
		if err := h.saveAddress(record); err != nil {
			return update(), err
		}
		return update(), nil
	}
	env, err := h.followEnvironment(ctx, config, record)
	if err != nil {
		return update(), err
	}
	settlement := parsePaymasterSettlement(outcome.Receipt, env.paymaster, env.account, env.payee)
	if !settlement.Found {
		return update(), errors.New("the forward's receipt carries no settlement by the paymaster; preserve recovery files")
	}
	recordSettlement(w, settlement)
	w.CollectHashes = append(w.CollectHashes, strings.ToLower(outcome.Hash))
	w.FundsWaitingInTransit, w.Phase, w.GaslessRefusal = false, "complete", ""
	w.CompletedOnPinnedRPC = config.ExitRPC == ""
	if err := h.saveAddress(record); err != nil {
		return update(), err
	}
	return update(), nil
}

// adoptVaultExit completes a mutual-close record whose note another
// transaction closed (a replayed close, or an escape of the reserved state
// finalized by someone else): the exit is found by the vault's logs, its
// receipt validated with the proof destination and corroborated, and the
// companion told; the payout waits in the transit account.
func (h *FundingHandler) adoptVaultExit(ctx context.Context, config fundingConfig, record *addressFundingRecord) error {
	w := record.Withdrawal
	gcfg := config.exitConfig()
	from := w.StartBlock
	if from == 0 {
		deployment, _, err := deployedDeployment(h.client.config.Network)
		if err != nil {
			return err
		}
		from = deployment.DeployBlock
	}
	tx, err := h.findVaultExitTransaction(ctx, gcfg, w, from)
	if err != nil {
		return err
	}
	if tx == "" {
		return errors.New("the vault shows no close or finalization of this note in a final block; there is nothing to collect yet (resume the withdrawal instead)")
	}
	receipt, final, err := h.addressFinalReceipt(ctx, gcfg, tx, true)
	if err != nil {
		return err
	}
	if !final {
		return errors.New("the transaction that closed the note is not final yet; retry later")
	}
	payout, err := validateWithdrawalReceipt(receipt, config, w, true)
	if err != nil {
		return err
	}
	if payout.EscapePaid != nil {
		if err := h.checkRelayedEscapePayout(ctx, config, w, *payout.EscapePaid, receipt); err != nil {
			return err
		}
		w.Payout = *payout.EscapePaid
	}
	if err := h.corroborateWithdrawalClosed(ctx, config, w.NoteID, receipt); err != nil {
		return err
	}
	return h.completeGaslessWithdrawal(ctx, config, record, tx, paymasterSettlement{}, true)
}

// transitAction serves --collect, --sweep and --claim-credit for a saved
// gasless withdrawal: a sponsored FORWARD of the transit account's balance,
// its wallet-paid sweep (the account's creation first), or the delivery of
// a payout the paymaster credited. The note must be closed first; a close
// another transaction made is adopted.
func (h *FundingHandler) transitAction(ctx context.Context, config fundingConfig, record *addressFundingRecord, options addressWithdrawalOptions, update func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	if w.Transit == nil {
		return update(), errors.New("this withdrawal has no transit account (it was not prepared with --fees payout); nothing to collect, sweep or claim")
	}
	if record.Pending != nil {
		if !transitKinds[record.Pending.Kind] {
			return update(), errors.New("recover the saved transaction before collecting from the transit account")
		}
		if err := h.followTransitTransaction(ctx, config, record); err != nil {
			return update(), err
		}
		if record.Pending != nil {
			return update(), nil
		}
	}
	switch w.Phase {
	case "op_built", "op_submitted", "forward_op_built", "forward_op_submitted", "finalize_op_built", "finalize_op_submitted", "withdrawal_pending", "confirming", "escape_pending", "finalize_pending":
		return update(), errors.New("a sponsored operation is in flight; resume it with the same destination first")
	case "complete":
	default:
		if w.Mode == "escape" {
			return update(), errors.New("follow the escape with zkapi-clientd withdraw --escape --to " + w.Destination + " first; its payout is collected once the escape is finalized")
		}
		if err := h.adoptVaultExit(ctx, config, record); err != nil {
			if errors.Is(err, errWithdrawalVerificationPending) {
				next := update()
				next.Message = withdrawalVerifyingMessage
				return next, nil
			}
			return update(), err
		}
	}
	// A FORWARD the bundler refused or dropped stays journaled on the
	// complete record: if it was included after all, it is followed (its
	// settlement closes the record), never replaced by another forward or
	// a sweep of a balance it already delivered.
	if u := w.UserOp; u != nil && gaslessKindOf(u.Kind) == gaslessKindForward && u.TransactionHash == "" {
		late, err := h.lateUserOperation(ctx, config, record)
		if err != nil {
			return update(), err
		}
		if late {
			if mode := quoteMode(ctx); mode != nil && mode.Capture != nil {
				command := "zkapi-clientd withdraw --to " + w.Destination
				if w.Mode == "escape" {
					command = "zkapi-clientd withdraw --escape --to " + w.Destination
				}
				return update(), errors.New("the sponsored forward the bundler refused or dropped was included after all; follow it with " + command + " (nothing else needs to be signed)")
			}
			return h.resumeForward(ctx, config, record, update)
		}
	}
	if quoteMode(ctx) == nil {
		return update(), errors.New("review and approve a current payment quote before signing")
	}
	// The wallet-paid sweep and credit claim use the contracts journaled
	// with the record and work whatever the current profile pins; the
	// sponsored FORWARD needs the current pins to name the record's
	// paymaster and factory (gasless_record_not_pinned otherwise).
	var env *gaslessEnvironment
	var err error
	if options.ClaimCredit || options.Sweep {
		env, err = h.journaledEnvironment(ctx, config, record)
	} else {
		env, err = h.gaslessEnvironment(ctx, config, record, options)
	}
	if err != nil {
		return update(), err
	}
	switch {
	case options.ClaimCredit:
		if !w.PaymasterCredited {
			return update(), errors.New("the paymaster holds no credited payout for this withdrawal")
		}
		credit, err := h.gaslessWord(ctx, env, env.paymaster, "0x"+selectorCredits+addressABIWord(strings.ToLower(env.payee.Hex())))
		if err != nil {
			return update(), err
		}
		if credit.Sign() == 0 {
			// claimCredit is permissionless: someone else delivered the
			// credit. Nothing waits in the paymaster any more (what reached
			// Y is not known here, so no figure is shown for it).
			w.PaymasterCredited, w.PayoutCredited, w.ReceivedWei = false, false, ""
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
			return update(), errors.New("the paymaster holds no credit for this destination; it was claimed already, and the withdrawal no longer waits for it")
		}
		if err := h.signAddressTransaction(ctx, config, record, "gasless_claim", env.paymaster.Hex(), w.transitClaimCalldata()); err != nil {
			return update(), err
		}
	case options.Sweep:
		kind, to, data, err := h.transitSweepIntent(ctx, env)
		if errors.Is(err, errTransitEmpty) && w.FundsWaitingInTransit {
			// Someone else swept or forwarded the balance (S.sweep() and a
			// FORWARD pay Y whoever sends them): nothing waits in S.
			w.FundsWaitingInTransit = false
			if saveErr := h.saveAddress(record); saveErr != nil {
				return update(), saveErr
			}
		}
		if err != nil {
			return update(), err
		}
		if err := h.signAddressTransaction(ctx, config, record, kind, to, data); err != nil {
			return update(), err
		}
	default:
		balance, evidence, err := h.transitBalance(ctx, env, w.NoteID)
		if err != nil {
			return update(), err
		}
		if balance.Sign() == 0 {
			w.FundsWaitingInTransit = false
			if err := h.saveAddress(record); err != nil {
				return update(), err
			}
			return update(), errors.New("the transit account holds nothing to collect")
		}
		if !evidence {
			return update(), errors.New("the paymaster holds no evidence for a sponsored forward of this balance; deliver it with zkapi-clientd withdraw --sweep --to " + w.Destination + " (paid by the local signing address)")
		}
		if err := h.submitUserOperation(ctx, config, record, gaslessKindForward, nil); err != nil {
			if GaslessRefusalCode(err) != "" {
				// The record stays complete (the note is closed): the
				// refusal is shown with the payout waiting in the transit
				// account, for --collect again or --sweep.
				w.GaslessRefusal, w.FundsWaitingInTransit = err.Error(), true
				if saveErr := h.saveAddress(record); saveErr != nil {
					return update(), saveErr
				}
			}
			return update(), err
		}
	}
	return update(), nil
}
