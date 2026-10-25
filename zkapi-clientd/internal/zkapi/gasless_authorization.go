package zkapi

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The payout-only withdrawal and its bounded authorization.
//
// A deployment that publishes reviewed gasless support offers one way to
// withdraw: the network fee is paid from the payout by a sponsored
// operation, as in the web app. The owner approves a close once, for this
// destination, note and transit account, under a maximum the payout may lose
// to the fee (MaxTotalFeeWei). The operation is then built at the fees of the
// moment it is signed, and rebuilt, re-signed or re-proved within that
// maximum (a fee that rose or fell, a bundler that dropped or refused it, a
// proof that expired, a restart) without asking again. Anything outside it
// (a higher maximum, a raised flat fee or debt, another destination or note)
// needs a new quote and approval. The paymaster enforces every signed copy's
// own maximum on chain; the authorization is the owner's bound across copies.

// gaslessAuthorization is the journaled approval of a payout close. The
// identity fields repeat the record's so a tampered journal is refused; the
// bounds are absolute wei fixed at approval.
type gaslessAuthorization struct {
	QuoteID         string `json:"quote_id"`
	ApprovedAt      int64  `json:"approved_at"`
	DeploymentID    string `json:"deployment_id"`
	ChainID         uint64 `json:"chain_id"`
	Contract        string `json:"contract_address"`
	Address         string `json:"address"`
	NoteID          uint64 `json:"note_id"`
	Binding         string `json:"binding"`
	Amount          uint64 `json:"amount"`
	Destination     string `json:"destination"`
	TransitAccount  string `json:"transit_account"`
	BundlerURL      string `json:"bundler_url"`
	PayoutWei       string `json:"payout_wei"`
	MaxTotalFeeWei  string `json:"max_total_fee_wei"`
	FlatFeeCapWei   string `json:"flat_fee_cap_wei"`
	OwedWei         string `json:"owed_wei"`
	MinNetPayoutWei string `json:"min_net_payout_wei"`
	EstimatedFeeWei string `json:"estimated_fee_wei,omitempty"`
	// Nonce is the EntryPoint nonce of the first copy signed under the
	// authorization. Every later copy (a re-sign, a fee bump, a re-proof)
	// shares it, so at most one is ever included and charged; a nonce that
	// moved means one was, and the authorization does not follow it.
	Nonce string `json:"nonce,omitempty"`
	// SignedHashes are every copy signed under it and FromBlock the block
	// the first was sent at: a rebuilt copy's journal starts with them, so
	// an earlier copy a bundler includes late is still found and settles
	// the withdrawal.
	SignedHashes      []string `json:"signed_hashes,omitempty"`
	FromBlock         uint64   `json:"from_block,omitempty"`
	FeeCapGwei        uint64   `json:"fee_cap_gwei,omitempty"`
	AllowExpensiveGas bool     `json:"allow_expensive_gas,omitempty"`
	// Rebuilds counts the operations signed under the authorization after
	// the approval's own; Revoked is why it can no longer be used.
	Rebuilds int    `json:"rebuilds,omitempty"`
	Revoked  string `json:"revoked,omitempty"`
}

// maxAuthorizedRebuilds bounds the operations signed under one
// authorization without the owner (each a copy at the same nonce, so at
// most one is ever included); past it the owner reviews a new quote.
const maxAuthorizedRebuilds = 8

// authorizedQuoteLifetime is how long an authorize-once quote can be
// approved: its fees are not the ones signed (the operation is built at
// approval, within the maximum), so it only bounds the decision.
const authorizedQuoteLifetime = 30 * time.Minute

// authorizedReproveWait is how long after a copy's proof lifetime ends a
// re-proved copy waits, so no earlier copy can still validate when the
// bundler sees its replacement at the same nonce.
const authorizedReproveWait = 30 * time.Second

func (a *gaslessAuthorization) usable() bool {
	return a != nil && a.Revoked == ""
}

// usableAuthorization is the record's authorization while it can carry a
// close: usable, and naming the record's own note, binding, payout address
// and transit account.
func usableAuthorization(w *addressWithdrawalRecord) *gaslessAuthorization {
	if w == nil || w.Mode == "escape" || w.Transit == nil || w.FeePayer != "payout" || !w.Authorization.usable() {
		return nil
	}
	a := w.Authorization
	if a.NoteID != w.NoteID || a.Binding != w.Binding || !strings.EqualFold(a.Destination, w.Destination) || !strings.EqualFold(a.TransitAccount, w.Transit.Account) {
		return nil
	}
	return a
}

// authorizationMatches reports an authorization that names this record's
// deployment, chain, vault, wallet, note, binding, amount, payout, payout
// address, transit account and bundler.
func authorizationMatches(a *gaslessAuthorization, record *addressFundingRecord, payout *big.Int, bundler string) bool {
	w := record.Withdrawal
	return a != nil && w != nil && w.Transit != nil && a.DeploymentID == record.DeploymentID && a.ChainID == record.ChainID && strings.EqualFold(a.Contract, record.Contract) && strings.EqualFold(a.Address, record.Address) &&
		a.NoteID == w.NoteID && a.Binding == w.Binding && a.Amount == w.Amount && a.PayoutWei == payout.String() && strings.EqualFold(a.Destination, w.Destination) && strings.EqualFold(a.TransitAccount, w.Transit.Account) && a.BundlerURL == bundler
}

func (a *gaslessAuthorization) wei(value string) *big.Int {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 {
		return nil
	}
	return n
}

// remember keeps the copies of u (signed under the authorization) and the
// block it was sent at before the record lets u go for a rebuild.
func (a *gaslessAuthorization) remember(u *addressUserOp) {
	if a == nil || u == nil {
		return
	}
	for _, hash := range append(append([]string{}, u.Hashes...), u.Hash) {
		known := hash == ""
		for _, saved := range a.SignedHashes {
			known = known || strings.EqualFold(saved, hash)
		}
		if !known {
			a.SignedHashes = append(a.SignedHashes, hash)
		}
	}
	if u.SubmittedAtBlock != 0 && (a.FromBlock == 0 || u.SubmittedAtBlock < a.FromBlock) {
		a.FromBlock = u.SubmittedAtBlock
	}
}

// revoke ends the authorization with its reason: a new quote and approval
// are needed.
func (a *gaslessAuthorization) revoke(reason string) {
	if a != nil && a.Revoked == "" {
		a.Revoked = reason
	}
}

// retryableGaslessCodes are the refusals an authorization outlives: a
// bundler or paymaster that is unavailable for now, fees above the
// authorized maximum for now, a copy the bundler refused or dropped (its
// replacement is signed within the maximum), a proof that expired (proved
// again from the kept clearance). Anything else (a reverted operation,
// which used one of the key's attempts, a closed note, a consumed nonce, a
// policy mismatch, exhausted attempts, an invalid payee, an unpinned record,
// a payout the fee would eat) ends it.
var retryableGaslessCodes = map[string]bool{
	"bundler_unavailable":         true,
	"bundler_refused":             true,
	"gas_above_paymaster_ceiling": true,
	"paymaster_underfunded":       true,
	"sponsorship_paused":          true,
	"exits_paused":                true,
	"op_expired":                  true,
	"fee_bump_needs_quote":        true,
	CodeFeeAboveAuthorization:     true,
}

// refusalCode is the code a journaled refusal reason starts with.
func refusalCode(reason string) string {
	code, _, _ := strings.Cut(reason, ":")
	return strings.TrimSpace(code)
}

// retryableRefusal reports a refusal reason an authorization outlives. A
// bundler refusal naming an EntryPoint validation failure (an AA code) is
// the operation's, not the moment's, and ends it.
func retryableRefusal(reason string) bool {
	code := refusalCode(reason)
	if !retryableGaslessCodes[code] {
		return false
	}
	return code != "bundler_refused" || !aaCodeInMessage.MatchString(strings.ToLower(reason))
}

// retryableUnderAuthorization reports a gasless_refused close that the next
// resume retries within its authorization.
func retryableUnderAuthorization(w *addressWithdrawalRecord) bool {
	return w != nil && w.Phase == "gasless_refused" && !w.FundsWaitingInTransit && usableAuthorization(w) != nil && retryableRefusal(w.GaslessRefusal)
}

// newWithdrawalFees is how a new withdrawal on this deployment pays its fee:
// "payout" where the packaged deployment publishes reviewed gasless support,
// else "wallet".
func (h *FundingHandler) newWithdrawalFees() string {
	deployment, _, err := deployedDeployment(h.client.config.Network)
	if err != nil || deployment.Gasless == nil {
		return "wallet"
	}
	if _, err := deployment.Gasless.validate(); err != nil {
		return "wallet"
	}
	return "payout"
}

// authorizationBound is the default maximum the payout may lose to a close's
// fee: the deployment's normal limits, as the web app uses them when no
// tighter cap is given. It is the uneconomic fraction of the payout (unless
// the owner accepted an expensive fee), at most what the paymaster's policy
// lets one operation cost plus its flat fee and, for a contract payout
// address, the credit surcharge of a failed push at the fee ceiling. A
// --fee-cap-gwei tightens it; nothing widens it.
func authorizationBound(payout *big.Int, live gaslessLive, g gaslessGasPolicy, percent uint64, payeeHasCode bool, options addressWithdrawalOptions) *big.Int {
	bound := new(big.Int).Add(live.MaxSponsoredCost, live.FlatFee)
	if payeeHasCode {
		bound.Add(bound, new(big.Int).Mul(new(big.Int).SetUint64(g.CreditGas), live.MaxFeeCeiling))
	}
	if !options.AllowExpensiveGas {
		fraction := new(big.Int).Quo(new(big.Int).Mul(payout, new(big.Int).SetUint64(percent)), big.NewInt(100))
		if fraction.Cmp(bound) < 0 {
			bound = fraction
		}
	}
	if options.FeeCapGwei != 0 {
		if userCap := new(big.Int).Mul(new(big.Int).SetUint64(options.FeeCapGwei), big.NewInt(1_000_000_000)); userCap.Cmp(bound) < 0 {
			bound = userCap
		}
	}
	return bound
}

// payoutLoss is the most the payout can lose to op: its maximum cost, the
// flat fee and, for a contract payout address, the credit surcharge at its
// maxFeePerGas.
func payoutLoss(op *gaslessUserOp, flatFee *big.Int, g gaslessGasPolicy, payeeHasCode bool) *big.Int {
	loss := new(big.Int).Add(op.maxCost(), flatFee)
	if payeeHasCode {
		loss.Add(loss, new(big.Int).Mul(new(big.Int).SetUint64(g.CreditGas), op.MaxFeePerGas))
	}
	return loss
}

// clampGaslessFees lowers op's maxFeePerGas, when the shared fee rule's
// headroom (2 × base + tip) would take the operation past bound or past the
// paymaster's policy, to the most that fits, provided the operation still
// pays the current base fee plus its tip: maxFeePerGas is a ceiling, and the
// EntryPoint charges min(maxFee, base + tip). The fee rule itself (and its
// table shared with the SDK) is unchanged. Its preVerificationGas follows
// the fees it is signed with. When nothing that fits is includable now op is
// left as built, so the usual checks refuse it with their reason.
func clampGaslessFees(op *gaslessUserOp, live gaslessLive, g gaslessGasPolicy, bound *big.Int, payeeHasCode bool, minimumPVG uint64) {
	for i := 0; i < 3; i++ {
		if payoutLoss(op, live.FlatFee, g, payeeHasCode).Cmp(bound) <= 0 && op.maxCost().Cmp(live.MaxSponsoredCost) <= 0 {
			return
		}
		gas := new(big.Int).SetUint64(op.PreVerificationGas + op.VerificationGasLimit + op.CallGasLimit + op.PaymasterVerificationGasLimit + op.PaymasterPostOpGasLimit)
		perLoss := new(big.Int).Set(gas)
		if payeeHasCode {
			perLoss.Add(perLoss, new(big.Int).SetUint64(g.CreditGas))
		}
		budget := new(big.Int).Sub(bound, live.FlatFee)
		if budget.Sign() <= 0 || gas.Sign() == 0 {
			return
		}
		limit := new(big.Int).Quo(budget, perLoss)
		if policy := new(big.Int).Quo(live.MaxSponsoredCost, gas); policy.Cmp(limit) < 0 {
			limit = policy
		}
		if limit.Cmp(op.MaxFeePerGas) >= 0 {
			return
		}
		priority := op.MaxPriorityFeePerGas
		if live.BaseFee == nil || new(big.Int).Add(live.BaseFee, priority).Cmp(limit) > 0 {
			return
		}
		op.MaxFeePerGas = limit
		op.PreVerificationGas = op.requiredPreVerificationGas(g)
		if op.PreVerificationGas < minimumPVG {
			op.PreVerificationGas = minimumPVG
		}
	}
}

// newGaslessAuthorization turns an approved authorize-once quote into the
// record's authorization.
func newGaslessAuthorization(q *AddressPaymentQuote, w *addressWithdrawalRecord) (*gaslessAuthorization, error) {
	maximum, ok1 := new(big.Int).SetString(q.MaxTotalFeeWei, 10)
	minimum, ok2 := new(big.Int).SetString(q.MinNetPayoutWei, 10)
	payout, ok3 := new(big.Int).SetString(q.PayoutWei, 10)
	flat, ok4 := new(big.Int).SetString(q.FlatFeeWei, 10)
	owed, ok5 := new(big.Int).SetString(q.OwedWei, 10)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || maximum.Sign() <= 0 || minimum.Sign() <= 0 || flat.Sign() < 0 || owed.Sign() < 0 || new(big.Int).Sub(new(big.Int).Sub(payout, maximum), owed).Cmp(minimum) != 0 {
		return nil, errAddressQuoteChanged
	}
	return &gaslessAuthorization{
		QuoteID: q.ID, ApprovedAt: time.Now().Unix(), DeploymentID: q.DeploymentID, ChainID: q.ChainID, Contract: q.Contract, Address: q.Address,
		NoteID: w.NoteID, Binding: w.Binding, Amount: w.Amount, Destination: w.Destination, TransitAccount: w.Transit.Account, BundlerURL: q.BundlerURL,
		PayoutWei: q.PayoutWei, MaxTotalFeeWei: q.MaxTotalFeeWei, FlatFeeCapWei: q.FlatFeeWei, OwedWei: q.OwedWei, MinNetPayoutWei: q.MinNetPayoutWei,
		EstimatedFeeWei: q.ExpectedFeeWei, FeeCapGwei: q.FeeCapGwei, AllowExpensiveGas: q.AllowExpensiveGas,
	}, nil
}

// checkGaslessAuthorization refuses an operation outside the authorization:
// a flat fee or debt above what was approved, or a payout loss above the
// maximum (fee_above_authorization, which a later retry may fit). The
// identity was checked by usableAuthorization.
func checkGaslessAuthorization(a *gaslessAuthorization, amounts gaslessAmounts, op *gaslessUserOp, g gaslessGasPolicy) error {
	maximum, flatCap, owed := a.wei(a.MaxTotalFeeWei), a.wei(a.FlatFeeCapWei), a.wei(a.OwedWei)
	if maximum == nil || flatCap == nil || owed == nil {
		return fmt.Errorf("the saved withdrawal authorization is invalid; preserve the recovery file")
	}
	if amounts.FlatFee.Cmp(flatCap) > 0 {
		return refuse(CodeFeeAboveAuthorization, "the paymaster's flat fee rose to %s wei, above the %s wei you approved; review a new quote (zkapi-clientd withdraw --to %s) to approve it", amounts.FlatFee, flatCap, a.Destination)
	}
	if amounts.Owed.Cmp(owed) > 0 {
		return refuse(CodeFeeAboveAuthorization, "the transit account owes %s wei, above the %s wei you approved; review a new quote (zkapi-clientd withdraw --to %s)", amounts.Owed, owed, a.Destination)
	}
	if loss := payoutLoss(op, amounts.FlatFee, g, amounts.PayeeHasCode); loss.Cmp(maximum) > 0 {
		return refuse(CodeFeeAboveAuthorization, "the network fee now could take up to %s wei from the payout, above the %s wei you authorized; it is retried within your authorization when fees fall, or review a new quote (zkapi-clientd withdraw --to %s) to authorize a higher maximum", loss, maximum, a.Destination)
	}
	return nil
}
