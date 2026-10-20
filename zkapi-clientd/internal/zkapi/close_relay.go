package zkapi

// Close relay mode for cooperative withdrawals (serverd's close relay, the
// companion's /oa/v1/withdraw/relay/* routes).
//
// The relay is opt-in. A relayed close costs the operator's fee, charged as
// one ordinary metered request at the note's current state before the
// withdrawal is prepared; the close is then cleared and proved at the
// successor, so the fee sits in the close's treasury share. The companion
// makes that request and talks to the protocol server for the relay, over
// the same transport (Tor when configured) as every other protocol request:
// this file only drives it.
//
// The user is never at the relay's mercy: the close's proof binds its
// destination and amount, the wallet keeps it, and CloseRelayFollower
// submits it itself, through the ordinary wallet-paid or gasless path, when
// the relay has not landed it by valid_until minus a margin (or reports it
// failed or expired). The withdrawal stays pending until the vault's
// MutualClose event for the close's nullifier is seen.

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// DefaultCloseRelaySelfSubmitMargin is how long before a relayed close's
// valid_until the client stops waiting for the relay and submits the close
// itself. It is below the relay's default urgent margin (30 minutes, when the
// relay sends at once) and above its default cutoff (5 minutes, after which
// the relay never sends), so a working relay has normally landed the close
// before the client acts, and a client that acts still has 20 minutes.
const DefaultCloseRelaySelfSubmitMargin = 20 * time.Minute

// DefaultCloseRelayPoll is how often the relay's status is read.
const DefaultCloseRelayPoll = 30 * time.Second

// mutualCloseTopic is keccak256("MutualClose(uint32,uint256,uint128,address)").
const mutualCloseTopic = "0x1f43fa4711ca18e1d26398f26bf598bd3a62992cdd0e84f055f2bb506e9d7031"

// CloseRelayTicket is the companion's view of the paid relay fee.
type CloseRelayTicket struct {
	Status     string `json:"status"`
	NoteID     uint32 `json:"note_id"`
	FeeUnits   string `json:"fee_units"`
	TicketHash string `json:"ticket_hash"`
}

// CloseRelayStatus is the relay's view of the close (the server's
// CloseRelayStatusResponse). Status is queued, submitted, landed, closed,
// failed or expired, or unknown when the relay holds no such close.
type CloseRelayStatus struct {
	Status              string `json:"status"`
	WithdrawalNullifier string `json:"withdrawal_nullifier,omitempty"`
	NoteID              uint32 `json:"note_id,omitempty"`
	ValidUntil          uint64 `json:"valid_until,omitempty"`
	TransactionHash     string `json:"transaction_hash,omitempty"`
	BlockNumber         uint64 `json:"block_number,omitempty"`
	Detail              string `json:"detail,omitempty"`
	SelfSubmit          bool   `json:"self_submit"`
}

// PayCloseRelayFee pays the relay fee at the note's current state (one
// metered request). Call it before the withdrawal is prepared; it is
// idempotent and resumes a fee request whose answer was lost.
func (c *Client) PayCloseRelayFee(ctx context.Context) (CloseRelayTicket, error) {
	var ticket CloseRelayTicket
	raw, err := c.request(ctx, http.MethodPost, "/oa/v1/withdraw/relay/fee", []byte("{}"))
	if err != nil {
		return ticket, err
	}
	if json.Unmarshal(raw, &ticket) != nil || ticket.Status != "paid" || !isHex(ticket.TicketHash, 32) {
		return ticket, errors.New("invalid close relay fee response")
	}
	return ticket, nil
}

// SubmitCloseRelay hands the prepared close to the relay. The relay answers
// the same close submitted again with its status.
func (c *Client) SubmitCloseRelay(ctx context.Context) (CloseRelayStatus, error) {
	return c.closeRelayCall(ctx, http.MethodPost, "/oa/v1/withdraw/relay/submit", []byte("{}"))
}

// CloseRelayState reads the relay's status of the prepared close.
func (c *Client) CloseRelayState(ctx context.Context) (CloseRelayStatus, error) {
	return c.closeRelayCall(ctx, http.MethodGet, "/oa/v1/withdraw/relay/status", nil)
}

func (c *Client) closeRelayCall(ctx context.Context, method, path string, body []byte) (CloseRelayStatus, error) {
	var status CloseRelayStatus
	raw, err := c.request(ctx, method, path, body)
	if err != nil {
		return status, err
	}
	if json.Unmarshal(raw, &status) != nil || !knownCloseRelayStatus(status.Status) {
		return CloseRelayStatus{}, errors.New("invalid close relay status")
	}
	return status, nil
}

func knownCloseRelayStatus(status string) bool {
	switch status {
	case "queued", "submitted", "landed", "closed", "failed", "expired", "unknown":
		return true
	}
	return false
}

// CloseRelayAction is what a client does next with a relayed close.
type CloseRelayAction int

const (
	// CloseRelayWait: the relay holds the close and there is time left.
	CloseRelayWait CloseRelayAction = iota
	// CloseRelayResubmit: the relay does not hold the close (for example its
	// submission was lost); hand it over again.
	CloseRelayResubmit
	// CloseRelaySelfSubmit: submit the close through the client's own path
	// now.
	CloseRelaySelfSubmit
	// CloseRelayConfirm: the relay reports the note closed; wait for the
	// vault's MutualClose event (the client's own check) until the deadline.
	CloseRelayConfirm
)

// DecideCloseRelay is the client's rule for a relayed close whose proof is
// valid until validUntil: submit it yourself once the relay gives it back
// (failed, expired) or once now is within margin of validUntil without a
// landing; resubmit a close the relay does not hold while there is time;
// otherwise wait. A status the client could not read counts as no landing.
func DecideCloseRelay(status *CloseRelayStatus, validUntil uint64, now time.Time, margin time.Duration) CloseRelayAction {
	deadline := time.Unix(int64(validUntil), 0).Add(-margin)
	late := !now.Before(deadline)
	if status != nil {
		switch {
		case status.Status == "landed" || status.Status == "closed":
			return CloseRelayConfirm
		case status.SelfSubmit || status.Status == "failed" || status.Status == "expired":
			return CloseRelaySelfSubmit
		case late:
			return CloseRelaySelfSubmit
		case status.Status == "unknown":
			return CloseRelayResubmit
		}
		return CloseRelayWait
	}
	if late {
		return CloseRelaySelfSubmit
	}
	return CloseRelayWait
}

// CloseRelayOutcome is how a followed close ended.
type CloseRelayOutcome string

const (
	// CloseRelayLanded: the vault's MutualClose event for the close was seen
	// after the relay reported it landed or closed.
	CloseRelayLanded CloseRelayOutcome = "relayed"
	// CloseRelaySelfSubmitted: the client handed the close to its own
	// submission path, which confirms the payout as it always does.
	CloseRelaySelfSubmitted CloseRelayOutcome = "self_submitted"
)

// CloseRelayFollower follows a relayed close until the vault's MutualClose
// event for it is seen, or until the client must submit it itself.
type CloseRelayFollower struct {
	// Status reads the relay's status (CloseRelayState).
	Status func(context.Context) (CloseRelayStatus, error)
	// Resubmit hands the close to the relay again (SubmitCloseRelay).
	Resubmit func(context.Context) (CloseRelayStatus, error)
	// CloseSeen reports whether the vault's MutualClose event for the close
	// is final on chain (the client's own RPC; see MutualCloseLogMatches).
	CloseSeen func(context.Context) (bool, error)
	// SelfSubmit submits the close through the client's own path.
	SelfSubmit func(context.Context) error
	Now        func() time.Time
	Poll       time.Duration
	Margin     time.Duration
	// Sleep waits between polls; tests replace it.
	Sleep func(context.Context, time.Duration) error
}

// Follow follows the close whose proof is valid until validUntil.
func (f CloseRelayFollower) Follow(ctx context.Context, validUntil uint64) (CloseRelayOutcome, error) {
	now, poll, margin, sleep := f.Now, f.Poll, f.Margin, f.Sleep
	if now == nil {
		now = time.Now
	}
	if poll <= 0 {
		poll = DefaultCloseRelayPoll
	}
	if margin <= 0 {
		margin = DefaultCloseRelaySelfSubmitMargin
	}
	if sleep == nil {
		sleep = func(ctx context.Context, wait time.Duration) error {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	selfSubmit := func() (CloseRelayOutcome, error) {
		if err := f.SelfSubmit(ctx); err != nil {
			return "", err
		}
		return CloseRelaySelfSubmitted, nil
	}
	for {
		if seen, err := f.CloseSeen(ctx); err == nil && seen {
			return CloseRelayLanded, nil
		}
		var current *CloseRelayStatus
		if status, err := f.Status(ctx); err == nil {
			current = &status
		}
		switch DecideCloseRelay(current, validUntil, now(), margin) {
		case CloseRelaySelfSubmit:
			// The event may have appeared since the first read: never send a
			// close that would only revert.
			if seen, err := f.CloseSeen(ctx); err == nil && seen {
				return CloseRelayLanded, nil
			}
			return selfSubmit()
		case CloseRelayResubmit:
			if f.Resubmit != nil {
				_, _ = f.Resubmit(ctx)
			}
		case CloseRelayConfirm:
			// Reported landed or closed: wait for the event itself, until
			// the deadline makes the client act.
			if !now().Before(time.Unix(int64(validUntil), 0).Add(-margin)) {
				if seen, err := f.CloseSeen(ctx); err == nil && seen {
					return CloseRelayLanded, nil
				}
				return selfSubmit()
			}
		}
		if err := sleep(ctx, poll); err != nil {
			return "", err
		}
	}
}

// CloseRelayLog is one receipt or eth_getLogs entry.
type CloseRelayLog struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
	Removed bool     `json:"removed"`
	// TransactionHash is set on eth_getLogs entries.
	TransactionHash string `json:"transactionHash,omitempty"`
}

// MutualCloseLogMatches reports whether logs hold the vault's MutualClose of
// exactly this close: emitted by the vault, for the note, at the nullifier,
// paying finalBalance (native units) to destination. The transaction that
// carried it (the relay's batch, or anyone's) does not matter: the vault's
// event is the payout's evidence.
func MutualCloseLogMatches(logs []CloseRelayLog, vault string, noteID uint32, nullifier string, finalBalance uint64, destination string) bool {
	want := func(value *big.Int) string { return addressABIWordFromBig(value) }
	nullifierValue, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(nullifier), "0x"), 16)
	if !ok {
		return false
	}
	destinationValue, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(destination), "0x"), 16)
	if !ok {
		return false
	}
	data := "0x" + want(nullifierValue) + want(new(big.Int).SetUint64(finalBalance)) + want(destinationValue)
	note := "0x" + want(new(big.Int).SetUint64(uint64(noteID)))
	for _, log := range logs {
		if log.Removed || !strings.EqualFold(log.Address, vault) || len(log.Topics) != 2 {
			continue
		}
		if strings.EqualFold(log.Topics[0], mutualCloseTopic) && strings.EqualFold(log.Topics[1], note) && strings.EqualFold(log.Data, data) {
			return true
		}
	}
	return false
}

// addressABIWordFromBig is value as one 32-byte ABI word, 64 hex digits.
func addressABIWordFromBig(value *big.Int) string {
	digits := value.Text(16)
	if len(digits) >= 64 {
		return digits[len(digits)-64:]
	}
	return strings.Repeat("0", 64-len(digits)) + digits
}

// CloseRelayTerms are the protocol server's relay terms, read through the
// companion (GET /v2/withdraw/relay/terms).
type CloseRelayTerms struct {
	Enabled            bool   `json:"enabled"`
	FeeUnits           string `json:"fee_units,omitempty"`
	MinValiditySeconds uint64 `json:"min_validity_seconds,omitempty"`
	ExitBatcher        string `json:"exit_batcher,omitempty"`
}

// errCloseRelayUnavailable: the protocol server does not relay closes.
var errCloseRelayUnavailable = errors.New("the zkAPI server does not relay cooperative closes; withdraw with --fees wallet or --fees payout")

// CloseRelayTerms reads the relay's terms.
func (c *Client) CloseRelayTerms(ctx context.Context) (CloseRelayTerms, error) {
	var terms CloseRelayTerms
	raw, err := c.request(ctx, http.MethodGet, "/oa/v1/withdraw/relay/terms", nil)
	if err != nil {
		return terms, err
	}
	if json.Unmarshal(raw, &terms) != nil {
		return CloseRelayTerms{}, errors.New("invalid close relay terms")
	}
	return terms, nil
}

// fee is the relay fee in native units, or an error when the relay is off.
func (t CloseRelayTerms) fee() (uint64, error) {
	if !t.Enabled {
		return 0, errCloseRelayUnavailable
	}
	fee, ok := new(big.Int).SetString(t.FeeUnits, 10)
	if !ok || fee.Sign() <= 0 || !fee.IsUint64() {
		return 0, errors.New("invalid close relay fee")
	}
	return fee.Uint64(), nil
}

// relayFallbackGas is the gas limit a relay quote reserves for the
// wallet-paid close it pre-authorizes: a mutualClose measures about 307,500
// gas, and the signer pads its own estimate by 20% plus 50,000.
const relayFallbackGas = 450_000

// addressRelayRecord is a relayed cooperative close (--fees relay).
type addressRelayRecord struct {
	// FeeUnits is the relay fee the approved quote named.
	FeeUnits uint64 `json:"fee_units"`
	// TicketHash identifies the paid fee (the companion keeps its secret).
	TicketHash string `json:"ticket_hash,omitempty"`
	// Phase: "approved" (the fee is not paid yet), "fee_paid", "submitted"
	// (the relay holds the close) or "self_submitted" (the wallet-paid close
	// replaced it).
	Phase string `json:"phase"`
	// Fallback is the approved relay quote. Its approval authorizes, besides
	// the fee, one wallet-paid close of this exact withdrawal (its binding,
	// amount, destination and nonce) within its fee reserve, should the relay
	// not land the close in time.
	Fallback AddressPaymentQuote `json:"fallback"`
	// Status is the relay's last reported status.
	Status string `json:"status,omitempty"`
}

// closeRelayStep handles a withdrawal whose fee mode is the relay (--fees
// relay, or zkapi.withdrawal_fees relay): its quote, its approval (pay the
// fee, prepare the close at the successor state, hand it to the relay), and
// following it until the vault's MutualClose of the close is final, or until
// the client submits the close itself through the wallet-paid path the
// approval pre-authorized. handled is false for everything else, which the
// ordinary withdrawal path continues.
func (h *FundingHandler) closeRelayStep(ctx context.Context, config fundingConfig, record *addressFundingRecord, wallet withdrawalWallet, options addressWithdrawalOptions, update func() AddressWithdrawalStatus) (bool, AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	if w == nil || w.Mode == "escape" || w.Transit != nil || w.Phase == "complete" {
		return false, AddressWithdrawalStatus{}, nil
	}
	relayed := func() AddressWithdrawalStatus {
		status := update()
		status.FeePayer = "relay"
		if w.Relay != nil {
			status.RelayStatus = w.Relay.Status
			status.RelayFeeUnits = new(big.Int).SetUint64(w.Relay.FeeUnits).String()
		}
		setCloseRelayMessage(&status)
		return status
	}

	if w.FeePayer != "relay" {
		if options.Fees != "relay" {
			return false, AddressWithdrawalStatus{}, nil
		}
		// Only a withdrawal nothing was prepared for yet can move to the
		// relay: the fee must be paid before the close is proved.
		if w.Binding != "" || record.Pending != nil || (w.Phase != "quoted" && w.Phase != "waiting_settlement" && w.Phase != "waiting_funds") {
			return true, update(), errors.New("this withdrawal is already prepared for a wallet-paid close; finish it with --fees wallet")
		}
		w.FeePayer, w.Phase = "relay", "quoted"
		if err := h.saveAddress(record); err != nil {
			return true, update(), err
		}
	}
	// A named --fees wallet gives the close back to the wallet-paid path
	// (the relay may still land a close it holds; the wallet's own then
	// reverts, and --confirm names the relay's transaction).
	if options.Fees == "wallet" || options.Fees == "payout" {
		if options.Fees == "payout" {
			return true, relayed(), errors.New("a relayed withdrawal falls back to the wallet-paid close only (--fees wallet)")
		}
		if record.Pending != nil || w.Phase == "confirming" {
			return false, AddressWithdrawalStatus{}, nil
		}
		w.FeePayer = ""
		if w.Phase == "relay_submitted" {
			w.Phase = "quoted"
		}
		if w.Relay != nil {
			w.Relay.Phase = "self_submitted"
		}
		if err := h.saveAddress(record); err != nil {
			return true, update(), err
		}
		return false, AddressWithdrawalStatus{}, nil
	}
	mode := quoteMode(ctx)
	switch {
	case w.Phase == "confirming" && w.SettlementHash != "":
		status, err := h.finishRelayedClose(ctx, config, record, w.SettlementHash, relayed)
		return true, status, err
	case w.Phase == "relay_submitted":
		if mode != nil && mode.Capture != nil {
			return true, relayed(), errors.New("the relay holds this close; follow it with zkapi-clientd withdraw --resume")
		}
		status, err := h.followCloseRelay(ctx, config, record, wallet, relayed, update)
		return true, status, err
	case mode != nil && mode.Capture != nil:
		status, err := h.quoteCloseRelay(ctx, config, record, wallet, mode, relayed)
		return true, status, err
	case mode != nil && mode.Approval != nil:
		status, err := h.approveCloseRelay(ctx, config, record, wallet, mode.Approval, relayed)
		return true, status, err
	}
	return true, relayed(), nil
}

// quoteCloseRelay quotes a relayed close: the payout (the balance less the
// relay fee) and, as for a wallet-paid close, the fee reserve of the
// wallet-paid close that approving it pre-authorizes as the fallback.
func (h *FundingHandler) quoteCloseRelay(ctx context.Context, config fundingConfig, record *addressFundingRecord, wallet withdrawalWallet, mode *addressQuoteMode, relayed func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	if record.Pending != nil {
		return relayed(), errors.New("a signed payment is still pending; no relay quote was made")
	}
	if wallet.Note == nil {
		return relayed(), errors.New("the reserved private note is missing; restore its recovery state")
	}
	var fee uint64
	if w.Relay != nil && w.Relay.Phase != "approved" {
		// Paid already: the note's balance is the payout.
		fee = w.Relay.FeeUnits
		w.Amount = wallet.Note.Balance
	} else {
		terms, err := h.client.CloseRelayTerms(ctx)
		if err != nil {
			return relayed(), err
		}
		if fee, err = terms.fee(); err != nil {
			return relayed(), err
		}
		if wallet.Note.Balance <= fee {
			return relayed(), errors.New("the private balance does not cover the relay fee; withdraw with --fees wallet")
		}
		w.Amount = wallet.Note.Balance - fee
	}
	nonce, err := h.addressQuantity(ctx, config, "eth_getTransactionCount", []any{record.Address, "pending"})
	if err != nil {
		return relayed(), err
	}
	if !nonce.IsUint64() || nonce.BitLen() > 53 {
		return relayed(), errors.New("invalid payment nonce")
	}
	balance, err := h.addressQuantity(ctx, config, "eth_getBalance", []any{record.Address, "pending"})
	if err != nil {
		return relayed(), err
	}
	fees, err := h.addressLowFees(ctx, config, relayFallbackGas)
	if err != nil {
		return relayed(), err
	}
	gas := new(big.Int).SetUint64(relayFallbackGas)
	quote, err := h.savePaymentQuote(record, "withdrawal", config.Contract, new(big.Int), balance, gas, relayFallbackGas, nonce.Uint64(), fees, "")
	if err != nil {
		return relayed(), err
	}
	quote.FeePolicy, quote.RelayFeeUnits = "relay", new(big.Int).SetUint64(fee).String()
	record.Quote = &quote
	if err := h.saveAddress(record); err != nil {
		return relayed(), err
	}
	*mode.Capture = quote
	return relayed(), nil
}

// approveCloseRelay carries out an approved relay quote: pay the fee (one
// metered request at the note's state), prepare the close at the successor
// state, and hand it to the relay. Every step is journaled and resumes.
func (h *FundingHandler) approveCloseRelay(ctx context.Context, config fundingConfig, record *addressFundingRecord, wallet withdrawalWallet, q *AddressPaymentQuote, relayed func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	fee, ok := new(big.Int).SetString(q.RelayFeeUnits, 10)
	if q.FeePolicy != "relay" || !ok || !fee.IsUint64() || record.Quote == nil || record.Quote.ID != q.ID || q.Kind != "withdrawal" || q.ExpiresAt <= time.Now().UnixMilli() || q.NoteID != w.NoteID || !strings.EqualFold(q.Destination, w.Destination) || q.Amount != w.Amount {
		return relayed(), errAddressQuoteChanged
	}
	if wallet.Note == nil {
		return relayed(), errors.New("the reserved private note is missing; restore its recovery state")
	}
	if w.Relay == nil {
		w.Relay = &addressRelayRecord{FeeUnits: fee.Uint64(), Phase: "approved"}
	}
	w.Relay.Fallback = *q
	if err := h.saveAddress(record); err != nil {
		return relayed(), err
	}
	previousBalance := wallet.Note.Balance
	if w.Relay.Phase == "approved" {
		ticket, err := h.client.PayCloseRelayFee(ctx)
		if err != nil {
			return relayed(), err
		}
		w.Relay.TicketHash, w.Relay.Phase = ticket.TicketHash, "fee_paid"
		if err := h.saveAddress(record); err != nil {
			return relayed(), err
		}
	}
	plan, _, err := h.relayClosePlan(ctx, config, record, previousBalance)
	if err != nil {
		return relayed(), err
	}
	w.Relay.Fallback.Binding, w.Relay.Fallback.Amount = w.Binding, w.Amount
	w.StartBlock = h.latestBlock(ctx, config)
	w.ValidUntil = plan.PublicInputs.ValidUntil
	if err := h.saveAddress(record); err != nil {
		return relayed(), err
	}
	status, err := h.client.SubmitCloseRelay(ctx)
	if err != nil {
		return relayed(), err
	}
	w.Relay.Phase, w.Relay.Status, w.Phase = "submitted", status.Status, "relay_submitted"
	record.Quote = nil
	if err := h.saveAddress(record); err != nil {
		return relayed(), err
	}
	return relayed(), nil
}

// relayClosePlan prepares the cooperative close at the note's current state
// (the companion reuses a live one, or proves it again from the kept
// clearance) and binds it to the withdrawal, as the wallet-paid path does.
func (h *FundingHandler) relayClosePlan(ctx context.Context, config fundingConfig, record *addressFundingRecord, previousBalance uint64) (withdrawalPlan, string, error) {
	w := record.Withdrawal
	var plan withdrawalPlan
	body, _ := json.Marshal(map[string]any{"destination": w.proofDestination()})
	raw, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/prepare", body)
	if err != nil {
		return plan, "", err
	}
	if json.Unmarshal(raw, &plan) != nil {
		return plan, "", errors.New("invalid withdrawal proof response")
	}
	if w.Amount != 0 && plan.PublicInputs.FinalBalance != w.Amount {
		return plan, "", errors.New("the close does not pay the quoted amount (the balance less the relay fee); preserve recovery files")
	}
	data, binding, err := withdrawalCalldata(plan, config, w, previousBalance, time.Now())
	if err != nil {
		return plan, "", err
	}
	raw, err = h.client.request(ctx, http.MethodGet, "/oa/v1/withdraw/status", nil)
	if err != nil {
		return plan, "", err
	}
	var reserved withdrawalBridgeStatus
	expected := *w
	expected.Amount, expected.Nullifier = plan.PublicInputs.FinalBalance, "0x"+addressABIWord(plan.PublicInputs.Nullifier)
	if json.Unmarshal(raw, &reserved) != nil || reserved.Phase != "reserved" || !withdrawalStatusMatches(reserved, &expected) {
		return plan, "", errors.New("withdrawal proof does not match its saved reservation")
	}
	w.Amount, w.Nullifier, w.Binding = expected.Amount, expected.Nullifier, binding
	return plan, data, nil
}

// followCloseRelay follows a close the relay holds: done once the vault's
// MutualClose of exactly this close is final (whoever's transaction carried
// it); otherwise the relay's status and the deadline decide (DecideCloseRelay):
// wait, hand the close over again, or submit it through the wallet-paid path
// the approval pre-authorized.
func (h *FundingHandler) followCloseRelay(ctx context.Context, config fundingConfig, record *addressFundingRecord, wallet withdrawalWallet, relayed, base func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	if hash, err := h.findMutualClose(ctx, config, w); err == nil && hash != "" {
		return h.finishRelayedClose(ctx, config, record, hash, relayed)
	}
	var current *CloseRelayStatus
	if status, err := h.client.CloseRelayState(ctx); err == nil {
		current = &status
		if w.Relay.Status != status.Status {
			w.Relay.Status = status.Status
			if err := h.saveAddress(record); err != nil {
				return relayed(), err
			}
		}
	}
	now := time.Now()
	action := DecideCloseRelay(current, w.ValidUntil, now, DefaultCloseRelaySelfSubmitMargin)
	late := !now.Before(time.Unix(int64(w.ValidUntil), 0).Add(-DefaultCloseRelaySelfSubmitMargin))
	switch {
	case action == CloseRelayResubmit:
		if status, err := h.client.SubmitCloseRelay(ctx); err == nil {
			w.Relay.Status = status.Status
			_ = h.saveAddress(record)
		}
	case action == CloseRelaySelfSubmit || (action == CloseRelayConfirm && late):
		return h.closeRelayFallback(ctx, config, record, wallet, relayed, base)
	}
	return relayed(), nil
}

// closeRelayFallback submits the close through the wallet-paid path, under
// the approved relay quote's pre-authorization: the same binding, amount,
// destination and nonce, within its fee reserve. When that authority no
// longer applies (another transaction took the nonce, or fees rose beyond
// the reserve) the withdrawal returns to a wallet-paid quote for the owner
// to approve.
func (h *FundingHandler) closeRelayFallback(ctx context.Context, config fundingConfig, record *addressFundingRecord, wallet withdrawalWallet, relayed, base func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	if wallet.Note == nil {
		return relayed(), errors.New("the reserved private note is missing; restore its recovery state")
	}
	_, data, err := h.relayClosePlan(ctx, config, record, wallet.Note.Balance)
	if err != nil {
		return relayed(), err
	}
	approved := w.Relay.Fallback
	approved.Binding, approved.Amount = w.Binding, w.Amount
	// The approval covered this close until the relay gave it back; the
	// signer checks the quote's other bindings as for any approval.
	approved.ExpiresAt = time.Now().Add(time.Minute).UnixMilli()
	record.Quote = &approved
	signing := context.WithValue(ctx, addressQuoteContextKey{}, &addressQuoteMode{Approval: &approved})
	err = h.signAddressTransaction(signing, config, record, "withdrawal", config.Contract, data)
	switch {
	case err == nil:
		w.Relay.Phase, w.FeePayer = "self_submitted", ""
		if err := h.saveAddress(record); err != nil {
			return base(), err
		}
		return base(), nil
	case errors.Is(err, errAddressNeedsETH):
		status := relayed()
		status.Message = "The relay did not land the close in time, and its wallet-paid fallback needs ETH for network fees: " + err.Error()
		return status, nil
	case errors.Is(err, errAddressQuoteChanged):
		record.Quote = nil
		w.Relay.Phase, w.FeePayer, w.Phase = "self_submitted", "", "quoted"
		if err := h.saveAddress(record); err != nil {
			return relayed(), err
		}
		status := base()
		status.Message = "The relay did not land the close in time and its pre-approved fallback no longer applies (the fee or nonce changed); review and approve a wallet-paid close: zkapi-clientd withdraw --to " + w.Destination + " --fees wallet"
		return status, nil
	}
	return relayed(), err
}

// findMutualClose is the transaction that emitted the vault's MutualClose of
// exactly this close, read through the payment RPC from the block the close
// was handed to the relay; "" when there is none yet.
func (h *FundingHandler) findMutualClose(ctx context.Context, config fundingConfig, w *addressWithdrawalRecord) (string, error) {
	var logs []CloseRelayLog
	filter := map[string]any{"address": config.Contract, "fromBlock": "0x" + new(big.Int).SetUint64(w.StartBlock).Text(16), "toBlock": "latest", "topics": []string{mutualCloseTopic, "0x" + addressABIWordFromBig(new(big.Int).SetUint64(w.NoteID))}}
	if err := h.addressRPC(ctx, config, "eth_getLogs", []any{filter}, &logs); err != nil {
		return "", err
	}
	for _, log := range logs {
		if MutualCloseLogMatches([]CloseRelayLog{log}, config.Contract, uint32(w.NoteID), w.Nullifier, w.Amount, w.proofDestination()) && isHex(log.TransactionHash, 32) {
			return log.TransactionHash, nil
		}
	}
	return "", nil
}

// finishRelayedClose completes a withdrawal whose close the transaction at
// hash landed: once its receipt is final and shows the vault's MutualClose of
// exactly this close (whoever sent it: the relay's batcher, or anyone), and
// the vault and indexer show the note closed, the companion confirms it.
func (h *FundingHandler) finishRelayedClose(ctx context.Context, config fundingConfig, record *addressFundingRecord, hash string, relayed func() AddressWithdrawalStatus) (AddressWithdrawalStatus, error) {
	w := record.Withdrawal
	receipt, final, err := h.addressFinalReceipt(ctx, config, hash, true)
	if err != nil {
		return relayed(), err
	}
	if !final {
		status := relayed()
		status.TransactionHash = hash
		status.Message = "The relayed close landed; waiting for Ethereum finality before finishing."
		return status, nil
	}
	if _, err := validateWithdrawalReceipt(receipt, config, w, true); err != nil {
		return relayed(), err
	}
	if err := h.corroborateWithdrawalClosed(ctx, config, w.NoteID, receipt); err != nil {
		if errors.Is(err, errWithdrawalVerificationPending) {
			status := relayed()
			status.TransactionHash = hash
			status.Message = withdrawalVerifyingMessage
			return status, nil
		}
		return relayed(), err
	}
	w.Phase, w.SettlementHash, w.TransactionHash = "confirming", strings.ToLower(hash), ""
	if err := h.saveAddress(record); err != nil {
		return relayed(), err
	}
	body, _ := json.Marshal(map[string]string{"transaction_hash": hash})
	raw, err := h.client.request(ctx, http.MethodPost, "/oa/v1/withdraw/confirm", body)
	if err != nil {
		return relayed(), err
	}
	var confirmed withdrawalBridgeStatus
	if json.Unmarshal(raw, &confirmed) != nil || !withdrawalStatusMatches(confirmed, w) || confirmed.Phase != "complete" || !strings.EqualFold(confirmed.TransactionHash, hash) {
		return relayed(), errors.New("invalid withdrawal confirmation; preserve the saved transaction")
	}
	if err := h.archiveWithdrawnDeposit(config, record); err != nil {
		return relayed(), err
	}
	record.Amount, record.Commitment, record.Phase = 0, "", "ready"
	w.Phase = "complete"
	if err := h.saveAddress(record); err != nil {
		return relayed(), err
	}
	status := relayed()
	status.PrivateBalance = 0
	return status, nil
}

// setCloseRelayStatus copies a relayed withdrawal's public progress into
// the status.
func setCloseRelayStatus(status *AddressWithdrawalStatus, w *addressWithdrawalRecord) {
	if w == nil || w.FeePayer != "relay" {
		return
	}
	status.FeePayer = "relay"
	if w.Relay != nil {
		status.RelayStatus = w.Relay.Status
		status.RelayFeeUnits = new(big.Int).SetUint64(w.Relay.FeeUnits).String()
	}
}

// setCloseRelayMessage writes the message of a relayed withdrawal's phases;
// false for a phase it has no message of its own for.
func setCloseRelayMessage(status *AddressWithdrawalStatus) bool {
	switch status.Phase {
	case "quoted":
		status.Message = "Withdrawal is reserved for the operator's close relay; review the relay quote (its fee, and the wallet-paid fallback it pre-authorizes) and approve it."
	case "relay_submitted":
		status.Message = "The operator's relay holds the cooperative close and lands it in a batch. If it has not landed 20 minutes before the proof expires, this client submits it itself (wallet-paid). New inference is paused."
		if status.RelayStatus != "" {
			status.Message += " Relay status: " + status.RelayStatus + "."
		}
	case "confirming":
		status.Message = "The relayed close is final on Ethereum; resume to finish local recovery bookkeeping."
	case "complete":
		status.Message = "The relay closed the note: the remaining private balance, less the relay fee, was paid to the destination."
	default:
		return false
	}
	return true
}
