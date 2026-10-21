package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ServeAdminHTTP is mounted behind API bearer, browser-origin, and owner
// management-token checks. Quoting cannot sign; approval names a saved quote.
func (h *FundingHandler) ServeAdminHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "JSON required"})
		return
	}
	decode := func(body any) error { return decodeJSON(http.MaxBytesReader(w, r.Body, 1024), body) }
	var result any
	var err error
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/funding/address":
		result, err = h.Address(ctx)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/withdrawal":
		result, err = h.AddressWithdrawal(ctx)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/escape":
		result, err = h.AddressWithdrawal(ctx)
	case r.URL.Path == "/admin/withdrawal/gasless":
		// Design 3.1: the gasless pre-flight, with the request's bundler.
		var body withdrawalRequestOptions
		if r.Method == http.MethodPost {
			err = decode(&body)
		}
		if err == nil {
			result, err = h.GaslessAvailability(WithWithdrawalOptions(ctx, body.options()))
		}
	case r.Method == http.MethodPost && (r.URL.Path == "/admin/escape" || r.URL.Path == "/admin/escape/quote"):
		// Design §6.4 E4: conceded is the amount the owner confirmed after
		// reviewing the decision; without it only the decision is returned.
		var body struct {
			Destination string  `json:"destination"`
			NoteID      *uint64 `json:"note_id"`
			Conceded    *uint64 `json:"conceded,omitempty"`
			EarlyExit   string  `json:"early_exit,omitempty"`
			withdrawalRequestOptions
		}
		if err = decode(&body); err == nil {
			ctx = WithWithdrawalOptions(ctx, body.options())
			if body.NoteID == nil {
				err = errors.New("an escape requires the selected private note ID")
			} else if r.URL.Path == "/admin/escape/quote" {
				result, err = h.QuoteAddressEscape(ctx, body.Destination, *body.NoteID, body.Conceded, body.EarlyExit)
			} else {
				result, err = h.EscapeAddress(ctx, body.Destination, *body.NoteID, body.Conceded, body.EarlyExit)
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/escape/cancel":
		var body struct{}
		if err = decode(&body); err == nil {
			result, err = h.CancelAddressEscape(ctx)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/escape/claim/quote":
		var body struct {
			Destination string `json:"destination"`
		}
		if err = decode(&body); err == nil {
			result, err = h.QuoteEscapeClaim(ctx, body.Destination)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/escape/approve":
		var body struct {
			QuoteID string `json:"quote_id"`
		}
		if err = decode(&body); err == nil {
			if len(body.QuoteID) != 64 {
				err = errors.New("invalid quote ID")
			} else {
				result, err = h.ApproveAddressEscape(ctx, body.QuoteID)
			}
		}
	case r.Method == http.MethodGet && r.URL.Path == "/admin/escape/quote":
		result, err = h.SavedEscapeQuote(ctx)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/return":
		result, err = h.AddressReturn(ctx)
	case r.Method == http.MethodGet && (r.URL.Path == "/admin/funding/quote" || r.URL.Path == "/admin/withdrawal/quote" || r.URL.Path == "/admin/return/quote"):
		kind := "deposit"
		if r.URL.Path == "/admin/withdrawal/quote" {
			kind = "withdrawal"
		} else if r.URL.Path == "/admin/return/quote" {
			kind = "return"
		}
		result, err = h.SavedAddressQuote(ctx, kind)
	case r.Method == http.MethodPost && r.URL.Path == "/admin/funding/quote":
		var body struct {
			Amount   uint64 `json:"amount"`
			MicroUSD uint64 `json:"micro_usd"`
		}
		if err = decode(&body); err == nil {
			if (body.Amount == 0) == (body.MicroUSD == 0) {
				err = errors.New("choose one positive ETH or USD principal")
			} else if body.MicroUSD != 0 {
				result, err = h.QuoteAddressDepositUSD(ctx, body.MicroUSD)
			} else {
				result, err = h.QuoteAddressDeposit(ctx, body.Amount)
			}
		}
	case r.Method == http.MethodPost && (r.URL.Path == "/admin/funding/approve" || r.URL.Path == "/admin/withdrawal/approve" || r.URL.Path == "/admin/return/approve"):
		var body struct {
			QuoteID string `json:"quote_id"`
		}
		if err = decode(&body); err == nil {
			if len(body.QuoteID) != 64 {
				err = errors.New("invalid quote ID")
			} else {
				switch r.URL.Path {
				case "/admin/funding/approve":
					result, err = h.ApproveAddressDeposit(ctx, body.QuoteID)
				case "/admin/withdrawal/approve":
					result, err = h.ApproveAddressWithdrawal(ctx, body.QuoteID)
				case "/admin/return/approve":
					result, err = h.ApproveAddressReturn(ctx, body.QuoteID)
				}
			}
		}
	case r.Method == http.MethodPost && (r.URL.Path == "/admin/withdrawal" || r.URL.Path == "/admin/withdrawal/quote"):
		var body struct {
			Destination                 string  `json:"destination"`
			NoteID                      *uint64 `json:"note_id"`
			RetryTransactionHash        string  `json:"retry_transaction_hash,omitempty"`
			ConfirmationTransactionHash string  `json:"confirmation_transaction_hash,omitempty"`
			AcceptUnsettledRequestRisk  bool    `json:"accept_unsettled_request_risk,omitempty"`
			withdrawalRequestOptions
		}
		if err = decode(&body); err == nil {
			ctx = WithWithdrawalOptions(ctx, body.options())
			if body.NoteID == nil {
				err = errors.New("withdrawal requires the selected private note ID")
			} else if r.URL.Path == "/admin/withdrawal/quote" {
				if body.ConfirmationTransactionHash != "" {
					err = errors.New("receipt adoption cannot create a quote")
				} else {
					result, err = h.QuoteAddressWithdrawal(ctx, body.Destination, *body.NoteID, body.RetryTransactionHash, body.AcceptUnsettledRequestRisk)
				}
			} else if body.AcceptUnsettledRequestRisk {
				err = errors.New("the unsettled-request acknowledgement is given only with a new withdrawal quote")
			} else {
				result, err = h.WithdrawAddress(ctx, body.Destination, *body.NoteID, body.RetryTransactionHash, body.ConfirmationTransactionHash)
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/funding/deposit":
		var body struct {
			Amount uint64 `json:"amount"`
		}
		if err = decode(&body); err == nil {
			if body.Amount == 0 {
				err = errors.New("missing saved deposit amount")
			} else {
				result, err = h.FundAddress(ctx, body.Amount)
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/funding/rebind":
		// Both IDs are optional; the handler re-derives and verifies the
		// binding itself. Range-check before any companion or chain access.
		var body struct {
			NoteID        *uint64 `json:"note_id"`
			ReplaceNoteID *uint64 `json:"replace_note_id"`
		}
		if err = decode(&body); err == nil {
			if (body.NoteID != nil && *body.NoteID > 0xffffffff) || (body.ReplaceNoteID != nil && *body.ReplaceNoteID > 0xffffffff) {
				err = errors.New("note IDs must be 32-bit vault note IDs")
			} else {
				result, err = h.RebindDeposit(ctx, body.NoteID, body.ReplaceNoteID)
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/return/quote":
		var body struct {
			Destination string `json:"destination"`
			AmountWei   string `json:"amount_wei"`
		}
		if err = decode(&body); err == nil {
			result, err = h.QuoteAddressReturn(ctx, body.Destination, body.AmountWei)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/return":
		// The replay endpoint accepts no instructions that could change value,
		// destination, nonce, or fees of the saved signed transaction.
		if r.ContentLength > 0 {
			var body struct{}
			err = decode(&body)
		}
		if err == nil {
			result, err = h.ResumeAddressReturn(ctx)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unknown management endpoint"})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		failure := map[string]string{"error": err.Error()}
		// The guided withdrawal acts on these refusals, and repair's
		// refused release names ownership_proof_sent, so their code crosses
		// the management boundary as well as the message.
		var companion *Error
		if errors.As(err, &companion) && (companion.Code == "unsettled_request_state" || companion.Code == "unsettled_clearance_reserved" || companion.Code == "receipt_journal_missing" || companion.Code == "ownership_proof_sent" || companion.Code == "escape_required" || companion.Code == "device_not_newest" || companion.Code == "conceded_mismatch") {
			failure["code"] = companion.Code
		}
		// A gasless refusal names its reason so a guided flow can offer the
		// wallet-paid path.
		if code := GaslessRefusalCode(err); code != "" {
			failure["code"] = code
		}
		_ = json.NewEncoder(w).Encode(failure)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

// withdrawalRequestOptions are the gasless choices a withdrawal or escape
// request carries (design 3.3).
type withdrawalRequestOptions struct {
	Fees              string `json:"fees,omitempty"`
	FeeCapGwei        uint64 `json:"fee_cap_gwei,omitempty"`
	BundlerURL        string `json:"bundler_url,omitempty"`
	AllowExpensiveGas bool   `json:"allow_expensive_gas,omitempty"`
	Collect           bool   `json:"collect,omitempty"`
	Sweep             bool   `json:"sweep,omitempty"`
	ClaimCredit       bool   `json:"claim_credit,omitempty"`
}

func (o withdrawalRequestOptions) options() addressWithdrawalOptions {
	return addressWithdrawalOptions{Fees: o.Fees, FeeCapGwei: o.FeeCapGwei, BundlerURL: o.BundlerURL, AllowExpensiveGas: o.AllowExpensiveGas, Collect: o.Collect, Sweep: o.Sweep, ClaimCredit: o.ClaimCredit}
}
