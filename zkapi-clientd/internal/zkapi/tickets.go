package zkapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
)

// Billing modes. Metered (the default) settles each key from its measured
// usage after it is retired, one key at a time. Ticket mode buys fixed-price
// tickets: each purchase settles at the tier's price when it is bought, so
// several tickets' keys can serve requests at the same time.
const (
	BillingMetered = "metered"
	BillingTicket  = "ticket"
)

// ticketPurchaseAttempts bounds resends of one purchase ID after a lost
// companion reply; the same ID never buys a second ticket.
const ticketPurchaseAttempts = 3

// ticketTier is one tier of the protocol server's ticket catalog.
type ticketTier struct {
	TierID              uint32 `json:"tier_id"`
	TierName            string `json:"tier_name"`
	OATickets           uint32 `json:"oa_tickets"`
	PriceMicroUSD       uint64 `json:"price_micro_usd"`
	CreditLimitMicroUSD uint64 `json:"credit_limit_micro_usd"`
	DurationSeconds     uint64 `json:"duration_seconds"`
}

type ticketCatalog struct {
	Catalog struct {
		Version   int          `json:"version"`
		KeySource string       `json:"key_source"`
		Tiers     []ticketTier `json:"tiers"`
	} `json:"catalog"`
}

// ticketLease is a handed-out ticket: its key and the claim to release.
type ticketLease struct {
	providerLease
	ClientRequestID string     `json:"client_request_id"`
	PurchaseID      string     `json:"purchase_id"`
	Tier            ticketTier `json:"tier"`
	PriceUnits      uint64     `json:"price_units"`
}

func (c *Client) ticketMode() bool { return c.config.BillingMode == BillingTicket }

// ReleaseTicketClaims returns every ticket a previous run of this client
// handed out to the companion's inventory: none is in use after a restart.
func (c *Client) ReleaseTicketClaims(ctx context.Context) error {
	if !c.ticketMode() {
		return nil
	}
	return c.recoverTickets(ctx)
}

func (c *Client) checkTickets(ctx context.Context) error {
	if err := c.Check(ctx); err != nil {
		return err
	}
	data, err := c.request(ctx, http.MethodGet, "/oa/v1/status", nil)
	if err != nil {
		return err
	}
	var status struct {
		TicketsVersion int `json:"tickets_version"`
	}
	if json.Unmarshal(data, &status) != nil || status.TicketsVersion < 1 {
		return &Error{http.StatusBadGateway, "companion_tickets_unsupported"}
	}
	return nil
}

// ticketTierFor maps the request's model to the catalog tier whose OA ticket
// count is the model's (/chat/model-tickets), as the OA org prices it.
func (c *Client) ticketTierFor(ctx context.Context, body json.RawMessage) (ticketTier, error) {
	var request struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &request) != nil || request.Model == "" || strings.TrimSpace(request.Model) != request.Model {
		return ticketTier{}, &Error{http.StatusBadRequest, "invalid_model"}
	}
	count, err := c.modelTicketCount(ctx, request.Model)
	if err != nil {
		return ticketTier{}, err
	}
	raw, err := c.request(ctx, http.MethodGet, "/oa/v1/tickets", nil)
	if err != nil {
		return ticketTier{}, err
	}
	var catalog ticketCatalog
	if json.Unmarshal(raw, &catalog) != nil || catalog.Catalog.Version != 1 || catalog.Catalog.KeySource != "oa_org" {
		return ticketTier{}, &Error{http.StatusBadGateway, "invalid_companion_response"}
	}
	for _, tier := range catalog.Catalog.Tiers {
		if tier.OATickets == count {
			return tier, nil
		}
	}
	return ticketTier{}, &Error{http.StatusBadRequest, "model_ticket_tier_unavailable"}
}

// modelTicketCount is the model's OA ticket count: its explicit assignment,
// else the web's untiered rule (premium opus/image names cost 3 tickets,
// others 1). A disabled model has none.
func (c *Client) modelTicketCount(ctx context.Context, model string) (uint32, error) {
	var counts map[string]uint64
	if err := c.modelPolicyJSON(ctx, "/chat/model-tickets", &counts); err != nil {
		return 0, err
	}
	var availability struct {
		Disabled *[]string `json:"disabled_models"`
	}
	if err := c.modelPolicyJSON(ctx, "/chat/pinned-models", &availability); err != nil {
		return 0, err
	}
	if availability.Disabled == nil {
		return 0, &Error{http.StatusBadGateway, "model_policy_unavailable"}
	}
	base := strings.TrimSuffix(model, ":online")
	for _, id := range *availability.Disabled {
		if id == model || id == base {
			return 0, &Error{http.StatusBadRequest, "model_budget_unavailable"}
		}
	}
	for _, id := range []string{model, base} {
		if count, ok := counts[id]; ok {
			if count == 0 || count > 1_000 {
				return 0, &Error{http.StatusBadRequest, "model_budget_unavailable"}
			}
			return uint32(count), nil
		}
	}
	catalog, err := c.publicModelIDs(ctx)
	if err != nil {
		return 0, err
	}
	if !catalog[base] && !catalog[model] {
		return 0, &Error{http.StatusBadRequest, "model_not_found"}
	}
	name := strings.ToLower(base)
	if strings.Contains(name, "opus") || strings.Contains(name, "image") {
		return 3, nil
	}
	return 1, nil
}

func newPurchaseID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "clientd-" + hex.EncodeToString(random[:]), nil
}

// recoverTickets returns, once per process and before this process claims
// any ticket, the claims an earlier run left in the companion's inventory.
// Later calls are no-ops, so a delayed startup call can never release a
// claim held by a request of this process.
func (c *Client) recoverTickets(ctx context.Context) error {
	c.ticketRecoveryMu.Lock()
	defer c.ticketRecoveryMu.Unlock()
	if c.ticketsRecovered {
		return nil
	}
	if _, err := c.request(ctx, http.MethodPost, "/oa/v1/tickets/release-all", []byte("{}")); err != nil {
		return err
	}
	c.ticketsRecovered = true
	return nil
}

// acquireTicket hands out one ticket of exactly the terms the request's
// model selects: an unclaimed one from the companion's inventory, or a newly
// bought one. A lost companion reply is retried with the same purchase ID,
// which never buys twice. Terms the server no longer sells are selected again
// once from the current catalog.
func (c *Client) acquireTicket(ctx context.Context, body json.RawMessage) (ticketLease, error) {
	if err := c.checkTickets(ctx); err != nil {
		return ticketLease{}, err
	}
	if err := c.recoverTickets(ctx); err != nil {
		return ticketLease{}, err
	}
	for reselected := false; ; reselected = true {
		ticket, err := c.acquireTicketOnce(ctx, body)
		var failure *Error
		if !reselected && errors.As(err, &failure) && failure.Code == "ticket_terms_changed" {
			continue
		}
		return ticket, err
	}
}

func (c *Client) acquireTicketOnce(ctx context.Context, body json.RawMessage) (ticketLease, error) {
	tier, err := c.ticketTierFor(ctx, body)
	if err != nil {
		return ticketLease{}, err
	}
	purchaseID, err := newPurchaseID()
	if err != nil {
		return ticketLease{}, err
	}
	payload, _ := json.Marshal(map[string]any{"terms": tier, "purchase_id": purchaseID})
	activity.Diagnostic(ctx, "payment: ticket tier %d (%s) at a fixed %d micro-USD; settles when bought", tier.TierID, tier.TierName, tier.PriceMicroUSD)
	var raw json.RawMessage
	for attempt := 0; ; attempt++ {
		raw, err = c.request(ctx, http.MethodPost, "/oa/v1/ticket", payload)
		var failure *Error
		if err == nil || attempt+1 >= ticketPurchaseAttempts || !errors.As(err, &failure) || failure.Code != "companion_unavailable" {
			break
		}
		select {
		case <-ctx.Done():
			return ticketLease{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return ticketLease{}, err
	}
	var ticket ticketLease
	now := uint64(c.now().Unix())
	if json.Unmarshal(raw, &ticket) != nil || ticket.PurchaseID != purchaseID || ticket.ClientRequestID == "" ||
		ticket.Tier != tier || ticket.PriceUnits == 0 ||
		!usableVerification(ticket.Verified, ticket.VerificationStatus, ticket.VerificationDetail) ||
		ticket.APIKey == "" || strings.ContainsAny(ticket.APIKey, "\r\n") || ticket.ExpiresAt <= now+1 ||
		ticket.ExpiresAt > 1<<63-1 || strings.TrimRight(ticket.BaseURL, "/") != c.config.InferenceBaseURL {
		// The key was never used: return the claim, unconsumed.
		c.releaseTicket(ticket.ClientRequestID, purchaseID, false)
		return ticketLease{}, &Error{http.StatusBadGateway, "invalid_verified_lease"}
	}
	c.leaseMu.Lock()
	c.keySerial++
	ticket.serial = c.keySerial
	c.leaseMu.Unlock()
	activity.Diagnostic(ctx, "payment: key=%d from ticket (tier %d); charged %d gwei at purchase", ticket.serial, tier.TierID, ticket.PriceUnits)
	activity.Report(ctx, activity.Event{Kind: activity.KeyFresh, Key: ticket.serial})
	return ticket, nil
}

// releaseTicket ends a ticket's hand-out. A ticket serves one request: once
// the request was sent (whatever its outcome, including an ambiguous one) it
// is consumed and its key erased. Only a ticket whose key was never used
// returns to the inventory.
func (c *Client) releaseTicket(clientRequestID, purchaseID string, consume bool) {
	if clientRequestID == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{"client_request_id": clientRequestID, "purchase_id": purchaseID, "consume": consume})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = c.request(ctx, http.MethodPost, "/oa/v1/ticket/release", payload)
}
