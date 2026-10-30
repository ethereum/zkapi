package zkapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

// Delegate sends one self-contained, non-streaming completion as an
// independent request. Unlike Complete it never classifies a conversation:
// every call gets a fresh Tor isolation identity, a fresh lease that is neither
// taken from nor left in the reuse cache, and (when rewriting is configured) a
// transcript that exists only for this call. Chat conversation, transcript and
// cached-key state are not read or extended. The request slot, lease
// acquisition, budget and settlement are the same as for chat; in ticket
// billing mode each delegation buys its own ticket, as each chat request does.
//
// Delegation is defined only for daemon-native Tor routing. Without it the call
// is refused before queueing, model policy, rewriting or any lease request.
func (c *Client) Delegate(ctx context.Context, body json.RawMessage) (*http.Response, error) {
	if !c.config.TorMode || !relay.IsTor(c.config.TorEndpoint) {
		return nil, &Error{http.StatusPreconditionFailed, "delegation_requires_tor"}
	}
	if err := checkDelegationBody(body); err != nil {
		return nil, err
	}
	select {
	case c.requestSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-c.requestSlot }
	transferred := false
	var selectedKey uint64
	defer func() {
		if !transferred {
			if selectedKey != 0 {
				activity.Report(ctx, activity.Event{Kind: activity.KeyReleased, Key: selectedKey})
			}
			release()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identity, err := relay.NewTorIdentity()
	if err != nil {
		return nil, &Error{http.StatusBadGateway, "tor_preparation_failed"}
	}
	body, err = c.prepareDelegation(ctx, body, identity)
	if err != nil {
		return nil, err
	}
	if c.ticketMode() {
		// Ticket billing: the delegation buys its own fixed-price ticket, a
		// key no other request uses, consumed after this call. The ticket is
		// settled when bought, so its inference runs outside the request slot.
		ticket, err := c.acquireTicket(ctx, body)
		if err != nil {
			return nil, err
		}
		transferred = true
		release()
		return c.completeWithTicket(ctx, body, identity, ticket)
	}
	// A key cached by chat is a provider-visible identifier of that chat. It
	// never serves a delegation, and reuse=false leaves no key for chat.
	c.cachedLease = nil
	lease, err := c.waitForLease(ctx, body, false)
	if err != nil {
		return nil, err
	}
	selectedKey = lease.serial
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(relay.WithTorIdentity(ctx, identity), http.MethodPost, c.config.InferenceBaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create inference request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+lease.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := c.inference.Do(req)
	if response != nil {
		response.Header.Del("X-OA-Verification-Detail")
		response.Header.Set("X-OA-Verification-Status", lease.VerificationStatus)
		if lease.VerificationStatus == "verifier-unavailable" {
			response.Header.Set("X-OA-Verification-Detail", lease.VerificationDetail)
		}
	}
	if err != nil {
		// Provider usage is ambiguous after a transport failure. Never retry.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{http.StatusBadGateway, "inference_transport_failed"}
	}
	response.Body = holdResponseSlotResult(ctx, response.Body, func(complete bool) {
		c.cachedLease = nil
		activity.Report(ctx, activity.Event{Kind: activity.KeyReleased, Key: lease.serial,
			Complete: complete && response.StatusCode >= 200 && response.StatusCode < 300})
		release()
	})
	transferred = true
	return response, nil
}

// checkDelegationBody is defense in depth behind the server's construction:
// a delegation is one non-streaming completion without provider plugins,
// tools or web search, whatever the caller assembled.
func checkDelegationBody(body json.RawMessage) error {
	var values map[string]json.RawMessage
	if json.Unmarshal(body, &values) != nil || values == nil {
		return &Error{http.StatusBadRequest, "invalid_delegation"}
	}
	for key := range values {
		switch key {
		case "model", "messages", "max_tokens", "stream", "reasoning":
		default:
			return &Error{http.StatusBadRequest, "invalid_delegation"}
		}
	}
	var model string
	if json.Unmarshal(values["model"], &model) != nil || model == "" || strings.HasSuffix(strings.ToLower(model), ":online") {
		return &Error{http.StatusBadRequest, "invalid_delegation"}
	}
	if stream, ok := values["stream"]; ok && string(stream) != "false" {
		return &Error{http.StatusBadRequest, "invalid_delegation"}
	}
	return nil
}

// prepareDelegation opens this call's isolated Tor stream while any configured
// rewrite runs, so an unavailable Tor fails before a lease is requested. The
// rewrite uses a transcript scoped to this call: no earlier delegation or chat
// turn is replayed, and nothing is retained for later requests.
func (c *Client) prepareDelegation(ctx context.Context, body json.RawMessage, identity string) (json.RawMessage, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	prepare := c.prepareTor
	if prepare == nil {
		prepare = relay.PrepareTor
	}
	ready := make(chan error, 1)
	go func() { ready <- prepare(ctx, c.config.TorEndpoint, c.config.InferenceBaseURL, identity) }()
	var err error
	if c.config.Rewriter.Enabled() {
		var transcript rewriter.Transcript
		// No notice is published: delegation results carry no rewrite preview.
		body, _, err = transcript.Rewrite(ctx, body, c.config.Rewriter)
		if err != nil {
			cancel()
		}
	}
	routeErr := <-ready
	if err != nil {
		return nil, err
	}
	if routeErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{http.StatusBadGateway, "tor_preparation_failed"}
	}
	return body, nil
}
