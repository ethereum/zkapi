package zkapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"

	"context"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
)

// Only the immediately preceding request is remembered. Keeping one-way
// message digests bounds retained state and avoids storing prompts. Access is
// serialized by requestSlot, including through the end of streamed responses.
// This is a heuristic, not a user identity: identical histories are linked.
// Interleaved chats conservatively rotate instead of searching old histories.
type conversation struct {
	messages [][32]byte
	identity string
	serial   uint64
}

func (c *Client) reportConversation(ctx context.Context, previous uint64) {
	kind := "same (previous messages are a prefix)"
	if previous != c.conversation.serial {
		kind = "new (no previous prefix); fresh key required"
	}
	activity.Diagnostic(ctx, "conversation=%d %s", c.conversation.serial, kind)
}

func messageDigests(body json.RawMessage) ([][32]byte, error) {
	var request struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &request); err != nil || len(request.Messages) == 0 {
		return nil, errors.New("Tor conversation requires messages")
	}
	digests := make([][32]byte, len(request.Messages))
	for i, message := range request.Messages {
		decoder := json.NewDecoder(bytes.NewReader(message))
		decoder.UseNumber() // Never collapse distinct large integers through float64.
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || value == nil {
			return nil, errors.New("invalid Tor conversation message")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, errors.New("invalid message JSON")
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		digests[i] = sha256.Sum256(canonical)
	}
	return digests, nil
}

func (c *Client) selectConversation(body json.RawMessage) (string, error) {
	messages, err := messageDigests(body)
	if err != nil {
		return "", err
	}
	previous := c.conversation
	continues := previous.identity != "" && len(messages) >= len(previous.messages)
	if continues {
		for i, digest := range previous.messages {
			if messages[i] != digest {
				continues = false
				break
			}
		}
	}
	identity := previous.identity
	if !continues {
		identity, err = relay.NewTorIdentity()
		if err != nil {
			return "", err
		}
		// A key is also a provider-visible identifier. It must never follow us
		// onto a new conversation circuit, even within the reuse window.
		c.cachedLease = nil
	}
	serial := previous.serial
	if !continues {
		serial++
	}
	c.conversation = conversation{messages: messages, identity: identity, serial: serial}
	return identity, nil
}
