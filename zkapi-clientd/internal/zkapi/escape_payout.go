package zkapi

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// Design §6.4 E5: an escape pays B − c_final, where c_final is the largest of
// the concession at initiation and every EscapeConcessionRaised for the note
// between initiation and finalization; a raise never takes more than the
// state's bound b. The same rule as the companion's
// (zkapi-client exit_policy::match_escape_payout), checked against the shared
// vectors in protocol/rust/crates/zkapi-client/tests/vectors/exit-rules.json.

var escapeConcessionRaisedTopic = crypto.Keccak256Hash([]byte("EscapeConcessionRaised(uint32,uint256,uint128,uint128)")).Hex()

// escapePayoutMatch is what a finalized or credited escape payout shows.
type escapePayoutMatch struct {
	Matches       bool
	ConcededFinal uint64
	// ExceededBound is E5's concession_exceeded_bound alert: the payout is
	// below B − b. The record still closes.
	ExceededBound bool
}

// matchEscapePayout accepts paid iff paid == B − max(c_init, raises...) and
// paid <= B − c_init. bound, when known, decides only the alert.
func matchEscapePayout(paid, stateBalance, concededAtInit uint64, raises []uint64, bound *uint64) escapePayoutMatch {
	final := concededAtInit
	for _, raise := range raises {
		if raise > final {
			final = raise
		}
	}
	if final > stateBalance || concededAtInit > stateBalance || paid != stateBalance-final {
		return escapePayoutMatch{}
	}
	exceeded := bound != nil && *bound < stateBalance && paid < stateBalance-*bound
	return escapePayoutMatch{Matches: true, ConcededFinal: final, ExceededBound: exceeded}
}

// escapeRaises reads the concessions EscapeConcessionRaised recorded for
// noteID at nullifier between fromBlock and toBlock through the pinned RPC.
func (h *FundingHandler) escapeRaises(ctx context.Context, config fundingConfig, noteID uint64, nullifier string, fromBlock, toBlock uint64) ([]uint64, error) {
	var logs []struct {
		Address string   `json:"address"`
		Topics  []string `json:"topics"`
		Data    string   `json:"data"`
		Removed bool     `json:"removed"`
	}
	filter := map[string]any{"address": config.Contract, "fromBlock": fmt.Sprintf("0x%x", fromBlock), "toBlock": fmt.Sprintf("0x%x", toBlock), "topics": []string{escapeConcessionRaisedTopic, fmt.Sprintf("0x%064x", noteID)}}
	if err := h.addressRPC(ctx, config, "eth_getLogs", []any{filter}, &logs); err != nil {
		return nil, err
	}
	var raises []uint64
	for _, log := range logs {
		if log.Removed || !strings.EqualFold(log.Address, config.Contract) || len(log.Topics) != 2 || !strings.EqualFold(log.Topics[0], escapeConcessionRaisedTopic) {
			continue
		}
		if !isHex(log.Data, 96) {
			return nil, errors.New("invalid EscapeConcessionRaised log")
		}
		data := strings.TrimPrefix(log.Data, "0x")
		if !strings.EqualFold(data[:64], addressABIWord(nullifier)) {
			continue
		}
		conceded, ok := new(big.Int).SetString(data[64:128], 16)
		if !ok || !conceded.IsUint64() {
			return nil, errors.New("invalid EscapeConcessionRaised log")
		}
		raises = append(raises, conceded.Uint64())
	}
	return raises, nil
}
