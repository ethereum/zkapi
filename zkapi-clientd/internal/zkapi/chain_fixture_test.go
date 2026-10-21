package zkapi

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
)

// fixtureHeader is a minimal post-London block header at number with block
// time at. Its Hash is what an indexer view of that block names.
func fixtureHeader(number uint64, at int64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(number), Time: uint64(at), Difficulty: new(big.Int), Extra: []byte{}, BaseFee: big.NewInt(1_000_000_000)}
}

// fixtureNote is one vault notes(uint32) entry served by a test RPC.
type fixtureNote struct {
	commitment     string
	amount, expiry uint64
	status         uint8
}

func encodeVaultNote(note fixtureNote) string {
	commitment := note.commitment
	if commitment == "" {
		commitment = "0x0"
	}
	return "0x" + strings.ToLower(addressABIWord(commitment)) + fmt.Sprintf("%064x%064x%064x", note.amount, note.expiry, note.status)
}

// testTree computes the root and bottom-up siblings for index over a dense
// leaf prefix, exactly as the vault's incremental tree does.
func testTree(leaves []*big.Int, index uint32) (*big.Int, []*big.Int) {
	zero := merkleZeroHashes()
	level := append([]*big.Int{}, leaves...)
	position := uint64(index)
	siblings := make([]*big.Int, 0, merkleDepth)
	for depth := 0; depth < merkleDepth; depth++ {
		if sibling := position ^ 1; sibling < uint64(len(level)) {
			siblings = append(siblings, level[sibling])
		} else {
			siblings = append(siblings, zero[depth])
		}
		next := make([]*big.Int, (len(level)+1)/2)
		for i := range next {
			right := zero[depth]
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}
			next[i] = merkleNode(level[2*i], right)
		}
		level = next
		position >>= 1
	}
	if len(level) == 0 {
		return zero[merkleDepth], siblings
	}
	return level[0], siblings
}

func fieldHexes(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = fmt.Sprintf("0x%x", value)
	}
	return out
}

func fieldValue(value string) *big.Int {
	parsed, ok := parseFieldElement(value)
	if !ok {
		panic("invalid fixture field " + value)
	}
	return parsed
}

// depositEventReceipt is a successful receipt with one NoteDeposited log
// whose newRoot is zero.
func depositEventReceipt(contract string, noteID uint32, commitment string, amount, expiry uint64) ethReceipt {
	return depositEventReceiptAt(contract, noteID, commitment, amount, expiry, nil)
}

// depositEventReceiptAt is depositEventReceipt with NoteDeposited.newRoot.
func depositEventReceiptAt(contract string, noteID uint32, commitment string, amount, expiry uint64, root *big.Int) ethReceipt {
	if root == nil {
		root = new(big.Int)
	}
	raw := fmt.Sprintf(`{"status":"0x1","to":%q,"logs":[{"address":%q,"topics":[%q,"0x%064x","0x%s"],"data":"0x%064x%064x%064x"}]}`, contract, contract, depositEventTopic, noteID, addressABIWord(commitment), amount, expiry, root)
	var receipt ethReceipt
	_ = json.Unmarshal([]byte(raw), &receipt)
	return receipt
}

func snapshotBody(leaves []*big.Int, block uint64, hash string) map[string]any {
	root, _ := testTree(leaves, 0)
	return map[string]any{"root": fmt.Sprintf("0x%x", root), "next_note_id": len(leaves), "leaves": fieldHexes(leaves), "block_number": block, "block_hash": hash}
}
