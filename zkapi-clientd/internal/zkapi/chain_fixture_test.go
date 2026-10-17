package zkapi

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
)

// The vault's incremental Merkle tree, which the fixture indexers' roots
// follow (zkapi-core v2.rs; checked against the Rust vectors in
// poseidon_test.go). clientd itself never hashes the tree: activation is the
// companion's reading of the vault.
const merkleDepth = 32

var domainNode = poseidonDomain("zkapi.v2.node")

// merkleNode mirrors v2::merkle_node (the vault's MerkleUpdateLib.poseidonNodeHash): one
// permutation of the state (domainNode, left, right), rate lane one.
func merkleNode(left, right *big.Int) *big.Int {
	state := [poseidonWidth]*big.Int{
		new(big.Int).Set(domainNode),
		new(big.Int).Mod(left, bn254ScalarModulus),
		new(big.Int).Mod(right, bn254ScalarModulus),
	}
	poseidonPermute(&state)
	return state[1]
}

var merkleZeroHashes = sync.OnceValue(func() [merkleDepth + 1]*big.Int {
	var zero [merkleDepth + 1]*big.Int
	zero[0] = new(big.Int)
	for level := 1; level <= merkleDepth; level++ {
		zero[level] = merkleNode(zero[level-1], zero[level-1])
	}
	return zero
})

// merkleRoot mirrors v2::merkle_root for a leaf and its 32 bottom-up siblings.
func merkleRoot(index uint32, leaf *big.Int, siblings []*big.Int) *big.Int {
	current := new(big.Int).Set(leaf)
	for level, sibling := range siblings {
		if (index>>level)&1 == 0 {
			current = merkleNode(current, sibling)
		} else {
			current = merkleNode(sibling, current)
		}
	}
	return current
}

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

// depositEventReceipt is a successful receipt with one NoteDeposited log.
func depositEventReceipt(contract string, noteID uint32, commitment string, amount, expiry uint64) ethReceipt {
	raw := fmt.Sprintf(`{"status":"0x1","to":%q,"logs":[{"address":%q,"topics":[%q,"0x%064x","0x%s"],"data":"0x%064x%064x"}]}`, contract, contract, depositEventTopic, noteID, addressABIWord(commitment), amount, expiry)
	var receipt ethReceipt
	_ = json.Unmarshal([]byte(raw), &receipt)
	return receipt
}

// snapshotBody is an indexer snapshot that records notes, none of them
// activated yet: its tree is still empty.
func snapshotBody(notes []fixtureNote, block uint64, hash string) map[string]any {
	recorded, tree := make([]*big.Int, len(notes)), make([]*big.Int, len(notes))
	for id, note := range notes {
		recorded[id], tree[id] = noteLeaf(uint32(id), fieldValue(note.commitment), note.amount, note.expiry), new(big.Int)
	}
	root, _ := testTree(tree, 0)
	return map[string]any{"root": fmt.Sprintf("0x%x", root), "next_note_id": len(notes), "activation_cursor": 0, "leaves": fieldHexes(tree), "note_leaves": fieldHexes(recorded), "notes": fixtureNoteRecords(notes), "block_number": block, "block_hash": hash}
}
