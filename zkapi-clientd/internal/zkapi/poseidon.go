package zkapi

import (
	"fmt"
	"math/big"
	"sync"
)

// A Go port of zkAPI v2's own Poseidon (zkapi-core v2.rs, arkworks
// PoseidonSponge), used only to recompute public note leaves and Merkle nodes
// from vault state and the indexer's privacy-safe tree snapshot. It is not
// circomlib Poseidon.
const (
	poseidonWidth         = 3
	poseidonRate          = 2
	poseidonFullRounds    = 8
	poseidonPartialRounds = 57
	poseidonRounds        = poseidonFullRounds + poseidonPartialRounds
	merkleDepth           = 32
)

var bn254ScalarModulus, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)

var poseidonARK, poseidonMDS = loadPoseidonParameters()

var (
	// domainLeaf is DOMAIN_LEAF' of vault revision 4 (circuit
	// zkapi-v2-concession-v2), the capacity domain of a note leaf.
	domainLeaf = poseidonDomain("zkapi.v2c.leaf")
	domainNode = poseidonDomain("zkapi.v2.node")
)

func loadPoseidonParameters() (ark [poseidonRounds * poseidonWidth]*big.Int, mds [poseidonWidth][poseidonWidth]*big.Int) {
	parse := func(value string) *big.Int {
		parsed, ok := new(big.Int).SetString(value, 16)
		if !ok || parsed.Cmp(bn254ScalarModulus) >= 0 {
			panic(fmt.Sprintf("invalid packaged Poseidon constant %s", value))
		}
		return parsed
	}
	for i, value := range poseidonRoundConstantHex {
		ark[i] = parse(value)
	}
	for i, row := range poseidonMDSHex {
		for j, value := range row {
			mds[i][j] = parse(value)
		}
	}
	return ark, mds
}

// poseidonDomain mirrors Fr::from_be_bytes_mod_order(label).
func poseidonDomain(label string) *big.Int {
	return new(big.Int).Mod(new(big.Int).SetBytes([]byte(label)), bn254ScalarModulus)
}

func poseidonPermute(state *[poseidonWidth]*big.Int) {
	square, product := new(big.Int), new(big.Int)
	var mixed [poseidonWidth]*big.Int
	for i := range mixed {
		mixed[i] = new(big.Int)
	}
	sbox := func(value *big.Int) {
		square.Mul(value, value).Mod(square, bn254ScalarModulus)
		square.Mul(square, square).Mod(square, bn254ScalarModulus)
		value.Mul(square, value).Mod(value, bn254ScalarModulus)
	}
	for round := 0; round < poseidonRounds; round++ {
		full := round < poseidonFullRounds/2 || round >= poseidonFullRounds/2+poseidonPartialRounds
		for i, value := range state {
			value.Add(value, poseidonARK[round*poseidonWidth+i])
			if value.Cmp(bn254ScalarModulus) >= 0 {
				value.Sub(value, bn254ScalarModulus)
			}
			if i == 0 || full {
				sbox(value)
			}
		}
		for i := range mixed {
			mixed[i].SetUint64(0)
			for j, value := range state {
				mixed[i].Add(mixed[i], product.Mul(value, poseidonMDS[i][j]))
			}
			mixed[i].Mod(mixed[i], bn254ScalarModulus)
		}
		for i := range state {
			state[i].Set(mixed[i])
		}
	}
}

// poseidonHash mirrors v2::hash_fields: one duplex sponge (capacity lane 0)
// absorbs inputs into the two rate lanes, permuting only when a further input
// needs a full lane, then squeezes rate lane one after a final permutation.
// Inputs are reduced modulo r like Fr::from_be_bytes_mod_order.
func poseidonHash(inputs ...*big.Int) *big.Int {
	state := [poseidonWidth]*big.Int{new(big.Int), new(big.Int), new(big.Int)}
	next := 0
	for _, input := range inputs {
		if next == poseidonRate {
			poseidonPermute(&state)
			next = 0
		}
		lane := state[1+next]
		lane.Add(lane, new(big.Int).Mod(input, bn254ScalarModulus))
		if lane.Cmp(bn254ScalarModulus) >= 0 {
			lane.Sub(lane, bn254ScalarModulus)
		}
		next++
	}
	poseidonPermute(&state)
	return state[1]
}

// noteFields mirrors v2::note_fields, the vault's NoteLeafLib.pack and the
// withdrawal statement's public input 8: noteID·2^192 + amount·2^64 + expiry,
// below 2^224. Deposits are at most 2^53 - 1 units, so a uint64 amount covers
// every note of the vault.
func noteFields(noteID uint32, amount, expiry uint64) *big.Int {
	fields := new(big.Int).Lsh(new(big.Int).SetUint64(uint64(noteID)), 192)
	fields.Or(fields, new(big.Int).Lsh(new(big.Int).SetUint64(amount), 64))
	return fields.Or(fields, new(big.Int).SetUint64(expiry))
}

// noteLeaf mirrors v2::note_leaf, the vault's NoteLeafLib.computeLeaf: one
// permutation of (domainLeaf, commitment, noteFields(noteID, amount, expiry)),
// rate lane one.
func noteLeaf(noteID uint32, commitment *big.Int, amount, expiry uint64) *big.Int {
	return noteLeafFromFields(commitment, noteFields(noteID, amount, expiry))
}

// noteLeafFromFields mirrors v2::note_leaf_from_fields over packed fields.
func noteLeafFromFields(commitment, fields *big.Int) *big.Int {
	return poseidonCompress(domainLeaf, commitment, fields)
}

// merkleNode mirrors v2::merkle_node (the vault's MerkleUpdateLib.poseidonNodeHash).
func merkleNode(left, right *big.Int) *big.Int {
	return poseidonCompress(domainNode, left, right)
}

// poseidonCompress is one permutation of the state (domain, left, right),
// returning rate lane one. The domain sits in the capacity lane, so a node
// and a leaf each cost one permutation and cannot collide with each other or
// with a poseidonHash output, whose capacity lane starts at zero.
func poseidonCompress(domain, left, right *big.Int) *big.Int {
	state := [poseidonWidth]*big.Int{
		new(big.Int).Set(domain),
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

// parseFieldElement accepts the indexer's and companion's 0x hex (with or
// without leading zeros) only when it is a canonical BN254 scalar.
func parseFieldElement(value string) (*big.Int, bool) {
	if !isField(value) {
		return nil, false
	}
	parsed, ok := new(big.Int).SetString(value[2:], 16)
	if !ok || parsed.Cmp(bn254ScalarModulus) >= 0 {
		return nil, false
	}
	return parsed, true
}
