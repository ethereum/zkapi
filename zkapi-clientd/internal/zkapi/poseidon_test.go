package zkapi

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The vectors were produced by zkapi-core's own v2 functions (arkworks), not
// by this port, so a transcription error in any constant fails here.
type poseidonVectors struct {
	Modulus  string            `json:"modulus"`
	Domains  map[string]string `json:"domains"`
	Fields   []hashVector      `json:"hash_fields"`
	Reduced  []hashVector      `json:"hash_felts_reduced"`
	Register []struct {
		Secret     string `json:"secret"`
		Commitment string `json:"commitment"`
	} `json:"registration_commitment"`
	Leaves []struct {
		NoteID     uint32 `json:"note_id"`
		Commitment string `json:"commitment"`
		Amount     string `json:"amount"`
		Expiry     string `json:"expiry_ts"`
		Fields     string `json:"fields"`
		Leaf       string `json:"leaf"`
	} `json:"note_leaf"`
	Nodes []struct {
		Left, Right, Node string
	} `json:"merkle_node"`
	Zero  []string `json:"zero_hashes"`
	Roots []struct {
		NoteID   uint32   `json:"note_id"`
		Leaf     string   `json:"leaf"`
		Siblings []string `json:"siblings"`
		Root     string   `json:"root"`
	} `json:"merkle_root"`
}

type hashVector struct {
	Inputs []string `json:"inputs"`
	Output string   `json:"output"`
}

func loadPoseidonVectors(t *testing.T) poseidonVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "poseidon-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors poseidonVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func vectorInt(t *testing.T, value string) *big.Int {
	t.Helper()
	parsed, ok := new(big.Int).SetString(value[2:], 16)
	if !ok {
		t.Fatalf("invalid vector %s", value)
	}
	return parsed
}

func fieldWord(value *big.Int) string { return fmt.Sprintf("0x%064x", value) }

func TestPoseidonPortMatchesZkapiCoreVectors(t *testing.T) {
	vectors := loadPoseidonVectors(t)
	if fieldWord(bn254ScalarModulus) != vectors.Modulus {
		t.Fatal("wrong BN254 scalar modulus")
	}
	for label, want := range vectors.Domains {
		if got := fieldWord(poseidonDomain(label)); got != want {
			t.Errorf("domain %s = %s, want %s", label, got, want)
		}
	}
	for _, vector := range append(append([]hashVector{}, vectors.Fields...), vectors.Reduced...) {
		inputs := make([]*big.Int, len(vector.Inputs))
		for i, input := range vector.Inputs {
			inputs[i] = vectorInt(t, input)
		}
		if got := fieldWord(poseidonHash(inputs...)); got != vector.Output {
			t.Errorf("hash of %d inputs = %s, want %s", len(inputs), got, vector.Output)
		}
	}
	if len(vectors.Fields) < 8 || len(vectors.Reduced) == 0 || len(vectors.Leaves) == 0 || len(vectors.Nodes) == 0 || len(vectors.Roots) == 0 || len(vectors.Register) == 0 {
		t.Fatal("incomplete Poseidon vectors")
	}
	registration := poseidonDomain("zkapi.v2.reg")
	for _, vector := range vectors.Register {
		if got := fieldWord(poseidonHash(registration, vectorInt(t, vector.Secret), new(big.Int))); got != vector.Commitment {
			t.Errorf("registration commitment = %s, want %s", got, vector.Commitment)
		}
	}
	for _, vector := range vectors.Leaves {
		amount, ok := new(big.Int).SetString(vector.Amount, 10)
		expiry, err := strconv.ParseUint(vector.Expiry, 10, 64)
		if !ok || err != nil || vector.Fields == "" {
			t.Fatal("invalid leaf vector")
		}
		// The packing of input 8 over the full uint128 amount range:
		// noteID·2^192 + amount·2^64 + expiry.
		fields := new(big.Int).Lsh(new(big.Int).SetUint64(uint64(vector.NoteID)), 192)
		fields.Or(fields, new(big.Int).Lsh(amount, 64)).Or(fields, new(big.Int).SetUint64(expiry))
		if fieldWord(fields) != vector.Fields {
			t.Errorf("fields %d = %s, want %s", vector.NoteID, fieldWord(fields), vector.Fields)
		}
		commitment := vectorInt(t, vector.Commitment)
		if got := noteLeafFromFields(commitment, vectorInt(t, vector.Fields)); fieldWord(got) != vector.Leaf {
			t.Errorf("leaf %d = %s, want %s", vector.NoteID, fieldWord(got), vector.Leaf)
		}
		if amount.IsUint64() {
			if fieldWord(noteFields(vector.NoteID, amount.Uint64(), expiry)) != vector.Fields {
				t.Errorf("noteFields %d differs from the protocol packing", vector.NoteID)
			}
			if fieldWord(noteLeaf(vector.NoteID, commitment, amount.Uint64(), expiry)) != vector.Leaf {
				t.Errorf("noteLeaf %d differs from the protocol leaf", vector.NoteID)
			}
		}
	}
	// The leaf is the node's compression under another capacity domain, and
	// the shared vectors of design C pin it (the vault's NoteLeafLib, the
	// circuit and zkapi-core agree on them).
	if fieldWord(domainLeaf) != vectors.Domains["zkapi.v2c.leaf"] || fieldWord(domainLeaf) != "0x0000000000000000000000000000000000007a6b6170692e7632632e6c656166" {
		t.Fatal("the leaf domain is not zkapi.v2c.leaf")
	}
	for _, pinned := range []struct{ got, want string }{
		{fieldWord(poseidonCompress(domainLeaf, big.NewInt(1), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)))), "0x00381941483a5233ff52ff1e1a0b79464c7316b7b4f609468ba5de81d2686d42"},
		{fieldWord(noteFields(7, 5_000_000, 4_000_000_000)), "0x0000000000000007000000000000000000000000004c4b4000000000ee6b2800"},
		{fieldWord(noteLeaf(7, vectorInt(t, "0x26538304fc53474b13823162f0b9667c1538c7360828d3a1a2e8ffa019a2f8cc"), 5_000_000, 4_000_000_000)), "0x1698e82280376fc3506cb7ebf7278db1764d0183aea5fd4d3b475c644b61395f"},
		{fieldWord(poseidonHash(poseidonDomain("zkapi.v2.reg"), big.NewInt(42), new(big.Int))), "0x26538304fc53474b13823162f0b9667c1538c7360828d3a1a2e8ffa019a2f8cc"},
		{fieldWord(merkleNode(big.NewInt(1), big.NewInt(2))), "0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1"},
	} {
		if pinned.got != pinned.want {
			t.Errorf("design C vector = %s, want %s", pinned.got, pinned.want)
		}
	}
	for _, vector := range vectors.Nodes {
		if got := fieldWord(merkleNode(vectorInt(t, vector.Left), vectorInt(t, vector.Right))); got != vector.Node {
			t.Errorf("node = %s, want %s", got, vector.Node)
		}
	}
	zero := merkleZeroHashes()
	if len(vectors.Zero) != len(zero) {
		t.Fatal("zero hash depth differs")
	}
	for level, want := range vectors.Zero {
		if fieldWord(zero[level]) != want {
			t.Errorf("zero hash %d differs", level)
		}
	}
	for _, vector := range vectors.Roots {
		siblings := make([]*big.Int, len(vector.Siblings))
		for i, sibling := range vector.Siblings {
			siblings[i] = vectorInt(t, sibling)
		}
		if got := fieldWord(merkleRoot(vector.NoteID, vectorInt(t, vector.Leaf), siblings)); got != vector.Root {
			t.Errorf("root for note %d = %s, want %s", vector.NoteID, got, vector.Root)
		}
	}
}

func TestParseFieldElementRequiresCanonicalScalar(t *testing.T) {
	for _, value := range []string{"0x0", "0x1", "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"} {
		if _, ok := parseFieldElement(value); !ok {
			t.Errorf("rejected %s", value)
		}
	}
	for _, value := range []string{"", "0x", "1", "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "0x" + "f" + fmt.Sprintf("%064x", 0), "0xg"} {
		if _, ok := parseFieldElement(value); ok {
			t.Errorf("accepted %s", value)
		}
	}
}
