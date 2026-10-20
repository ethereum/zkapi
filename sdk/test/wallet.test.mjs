import test from "node:test";
import assert from "node:assert/strict";

import { readFileSync } from "node:fs";

import wallet from "../wallet.js";
import { keccak256, selector } from "./helpers/keccak.mjs";

test("escape-period labels follow the deployed vault duration", () => {
  assert.equal(wallet.ABI.currentRoot, "fdab463d");
  assert.equal(wallet.ABI.challengePeriod, "f3f480d9");
  assert.equal(wallet.ABI.legacyChallengePeriod, "c3a079ed");
  assert.equal(wallet.escapePeriodLabel(60), "1-minute");
  assert.equal(wallet.escapePeriodPhrase(60), "1 minute");
  assert.equal(wallet.escapePeriodBadge(60), "1m");
  assert.equal(wallet.escapePeriodPhrase(86_400), "1 day");
  assert.equal(wallet.escapePeriodPhrase(172_800), "2 days");
  assert.equal(wallet.escapePeriodBadge(30), "30s");
});

test("deposit calldata uses the deployed vault signature: commitment and amount, no siblings", () => {
  const plan = {
    commitment: "0x2a",
    zero_path: Array.from({ length: 32 }, (_, index) => `0x${(index + 1).toString(16)}`),
  };
  const encoded = wallet.encodeDeposit(plan, 100_000n);
  assert.ok(encoded.startsWith("0x56d2e1ea"));
  assert.equal(encoded.length, 2 + 8 + (2 * 64));
  assert.equal(encoded.slice(10, 74), wallet.abiWord("0x2a"));
  assert.equal(encoded.slice(74, 138), wallet.abiWord(100_000n));
});

test("NoteDeposited receipt parsing returns the assigned note id, amount and expiry (2 data words, no root)", () => {
  const vault = "0x590df9abbfb21074016daa486c771ae0af729ee2";
  const log = {
    address: vault.toUpperCase().replace("0X", "0x"),
    topics: [wallet.ABI.noteDeposited, `0x${wallet.abiWord(21n)}`, `0x${wallet.abiWord(42n)}`],
    data: `0x${wallet.abiWord(100_000n)}${wallet.abiWord(1_800_000_000n)}`,
  };
  assert.deepEqual(wallet.parseNoteDeposited({ logs: [log] }, vault), {
    noteId: 21n,
    commitment: `0x${wallet.abiWord(42n)}`,
    amount: 100_000n,
    expiryTs: 1_800_000_000n,
  });
  // A revision-3 log (a third root word), a removed log or another vault's is not this deposit.
  assert.equal(wallet.parseNoteDeposited({ logs: [{ ...log, data: `${log.data}${wallet.abiWord(99n)}` }] }, vault), null);
  assert.equal(wallet.parseNoteDeposited({ logs: [{ ...log, removed: true }] }, vault), null);
  assert.equal(wallet.parseNoteDeposited({ logs: [log] }, "0x4386fdbda35d995beb3bf8625118ec5982ec81fe"), null);
});

test("noteFields packs note id, deposit and expiry as public input 8, and refuses values that do not fit", () => {
  // The design C vector (exit-rules.json exit_inputs.leaf[0]).
  assert.equal(wallet.packNoteFields(7, "5000000", "4000000000"),
    0x0000000000000007000000000000000000000000004c4b4000000000ee6b2800n);
  assert.equal(wallet.packNoteFields(2 ** 32 - 1, (2n ** 128n - 1n).toString(), (2n ** 64n - 1n).toString()), 2n ** 224n - 1n);
  assert.deepEqual(wallet.unpackNoteFields(0x0000000000000007000000000000000000000000004c4b4000000000ee6b2800n),
    { noteId: 7, depositAmount: 5_000_000n, expiryTs: 4_000_000_000n });
  assert.throws(() => wallet.packNoteFields(2 ** 32, 1, 1), /uint32/);
  assert.throws(() => wallet.packNoteFields(1, (2n ** 128n).toString(), 1), /uint128/);
  assert.throws(() => wallet.packNoteFields(1, 1, (2n ** 64n).toString()), /uint64/);
  assert.throws(() => wallet.packNoteFields(1, 2 ** 60, 1), /exact unsigned integer/);
  assert.throws(() => wallet.unpackNoteFields(2n ** 224n), /uint224/);
});

test("noteRecord, noteLeaves and effectiveExpiry encode and decode only their exact shapes", () => {
  const words = (...values) => `0x${values.map((value) => wallet.abiWord(value)).join("")}`;
  assert.equal(wallet.encodeNoteRecord(21), `0xd154f5bf${wallet.abiWord(21n)}`);
  assert.deepEqual(wallet.decodeNoteRecord(words(0x1234n, 1n)), { leaf: 0x1234n, status: 1, statusName: "active" });
  // A retired note: Closed with a zero leaf.
  assert.deepEqual(wallet.decodeNoteRecord(words(0n, 3n)), { leaf: 0n, status: 3, statusName: "closed" });
  assert.throws(() => wallet.decodeNoteRecord(words(1n, 4n)), /status/);
  assert.throws(() => wallet.decodeNoteRecord(words(1n)), /exactly 2/);
  // The removed notes(uint32) getter answered 4 words.
  assert.throws(() => wallet.decodeNoteRecord(words(1n, 2n, 3n, 1n)), /exactly 2/);
  assert.throws(() => wallet.decodeNoteRecord(words(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n, 1n)),
    /field element/);
  assert.equal(wallet.encodeNoteLeaves(2048, 5), `0x31749c58${wallet.abiWord(2048n)}${wallet.abiWord(5n)}`);
  assert.deepEqual(wallet.decodeNoteLeaves(words(32n, 2n, 7n, 0n), 2), [7n, 0n]);
  assert.throws(() => wallet.decodeNoteLeaves(words(32n, 2n, 7n, 0n), 3), /exactly 5/);
  assert.throws(() => wallet.decodeNoteLeaves(words(64n, 1n, 7n), 1), /one array/);
  assert.equal(wallet.encodeEffectiveExpiry(7, "0x26538304fc53474b13823162f0b9667c1538c7360828d3a1a2e8ffa019a2f8cc", 5_000_000n, 4_000_000_000n),
    `0x5a747a98${wallet.abiWord(7n)}26538304fc53474b13823162f0b9667c1538c7360828d3a1a2e8ffa019a2f8cc`
      + `${wallet.abiWord(5_000_000n)}${wallet.abiWord(4_000_000_000n)}`);
  assert.equal(wallet.NOTE_STATUS.active, 1);
});

const GOLDEN = JSON.parse(readFileSync(new URL("./fixtures/vault-calldata-golden.json", import.meta.url), "utf8"));
const PROOF_BYTES = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
const SCALAR_MODULUS_MINUS_ONE = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
const SUCCESSOR = "0x2a5c6b0e9f1d3b7a8c4e2f6a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f2a3b4c";

// The statements of the golden vectors in sdk/test/fixtures/vault-calldata-golden.json
// (generated with Foundry `cast calldata` from the vault revision 4 signatures: word 3
// the note leaf, word 8 noteFields = note_id·2^192 + deposit_amount·2^64 + expiry_ts).
function escapePlan(changes = {}) {
  return {
    mode: "escape",
    public_inputs: {
      protocol_version: 2,
      chain_id: 11_155_111,
      contract_address: "0x590df9abbfb21074016daa486c771ae0af729ee2",
      note_leaf: SCALAR_MODULUS_MINUS_ONE,
      state_signing_key_x: "0x12",
      state_signing_key_y: "0x13",
      clearance_signing_key_x: "0x14",
      clearance_signing_key_y: "0x15",
      note_id: 21,
      // The widest deposit and expiry: the low 192 bits of noteFields are set.
      deposit_amount: (2n ** 128n - 1n).toString(),
      expiry_ts: (2n ** 64n - 1n).toString(),
      final_balance: Number.MAX_SAFE_INTEGER,
      destination: Array(20).fill(0x22),
      withdrawal_nullifier: "0x16",
      kind: 0,
      next_nullifier: SUCCESSOR,
      conceded: 100,
      valid_until: 1_800_010_800,
      ...changes,
    },
    proof: { backend: "groth16_bn254", proof: PROOF_BYTES.toString("base64") },
  };
}

function mutualPlan(changes = {}) {
  return {
    mode: "mutual",
    public_inputs: {
      protocol_version: 2,
      chain_id: 1,
      contract_address: "0x4386fdbda35d995beb3bf8625118ec5982ec81fe",
      // The design C leaf vector: note 7, 5,000,000 units, expiry 4,000,000,000.
      note_leaf: "0x1698e82280376fc3506cb7ebf7278db1764d0183aea5fd4d3b475c644b61395f",
      state_signing_key_x: "0x12",
      state_signing_key_y: "0x13",
      clearance_signing_key_x: "0x14",
      clearance_signing_key_y: "0x15",
      note_id: 7,
      deposit_amount: 5_000_000,
      expiry_ts: 4_000_000_000,
      final_balance: 1_850_000,
      destination: "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f",
      withdrawal_nullifier: "0x16",
      kind: 1,
      next_nullifier: "0x0",
      conceded: 0,
      valid_until: "18446744073709551615",
      ...changes,
    },
    proof: { backend: "groth16_bn254", proof: PROOF_BYTES.toString("base64") },
  };
}

const ESCAPE_DESTINATION = "0x2222222222222222222222222222222222222222";
const MUTUAL_DESTINATION = "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f";

// The real revision-4 vault's selectors and event topics, from the compiled
// protocol/contracts sources (crates/zkapi-serverd/tests/fixtures/
// check-calldata-golden.sh keeps this file equal to them).
const REAL_VAULT = JSON.parse(readFileSync(new URL("../../crates/zkapi-serverd/tests/fixtures/vault_calldata_golden.json", import.meta.url), "utf8"));

test("every selector and event topic is the real vault's", () => {
  const legacy = new Set(["legacyChallengePeriod"]);
  const events = {
    noteDeposited: "NoteDeposited",
    mutualCloseEvent: "MutualClose",
    escapeInitiatedEvent: "EscapeWithdrawalInitiated",
    escapeFinalizedEvent: "EscapeWithdrawalFinalized",
    escapeChallengedEvent: "EscapeWithdrawalChallenged",
    escapeConcessionRecordedEvent: "EscapeConcessionRecorded",
    escapeConcessionRaisedEvent: "EscapeConcessionRaised",
    closedLeafRetiredEvent: "ClosedLeafRetired",
    expiredClaimedEvent: "ExpiredClaimed",
    escapePayoutDeferredEvent: "EscapePayoutDeferred",
    escapePayoutClaimedEvent: "EscapePayoutClaimed",
  };
  let checked = 0;
  for (const [name, value] of Object.entries(wallet.ABI)) {
    if (legacy.has(name)) continue;
    if (events[name]) {
      assert.equal(value, REAL_VAULT.events[events[name]].topic0, name);
    } else {
      assert.equal(`0x${value}`, REAL_VAULT.selectors[name], name);
    }
    checked += 1;
  }
  assert.equal(checked, Object.keys(wallet.ABI).length - legacy.size);
  // The decoders read the logs the real vault emits (VaultCalldataGolden.t.sol).
  const vault = "0x00000000000000000000000000000000000000aa";
  const log = name => ({ address: vault, data: REAL_VAULT.events[name].data,
    topics: REAL_VAULT.events[name].topics.slice(2).match(/.{64}/g).map(word => `0x${word}`) });
  // The tree and lifecycle events the SDK's strict decoder reads (others,
  // such as MutualClose, are matched by topic in the receipt matchers).
  const decodable = ["NoteDeposited", "EscapeWithdrawalInitiated", "EscapeConcessionRecorded", "EscapeConcessionRaised",
    "EscapeWithdrawalChallenged", "ClosedLeafRetired", "ExpiredClaimed"];
  const decoded = Object.fromEntries(decodable.map(name => [name, wallet.decodeVaultEvent(log(name), vault)]));
  assert.deepEqual(decoded.NoteDeposited, { event: "NoteDeposited", noteId: 7n, commitment: `0x${"0c0c".padStart(64, "0")}`,
    amount: 1_000_000n, expiryTs: 2_000_000_000n });
  assert.deepEqual(wallet.parseNoteDeposited({ logs: [log("NoteDeposited")] }, vault),
    { noteId: 7n, commitment: `0x${"0c0c".padStart(64, "0")}`, amount: 1_000_000n, expiryTs: 2_000_000_000n });
  assert.equal(decoded.EscapeWithdrawalInitiated.challengeDeadline, 2_000_086_400n);
  assert.deepEqual(wallet.parseWithdrawalReceipt({ logs: [log("EscapeWithdrawalInitiated")] }, vault, "escape"),
    { noteId: 7n, finalBalance: 900_000n, destination: "0x1111111111111111111111111111111111111111", challengeDeadline: 2_000_086_400n });
  assert.deepEqual(decoded.EscapeWithdrawalChallenged, { event: "EscapeWithdrawalChallenged", noteId: 7n, nullifier: 0x0101n });
  assert.deepEqual(decoded.ExpiredClaimed, { event: "ExpiredClaimed", noteId: 7n, depositAmount: 1_000_000n });
  assert.deepEqual(decoded.ClosedLeafRetired, { event: "ClosedLeafRetired", noteId: 7n });
  assert.equal(decoded.EscapeWithdrawalInitiated.destination.toLowerCase(), "0x1111111111111111111111111111111111111111");
  assert.deepEqual(wallet.escapeConcessionRecorded({ logs: [log("EscapeConcessionRecorded")] }, vault, 7),
    { nextNullifier: 0x0202n, stateBalance: 1_000_000n, conceded: 100_000n });
  assert.deepEqual(wallet.escapeConcessionRaises({ logs: [log("EscapeConcessionRaised")] }, vault, 7),
    [{ nullifier: 0x0101n, conceded: 150_000n, finalBalance: 850_000n }]);
  for (const [name, event] of Object.entries(decoded)) {
    assert.equal(event?.event, name, name);
    assert.equal(event.noteId ?? 7n, 7n, name);
  }
  assert.equal(REAL_VAULT.getter_words.pendingConcessions, 3);
  assert.equal(REAL_VAULT.getter_words.pendingWithdrawals, 6);
  assert.equal(REAL_VAULT.getter_words.noteRecord, 2);
  // The removed revision-3 getters are gone from the vault and from the SDK.
  for (const removed of ["notes", "knownRoots", "isKnownRoot", "ROOT_HISTORY_WINDOW"]) {
    assert.equal(REAL_VAULT.selectors[removed], undefined, removed);
    assert.equal(wallet.ABI[removed], undefined, removed);
  }
  assert.equal(wallet.decodePendingConcessions(`0x${"00".repeat(96)}`).nextNullifier, 0n);
});

// The shared withdrawal golden vector (design §11 WP-F): real kind-0 and
// kind-1 proofs whose calldata Forge pins to abi.encodeCall against the real
// vault; scripts/check-withdrawal-golden.mjs submits this encoder's output to
// a vault on Anvil, with the Rust and Go encoders'.
test("real proofs encode to the shared withdrawal golden vector", () => {
  const golden = JSON.parse(readFileSync(new URL("../../protocol/contracts/test/fixtures/withdrawal-golden.json", import.meta.url), "utf8"));
  for (const [name, mode] of [["escape", "escape"], ["close", "mutual"]]) {
    const statement = golden[name];
    const destination = `0x${Buffer.from(statement.public_inputs.destination).toString("hex")}`;
    const calldata = wallet.encodeWithdrawal(
      { mode, public_inputs: statement.public_inputs, proof: { backend: "groth16_bn254", proof: statement.proof } },
      mode, destination, golden.deployment.vault, { conceded: statement.public_inputs.conceded });
    assert.equal(calldata, statement.calldata, name);
    assert.equal(statement.proof_hex, `0x${Buffer.from(statement.proof, "base64").toString("hex")}`);
  }
});

test("every vault selector and event topic is the keccak of its signature", () => {
  const W = wallet.WITHDRAWAL_TUPLE;
  const Q = wallet.REQUEST_TUPLE;
  assert.equal(W, "(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint256,uint128,address,uint256,uint8,uint256,uint128,uint64)");
  assert.equal(Q, "(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256)");
  const selectors = {
    initiateEscapeWithdrawal: [`initiateEscapeWithdrawal(${W},bytes)`, "8cd67c60"],
    mutualClose: [`mutualClose(${W},bytes)`, "bce12a6c"],
    finalizeEscapeWithdrawal: ["finalizeEscapeWithdrawal(uint32)", "ff8f5585"],
    raiseEscapeConcession: [`raiseEscapeConcession(uint32,${Q},bytes,uint128)`, "dd0064ba"],
    challengeEscapeWithdrawal: [`challengeEscapeWithdrawal(uint32,${Q},bytes)`, "da0ce43d"],
    pendingWithdrawals: ["pendingWithdrawals(uint32)", "a2f9f1ce"],
    pendingConcessions: ["pendingConcessions(uint32)", "f8ffe6e0"],
    challengedNullifiers: ["challengedNullifiers(uint256)", "6cda756a"],
    usedNullifiers: ["usedNullifiers(uint256)", "aad24061"],
    effectiveExpiry: ["effectiveExpiry(uint32,bytes32,uint128,uint64)", "5a747a98"],
    claimExpired: ["claimExpired(uint32,bytes32,uint128,uint64)", "ad610550"],
    currentRoot: ["currentRoot()", "fdab463d"],
    nextNoteId: ["nextNoteId()", "7a2043a3"],
    challengePeriod: ["challengePeriod()", "f3f480d9"],
    noteRecord: ["noteRecord(uint32)", "d154f5bf"],
    noteLeaves: ["noteLeaves(uint32,uint32)", "31749c58"],
    minDeposit: ["minDeposit()", "41b3d185"],
    CONCESSION_ESCAPE_VERSION: ["CONCESSION_ESCAPE_VERSION()", "5e00b426"],
    LEAF_BOUND_EXIT_VERSION: ["LEAF_BOUND_EXIT_VERSION()", "c0baafb1"],
    maxPauseDuration: ["maxPauseDuration()", "64433d27"],
    noteTtl: ["noteTtl()", "225af2e7"],
    proofAdapter: ["proofAdapter()", "efc91e58"],
    stateSigningKeyX: ["stateSigningKeyX()", "15fa2a9a"],
    stateSigningKeyY: ["stateSigningKeyY()", "230e2a24"],
    clearanceSigningKeyX: ["clearanceSigningKeyX()", "dc41d636"],
    clearanceSigningKeyY: ["clearanceSigningKeyY()", "112cd6bc"],
    CIRCUIT_ID_HASH: ["CIRCUIT_ID_HASH()", "da0e8385"],
    REQUEST_VK_HASH: ["REQUEST_VK_HASH()", "fe351488"],
    WITHDRAWAL_VK_HASH: ["WITHDRAWAL_VK_HASH()", "7fcd0926"],
    claimEscapePayout: ["claimEscapePayout(address)", "88c10aee"],
    escapePayoutCredits: ["escapePayoutCredits(address)", "91f6e93a"],
  };
  for (const [name, [signature, pinned]] of Object.entries(selectors)) {
    assert.equal(selector(signature), pinned, signature);
    assert.equal(wallet.ABI[name], pinned, name);
  }
  const topics = {
    escapeInitiatedEvent: ["EscapeWithdrawalInitiated(uint32,uint256,uint128,address,uint64)",
      "0x5ad24b4d5235cdf161caf23bb21550824a1be902576056f666b56ac6c424f4b1"],
    escapeChallengedEvent: ["EscapeWithdrawalChallenged(uint32,uint256)",
      "0x4bffb77581f1706ad6afe03cd651fb25b1b485f7eaef1826e2cc6f420f532161"],
    escapeConcessionRecordedEvent: ["EscapeConcessionRecorded(uint32,uint256,uint128,uint128)",
      "0x2254ee827bce198564720fe77733ebfab1a49361cd4f050f107445241b560b4d"],
    escapeConcessionRaisedEvent: ["EscapeConcessionRaised(uint32,uint256,uint128,uint128)",
      "0x3faf5608f821061643ff6fdfe6dd0f6d7fb074bb565f35e3537a86ac08f0897c"],
    closedLeafRetiredEvent: ["ClosedLeafRetired(uint32)",
      "0x733841afe92a19d5b309b7732cf095a30edfae784b7cc5f0a97dec7140fb8e13"],
    noteDeposited: ["NoteDeposited(uint32,bytes32,uint128,uint64)",
      "0x3d5756e39e88718c2260db175f4f454d73fbd02468313b9406bf5c0733481c36"],
    expiredClaimedEvent: ["ExpiredClaimed(uint32,uint128)",
      "0xe5962fdd811b0b8d9b9cdaf37e396f36dd238f127d52ef65ae07d96edb32fd96"],
  };
  for (const [name, [signature, pinned]] of Object.entries(topics)) {
    assert.equal(keccak256(signature), pinned, signature);
    assert.equal(wallet.ABI[name], pinned, name);
  }
  // The adapter's CIRCUIT_ID_HASH constant.
  assert.equal(keccak256("zkapi-v2-concession-v2"),
    "0xcbe7e9ff73a9d6e589b63f04856d01d48cc2306851a024a7621aab30a50488c1");
  // The retired note-bound and revision-3 selectors are gone.
  for (const retired of ["9073639b", "7fca9c82", "72cd2e44", "a38d62aa", "9f18e4ed", "7cb4a03c", "a940507e", "1fe72de0",
    "12ad7381", "a6232a93"]) {
    assert.equal(Object.values(wallet.ABI).includes(retired), false, retired);
  }
});

test("escape calldata is the 16-word statement, word 3 the leaf and word 8 the note fields, and the proof (836 bytes)", () => {
  const encoded = wallet.encodeWithdrawal(escapePlan(), "escape", ESCAPE_DESTINATION,
    "0x590DF9ABBFB21074016DAA486C771AE0AF729EE2", { conceded: 100n });
  assert.equal(encoded, GOLDEN.initiateEscapeWithdrawal);
  assert.equal((encoded.length - 2) / 2, 836);
  assert.equal(wallet.WITHDRAWAL_CALLDATA_BYTES, 836);
  const word = (index) => encoded.slice(10 + index * 64, 10 + (index + 1) * 64);
  assert.equal(word(3), SCALAR_MODULUS_MINUS_ONE.slice(2), "noteLeaf");
  assert.equal(word(8), wallet.abiWord((21n << 192n) | ((1n << 192n) - 1n)), "noteFields");
  assert.equal(word(12), wallet.abiWord(0n), "kind");
  assert.equal(word(14), wallet.abiWord(100n), "conceded");
  assert.equal(word(15), wallet.abiWord(1_800_010_800n), "valid_until");
  assert.equal(word(16), wallet.abiWord(0x220n), "bytes offset 17 * 32");
  assert.equal(word(17), wallet.abiWord(256n), "proof length");
  assert.equal(encoded.slice(-64), PROOF_BYTES.subarray(224).toString("hex"));
});

test("mutual-close calldata is the 16-word statement and the proof, byte for byte", () => {
  const encoded = wallet.encodeWithdrawal(mutualPlan(), "mutual", MUTUAL_DESTINATION);
  assert.equal(encoded, GOLDEN.mutualClose);
  assert.equal((encoded.length - 2) / 2, 836);
  assert.equal(encoded.slice(10 + 8 * 64, 10 + 9 * 64), "0000000000000007000000000000000000000000004c4b4000000000ee6b2800",
    "noteFields of the design C vector");
  assert.equal(wallet.encodeFinalizeEscape(21), `0x${wallet.ABI.finalizeEscapeWithdrawal}${wallet.abiWord(21)}`);
});

test("the withdrawal encoder refuses another kind, destination, vault or concession", () => {
  const encode = (plan, mode = "escape", destination = ESCAPE_DESTINATION, expected = {}) =>
    wallet.encodeWithdrawal(plan, mode, destination, plan.public_inputs.contract_address, expected);
  assert.throws(() => encode(escapePlan(), "escape", MUTUAL_DESTINATION), /destination/);
  assert.throws(() => wallet.encodeWithdrawal(escapePlan(), "escape", ESCAPE_DESTINATION, MUTUAL_DESTINATION), /vault/);
  assert.throws(() => encode(escapePlan(), "mutual"), /withdrawal mode/);
  // Kinds: an ownership proof (kind 2) or a close proof is never an escape.
  for (const kind of [1, 2, 3, "0"]) assert.throws(() => encode(escapePlan({ kind })), /kind-0 escape/);
  for (const kind of [0, 2]) assert.throws(() => encode(mutualPlan({ kind }), "mutual", MUTUAL_DESTINATION), /kind-1/);
  // An escape names its successor nullifier; a close names none and concedes nothing.
  assert.throws(() => encode(escapePlan({ next_nullifier: "0x0" })), /successor nullifier/);
  assert.throws(() => encode(escapePlan({ next_nullifier: "0x16" })), /successor nullifier/);
  assert.throws(() => encode(mutualPlan({ next_nullifier: "0x1" }), "mutual", MUTUAL_DESTINATION), /concede nothing/);
  assert.throws(() => encode(mutualPlan({ conceded: 1 }), "mutual", MUTUAL_DESTINATION), /concede nothing/);
  assert.throws(() => encode(escapePlan(), "escape", ESCAPE_DESTINATION, { conceded: 99 }), /concedes a different amount/);
  // Values that would encode another statement are refused, not truncated.
  assert.throws(() => encode(escapePlan({ valid_until: 0 })), /valid_until/);
  assert.throws(() => encode(escapePlan({ valid_until: (2n ** 64n).toString() })), /uint64/);
  assert.throws(() => encode(escapePlan({ final_balance: 2 ** 60 })), /exact unsigned integer/);
  assert.throws(() => encode(escapePlan({ conceded: -1 })), /uint128/);
  assert.throws(() => encode(escapePlan({ note_leaf: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001" })),
    /canonical field element/);
  assert.throws(() => encode(escapePlan({ note_leaf: "0x0" })), /no note leaf/);
  assert.throws(() => encode(escapePlan({ note_leaf: undefined })), /note leaf/);
  // A statement of vault revision 3 (bound to a root) is refused, also next to a leaf.
  assert.throws(() => encode(escapePlan({ active_root: "0x11" })), /earlier vault revision/);
  assert.throws(() => encode(escapePlan({ merkle_siblings: [] })), /earlier vault revision/);
  // The fields of word 8 must fit their widths.
  assert.throws(() => encode(escapePlan({ note_id: 2 ** 32 })), /uint32/);
  assert.throws(() => encode(escapePlan({ deposit_amount: (2n ** 128n).toString() })), /uint128/);
  assert.throws(() => encode(escapePlan({ expiry_ts: (2n ** 64n).toString() })), /uint64/);
  assert.throws(() => encode(escapePlan({ deposit_amount: undefined })), /exact unsigned integer/);
  assert.throws(() => encode(escapePlan({ withdrawal_tag: undefined, has_clearance: false, kind: undefined })), /kind-0/);
  const short = escapePlan();
  short.proof.proof = Buffer.alloc(255).toString("base64");
  assert.throws(() => encode(short), /256 bytes/);
});

test("a vault address with leading zero nibbles matches its field-element form in the proof", () => {
  // The WebAssembly serializes contract_address as a Felt252 (zkapi-types
  // felt.rs to_hex), which drops leading zeros: 0x0f12… arrives as 0xf12….
  const feltHex = (address) => `0x${address.slice(2).replace(/^0+/, "") || "0"}`;
  for (const vault of ["0x0f12345678901234567890123456789012345678", "0x00ab45678901234567890123456789012345678e",
    "0x0000000000000000000000000000000000000001"]) {
    const plan = escapePlan({ contract_address: feltHex(vault) });
    assert.notEqual(plan.public_inputs.contract_address.length, 42, "the fixture really is shorter");
    for (const expected of [vault, vault.toUpperCase().replace("0X", "0x")]) {
      const encoded = wallet.encodeWithdrawal(plan, "escape", ESCAPE_DESTINATION, expected, { conceded: 100n });
      assert.equal(encoded.slice(10 + 2 * 64, 10 + 3 * 64), wallet.abiWord(BigInt(vault)), "word 2 is the vault");
      assert.equal(encoded, wallet.encodeWithdrawal(escapePlan({ contract_address: vault }), "escape",
        ESCAPE_DESTINATION, vault, { conceded: 100n }));
    }
    const close = mutualPlan({ contract_address: feltHex(vault) });
    assert.equal((wallet.encodeWithdrawal(close, "mutual", MUTUAL_DESTINATION, vault).length - 2) / 2, 836);
  }
  // Another vault, or a vault that is not an address, is still refused.
  assert.throws(() => wallet.encodeWithdrawal(escapePlan({ contract_address: "0xf12345678901234567890123456789012345678" }),
    "escape", ESCAPE_DESTINATION, "0x1f12345678901234567890123456789012345678"), /different vault/);
  assert.throws(() => wallet.encodeWithdrawal(escapePlan({ contract_address: "0xf1" }), "escape", ESCAPE_DESTINATION, "0xf1"),
    /not a contract address/);
});

test("pendingWithdrawals and pendingConcessions decode only their exact shapes", () => {
  const words = (...values) => `0x${values.map((value) => wallet.abiWord(value)).join("")}`;
  assert.equal(wallet.encodePendingConcessions(21), `0xf8ffe6e0${wallet.abiWord(21n)}`);
  assert.equal(wallet.encodePendingWithdrawals(21), `0xa2f9f1ce${wallet.abiWord(21n)}`);
  assert.deepEqual(wallet.decodePendingConcessions(words(0x2an, 1_000n, 40n)),
    { nextNullifier: 0x2an, stateBalance: 1_000n, conceded: 40n });
  assert.throws(() => wallet.decodePendingConcessions(words(1n, 2n)), /exactly 3/);
  assert.throws(() => wallet.decodePendingConcessions(words(1n, 2n, 3n, 4n)), /exactly 3/);
  assert.throws(() => wallet.decodePendingConcessions(words(1n, 2n ** 128n, 3n)), /128 bits/);
  assert.deepEqual(wallet.decodePendingWithdrawals(words(1n, 5n, 6n, 960n, MUTUAL_DESTINATION, 1_900_000_000n)), {
    exists: true, activeRoot: 5n, withdrawalNullifier: 6n, finalBalance: 960n,
    destination: MUTUAL_DESTINATION, challengeDeadline: 1_900_000_000n,
  });
  assert.throws(() => wallet.decodePendingWithdrawals(words(2n, 5n, 6n, 960n, 0n, 1n)), /boolean/);
  assert.throws(() => wallet.decodePendingWithdrawals(words(1n, 5n, 6n, 960n, 2n ** 160n, 1n)), /160 bits/);
  assert.throws(() => wallet.decodePendingWithdrawals(words(1n, 5n, 6n, 960n, 0n)), /exactly 6/);
});

test("vault revision 4 events decode strictly and escape receipts carry their concession", () => {
  const vault = "0x590df9abbfb21074016daa486c771ae0af729ee2";
  const topicWord = (value) => `0x${wallet.abiWord(value)}`;
  const data = (...values) => `0x${values.map((value) => wallet.abiWord(value)).join("")}`;
  const initiated = { address: vault, topics: [wallet.ABI.escapeInitiatedEvent, topicWord(21n)],
    data: data(0x16n, 960n, ESCAPE_DESTINATION, 1_900_000_000n) };
  const recorded = { address: vault, topics: [wallet.ABI.escapeConcessionRecordedEvent, topicWord(21n)],
    data: data(0x2an, 1_000n, 40n) };
  const raised = { address: vault, topics: [wallet.ABI.escapeConcessionRaisedEvent, topicWord(21n)],
    data: data(0x16n, 70n, 930n) };
  const retired = { address: vault, topics: [wallet.ABI.closedLeafRetiredEvent, topicWord(4n)], data: "0x" };
  assert.deepEqual(wallet.decodeVaultEvent(recorded, vault),
    { event: "EscapeConcessionRecorded", noteId: 21n, nextNullifier: 0x2an, stateBalance: 1_000n, conceded: 40n });
  assert.deepEqual(wallet.decodeVaultEvent(raised, vault),
    { event: "EscapeConcessionRaised", noteId: 21n, nullifier: 0x16n, conceded: 70n, finalBalance: 930n });
  assert.deepEqual(wallet.decodeVaultEvent(retired, vault), { event: "ClosedLeafRetired", noteId: 4n });
  assert.deepEqual(wallet.decodeVaultEvent(initiated, vault), { event: "EscapeWithdrawalInitiated", noteId: 21n,
    nullifier: 0x16n, finalBalance: 960n, destination: ESCAPE_DESTINATION, challengeDeadline: 1_900_000_000n });
  // A revision-3 log with its root word is another ABI.
  assert.throws(() => wallet.decodeVaultEvent({ ...retired, data: data(0x77n) }, vault), /exactly 0/);
  assert.throws(() => wallet.decodeVaultEvent({ ...initiated, data: data(0x16n, 960n, ESCAPE_DESTINATION, 1_900_000_000n, 99n) },
    vault), /exactly 4/);
  // Other contracts, removed logs and other events are not vault events.
  assert.equal(wallet.decodeVaultEvent({ ...recorded, address: MUTUAL_DESTINATION }, vault), null);
  assert.equal(wallet.decodeVaultEvent({ ...recorded, removed: true }, vault), null);
  assert.equal(wallet.decodeVaultEvent({ ...recorded, topics: [wallet.ABI.escapePayoutClaimedEvent, topicWord(1n)] }, vault), null);
  // A known event with another shape is an ABI mismatch.
  assert.throws(() => wallet.decodeVaultEvent({ ...recorded, data: data(0x2an, 1_000n) }, vault), /exactly 3/);
  assert.throws(() => wallet.decodeVaultEvent({ ...recorded, topics: recorded.topics.slice(0, 1) }, vault), /topics/);
  assert.throws(() => wallet.decodeVaultEvent({ ...recorded, data: data(0x2an, 2n ** 128n, 0n) }, vault), /128 bits/);

  const receipt = { logs: [initiated, recorded] };
  assert.deepEqual(wallet.parseWithdrawalReceipt(receipt, vault, "escape"), {
    noteId: 21n, finalBalance: 960n, destination: ESCAPE_DESTINATION, challengeDeadline: 1_900_000_000n,
    concession: { nextNullifier: 0x2an, stateBalance: 1_000n, conceded: 40n },
  });
  assert.deepEqual(wallet.escapeConcessionRecorded(receipt, vault, 22), null);
  assert.deepEqual(wallet.escapeConcessionRaises({ logs: [raised, recorded, raised] }, vault, 21n),
    [{ nullifier: 0x16n, conceded: 70n, finalBalance: 930n }, { nullifier: 0x16n, conceded: 70n, finalBalance: 930n }]);
});

test("raise and defeat calldata decode to their request evidence", () => {
  const raise = wallet.decodeRaiseEscapeConcession(GOLDEN.raiseEscapeConcession);
  const expectedInputs = {
    protocol_version: 2, chain_id: 11_155_111, contract_address: "0x590df9abbfb21074016daa486c771ae0af729ee2",
    active_root: `0x${wallet.abiWord(0x11n)}`, state_signing_key_x: `0x${wallet.abiWord(0x12n)}`,
    state_signing_key_y: `0x${wallet.abiWord(0x13n)}`, request_time: 1_800_000_000, solvency_bound: 6_000_000,
    request_nullifier: `0x${wallet.abiWord(0x16n)}`, authorization_tag: `0x${wallet.abiWord(0x17n)}`,
    anonymous_commitment_x: `0x${wallet.abiWord(0x18n)}`, anonymous_commitment_y: `0x${wallet.abiWord(0x19n)}`,
  };
  assert.deepEqual(raise, { noteId: 21, publicInputs: expectedInputs,
    proof: { backend: "groth16_bn254", proof: PROOF_BYTES.toString("base64") }, amount: 5_000_000n });
  const defeat = wallet.decodeChallengeEscapeWithdrawal(GOLDEN.challengeEscapeWithdrawal);
  assert.deepEqual(defeat, { noteId: 21, publicInputs: { ...expectedInputs, request_nullifier: SUCCESSOR },
    proof: { backend: "groth16_bn254", proof: PROOF_BYTES.toString("base64") } });
  assert.equal((GOLDEN.raiseEscapeConcession.length - 2) / 2, 772);
  assert.equal((GOLDEN.challengeEscapeWithdrawal.length - 2) / 2, 740);
  assert.throws(() => wallet.decodeRaiseEscapeConcession(GOLDEN.challengeEscapeWithdrawal), /exactly/);
  assert.throws(() => wallet.decodeChallengeEscapeWithdrawal(GOLDEN.raiseEscapeConcession), /exactly/);
  assert.throws(() => wallet.decodeChallengeEscapeWithdrawal(`0xdd0064ba${GOLDEN.challengeEscapeWithdrawal.slice(10)}`),
    /another selector/);
});

test("withdrawal events expose note, destination, balance, and escape deadline", () => {
  const vault = "0x590df9abbfb21074016daa486c771ae0af729ee2";
  const receipt = {
    logs: [{
      address: vault,
      topics: [wallet.ABI.escapeInitiatedEvent, `0x${wallet.abiWord(21n)}`],
      data: `0x${wallet.abiWord(99n)}${wallet.abiWord(1_850_000n)}${wallet.addressWord("0x2222222222222222222222222222222222222222")}${wallet.abiWord(1_900_000_000n)}`,
    }],
  };
  assert.deepEqual(wallet.parseWithdrawalReceipt(receipt, vault, "escape"), {
    noteId: 21n,
    finalBalance: 1_850_000n,
    destination: "0x2222222222222222222222222222222222222222",
    challengeDeadline: 1_900_000_000n,
  });
});

// The two receipt layouts pinned by the vault's
// test_finalizeReceiptTellsPaidFromCreditedPayout: a paid finalization emits
// only EscapeWithdrawalFinalized; a credited one emits EscapePayoutDeferred
// (topics [topic0, noteId, destination], data abi.encode(uint128 amount))
// before the identical EscapeWithdrawalFinalized.
const PAYOUT_VAULT = "0x590df9abbfb21074016daa486c771ae0af729ee2";
const PAYOUT_DESTINATION = "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f";
const word = (value) => `0x${wallet.abiWord(value)}`;

function finalizedLog(destination = PAYOUT_DESTINATION, noteId = 0n) {
  return {
    address: PAYOUT_VAULT,
    topics: [wallet.ABI.escapeFinalizedEvent, word(noteId)],
    data: `0x${wallet.abiWord(99n)}${wallet.abiWord(700_000n)}${wallet.abiWord(destination)}`,
  };
}

function deferredLog({ noteId = 0n, destination = PAYOUT_DESTINATION, amount = 700_000n, ...overrides } = {}) {
  return {
    address: PAYOUT_VAULT,
    topics: [wallet.ABI.escapePayoutDeferredEvent, word(noteId), word(destination)],
    data: word(amount),
    removed: false,
    ...overrides,
  };
}

test("payout-credit selectors and topics match the hardened vault", () => {
  assert.equal(wallet.ABI.claimEscapePayout, "88c10aee");
  assert.equal(wallet.ABI.escapePayoutCredits, "91f6e93a");
  assert.equal(wallet.ABI.escapePayoutDeferredEvent,
    "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942");
  assert.equal(wallet.ABI.escapePayoutClaimedEvent,
    "0x6bf75371d42e9753c0913bf8fcecb651e8db173d99d7da0e4d836e91512bbe27");
  assert.equal(wallet.ESCAPE_PAYOUT_GAS, 100_000);
  assert.equal(wallet.encodeClaimEscapePayout(PAYOUT_DESTINATION),
    `0x88c10aee${"0".repeat(24)}${PAYOUT_DESTINATION.slice(2)}`);
  assert.equal(wallet.encodeEscapePayoutCredits(PAYOUT_DESTINATION),
    `0x91f6e93a${"0".repeat(24)}${PAYOUT_DESTINATION.slice(2)}`);
  assert.throws(() => wallet.encodeClaimEscapePayout("0x1234"), /destination/);
});

test("a credited escape finalization is reported as credited, never as paid", () => {
  const paid = wallet.parseWithdrawalReceipt({ status: "0x1", logs: [finalizedLog()] }, PAYOUT_VAULT, "finalize");
  assert.deepEqual(paid, {
    noteId: 0n,
    finalBalance: 700_000n,
    destination: PAYOUT_DESTINATION,
    payoutCredited: false,
  });

  const credited = wallet.parseWithdrawalReceipt({ status: "0x1", logs: [deferredLog(), finalizedLog()] },
    PAYOUT_VAULT, "finalize");
  assert.deepEqual(credited, {
    noteId: 0n,
    finalBalance: 700_000n,
    destination: PAYOUT_DESTINATION,
    payoutCredited: true,
    creditedAmount: 700_000n,
  });
  assert.equal(credited.payoutVerified, undefined);

  // Checksummed or upper-case addresses and topics still match.
  const mixedCase = deferredLog();
  mixedCase.address = PAYOUT_VAULT.toUpperCase().replace("0X", "0x");
  mixedCase.topics = mixedCase.topics.map((topic) => topic.toUpperCase().replace("0X", "0x"));
  assert.equal(wallet.parseWithdrawalReceipt({ logs: [finalizedLog(), mixedCase] }, PAYOUT_VAULT, "finalize")
    .payoutCredited, true);
});

test("only the vault's own non-removed credit for this note and destination counts", () => {
  const other = "0x1111111111111111111111111111111111111111";
  for (const log of [
    deferredLog({ removed: true }),
    deferredLog({ address: other }),
    deferredLog({ noteId: 1n }),
    deferredLog({ destination: other }),
    { ...deferredLog(), topics: deferredLog().topics.slice(0, 2) },
    { ...deferredLog(), topics: [wallet.ABI.escapePayoutClaimedEvent, word(PAYOUT_DESTINATION), word(0n)] },
  ]) {
    const parsed = wallet.parseWithdrawalReceipt({ logs: [log, finalizedLog()] }, PAYOUT_VAULT, "finalize");
    assert.equal(parsed.payoutCredited, false);
    assert.equal(parsed.creditedAmount, undefined);
  }
  // Doubtful data still reports a credit (with the finalized balance).
  const noData = wallet.parseWithdrawalReceipt({ logs: [deferredLog({ data: "0x" }), finalizedLog()] },
    PAYOUT_VAULT, "finalize");
  assert.equal(noData.payoutCredited, true);
  assert.equal(noData.creditedAmount, 700_000n);
  // A start or mutual-close receipt never carries the credit flag.
  assert.equal(wallet.parseWithdrawalReceipt({ logs: [deferredLog()] }, PAYOUT_VAULT, "finalize"), null);
});

test("only an exact EscapePayoutClaimed log for the destination proves a claim", () => {
  const claimed = (overrides = {}) => ({
    address: PAYOUT_VAULT,
    topics: [wallet.ABI.escapePayoutClaimedEvent, word(PAYOUT_DESTINATION)],
    data: word(700_000n),
    ...overrides,
  });
  assert.deepEqual(wallet.parseEscapePayoutClaim({ logs: [claimed()] }, PAYOUT_VAULT, PAYOUT_DESTINATION), {
    destination: PAYOUT_DESTINATION,
    amount: 700_000n,
  });
  assert.deepEqual(wallet.parseEscapePayoutClaim({ logs: [claimed()] }, PAYOUT_VAULT,
    PAYOUT_DESTINATION.toUpperCase().replace("0X", "0x")).amount, 700_000n);
  const other = "0x1111111111111111111111111111111111111111";
  for (const log of [
    claimed({ removed: true }),
    claimed({ address: other }),
    claimed({ topics: [wallet.ABI.escapePayoutClaimedEvent, word(other)] }),
    // Dirty upper bytes are not an exact address word.
    claimed({ topics: [wallet.ABI.escapePayoutClaimedEvent, `0x${"ff".repeat(12)}${PAYOUT_DESTINATION.slice(2)}`] }),
    claimed({ topics: [wallet.ABI.escapePayoutDeferredEvent, word(0n), word(PAYOUT_DESTINATION)] }),
    claimed({ data: "0x" }),
    claimed({ data: word(0n) }),
  ]) {
    assert.equal(wallet.parseEscapePayoutClaim({ logs: [log] }, PAYOUT_VAULT, PAYOUT_DESTINATION), null);
  }
});

// ---- Gasless withdrawals (protocol/contracts/src/gasless): a separate table,
// GASLESS_ABI, because none of these selectors and topics is the vault's. ----

test("every gasless selector and event topic is the keccak of its signature", () => {
  const { GASLESS_ABI, PACKED_USER_OPERATION_TUPLE } = wallet;
  assert.equal(PACKED_USER_OPERATION_TUPLE, "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)");
  const selectors = {
    withdraw: "withdraw(bytes)",
    owner: "owner()",
    payee: "payee()",
    sweep: "sweep()",
    createAccount: "createAccount(address,address)",
    getAddress: "getAddress(address,address)",
    accountCreationCodeHash: "accountCreationCodeHash()",
    accountCreationCode: "accountCreationCode()",
    implementation: "implementation()",
    paymaster: "paymaster()",
    factory: "factory()",
    entryPoint: "entryPoint()",
    vault: "vault()",
    WEI_PER_UNIT: "WEI_PER_UNIT()",
    policy: "policy()",
    maxFeeCeiling: "maxFeeCeiling()",
    priorityFeeCeiling: "priorityFeeCeiling()",
    callCap: "callCap(uint8)",
    attempts: "attempts(bytes32)",
    owed: "owed(address)",
    stranded: "stranded(address)",
    escapeNotePlusOne: "escapeNotePlusOne(address)",
    escapeSponsored: "escapeSponsored(uint32)",
    credits: "credits(address)",
    quote: "quote(uint8,address,uint32,uint256,uint256,uint256)",
    gasPolicy: "gasPolicy()",
    gasSchedule: "gasSchedule()",
    chargeFor: "chargeFor(uint8,uint256,uint256,uint256,uint256,bool,bool,uint256)",
    keyFor: "keyFor(uint8,uint256,uint32,address)",
    transitAccount: "transitAccount(address,address)",
    FORWARD_NONCE_KEY: "FORWARD_NONCE_KEY()",
    claimCredit: "claimCredit(address)",
    handleOps: `handleOps(${PACKED_USER_OPERATION_TUPLE}[],address)`,
    getNonce: "getNonce(address,uint192)",
    getUserOpHash: `getUserOpHash(${PACKED_USER_OPERATION_TUPLE})`,
    balanceOf: "balanceOf(address)",
    getDepositInfo: "getDepositInfo(address)",
    paused: "paused()",
    pausedAt: "pausedAt()",
    failedOpError: "FailedOp(uint256,string)",
    failedOpWithRevertError: "FailedOpWithRevert(uint256,string,bytes)",
  };
  const topics = {
    userOperationEvent: "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)",
    accountDeployedEvent: "AccountDeployed(bytes32,address,address,address)",
    userOperationRevertReasonEvent: "UserOperationRevertReason(bytes32,address,uint256,bytes)",
    postOpRevertReasonEvent: "PostOpRevertReason(bytes32,address,uint256,bytes)",
    sponsoredEvent: "Sponsored(bytes32,address,address,uint8,uint32,uint256)",
    settledEvent: "Settled(bytes32,address,address,uint8,uint32,uint256,uint256,uint256,uint256)",
    sponsorshipFailedEvent: "SponsorshipFailed(bytes32,address,uint8,uint32,uint256)",
    escapeInitiationOwedEvent: "EscapeInitiationOwed(address,uint32,uint256)",
    shortfallEvent: "Shortfall(address,uint32,uint256)",
    payoutCreditedEvent: "PayoutCredited(address,uint256)",
    creditClaimedEvent: "CreditClaimed(address,uint256)",
    collectedEvent: "Collected(address,address,uint256,uint256,uint256)",
    strandedEvent: "Stranded(address)",
    accountCreatedEvent: "AccountCreated(address,address,address)",
  };
  let checked = 0;
  for (const [name, signature] of Object.entries(selectors)) {
    assert.equal(GASLESS_ABI[name], selector(signature), signature);
    checked += 1;
  }
  for (const [name, signature] of Object.entries(topics)) {
    assert.equal(GASLESS_ABI[name], keccak256(signature), signature);
    checked += 1;
  }
  assert.equal(checked, Object.keys(GASLESS_ABI).length, "every entry of GASLESS_ABI is checked");
  // The vault's table is untouched by the new one.
  assert.equal(Object.keys(wallet.ABI).some((name) => name in GASLESS_ABI), false);
  // The paymaster's selectors for the vault's own calls are the vault's.
  assert.equal(selector("withdraw(bytes)"), "0968f264");
});

test("the transit account, factory and paymaster calls encode their exact calldata", () => {
  const owner = "0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7";
  const payee = "0x000000000000000000000000000000000009A7Ee";
  assert.equal(wallet.encodeCreateAccount(owner, payee), `0x133572ba${wallet.abiWord(owner)}${wallet.abiWord(payee)}`);
  assert.equal(wallet.encodeSweep(), "0x35faa416");
  assert.equal(wallet.encodeClaimCredit(payee), `0x60e27464${wallet.abiWord(payee)}`);
  assert.throws(() => wallet.encodeCreateAccount("0x12", payee), /owner/);
  assert.throws(() => wallet.encodeClaimCredit("0x12"), /payout address/);
  // withdraw(bytes) in the paymaster's strict layout: offset 0x20, length, bytes, zero padding.
  const vectors = JSON.parse(readFileSync(new URL("../../protocol/contracts/test/fixtures/transit-vectors.json", import.meta.url), "utf8"));
  assert.equal(wallet.encodeTransitWithdraw(vectors.close.vault_calldata), vectors.close.call_data.toLowerCase());
  const forward = wallet.encodeTransitWithdraw("0x");
  assert.equal(forward, `0x0968f264${wallet.abiWord(0x20)}${wallet.abiWord(0)}`);
  const finalize = wallet.encodeTransitWithdraw(wallet.encodeFinalizeEscape(21));
  assert.equal(finalize.slice(10, 74), wallet.abiWord(0x20));
  assert.equal(finalize.slice(74, 138), wallet.abiWord(36));
  assert.equal(finalize.slice(138, 138 + 72), wallet.encodeFinalizeEscape(21).slice(2));
  assert.equal(finalize.slice(138 + 72), "0".repeat(56), "padded to a word with zeros");
  assert.throws(() => wallet.encodeTransitWithdraw("0x1234"), /empty, a finalization \(36 bytes\) or an exit \(836 bytes\)/);
  assert.throws(() => wallet.encodeTransitWithdraw("0x123"), /hex byte string/);
});

test("parseWithdrawalReceipt filters by noteId when asked and is unchanged otherwise", () => {
  const vault = "0x590df9abbfb21074016daa486c771ae0af729ee2";
  const close = (noteId, destination) => ({
    address: vault,
    topics: [wallet.ABI.mutualCloseEvent, `0x${wallet.abiWord(noteId)}`],
    data: `0x${wallet.abiWord(0x16n)}${wallet.abiWord(1_850_000n)}${wallet.addressWord(destination)}`,
  });
  const receipt = { logs: [close(9n, ESCAPE_DESTINATION), close(21n, MUTUAL_DESTINATION)] };
  assert.equal(wallet.parseWithdrawalReceipt(receipt, vault, "mutual").noteId, 9n, "the first vault log, as before");
  assert.deepEqual(wallet.parseWithdrawalReceipt(receipt, vault, "mutual", { noteId: 21 }),
    { noteId: 21n, finalBalance: 1_850_000n, destination: MUTUAL_DESTINATION });
  assert.deepEqual(wallet.parseWithdrawalReceipt(receipt, vault, "mutual", { noteId: "21" }).noteId, 21n);
  assert.equal(wallet.parseWithdrawalReceipt(receipt, vault, "mutual", { noteId: 22 }), null);
  assert.equal(wallet.parseWithdrawalReceipt(receipt, vault, "mutual", { noteId: null }).noteId, 9n, "null means no filter");
  const finalized = { logs: [deferredLog({ noteId: 3n }), finalizedLog(PAYOUT_DESTINATION, 3n), finalizedLog(PAYOUT_DESTINATION, 0n)] };
  assert.equal(wallet.parseWithdrawalReceipt(finalized, PAYOUT_VAULT, "finalize", { noteId: 0 }).payoutCredited, false);
  assert.equal(wallet.parseWithdrawalReceipt(finalized, PAYOUT_VAULT, "finalize", { noteId: 3 }).payoutCredited, true);
});
