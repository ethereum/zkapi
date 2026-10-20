// Vault revision 4 (circuit zkapi-v2-concession-v2, leaf-bound exits).
// Selectors and topics are derived from the signatures beside them
// (sdk/test/wallet.test.mjs recomputes every one). WITHDRAWAL_TUPLE is
// Types.WithdrawalPublicInputs: 16 static words in public-input order, word 3
// the note's leaf (noteLeaf) and word 8 its packed fields (noteFields);
// REQUEST_TUPLE is Types.RequestPublicInputs.
const WITHDRAWAL_TUPLE = "(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint256,uint128,address,uint256,uint8,uint256,uint128,uint64)";
const REQUEST_TUPLE = "(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256)";

const ABI = Object.freeze({
  deposit: "56d2e1ea",
  // mutualClose(WITHDRAWAL_TUPLE,bytes)
  mutualClose: "bce12a6c",
  // initiateEscapeWithdrawal(WITHDRAWAL_TUPLE,bytes)
  initiateEscapeWithdrawal: "8cd67c60",
  // finalizeEscapeWithdrawal(uint32)
  finalizeEscapeWithdrawal: "ff8f5585",
  // raiseEscapeConcession(uint32,REQUEST_TUPLE,bytes,uint128): decoded only
  raiseEscapeConcession: "dd0064ba",
  // challengeEscapeWithdrawal(uint32,REQUEST_TUPLE,bytes): decoded only
  challengeEscapeWithdrawal: "da0ce43d",
  challengePeriod: "f3f480d9",
  legacyChallengePeriod: "c3a079ed",
  // currentRoot(): computed from the vault's frontier (a view of about 0.5M gas)
  currentRoot: "fdab463d",
  nextNoteId: "7a2043a3",
  // noteRecord(uint32): 2 words (uint256 leaf, uint8 status)
  noteRecord: "d154f5bf",
  // noteLeaves(uint32 start, uint32 count): uint256[]; reverts past nextNoteId
  noteLeaves: "31749c58",
  minDeposit: "41b3d185",
  // pendingWithdrawals(uint32): 6 words
  pendingWithdrawals: "a2f9f1ce",
  // pendingConcessions(uint32): 3 words (nextNullifier, stateBalance, conceded)
  pendingConcessions: "f8ffe6e0",
  challengedNullifiers: "6cda756a",
  usedNullifiers: "aad24061",
  // effectiveExpiry(uint32 noteId, bytes32 commitment, uint128 amount, uint64 expiryTs):
  // 0 for an unknown or retired note, or a preimage that is not its leaf's
  effectiveExpiry: "5a747a98",
  // claimExpired(uint32,bytes32,uint128,uint64): the treasury's; decoded only
  claimExpired: "ad610550",
  // Deployment pins (design §6.5): vault getters and adapter constants.
  CONCESSION_ESCAPE_VERSION: "5e00b426",
  LEAF_BOUND_EXIT_VERSION: "c0baafb1",
  maxPauseDuration: "64433d27",
  noteTtl: "225af2e7",
  proofAdapter: "efc91e58",
  stateSigningKeyX: "15fa2a9a",
  stateSigningKeyY: "230e2a24",
  clearanceSigningKeyX: "dc41d636",
  clearanceSigningKeyY: "112cd6bc",
  CIRCUIT_ID_HASH: "da0e8385",
  REQUEST_VK_HASH: "fe351488",
  WITHDRAWAL_VK_HASH: "7fcd0926",
  // NoteDeposited(uint32 indexed noteId, bytes32 indexed commitment, uint128 amount,
  // uint64 expiryTs): no event carries a root since revision 4.
  noteDeposited: "0x3d5756e39e88718c2260db175f4f454d73fbd02468313b9406bf5c0733481c36",
  mutualCloseEvent: "0x1f43fa4711ca18e1d26398f26bf598bd3a62992cdd0e84f055f2bb506e9d7031",
  // EscapeWithdrawalInitiated(uint32 indexed noteId, uint256 nullifier, uint128 finalBalance,
  // address destination, uint64 challengeDeadline): 4 data words.
  escapeInitiatedEvent: "0x5ad24b4d5235cdf161caf23bb21550824a1be902576056f666b56ac6c424f4b1",
  escapeFinalizedEvent: "0x163f2e46c4004f0ed9682e2db8c84efac31310720266b17ea9904ba348c26504",
  // EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier): a defeat by
  // successor evidence.
  escapeChallengedEvent: "0x4bffb77581f1706ad6afe03cd651fb25b1b485f7eaef1826e2cc6f420f532161",
  // EscapeConcessionRecorded(uint32 indexed noteId, uint256 nextNullifier, uint128 stateBalance,
  // uint128 conceded): follows EscapeWithdrawalInitiated in the same receipt.
  escapeConcessionRecordedEvent: "0x2254ee827bce198564720fe77733ebfab1a49361cd4f050f107445241b560b4d",
  // EscapeConcessionRaised(uint32 indexed noteId, uint256 nullifier, uint128 conceded,
  // uint128 finalBalance)
  escapeConcessionRaisedEvent: "0x3faf5608f821061643ff6fdfe6dd0f6d7fb074bb565f35e3537a86ac08f0897c",
  // ClosedLeafRetired(uint32 indexed noteId): no data
  closedLeafRetiredEvent: "0x733841afe92a19d5b309b7732cf095a30edfae784b7cc5f0a97dec7140fb8e13",
  // ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount)
  expiredClaimedEvent: "0xe5962fdd811b0b8d9b9cdaf37e396f36dd238f127d52ef65ae07d96edb32fd96",
  // A finalized escape whose push to the destination failed credits it instead:
  // EscapePayoutDeferred(uint32 indexed noteId, address indexed destination, uint128 amount)
  // precedes EscapeWithdrawalFinalized in the same receipt.
  escapePayoutDeferredEvent: "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942",
  // EscapePayoutClaimed(address indexed destination, uint128 amount)
  escapePayoutClaimedEvent: "0x6bf75371d42e9753c0913bf8fcecb651e8db173d99d7da0e4d836e91512bbe27",
  claimEscapePayout: "88c10aee",
  escapePayoutCredits: "91f6e93a",
});

// The ERC-4337 (EntryPoint v0.7.0) packed user operation, as handleOps and
// getUserOpHash take it.
const PACKED_USER_OPERATION_TUPLE = "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)";

// Gasless withdrawals (protocol/contracts/src/gasless): the transit account
// S, its factory, the withdrawal paymaster P and the canonical EntryPoint.
// Every selector and topic is derived from the signature beside it
// (sdk/test/wallet.test.mjs recomputes each one); none belongs to the vault.
const GASLESS_ABI = Object.freeze({
  // ---- ZkApiWithdrawalAccount (S) ----
  // withdraw(bytes): the only sponsored entry point
  withdraw: "0968f264",
  // owner()
  owner: "8da5cb5b",
  // payee()
  payee: "ae90b213",
  // sweep()
  sweep: "35faa416",
  // ---- ZkApiWithdrawalAccountFactory ----
  // createAccount(address,address)
  createAccount: "133572ba",
  // getAddress(address,address)
  getAddress: "5191620b",
  // accountCreationCodeHash()
  accountCreationCodeHash: "08a1a807",
  // accountCreationCode()
  accountCreationCode: "31c884df",
  // implementation()
  implementation: "5c60da1b",
  // ---- ZkApiWithdrawalPaymaster (P) ----
  // paymaster() (factory), factory(), entryPoint(), vault(), WEI_PER_UNIT()
  paymaster: "16e4cbf9",
  factory: "c45a0155",
  entryPoint: "b0d691fe",
  vault: "fbfa77cf",
  WEI_PER_UNIT: "a3bea703",
  // policy(): 5 words (maxSponsoredCost, flatFeeWei, minEscapeNetWei, escapesEnabled, sponsorshipPaused)
  policy: "0505c8c9",
  maxFeeCeiling: "981df567",
  priorityFeeCeiling: "c8fcbcdd",
  // callCap(uint8)
  callCap: "6e202337",
  // attempts(bytes32)
  attempts: "f6829c37",
  // owed(address)
  owed: "df18e047",
  // stranded(address)
  stranded: "97b69f6a",
  // escapeNotePlusOne(address)
  escapeNotePlusOne: "c72bb484",
  // escapeSponsored(uint32)
  escapeSponsored: "2f17904b",
  // credits(address)
  credits: "fe5ff468",
  // quote(uint8,address,uint32,uint256,uint256,uint256): 6 words
  quote: "e948303d",
  // gasPolicy(): 30 words (two uint256[4] then 22 scalars)
  gasPolicy: "3a5dbdc2",
  gasSchedule: "61ed0660", // gasSchedule()
  // chargeFor(uint8,uint256,uint256,uint256,uint256,bool,bool,uint256)
  chargeFor: "64452fce",
  // keyFor(uint8,uint256,uint32,address)
  keyFor: "15be61e4",
  // transitAccount(address,address)
  transitAccount: "d7734557",
  // FORWARD_NONCE_KEY()
  FORWARD_NONCE_KEY: "f0000eab",
  // claimCredit(address)
  claimCredit: "60e27464",
  // ---- EntryPoint v0.7.0 ----
  // handleOps(PACKED_USER_OPERATION_TUPLE[],address)
  handleOps: "765e827f",
  // getNonce(address,uint192)
  getNonce: "35567e1a",
  // getUserOpHash(PACKED_USER_OPERATION_TUPLE)
  getUserOpHash: "22cdde4c",
  // balanceOf(address)
  balanceOf: "70a08231",
  // getDepositInfo(address): 5 words
  getDepositInfo: "5287ce12",
  // ---- vault reads of the gasless pre-flight ----
  // paused(), pausedAt()
  paused: "5c975abb",
  pausedAt: "2e55d0f2",
  // ---- EntryPoint errors ----
  // FailedOp(uint256,string)
  failedOpError: "220266b6",
  // FailedOpWithRevert(uint256,string,bytes)
  failedOpWithRevertError: "65c8fd4d",
  // ---- topics ----
  // UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster,
  // uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)
  userOperationEvent: "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f",
  // AccountDeployed(bytes32 indexed userOpHash, address indexed sender, address factory, address paymaster)
  accountDeployedEvent: "0xd51a9c61267aa6196961883ecf5ff2da6619c37dac0fa92122513fb32c032d2d",
  // UserOperationRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason)
  userOperationRevertReasonEvent: "0x1c4fada7374c0a9ee8841fc38afe82932dc0f8e69012e927f061a8bae611a201",
  // PostOpRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason)
  postOpRevertReasonEvent: "0xf62676f440ff169a3a9afdbf812e89e7f95975ee8e5c31214ffdef631c5f4792",
  // Sponsored(bytes32 indexed key, address indexed sender, address indexed payee, uint8 kind, uint32 noteId, uint256 maxCost)
  sponsoredEvent: "0x4435f72baae96daeef8324fb3ed1d4f4d5978280cb6c5f9fdf74b64d467ee3c0",
  // Settled(bytes32 indexed key, address indexed sender, address indexed payee, uint8 kind, uint32 noteId,
  // uint256 received, uint256 charged, uint256 owedPaid, uint256 paidOut)
  settledEvent: "0xd42d05cc535635a5dda37221df3418f706f9917ccea103d9b084ec88c57493d7",
  // SponsorshipFailed(bytes32 indexed key, address indexed sender, uint8 kind, uint32 noteId, uint256 actualGasCost)
  sponsorshipFailedEvent: "0x96b6440447f40d6d398b5b5c86e4fbe9444a326945cbbd866acd96b8d71f9bde",
  // EscapeInitiationOwed(address indexed sender, uint32 indexed noteId, uint256 owedWei)
  escapeInitiationOwedEvent: "0xdba5f4325096f8184591cb09c50465f50cbb6583b018bd47baee376d31e034f7",
  // Shortfall(address indexed sender, uint32 noteId, uint256 shortfallWei)
  shortfallEvent: "0xa0b29cff3dff5187dcf13b9afbbe4060f1fb0b6458edebfd6781feb30aeceb82",
  // PayoutCredited(address indexed payee, uint256 amount)
  payoutCreditedEvent: "0xfa0ea8a012f094d1b6f48df9238391dcbfbbda9acf72c5fa9b26c32451e98a61",
  // CreditClaimed(address indexed payee, uint256 amount)
  creditClaimedEvent: "0x87e12c2565042763daa6bf5842ed2b6447f17f7e28f9a4905fe3959581396ead",
  // Collected(address indexed sender, address indexed payee, uint256 received, uint256 owedPaid, uint256 paidOut)
  collectedEvent: "0x91b3a0728743b4fa9ade16f0aa193f1e25f6ecd35942b9dfb43a7c6eac383955",
  // Stranded(address indexed sender)
  strandedEvent: "0x2795e7f49cdf8dc290338b2d31bac28df8bbfe68c3822ffc39789c5c77b472cf",
  // AccountCreated(address indexed account, address indexed owner, address indexed payee)
  accountCreatedEvent: "0x9db37ffcb3d1eadb0306e35c0453e35a675f2e80757b09251d848185ac5cc22a",
});

// Withdrawal proof kinds (public input 12). The vault accepts kind 0 only in
// initiateEscapeWithdrawal and kind 1 only in mutualClose; an ownership proof
// (kind 2) goes only to the server and is never encoded for the vault.
const WITHDRAWAL_KIND = Object.freeze({ escape: 0, mutual: 1, ownership: 2 });
// Calldata of initiateEscapeWithdrawal and mutualClose: selector, 16 tuple
// words, the bytes offset (17 * 32), the length (256) and 8 proof words.
const WITHDRAWAL_CALLDATA_BYTES = 4 + (16 + 1 + 1 + 8) * 32;

// Execution gas the hardened vault forwards when it pushes an escape payout
// (ESCAPE_PAYOUT_GAS()). A destination that needs more is only credited.
const ESCAPE_PAYOUT_GAS = 100_000;

function abiWord(value) {
  const hex = typeof value === "string" ? value.replace(/^0x/, "") : BigInt(value).toString(16);
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length > 64) {
    throw new Error("Value cannot be encoded for the vault contract.");
  }
  return hex.padStart(64, "0");
}

function addressWord(address) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address || "")) {
    throw new Error("MetaMask returned an invalid account address.");
  }
  return abiWord(address);
}

function destinationWord(destination) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(destination || "")) {
    throw new Error("The escape payout destination is not a valid address.");
  }
  return abiWord(destination);
}

function callData(selector, words) {
  return `0x${selector}${words.join("")}`;
}

function toBytes32(felt) {
  return `0x${String(felt).replace(/^0x/, "").padStart(64, "0")}`;
}

function normalizedEscapePeriod(seconds) {
  return Math.max(1, Number(seconds) || 24 * 60 * 60);
}

function escapePeriodLabel(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value % 86_400 === 0) return `${value / 86_400}-day`;
  if (value % 3_600 === 0) return `${value / 3_600}-hour`;
  if (value % 60 === 0) return `${value / 60}-minute`;
  return `${value}-second`;
}

function escapePeriodPhrase(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value % 86_400 === 0) {
    const days = value / 86_400;
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  if (value % 3_600 === 0) {
    const hours = value / 3_600;
    return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  if (value % 60 === 0) {
    const minutes = value / 60;
    return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
  }
  return `${value} ${value === 1 ? "second" : "seconds"}`;
}

function escapePeriodBadge(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value >= 3_600) return `${Math.round(value / 3_600)}h`;
  if (value >= 60) return `${Math.round(value / 60)}m`;
  return `${value}s`;
}

/**
 * deposit(bytes32 commitment, uint128 amount): the vault appends the note's
 * leaf at nextNoteId and stores it with the note (revision 4); no path or
 * root is sent or kept, and no exit ever needs one.
 */
function encodeDeposit(plan, amount) {
  return callData(ABI.deposit, [abiWord(toBytes32(plan.commitment)), abiWord(amount)]);
}

function decodeBase64(value) {
  if (typeof value !== "string" || !value) throw new Error("The daemon returned an empty withdrawal proof.");
  try {
    if (typeof atob === "function") {
      const decoded = atob(value);
      return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    }
    if (typeof Buffer === "function") return Uint8Array.from(Buffer.from(value, "base64"));
  } catch (_) {
    throw new Error("The daemon returned malformed base64 proof data.");
  }
  throw new Error("This browser cannot decode the withdrawal proof.");
}

function bytesHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function destinationHex(value) {
  if (typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
  if (!Array.isArray(value) || value.length !== 20
      || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error("The daemon returned an invalid withdrawal destination.");
  }
  return `0x${bytesHex(value)}`;
}

const SCALAR_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

// An unsigned integer of `bits` bits as a bigint. Accepts a safe JavaScript
// integer, a bigint, or a decimal or 0x-hex string; refuses a value that lost
// precision or does not fit, instead of encoding a different one.
function uintValue(value, bits, label) {
  let number;
  if (typeof value === "bigint") number = value;
  else if (typeof value === "number" && Number.isSafeInteger(value)) number = BigInt(value);
  else if (typeof value === "string" && /^(0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value)) number = BigInt(value);
  else throw new Error(`The withdrawal proof's ${label} is not an exact unsigned integer.`);
  if (number < 0n || number >= (1n << BigInt(bits))) {
    throw new Error(`The withdrawal proof's ${label} does not fit in uint${bits}.`);
  }
  return number;
}

// One static ABI word for an unsigned integer of `bits` bits (uintValue).
function uintWord(value, bits, label) {
  return uintValue(value, bits, label).toString(16).padStart(64, "0");
}

/**
 * A note's packed fields, public input 8 (noteFields):
 * noteId·2^192 + depositAmount·2^64 + expiryTs, below 2^224. The vault reads
 * the deposit and expiry of an exit from this word, and its leaf binds it.
 */
function packNoteFields(noteId, depositAmount, expiryTs) {
  return (uintValue(noteId, 32, "note id") << 192n)
    | (uintValue(depositAmount, 128, "deposit amount") << 64n)
    | uintValue(expiryTs, 64, "expiry");
}

/** The inverse of packNoteFields; refuses a word of 2^224 or more. */
function unpackNoteFields(fields) {
  const value = uintValue(fields, 224, "note fields");
  return {
    noteId: Number(value >> 192n),
    depositAmount: (value >> 64n) & ((1n << 128n) - 1n),
    expiryTs: value & ((1n << 64n) - 1n),
  };
}

// One static ABI word for a canonical BN254 field element given as 0x-hex.
function feltWord(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value) || BigInt(value) >= SCALAR_MODULUS) {
    throw new Error(`The withdrawal proof's ${label} is not a canonical field element.`);
  }
  return value.slice(2).toLowerCase().padStart(64, "0");
}

const ZERO_WORD = "0".repeat(64);

/**
 * Calldata for initiateEscapeWithdrawal (mode "escape", kind 0) or
 * mutualClose (mode "mutual", kind 1): the 16-word statement tuple, the
 * bytes offset 17 * 32, the length 256 and the 8 proof words (836 bytes).
 * Word 3 is the note's leaf (`note_leaf`), which the vault compares with the
 * leaf it stored at deposit, and word 8 its packed fields (`note_id`,
 * `deposit_amount`, `expiry_ts`): an exit carries no Merkle path or root. A
 * statement that names a root (`active_root`, an earlier revision's) is
 * refused. The proof must be of the mode's kind, pay `expectedDestination`
 * and name `expectedVault`; an escape must name its successor nullifier, a
 * close must concede nothing. `expected.conceded`, when given, is the amount
 * the user confirmed.
 */
function encodeWithdrawal(plan, expectedMode, expectedDestination, expectedVault, expected = {}) {
  const mode = String(expectedMode || "").toLowerCase();
  if (!["mutual", "escape"].includes(mode) || plan?.mode !== mode) {
    throw new Error("The daemon returned a different withdrawal mode than requested.");
  }
  if (plan?.proof?.backend !== "groth16_bn254") {
    throw new Error("The daemon returned an unsupported withdrawal proof backend.");
  }
  const inputs = plan.public_inputs || {};
  const destination = destinationHex(inputs.destination);
  if (destination !== String(expectedDestination || "").toLowerCase()) {
    throw new Error("The proof destination does not match the requested withdrawal address.");
  }
  // The statement's contract_address is a field element, serialized without
  // leading zeros (0x0f12… becomes 0xf12…): compare it as a number.
  const contract = uintWord(String(inputs.contract_address || ""), 160, "vault address");
  if (expectedVault) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(String(expectedVault))) {
      throw new Error("The expected vault is not a contract address.");
    }
    if (contract !== uintWord(String(expectedVault), 160, "expected vault")) {
      throw new Error("The withdrawal proof is bound to a different vault contract.");
    }
  }
  if (inputs.kind !== WITHDRAWAL_KIND[mode]) {
    throw new Error(mode === "escape"
      ? "The withdrawal proof is not a kind-0 escape proof."
      : "The withdrawal proof is not a kind-1 mutual-close proof.");
  }
  const nullifier = feltWord(inputs.withdrawal_nullifier, "withdrawal nullifier");
  const nextNullifier = feltWord(inputs.next_nullifier, "next nullifier");
  const conceded = uintWord(inputs.conceded, 128, "conceded amount");
  if (mode === "escape") {
    if (nextNullifier === ZERO_WORD || nextNullifier === nullifier) {
      throw new Error("The escape proof does not name its successor nullifier.");
    }
  } else if (nextNullifier !== ZERO_WORD || conceded !== ZERO_WORD) {
    throw new Error("A mutual-close proof must publish no successor nullifier and concede nothing.");
  }
  if (expected.conceded != null && BigInt(`0x${conceded}`) !== BigInt(expected.conceded)) {
    throw new Error("The escape proof concedes a different amount than the one confirmed.");
  }
  const validUntil = uintWord(inputs.valid_until, 64, "valid_until");
  if (validUntil === ZERO_WORD) throw new Error("The withdrawal proof has no valid_until.");
  if ("active_root" in inputs || "merkle_siblings" in inputs) {
    throw new Error("The withdrawal proof names a Merkle root: it was made for an earlier vault revision.");
  }
  const noteLeaf = feltWord(inputs.note_leaf, "note leaf");
  if (noteLeaf === ZERO_WORD) throw new Error("The withdrawal proof has no note leaf.");
  const noteFields = packNoteFields(inputs.note_id, inputs.deposit_amount, inputs.expiry_ts)
    .toString(16).padStart(64, "0");
  const proof = decodeBase64(plan.proof.proof);
  if (proof.length !== 256) {
    throw new Error("The Groth16 withdrawal proof must contain exactly 256 bytes.");
  }
  const tuple = [
    uintWord(inputs.protocol_version, 16, "protocol version"),
    uintWord(inputs.chain_id, 64, "chain id"),
    contract,
    noteLeaf,
    feltWord(inputs.state_signing_key_x, "state signing key"),
    feltWord(inputs.state_signing_key_y, "state signing key"),
    feltWord(inputs.clearance_signing_key_x, "clearance signing key"),
    feltWord(inputs.clearance_signing_key_y, "clearance signing key"),
    noteFields,
    uintWord(inputs.final_balance, 128, "final balance"),
    uintWord(destination, 160, "destination"),
    nullifier,
    uintWord(inputs.kind, 8, "kind"),
    nextNullifier,
    conceded,
    validUntil,
  ];
  const head = [...tuple, uintWord(17 * 32, 256, "offset")];
  const tail = [uintWord(proof.length, 256, "length"), ...Array.from({ length: 8 }, (_, index) => (
    bytesHex(proof.slice(index * 32, (index + 1) * 32))
  ))];
  const selector = mode === "mutual" ? ABI.mutualClose : ABI.initiateEscapeWithdrawal;
  const calldata = callData(selector, [...head, ...tail]);
  if (calldata.length !== 2 + 2 * WITHDRAWAL_CALLDATA_BYTES) throw new Error("Withdrawal calldata has the wrong length.");
  return calldata;
}

function encodeFinalizeEscape(noteId) {
  return callData(ABI.finalizeEscapeWithdrawal, [abiWord(noteId)]);
}

function encodeClaimEscapePayout(destination) {
  return callData(ABI.claimEscapePayout, [destinationWord(destination)]);
}

function encodeEscapePayoutCredits(destination) {
  return callData(ABI.escapePayoutCredits, [destinationWord(destination)]);
}

// ---- Gasless withdrawals: the transit account, factory and paymaster calls ----

function transitAddressWord(address, label) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address || "")) throw new Error(`The ${label} is not a valid address.`);
  return abiWord(address);
}

/**
 * Calldata of ZkApiWithdrawalAccount.withdraw(bytes vaultCall) in the strict
 * layout the paymaster accepts: the offset word 0x20, the length, the bytes
 * and zero padding to a word. `vaultCall` is empty (a forward of the transit
 * account's balance), 36 bytes (finalizeEscapeWithdrawal) or 836 bytes (a
 * mutual close or an escape initiation whose destination is the account).
 */
function encodeTransitWithdraw(vaultCall = "0x") {
  const hex = String(vaultCall ?? "0x").replace(/^0x/i, "").toLowerCase();
  if (hex.length % 2 || !/^[0-9a-f]*$/.test(hex)) throw new Error("The sponsored vault call is not a hex byte string.");
  const length = hex.length / 2;
  if (![0, 36, WITHDRAWAL_CALLDATA_BYTES].includes(length)) {
    throw new Error("A sponsored vault call is empty, a finalization (36 bytes) or an exit (836 bytes).");
  }
  const padded = hex.padEnd(Math.ceil(length / 32) * 64, "0");
  return callData(GASLESS_ABI.withdraw, [abiWord(0x20), abiWord(length), padded]);
}

/** ZkApiWithdrawalAccountFactory.createAccount(owner, payee). */
function encodeCreateAccount(owner, payee) {
  return callData(GASLESS_ABI.createAccount, [
    transitAddressWord(owner, "transit account owner"),
    transitAddressWord(payee, "payout address"),
  ]);
}

/** ZkApiWithdrawalAccount.sweep(): permissionless, forwards the balance through the paymaster. */
function encodeSweep() {
  return `0x${GASLESS_ABI.sweep}`;
}

/** ZkApiWithdrawalPaymaster.claimCredit(payee): anyone pays the payee its credited payouts. */
function encodeClaimCredit(payee) {
  return callData(GASLESS_ABI.claimCredit, [transitAddressWord(payee, "payout address")]);
}

function vaultLog(log, vaultAddress) {
  return log?.removed !== true
    && String(log?.address || "").toLowerCase() === String(vaultAddress || "").toLowerCase();
}

// The low 20 bytes of an indexed address topic.
function topicAddress(topic) {
  const hex = String(topic || "").replace(/^0x/, "");
  return /^[0-9a-fA-F]{40,64}$/.test(hex) ? `0x${hex.slice(-40)}`.toLowerCase() : null;
}

function firstWord(data) {
  const hex = String(data || "").replace(/^0x/, "");
  return /^[0-9a-fA-F]{64}/.test(hex) ? BigInt(`0x${hex.slice(0, 64)}`) : null;
}

/**
 * The EscapePayoutDeferred log of a finalization receipt: the vault closed
 * the escape but could not push its balance to the destination, so it
 * credited escapePayoutCredits(destination) instead. Matching is deliberately
 * lenient (any non-removed vault log with this topic, note and destination),
 * so a doubtful receipt is reported as credited, never as paid.
 */
function escapePayoutDeferred(receipt, vaultAddress, noteId, destination) {
  for (const log of receipt?.logs || []) {
    const topics = log?.topics;
    if (!vaultLog(log, vaultAddress) || !Array.isArray(topics) || topics.length !== 3
        || String(topics[0]).toLowerCase() !== ABI.escapePayoutDeferredEvent) continue;
    let loggedNoteId;
    try {
      loggedNoteId = BigInt(topics[1]);
    } catch (_) {
      continue;
    }
    if (loggedNoteId !== BigInt(noteId)
        || topicAddress(topics[2]) !== String(destination || "").toLowerCase()) continue;
    return { amount: firstWord(log.data) };
  }
  return null;
}

/**
 * The EscapePayoutClaimed log that proves claimEscapePayout paid `destination`.
 * Matching is strict: the indexed word must be exactly that address.
 */
function parseEscapePayoutClaim(receipt, vaultAddress, destination) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(destination || "")) return null;
  for (const log of receipt?.logs || []) {
    const topics = log?.topics;
    if (!vaultLog(log, vaultAddress) || !Array.isArray(topics) || topics.length !== 2
        || String(topics[0]).toLowerCase() !== ABI.escapePayoutClaimedEvent
        || !/^0x[0-9a-fA-F]{64}$/.test(topics[1] || "")
        || BigInt(topics[1]) !== BigInt(destination)) continue;
    const amount = firstWord(log.data);
    if (amount == null || amount === 0n) continue;
    return { destination: destination.toLowerCase(), amount };
  }
  return null;
}

/**
 * The vault's withdrawal event of `mode` in a receipt. By default the first
 * one; with `noteId` only this note's, because a receipt that settles a
 * bundle of sponsored operations carries other notes' vault logs too.
 */
function parseWithdrawalReceipt(receipt, vaultAddress, mode, { noteId = null } = {}) {
  const expectedTopic = mode === "mutual" ? ABI.mutualCloseEvent
    : mode === "escape" ? ABI.escapeInitiatedEvent
      : mode === "finalize" ? ABI.escapeFinalizedEvent : null;
  if (!expectedTopic) throw new Error("Unknown withdrawal receipt mode.");
  const expectedNoteId = noteId == null ? null : BigInt(noteId);
  for (const log of receipt?.logs || []) {
    if (log.address?.toLowerCase() !== vaultAddress.toLowerCase()
        || log.topics?.[0]?.toLowerCase() !== expectedTopic) continue;
    const data = String(log.data || "").replace(/^0x/, "");
    const minimumWords = mode === "escape" ? 4 : 3;
    if (log.topics.length < 2 || data.length < minimumWords * 64) continue;
    if (expectedNoteId != null && BigInt(log.topics[1]) !== expectedNoteId) continue;
    const result = {
      noteId: BigInt(log.topics[1]),
      finalBalance: BigInt(`0x${data.slice(64, 128)}`),
      destination: `0x${data.slice(128 + 24, 192)}`.toLowerCase(),
    };
    if (mode === "escape") {
      result.challengeDeadline = BigInt(`0x${data.slice(192, 256)}`);
      // The vault records the escape's successor nullifier, state balance
      // and initial concession in the same receipt.
      const concession = escapeConcessionRecorded(receipt, vaultAddress, result.noteId);
      if (concession) result.concession = concession;
    }
    if (mode === "finalize") {
      // EscapeWithdrawalFinalized alone does not prove the destination was
      // paid: on a hardened vault a failed push is credited instead.
      const credit = escapePayoutDeferred(receipt, vaultAddress, result.noteId, result.destination);
      result.payoutCredited = Boolean(credit);
      if (credit) result.creditedAmount = credit.amount ?? result.finalBalance;
    }
    return result;
  }
  return null;
}

/**
 * The NoteDeposited log of a deposit receipt: the note id the vault assigned,
 * the commitment, the amount and the expiry e (2 data words; no root). The
 * caller still checks noteRecord(noteId).leaf against the leaf of these.
 */
function parseNoteDeposited(receipt, vaultAddress) {
  for (const log of receipt?.logs || []) {
    if (log.removed === true || log.address?.toLowerCase() !== vaultAddress.toLowerCase()
        || log.topics?.[0]?.toLowerCase() !== ABI.noteDeposited) continue;
    const data = String(log.data || "").replace(/^0x/, "");
    if (log.topics.length >= 3 && /^[0-9a-fA-F]{128}$/.test(data)) {
      return {
        noteId: BigInt(log.topics[1]),
        commitment: log.topics[2],
        amount: BigInt(`0x${data.slice(0, 64)}`),
        expiryTs: BigInt(`0x${data.slice(64, 128)}`),
      };
    }
  }
  return null;
}

// ---- Strict decoders for vault revision 4 reads, logs and calldata ----

const UINT128_LIMIT = 1n << 128n;

function dataWords(data, count, label) {
  const hex = String(data ?? "").replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length !== count * 64) {
    throw new Error(`${label} must be exactly ${count} ABI words.`);
  }
  return Array.from({ length: count }, (_, index) => BigInt(`0x${hex.slice(index * 64, (index + 1) * 64) || "0"}`));
}

function boundedWord(value, bits, label) {
  if (value >= (1n << BigInt(bits))) throw new Error(`${label} does not fit in ${bits} bits.`);
  return value;
}

function wordAddress(value, label) {
  return `0x${boundedWord(value, 160, label).toString(16).padStart(40, "0")}`;
}

function wordHex(value) {
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function encodePendingWithdrawals(noteId) {
  return callData(ABI.pendingWithdrawals, [uintWord(noteId, 32, "note id")]);
}

function encodePendingConcessions(noteId) {
  return callData(ABI.pendingConcessions, [uintWord(noteId, 32, "note id")]);
}

/**
 * pendingWithdrawals(noteId): exactly 6 words (the shape of revision 2). Word
 * 1 (the old activeRoot) is always zero: no escape is bound to a root.
 */
function decodePendingWithdrawals(result) {
  const [exists, activeRoot, withdrawalNullifier, finalBalance, destination, challengeDeadline] =
    dataWords(result, 6, "pendingWithdrawals");
  if (exists > 1n) throw new Error("pendingWithdrawals.exists is not a boolean.");
  return {
    exists: exists === 1n,
    activeRoot,
    withdrawalNullifier,
    finalBalance: boundedWord(finalBalance, 128, "pendingWithdrawals.finalBalance"),
    destination: wordAddress(destination, "pendingWithdrawals.destination"),
    challengeDeadline: boundedWord(challengeDeadline, 64, "pendingWithdrawals.challengeDeadline"),
  };
}

/**
 * pendingConcessions(noteId): exactly 3 words, N_{k+1}, B_k and c. For a
 * pending escape, finalBalance + conceded == stateBalance.
 */
function decodePendingConcessions(result) {
  const [nextNullifier, stateBalance, conceded] = dataWords(result, 3, "pendingConcessions");
  return {
    nextNullifier,
    stateBalance: boundedWord(stateBalance, 128, "pendingConcessions.stateBalance"),
    conceded: boundedWord(conceded, 128, "pendingConcessions.conceded"),
  };
}

// noteRecord status values (Types.NoteStatus).
const NOTE_STATUS = Object.freeze({ uninitialized: 0, active: 1, pendingWithdrawal: 2, closed: 3 });
const NOTE_STATUS_NAMES = Object.freeze(["uninitialized", "active", "pending_withdrawal", "closed"]);

function encodeNoteRecord(noteId) {
  return callData(ABI.noteRecord, [uintWord(noteId, 32, "note id")]);
}

/**
 * noteRecord(noteId): exactly 2 words, the stored leaf and the status. A
 * retired note is Closed with a zero leaf; a slot never deposited is
 * Uninitialized with a zero leaf.
 */
function decodeNoteRecord(result) {
  const [leaf, status] = dataWords(result, 2, "noteRecord");
  if (leaf >= SCALAR_MODULUS) throw new Error("noteRecord.leaf is not a field element.");
  if (status > 3n) throw new Error("noteRecord.status is not a note status.");
  return { leaf, status: Number(status), statusName: NOTE_STATUS_NAMES[Number(status)] };
}

/** effectiveExpiry(noteId, commitment, amount, expiryTs): the preimage of the note's leaf. */
function encodeEffectiveExpiry(noteId, commitment, amount, expiryTs) {
  return callData(ABI.effectiveExpiry, [uintWord(noteId, 32, "note id"), feltWord(toBytes32(commitment), "commitment"),
    uintWord(amount, 128, "deposit amount"), uintWord(expiryTs, 64, "expiry")]);
}

/** noteLeaves(start, count): the vault reverts unless start + count <= nextNoteId. */
function encodeNoteLeaves(start, count) {
  return callData(ABI.noteLeaves, [uintWord(start, 32, "first note id"), uintWord(count, 32, "leaf count")]);
}

/** A noteLeaves(start, count) answer: exactly `count` field elements (0 for a retired note). */
function decodeNoteLeaves(result, count) {
  const expected = Number(count);
  const words = dataWords(result, 2 + expected, "noteLeaves");
  if (words[0] !== 32n || words[1] !== BigInt(expected)) throw new Error("noteLeaves is not one array of the requested length.");
  const leaves = words.slice(2);
  if (leaves.some(leaf => leaf >= SCALAR_MODULUS)) throw new Error("noteLeaves holds a value that is not a field element.");
  return leaves;
}

const VAULT_EVENTS = Object.freeze({
  [ABI.noteDeposited]: { name: "NoteDeposited", topics: 3, words: 2 },
  [ABI.escapeInitiatedEvent]: { name: "EscapeWithdrawalInitiated", topics: 2, words: 4 },
  [ABI.escapeConcessionRecordedEvent]: { name: "EscapeConcessionRecorded", topics: 2, words: 3 },
  [ABI.escapeConcessionRaisedEvent]: { name: "EscapeConcessionRaised", topics: 2, words: 3 },
  [ABI.escapeChallengedEvent]: { name: "EscapeWithdrawalChallenged", topics: 2, words: 1 },
  [ABI.closedLeafRetiredEvent]: { name: "ClosedLeafRetired", topics: 2, words: 0 },
  [ABI.expiredClaimedEvent]: { name: "ExpiredClaimed", topics: 2, words: 1 },
});

/**
 * Decode one vault log of the events above. Returns null for a removed log,
 * a log of another contract or another event; throws for a log of a known
 * event whose shape differs (a different vault ABI).
 */
function decodeVaultEvent(log, vaultAddress) {
  if (!vaultLog(log, vaultAddress) || !Array.isArray(log.topics)) return null;
  const topic = String(log.topics[0] || "").toLowerCase();
  const shape = VAULT_EVENTS[topic];
  if (!shape) return null;
  if (log.topics.length !== shape.topics || log.topics.some((entry) => !/^0x[0-9a-fA-F]{64}$/.test(entry || ""))) {
    throw new Error(`Malformed ${shape.name} log topics.`);
  }
  const noteId = boundedWord(BigInt(log.topics[1]), 32, `${shape.name}.noteId`);
  const words = dataWords(log.data, shape.words, `${shape.name} data`);
  const base = { event: shape.name, noteId };
  switch (shape.name) {
    case "NoteDeposited":
      return {
        ...base, commitment: String(log.topics[2]).toLowerCase(),
        amount: boundedWord(words[0], 128, "NoteDeposited.amount"),
        expiryTs: boundedWord(words[1], 64, "NoteDeposited.expiryTs"),
      };
    case "EscapeWithdrawalInitiated":
      return {
        ...base, nullifier: words[0], finalBalance: boundedWord(words[1], 128, "finalBalance"),
        destination: wordAddress(words[2], "destination"),
        challengeDeadline: boundedWord(words[3], 64, "challengeDeadline"),
      };
    case "EscapeConcessionRecorded":
      return {
        ...base, nextNullifier: words[0], stateBalance: boundedWord(words[1], 128, "stateBalance"),
        conceded: boundedWord(words[2], 128, "conceded"),
      };
    case "EscapeConcessionRaised":
      return {
        ...base, nullifier: words[0], conceded: boundedWord(words[1], 128, "conceded"),
        finalBalance: boundedWord(words[2], 128, "finalBalance"),
      };
    case "EscapeWithdrawalChallenged":
      return { ...base, nullifier: words[0] };
    case "ExpiredClaimed":
      return { ...base, depositAmount: boundedWord(words[0], 128, "ExpiredClaimed.depositAmount") };
    default:
      return base;
  }
}

function receiptEvents(receipt, vaultAddress, name, noteId) {
  const events = [];
  for (const log of receipt?.logs || []) {
    const event = decodeVaultEvent(log, vaultAddress);
    if (event?.event === name && (noteId == null || event.noteId === BigInt(noteId))) events.push(event);
  }
  return events;
}

/** The EscapeConcessionRecorded log of an initiation receipt for `noteId`. */
function escapeConcessionRecorded(receipt, vaultAddress, noteId) {
  const [event] = receiptEvents(receipt, vaultAddress, "EscapeConcessionRecorded", noteId);
  return event ? { nextNullifier: event.nextNullifier, stateBalance: event.stateBalance, conceded: event.conceded } : null;
}

/** Every EscapeConcessionRaised log of a receipt for `noteId`, in log order. */
function escapeConcessionRaises(receipt, vaultAddress, noteId) {
  return receiptEvents(receipt, vaultAddress, "EscapeConcessionRaised", noteId)
    .map(({ nullifier, conceded, finalBalance }) => ({ nullifier, conceded, finalBalance }));
}

const REQUEST_FIELDS = Object.freeze([
  ["protocol_version", 16], ["chain_id", 64], ["contract_address", 160], ["active_root", 0],
  ["state_signing_key_x", 0], ["state_signing_key_y", 0], ["request_time", 64], ["solvency_bound", 128],
  ["request_nullifier", 0], ["authorization_tag", 0], ["anonymous_commitment_x", 0], ["anonymous_commitment_y", 0],
]);

function base64Bytes(bytes) {
  if (typeof btoa === "function") return btoa(String.fromCharCode(...bytes));
  return Buffer.from(bytes).toString("base64");
}

// selector | noteId | 12 request words | offset | [amount] | 256 | 8 proof words
function decodeRequestEvidenceCall(calldata, selector, withAmount) {
  const hex = String(calldata || "").replace(/^0x/i, "").toLowerCase();
  const headWords = 1 + 12 + 1 + (withAmount ? 1 : 0);
  const words = dataWords(hex.slice(8), headWords + 1 + 8, "Evidence calldata");
  if (hex.slice(0, 8) !== selector) throw new Error("Evidence calldata has another selector.");
  if (words[13] !== BigInt(headWords * 32) || words[headWords] !== 256n) {
    throw new Error("Evidence calldata does not carry exactly one 256-byte proof.");
  }
  const publicInputs = {};
  REQUEST_FIELDS.forEach(([field, bits], index) => {
    const value = words[1 + index];
    if (field === "contract_address") publicInputs[field] = wordAddress(value, field);
    else if (bits) {
      boundedWord(value, bits, field);
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`Evidence ${field} exceeds 2^53.`);
      publicInputs[field] = Number(value);
    } else publicInputs[field] = wordHex(value);
  });
  const proofHex = hex.slice(8 + (headWords + 1) * 64);
  const proof = Uint8Array.from(proofHex.match(/../g), (byte) => parseInt(byte, 16));
  const decoded = {
    noteId: Number(boundedWord(words[0], 32, "noteId")),
    publicInputs,
    proof: { backend: "groth16_bn254", proof: base64Bytes(proof) },
  };
  if (withAmount) decoded.amount = boundedWord(words[14], 128, "amount");
  return decoded;
}

/** raiseEscapeConcession(noteId, inputs, proof, amount) calldata (772 bytes). */
function decodeRaiseEscapeConcession(calldata) {
  return decodeRequestEvidenceCall(calldata, ABI.raiseEscapeConcession, true);
}

/** challengeEscapeWithdrawal(noteId, inputs, proof) calldata (740 bytes). */
function decodeChallengeEscapeWithdrawal(calldata) {
  return decodeRequestEvidenceCall(calldata, ABI.challengeEscapeWithdrawal, false);
}

const walletCodec = Object.freeze({
  ABI,
  ESCAPE_PAYOUT_GAS,
  GASLESS_ABI,
  PACKED_USER_OPERATION_TUPLE,
  REQUEST_TUPLE,
  WITHDRAWAL_CALLDATA_BYTES,
  WITHDRAWAL_KIND,
  WITHDRAWAL_TUPLE,
  NOTE_STATUS,
  decodeChallengeEscapeWithdrawal,
  decodeNoteLeaves,
  decodeNoteRecord,
  decodePendingConcessions,
  decodePendingWithdrawals,
  decodeRaiseEscapeConcession,
  decodeVaultEvent,
  encodeEffectiveExpiry,
  encodeNoteLeaves,
  encodeNoteRecord,
  encodePendingConcessions,
  encodePendingWithdrawals,
  packNoteFields,
  unpackNoteFields,
  escapeConcessionRaises,
  escapeConcessionRecorded,
  abiWord,
  addressWord,
  callData,
  encodeClaimCredit,
  encodeClaimEscapePayout,
  encodeCreateAccount,
  encodeDeposit,
  encodeEscapePayoutCredits,
  encodeFinalizeEscape,
  encodeSweep,
  encodeTransitWithdraw,
  encodeWithdrawal,
  escapePeriodBadge,
  escapePeriodLabel,
  escapePeriodPhrase,
  parseEscapePayoutClaim,
  parseNoteDeposited,
  parseWithdrawalReceipt,
});

export default walletCodec;
export {
  ABI, ESCAPE_PAYOUT_GAS, GASLESS_ABI, PACKED_USER_OPERATION_TUPLE, REQUEST_TUPLE, WITHDRAWAL_CALLDATA_BYTES, WITHDRAWAL_KIND,
  WITHDRAWAL_TUPLE, NOTE_STATUS,
  decodeChallengeEscapeWithdrawal, decodeNoteLeaves, decodeNoteRecord, decodePendingConcessions, decodePendingWithdrawals,
  decodeRaiseEscapeConcession, decodeVaultEvent, encodeEffectiveExpiry, encodeNoteLeaves, encodeNoteRecord,
  encodePendingConcessions, encodePendingWithdrawals, packNoteFields, unpackNoteFields, escapeConcessionRaises,
  escapeConcessionRecorded, abiWord, addressWord, callData, encodeClaimCredit, encodeClaimEscapePayout, encodeCreateAccount,
  encodeDeposit, encodeEscapePayoutCredits, encodeFinalizeEscape, encodeSweep, encodeTransitWithdraw, encodeWithdrawal,
  escapePeriodBadge, escapePeriodLabel, escapePeriodPhrase, parseEscapePayoutClaim, parseNoteDeposited, parseWithdrawalReceipt };
