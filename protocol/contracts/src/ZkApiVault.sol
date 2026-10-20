// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {Types} from "./libraries/Types.sol";
import {Errors} from "./libraries/Errors.sol";
import {Events} from "./libraries/Events.sol";
import {MerkleUpdateLib} from "./libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "./libraries/NoteLeafLib.sol";
import {ReentrancyGuardTransient} from "./libraries/ReentrancyGuardTransient.sol";
import {IZkApiProofAdapter} from "./interfaces/IZkApiProofAdapter.sol";
import {IBn254Poseidon} from "./interfaces/IBn254Poseidon.sol";

/// @title ZkApiVault
/// @notice Native ETH settlement in whole gwei with in-protocol BN254 Groth16 verification, for
///         circuit zkapi-v2-concession-v2 (vault revision 4, leaf-bound exits).
/// @dev An escape names the nullifier N_k of the state it leaves and that state's derived successor
///      nullifier N_{k+1}, may concede an amount c, and pays B_k - c. Only a request proof at
///      N_{k+1} defeats it; a request proof at N_k can only raise c, to at most that request's
///      solvency bound.
///      Leaf-bound exits: each note is one storage word, its leaf L = P(d_leaf', R, F)[1] over its
///      registration commitment R and F = noteId * 2^192 + depositAmount * 2^64 + expiryTs, with its
///      status in the top two bits. A withdrawal proof publishes L and F and binds L to the owner's
///      secret; the vault compares L with the stored word and takes D and e from F. Exits therefore
///      need no Merkle path, no root, no indexer and no logs.
///      The request tree (request proofs only) has the notes' leaves in deposit order; the vault
///      keeps its frontier and computes currentRoot() on demand, and keeps no root history. The
///      server admits request proofs at any root it read from the vault within its grace window
///      (request_root_grace_seconds), so retireClosedLeaf takes effect for new requests at most
///      that long after it lands.
///      Ownership transfers are two-step and stay open while paused, for incident key rotation:
///      transferOwnership only nominates pendingOwner, and the current owner keeps every power
///      (including unpause and replacing the nomination) until the nominee calls acceptOwnership.
///      A mistyped or unusable nominee therefore cannot leave a paused vault without an owner.
///      Every hash (leaves, the frontier, currentRoot(), retirement sub-paths) is done by `poseidon`,
///      a Bn254PoseidonRuntime deployed separately and called with STATICCALL, so it can never change
///      the vault's state.
///      Under a broken verifier or setup (a forged proof) D comes from the forged noteFields, so one
///      forged exit can pay out the whole vault in one transaction, where a vault that read D from
///      storage would pay at most each note's deposit per forged exit; the eventual loss is the same
///      (a broken verifier also forges defeats and requests, and nothing can move funds out of a
///      paused vault). See docs/design/concession-exit.md, Amendment A3.
contract ZkApiVault is ReentrancyGuardTransient, Ownable2Step, Events {
    uint16 public constant PROTOCOL_VERSION = 2;
    /// @notice Capability marker of the concession exit (vault revision 3 and later).
    uint16 public constant CONCESSION_ESCAPE_VERSION = 1;
    /// @notice Capability marker of leaf-bound exits (vault revision 4): noteRecord, noteLeaves,
    ///         the computed currentRoot() and the withdrawal statement of zkapi-v2-concession-v2.
    uint16 public constant LEAF_BOUND_EXIT_VERSION = 1;
    /// @notice Minimum unpaused time between an unpause and the next pause.
    uint64 public constant PAUSE_COOLDOWN = 1 days;
    uint64 public constant DEFAULT_CHALLENGE_PERIOD = 24 hours;
    uint64 public constant EXPIRY_BUCKET = 1 days;
    uint256 public constant MERKLE_DEPTH = 32;
    /// @notice Lower bound of the treasury timelock; the delay is max(this, challengePeriod).
    uint64 public constant MIN_TREASURY_CHANGE_DELAY = 2 days;
    /// @notice Execution gas forwarded on treasury pushes; a failed push accrues to treasuryArrears.
    /// @dev A treasury that needs more gas to receive always accrues arrears. A caller cannot force
    ///      deferral by under-funding gas: when the push gets less than this, the 1/64 of gas the
    ///      vault keeps (under ~1.6k) cannot record arrears, so the whole call reverts.
    uint256 public constant TREASURY_PAYOUT_GAS = 100_000;
    /// @notice Execution gas forwarded on finalizeEscapeWithdrawal's push to the escape destination.
    ///         A failed push is credited to escapePayoutCredits; claimEscapePayout forwards all gas.
    /// @dev The cap bounds what a destination that burns its gas adds to finalization, so the
    ///      treasury share is paid at a bounded cost. It is far above the 2,300-gas stipend, which
    ///      smart-contract wallets can exceed; a destination that needs more gets a credit. As with
    ///      TREASURY_PAYOUT_GAS, under-funding gas cannot force a credit for a destination that
    ///      accepts within the cap and fails only by running out of gas: the 1/64 the vault keeps
    ///      cannot record one, so the call reverts. A receive that itself refuses when given less
    ///      gas returns the rest, so such a destination can be credited; the credit stays claimable.
    uint256 public constant ESCAPE_PAYOUT_GAS = 100_000;
    /// @dev Lower bound of unpauseClaimGrace; the grace is max(this, challengePeriod).
    uint64 private constant MIN_UNPAUSE_CLAIM_GRACE = 1 days;
    /// @dev Withdrawal kinds. Kind 2 (ownership proof, for the server's clearance) is never accepted.
    uint8 private constant KIND_ESCAPE = 0;
    uint8 private constant KIND_CLOSE = 1;
    /// @dev _nullifierWords: the two flags, and the shift of a pending escape's value above them.
    uint256 private constant USED = 1;
    uint256 private constant CHALLENGED = 2;
    uint256 private constant PAYLOAD_SHIFT = 2;
    /// @dev N_{k+1}'s word of a pending escape: the destination above the flags, the note's expiryTs
    ///      above the destination.
    uint256 private constant EXPIRY_SHIFT = PAYLOAD_SHIFT + 160;
    /// @dev _notes: the leaf in bits 0-253 (every leaf is a field element, below 2^254), the status
    ///      in bits 254-255.
    uint256 private constant STATUS_SHIFT = 254;
    uint256 private constant LEAF_MASK = (1 << STATUS_SHIFT) - 1;
    /// @dev _pauseEpochs: firstNoteId above the total paused duration.
    uint256 private constant EPOCH_FIRST_SHIFT = 64;

    /// Native asset sentinel retained for deployment and client compatibility.
    address public constant billingToken = address(0);
    uint256 public constant nativeAssetWeiPerUnit = 1 gwei;
    uint128 public constant MAX_NATIVE_UNITS = 9_007_199_254_740_991;
    uint64 public immutable noteTtl;
    uint64 public immutable challengePeriod;
    uint64 public immutable treasuryChangeDelay;
    /// @notice Unpaused time every note keeps after an unpause before claimExpired can take it.
    uint64 public immutable unpauseClaimGrace;
    uint128 public immutable requestChargeCap;
    IZkApiProofAdapter public immutable proofAdapter;
    uint256 public immutable stateSigningKeyX;
    uint256 public immutable stateSigningKeyY;
    uint256 public immutable clearanceSigningKeyX;
    uint256 public immutable clearanceSigningKeyY;
    /// @notice Longest time a pause blocks initiateEscapeWithdrawal and mutualClose; at least
    ///         2 * challengePeriod.
    uint64 public immutable maxPauseDuration;
    /// @notice The Poseidon contract (src/poseidon/Bn254PoseidonRuntime.sol) that hashes the note
    ///         leaves and the request tree (compress).
    IBn254Poseidon public immutable poseidon;
    /// @notice The smallest deposit, in gwei units: a leaf of the request tree locks at least this
    ///         much, which an exit or an expiry sweep releases.
    uint128 public immutable minDeposit;

    address public treasury;
    bool public paused;
    uint32 public nextNoteId;
    /// @notice Start of the current pause; zero while unpaused.
    uint64 public pausedAt;
    /// @notice Sum of all completed pause intervals, in seconds.
    uint64 public totalPausedDuration;
    /// @notice Treasury payouts (gwei units) whose push failed; see withdrawTreasuryArrears.
    uint128 public treasuryArrears;
    address public pendingTreasury;
    /// @notice Active-clock time (wall clock minus all paused time) from which acceptTreasury may
    ///         apply pendingTreasury; paused time never counts toward the delay.
    uint64 public pendingTreasuryReadyAt;
    /// @notice Time of the latest unpause; zero if the vault was never unpaused.
    uint64 public lastUnpausedAt;
    /// @notice Records in _pauseEpochs: unpauses that followed a deposit (see pausedBefore).
    uint32 public pauseEpochCount;

    /// @dev One word per note: its leaf | status << 254 (noteRecord). A retired note is Closed with
    ///      a zero leaf.
    mapping(uint32 => uint256) private _notes;
    /// @dev The pending escapes; read through pendingWithdrawals and pendingConcessions.
    mapping(uint32 => Types.Escape) private _escapes;
    /// @dev One word per nullifier, read through usedNullifiers (bit 0, USED) and
    ///      challengedNullifiers (bit 1, CHALLENGED). An escape writes the rest of its record above
    ///      the flags of the two words it consumes (PAYLOAD_SHIFT): N_{k+1} in N_k's word, and the
    ///      destination and the note's expiryTs in N_{k+1}'s, so that a pending escape costs four
    ///      fresh slots in all. A defeat clears both words except N_k's CHALLENGED; a finalization
    ///      leaves them, as only _escapes says whether an escape is pending. A word without USED
    ///      therefore holds no value: it is 0 or CHALLENGED.
    mapping(uint256 => uint256) private _nullifierWords;
    /// @notice Active-clock time until which a defeated escape's note stays out of claimExpired's
    ///         reach (challengePeriod after the defeat); zero if never needed. A note's active expiry
    ///         is max(expiryTs - pausedBefore(noteId), graceUntil(noteId)).
    mapping(uint32 => uint64) public graceUntil;
    /// @notice Escape payouts (gwei units) whose push to their destination failed, by destination;
    ///         see claimEscapePayout.
    mapping(address => uint128) public escapePayoutCredits;
    /// @dev Pause epochs, in order: firstNoteId << 64 | totalPausedDuration at an unpause, firstNoteId
    ///      being nextNoteId then. Consecutive unpauses without a deposit between them share a record.
    mapping(uint32 => uint256) private _pauseEpochs;
    /// @dev recordRoot's audit records: root => blockNumber << 32 | noteCount. Nothing reads them.
    mapping(uint256 => uint256) private _recordedRoots;
    /// @dev The request tree's frontier: see MerkleUpdateLib. Index 0 is unused.
    uint256[32] private _filledSubtrees;

    modifier whenNotPaused() {
        if (paused) revert Errors.Paused();
        _;
    }

    /// @dev Open while unpaused, and from pausedAt + maxPauseDuration on while paused.
    modifier whenExitsOpen() {
        if (paused && block.timestamp < uint256(pausedAt) + maxPauseDuration) revert Errors.Paused();
        _;
    }

    constructor(
        address treasury_,
        uint64 noteTtl_,
        uint64 challengePeriod_,
        uint128 requestChargeCap_,
        address proofAdapter_,
        uint256 stateSigningKeyX_,
        uint256 stateSigningKeyY_,
        uint256 clearanceSigningKeyX_,
        uint256 clearanceSigningKeyY_,
        address owner_,
        uint64 maxPauseDuration_,
        address poseidon_,
        uint128 minDeposit_
    ) Ownable(owner_) {
        if (
            treasury_ == address(0) || proofAdapter_ == address(0) || challengePeriod_ == 0
                || maxPauseDuration_ < 2 * uint256(challengePeriod_)
        ) {
            revert Errors.Unauthorized();
        }
        _requireField(stateSigningKeyX_);
        _requireField(stateSigningKeyY_);
        _requireField(clearanceSigningKeyX_);
        _requireField(clearanceSigningKeyY_);
        if (
            (stateSigningKeyX_ == 0 && stateSigningKeyY_ == 0)
                || (clearanceSigningKeyX_ == 0 && clearanceSigningKeyY_ == 0)
        ) revert Errors.InvalidDeploymentBinding();
        // The hasher must be a contract that answers compress(DOMAIN_NODE, 0, 0) with the tree's
        // first zero hash: a guard against a wrong address (an account without code, or another
        // contract of the deployment). Its identity is pinned by its runtime codehash off chain.
        if (
            poseidon_.code.length == 0
                || MerkleUpdateLib.poseidonNodeHash(IBn254Poseidon(poseidon_), 0, 0) != MerkleUpdateLib.zeroHash(1)
        ) revert Errors.InvalidDeploymentBinding();

        if (requestChargeCap_ == 0 || requestChargeCap_ > MAX_NATIVE_UNITS) {
            revert Errors.InvalidBalance();
        }
        if (minDeposit_ == 0 || minDeposit_ > MAX_NATIVE_UNITS) revert Errors.InvalidBalance();
        treasury = treasury_;
        noteTtl = noteTtl_;
        challengePeriod = challengePeriod_;
        treasuryChangeDelay =
            challengePeriod_ > MIN_TREASURY_CHANGE_DELAY ? challengePeriod_ : MIN_TREASURY_CHANGE_DELAY;
        unpauseClaimGrace = challengePeriod_ > MIN_UNPAUSE_CLAIM_GRACE ? challengePeriod_ : MIN_UNPAUSE_CLAIM_GRACE;
        requestChargeCap = requestChargeCap_;
        proofAdapter = IZkApiProofAdapter(proofAdapter_);
        stateSigningKeyX = stateSigningKeyX_;
        stateSigningKeyY = stateSigningKeyY_;
        clearanceSigningKeyX = clearanceSigningKeyX_;
        clearanceSigningKeyY = clearanceSigningKeyY_;
        maxPauseDuration = maxPauseDuration_;
        poseidon = IBn254Poseidon(poseidon_);
        minDeposit = minDeposit_;
    }

    /// @notice Deposits `amount` gwei units (at least minDeposit) under `commitment` as the next note:
    ///         stores its leaf and appends it to the request tree's frontier. No Merkle proof is
    ///         needed, so deposits never invalidate each other.
    /// @dev Gas depends on the note ID n: one compression per trailing one of n (none for an even
    ///      n, one on average) and, the first time a frontier level t is written (at n = 2^t - 1, 31
    ///      times in the vault's life), a fresh storage slot. A gas limit from eth_estimateGas covers
    ///      only the index it was estimated at, and a deposit that lands later may land on a dearer
    ///      one: clients add the trailing-ones levels of the next 64 indices to the estimate
    ///      (docs/deployment.md, deposit gas limit), and a depositor without that policy sends at
    ///      least 650,000 gas under mainnet pricing, or 850,000 where a fresh slot costs about
    ///      110,000 gas (EIP-8037): enough for every index, including n = 2^31 - 1. Unused gas is
    ///      refunded; running out of gas reverts with nothing deposited.
    function deposit(bytes32 commitment, uint128 amount) external payable nonReentrant whenNotPaused {
        if (amount > MAX_NATIVE_UNITS || msg.value != uint256(amount) * nativeAssetWeiPerUnit) {
            revert Errors.InvalidNativeValue();
        }
        if (amount == 0) revert Errors.ZeroAmount();
        if (amount < minDeposit) revert Errors.DepositTooSmall();
        if (commitment == bytes32(0)) revert Errors.InvalidCommitment();
        _requireField(uint256(commitment));

        uint32 noteId = nextNoteId;
        if (noteId == type(uint32).max) revert Errors.TreeFull();
        uint256 rawExpiry = block.timestamp + noteTtl;
        uint256 bucketedExpiry = ((rawExpiry + EXPIRY_BUCKET - 1) / EXPIRY_BUCKET) * EXPIRY_BUCKET;
        if (bucketedExpiry > type(uint64).max) revert Errors.InvalidFelt();
        uint64 expiryTs = uint64(bucketedExpiry);
        uint256 leaf = NoteLeafLib.computeLeaf(poseidon, commitment, NoteLeafLib.pack(noteId, amount, expiryTs));
        // A zero leaf is the retired (and the empty) leaf: it could never be told from one.
        if (leaf == 0) revert Errors.InvalidCommitment();
        if (noteId & 1 == 1) {
            MerkleUpdateLib.append(poseidon, _filledSubtrees, noteId, _notes[noteId - 1] & LEAF_MASK, leaf);
        }
        _notes[noteId] = _word(leaf, Types.NoteStatus.Active);
        nextNoteId = noteId + 1;
        emit NoteDeposited(noteId, commitment, amount, expiryTs);
    }

    /// @notice Closes an Active note with a clearance-backed (kind 1) withdrawal proof: pays
    ///         finalBalance to the destination and the rest of the deposit to the treasury.
    /// @dev Does not consult challengedNullifiers: the operator's clearance is its consent.
    function mutualClose(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        nonReentrant
        whenExitsOpen
    {
        _validateWithdrawalBinding(inputs);
        if (inputs.kind != KIND_CLOSE) revert Errors.WrongWithdrawalKind();
        if (block.timestamp > inputs.validUntil) revert Errors.ProofExpired();
        _requireDestination(inputs.destination);
        (uint32 noteId, uint128 depositAmount,) = _activeNote(inputs);
        uint128 finalBalance = inputs.finalBalance;
        if (finalBalance > depositAmount) revert Errors.InvalidBalance();
        proofAdapter.assertValidWithdrawal(inputs, proof);

        _consumeNullifier(inputs.withdrawalNullifier);
        _notes[noteId] = _word(inputs.noteLeaf, Types.NoteStatus.Closed);
        // The submitter chose this destination and can prove another, so a failed push reverts.
        if (finalBalance != 0) _transfer(inputs.destination, finalBalance);
        _payTreasury(depositAmount - finalBalance);
        emit MutualClose(noteId, inputs.withdrawalNullifier, finalBalance, inputs.destination);
    }

    /// @notice Starts an escape (kind 0) from the state at withdrawalNullifier N, paying
    ///         finalBalance = B - conceded after challengePeriod unless a request proof at
    ///         nextNullifier (the state's successor) defeats it first. Consumes N and nextNullifier.
    function initiateEscapeWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        nonReentrant
        whenExitsOpen
    {
        _validateWithdrawalBinding(inputs);
        if (inputs.kind != KIND_ESCAPE) revert Errors.WrongWithdrawalKind();
        if (block.timestamp > inputs.validUntil) revert Errors.ProofExpired();
        _requireDestination(inputs.destination);
        uint256 nullifier = inputs.withdrawalNullifier;
        uint256 nextNullifier = inputs.nextNullifier;
        if (nextNullifier == 0 || nextNullifier == nullifier) revert Errors.InvalidDeploymentBinding();
        uint256 word = _nullifierWords[nullifier];
        uint256 nextWord = _nullifierWords[nextNullifier];
        // A defeated escape stays defeated: its calldata is public, so anyone could replay it.
        if (word & CHALLENGED != 0) revert Errors.ChallengedNullifier();
        // The successor of this state was spent (it defeated an escape), so this state is stale.
        if (nextWord & CHALLENGED != 0) revert Errors.SupersededState();
        (uint32 noteId, uint128 depositAmount, uint64 expiryTs) = _activeNote(inputs);
        uint256 total = uint256(inputs.finalBalance) + inputs.conceded;
        if (total > depositAmount) revert Errors.InvalidBalance();
        proofAdapter.assertValidWithdrawal(inputs, proof);

        _requireUnused(nullifier, word);
        _requireUnused(nextNullifier, nextWord);
        uint64 deadline = uint64(block.timestamp) + challengePeriod;
        _notes[noteId] = _word(inputs.noteLeaf, Types.NoteStatus.PendingWithdrawal);
        // Neither word has a flag (checked above), so both are zero: these writes consume both
        // nullifiers and record N_{k+1} in N_k's word, and the destination and expiryTs in
        // N_{k+1}'s. N_{k+1} is below the field modulus (_requireUnused), so it fits above the flags;
        // 2 + 160 + 64 bits fit in N_{k+1}'s word.
        _nullifierWords[nullifier] = (nextNullifier << PAYLOAD_SHIFT) | USED;
        _nullifierWords[nextNullifier] =
            (uint256(expiryTs) << EXPIRY_SHIFT) | (uint256(uint160(inputs.destination)) << PAYLOAD_SHIFT) | USED;
        // Every amount is at most depositAmount, which _activeNote bounds by MAX_NATIVE_UNITS
        // (< 2^53); the casts are checked anyway.
        _escapes[noteId] = Types.Escape({
            withdrawalNullifier: nullifier,
            challengeDeadline: deadline,
            finalBalance: _toUint64(inputs.finalBalance),
            conceded: _toUint64(inputs.conceded),
            depositAmount: _toUint64(depositAmount)
        });
        emit EscapeWithdrawalInitiated(noteId, nullifier, inputs.finalBalance, inputs.destination, deadline);
        // casting to 'uint128' is safe because total is at most the uint128 depositAmount
        // forge-lint: disable-next-line(unsafe-typecast)
        emit EscapeConcessionRecorded(noteId, nextNullifier, uint128(total), inputs.conceded);
    }

    /// @notice Defeats a pending escape with a request proof at its successor nullifier N_{k+1},
    ///         which shows the owner held and spent the successor state. Anyone may call it.
    /// @dev The request's root, time and tag are not checked: historical evidence is valid. The
    ///      escape's nullifiers are released, N_k is flagged for good, and the note gets at least
    ///      challengePeriod of unpaused time before an expiry sweep.
    function challengeEscapeWithdrawal(uint32 noteId, Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external
        nonReentrant
    {
        (uint256 noteWord, Types.Escape storage escape) = _pendingEscape(noteId);
        _validateRequestBinding(inputs);
        uint256 nullifier = escape.withdrawalNullifier;
        uint256 nextNullifier = _nextNullifierOf(nullifier);
        // A request at the escaped nullifier never defeats; it can only raise the concession.
        if (inputs.requestNullifier != nextNullifier) revert Errors.NotSuccessorEvidence();
        proofAdapter.assertValidRequest(inputs, proof);

        // casting to 'uint64' is safe because N_{k+1}'s word holds the 64-bit expiryTs, and nothing
        // else, above the destination
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 expiryTs = uint64(_nullifierWords[nextNullifier] >> EXPIRY_SHIFT);
        _notes[noteId] = _word(noteWord & LEAF_MASK, Types.NoteStatus.Active);
        delete _escapes[noteId];
        // Releases both nullifiers and the escape's values in their words; N_k stays CHALLENGED.
        _nullifierWords[nullifier] = CHALLENGED;
        delete _nullifierWords[nextNullifier];
        _grantChallengeGrace(noteId, expiryTs);
        emit EscapeWithdrawalChallenged(noteId, nullifier);
    }

    /// @notice Raises a pending escape's concession, in place, with a request proof at the escaped
    ///         nullifier N_k: to min(amount, the request's solvencyBound, the state balance).
    ///         Anyone may call it. The deadline and nullifiers do not change, and a defeat stays
    ///         possible.
    function raiseEscapeConcession(
        uint32 noteId,
        Types.RequestPublicInputs calldata inputs,
        bytes calldata proof,
        uint128 amount
    ) external nonReentrant {
        (, Types.Escape storage escape) = _pendingEscape(noteId);
        _validateRequestBinding(inputs);
        uint256 nullifier = escape.withdrawalNullifier;
        if (inputs.requestNullifier != nullifier) revert Errors.NotStateEvidence();
        uint128 conceded = escape.conceded;
        uint128 stateBalance = escape.finalBalance + conceded;
        uint128 raised = amount < inputs.solvencyBound ? amount : inputs.solvencyBound;
        if (stateBalance < raised) raised = stateBalance;
        if (raised <= conceded) revert Errors.NotARaise();
        proofAdapter.assertValidRequest(inputs, proof);

        uint128 finalBalance = stateBalance - raised;
        // Both are at most stateBalance, the sum of the escape's two uint64 amounts, itself at most
        // the note's deposit (< 2^53).
        escape.conceded = _toUint64(raised);
        escape.finalBalance = _toUint64(finalBalance);
        emit EscapeConcessionRaised(noteId, nullifier, raised, finalBalance);
    }

    /// @notice Pays out an unchallenged escape after its deadline and closes the note. Neither
    ///         payee can block the other or the closure: finalBalance (as raised) goes to the
    ///         destination or, if that push fails, to escapePayoutCredits[destination]; the rest
    ///         of the deposit goes to the treasury or, if that push fails, to treasuryArrears.
    function finalizeEscapeWithdrawal(uint32 noteId) external nonReentrant {
        uint256 noteWord = _notes[noteId];
        Types.Escape storage escape = _escapes[noteId];
        uint64 deadline = escape.challengeDeadline;
        if (_status(noteWord) != Types.NoteStatus.PendingWithdrawal || deadline == 0) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp < deadline) revert Errors.ChallengeNotExpired();

        uint256 nullifier = escape.withdrawalNullifier;
        uint128 finalBalance = escape.finalBalance;
        uint128 operatorShare = escape.depositAmount - finalBalance;
        address destination = _destinationOf(_nextNullifierOf(nullifier));
        _notes[noteId] = _word(noteWord & LEAF_MASK, Types.NoteStatus.Closed);
        // Both nullifiers stay consumed; their words keep the values nothing reads any more.
        delete _escapes[noteId];
        if (finalBalance != 0 && !_push(destination, finalBalance, ESCAPE_PAYOUT_GAS)) {
            escapePayoutCredits[destination] += finalBalance;
            emit EscapePayoutDeferred(noteId, destination, finalBalance);
        }
        _payTreasury(operatorShare);
        emit EscapeWithdrawalFinalized(noteId, nullifier, finalBalance, destination);
    }

    /// @notice Pays `destination` all of its escape payouts whose push failed. Anyone may call it,
    ///         but only `destination` is paid. The push forwards all available gas; if it fails, the
    ///         call reverts and the credit is kept. Open while paused, like the escapes it completes.
    function claimEscapePayout(address destination) external nonReentrant {
        uint128 amount = escapePayoutCredits[destination];
        if (amount == 0) revert Errors.ZeroAmount();
        delete escapePayoutCredits[destination];
        emit EscapePayoutClaimed(destination, amount);
        _transfer(destination, amount);
    }

    /// @notice Sweeps an Active note past its effective expiry to the treasury, given the note's
    ///         registration commitment, deposit and expiry (from its NoteDeposited event), which must
    ///         reproduce the stored leaf. The leaf stays: the request circuit refuses requests after
    ///         the note's expiryTs.
    function claimExpired(uint32 noteId, bytes32 commitment, uint128 amount, uint64 expiryTs)
        external
        nonReentrant
        whenNotPaused
    {
        uint256 word = _notes[noteId];
        if (_status(word) != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        uint256 leaf = NoteLeafLib.computeLeaf(poseidon, commitment, NoteLeafLib.pack(noteId, amount, expiryTs));
        if (word & LEAF_MASK != leaf) revert Errors.NoteLeafMismatch();
        if (block.timestamp < _claimableAt(noteId, expiryTs)) revert Errors.NoteNotExpired();
        _notes[noteId] = _word(leaf, Types.NoteStatus.Closed);
        _payTreasury(amount);
        emit ExpiredClaimed(noteId, amount);
    }

    /// @notice Removes a Closed note's leaf from the request tree, so that request proofs at later
    ///         roots no longer contain it. Permissionless and open while paused; an operator tool.
    /// @dev `siblings` is the leaf's path (bottom up) at the current root, of which only the first
    ///      MerkleUpdateLib.retireLevel(noteId, nextNoteId) are read: callers zero-fill the rest,
    ///      which also keeps the calldata cheap. Reverts StaleRoot when they do not reproduce the
    ///      frontier node of the leaf's subtree, including when the leaf was already retired or
    ///      another retirement in that subtree landed first (refresh the path and retry).
    function retireClosedLeaf(uint32 noteId, uint256[32] calldata siblings) external nonReentrant {
        uint256 word = _notes[noteId];
        if (_status(word) != Types.NoteStatus.Closed) revert Errors.NoteNotClosed();
        uint256 leaf = word & LEAF_MASK;
        if (leaf == 0) revert Errors.StaleRoot();
        MerkleUpdateLib.retire(poseidon, _filledSubtrees, nextNoteId, noteId, leaf, siblings);
        _notes[noteId] = _word(0, Types.NoteStatus.Closed);
        emit ClosedLeafRetired(noteId);
    }

    /// @notice Records the request tree's current root with the note count and block number, as a
    ///         permissionless audit trail of roots: recordedRoot(root) says the vault's root was
    ///         `root`, over that many notes, at that block. Nothing in the vault, the server or the
    ///         clients depends on it: the first record of a root is kept, and every call emits
    ///         RootRecorded.
    function recordRoot() external returns (uint256 root) {
        uint32 noteCount = nextNoteId;
        root = currentRoot();
        // casting to 'uint64' is safe because block numbers stay below 2^64
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 blockNumber = uint64(block.number);
        if (_recordedRoots[root] == 0) {
            _recordedRoots[root] = (uint256(blockNumber) << 32) | noteCount;
        }
        emit RootRecorded(root, noteCount, blockNumber);
    }

    /// @notice Schedules a treasury change; acceptTreasury applies it after treasuryChangeDelay of
    ///         unpaused time.
    function setTreasury(address newTreasury) external onlyOwner whenNotPaused {
        if (newTreasury == address(0) || newTreasury == address(this)) revert Errors.Unauthorized();
        uint64 readyAt = uint64(_activeClock()) + treasuryChangeDelay;
        pendingTreasury = newTreasury;
        pendingTreasuryReadyAt = readyAt;
        emit TreasuryChangeScheduled(newTreasury, readyAt);
    }

    function acceptTreasury() external onlyOwner whenNotPaused {
        address newTreasury = pendingTreasury;
        if (newTreasury == address(0)) revert Errors.NoPendingTreasuryChange();
        if (_activeClock() < pendingTreasuryReadyAt) revert Errors.TreasuryChangeNotReady();
        treasury = newTreasury;
        delete pendingTreasury;
        delete pendingTreasuryReadyAt;
        emit TreasurySet(newTreasury);
    }

    function cancelTreasuryChange() external onlyOwner {
        address cancelled = pendingTreasury;
        if (cancelled == address(0)) revert Errors.NoPendingTreasuryChange();
        delete pendingTreasury;
        delete pendingTreasuryReadyAt;
        emit TreasuryChangeCancelled(cancelled);
    }

    /// @notice Pays treasury shares whose push failed to the current treasury.
    function withdrawTreasuryArrears() external nonReentrant whenNotPaused {
        uint128 amount = treasuryArrears;
        if (amount == 0) revert Errors.ZeroAmount();
        treasuryArrears = 0;
        address recipient = treasury;
        _transfer(recipient, amount);
        emit TreasuryArrearsPaid(recipient, amount);
    }

    /// @notice Blocks deposit, claimExpired, setTreasury, acceptTreasury, withdrawTreasuryArrears
    ///         and renounceOwnership until unpause. Blocks for at most maxPauseDuration:
    ///         initiateEscapeWithdrawal and mutualClose, which reopen at pausedAt + maxPauseDuration
    ///         even while paused. Stay open while paused: challengeEscapeWithdrawal,
    ///         raiseEscapeConcession, finalizeEscapeWithdrawal and claimEscapePayout, so escapes in
    ///         flight resolve and credited payouts can be delivered, retireClosedLeaf and recordRoot,
    ///         and cancelTreasuryChange, transferOwnership and acceptOwnership. A pause needs
    ///         PAUSE_COOLDOWN since the latest unpause.
    function pause() external onlyOwner whenNotPaused {
        uint64 unpausedAt = lastUnpausedAt;
        if (unpausedAt != 0 && block.timestamp < uint256(unpausedAt) + PAUSE_COOLDOWN) {
            revert Errors.PauseCooldown();
        }
        paused = true;
        pausedAt = uint64(block.timestamp);
        emit Paused(msg.sender);
    }

    /// @dev Records the pause epoch the next deposits fall in: {nextNoteId, totalPausedDuration},
    ///      overwriting the latest record when no deposit happened since it (the same nextNoteId).
    function unpause() external onlyOwner {
        if (!paused) revert Errors.NotPaused();
        uint64 total = totalPausedDuration + (uint64(block.timestamp) - pausedAt);
        totalPausedDuration = total;
        paused = false;
        pausedAt = 0;
        lastUnpausedAt = uint64(block.timestamp);
        uint32 first = nextNoteId;
        uint32 count = pauseEpochCount;
        uint256 epoch = (uint256(first) << EPOCH_FIRST_SHIFT) | total;
        if (count != 0 && _epochFirst(_pauseEpochs[count - 1]) == first) {
            _pauseEpochs[count - 1] = epoch;
        } else {
            _pauseEpochs[count] = epoch;
            pauseEpochCount = count + 1;
        }
        emit Unpaused(msg.sender);
    }

    /// @dev Prevents making a pause permanent by renouncing; renouncing also clears pendingOwner.
    ///      A pause that is never lifted blocks exits for at most maxPauseDuration, and nothing can
    ///      sweep notes while paused.
    function renounceOwnership() public override onlyOwner whenNotPaused {
        super.renounceOwnership();
    }

    /// @notice The request tree's root over its nextNoteId leaves, computed from the frontier (at
    ///         most 32 compressions, about 0.5M gas in an eth_call). A historical root is this call at
    ///         that block. The server and clients read it at a pinned block hash.
    function currentRoot() public view returns (uint256) {
        uint32 count = nextNoteId;
        uint256 lastLeaf = count & 1 == 1 ? _notes[count - 1] & LEAF_MASK : 0;
        return MerkleUpdateLib.root(poseidon, _filledSubtrees, count, lastLeaf);
    }

    /// @notice A note's stored leaf and status (Uninitialized with leaf 0 for an unused ID; Closed
    ///         with leaf 0 once retired).
    function noteRecord(uint32 noteId) external view returns (uint256 leaf, Types.NoteStatus status) {
        uint256 word = _notes[noteId];
        return (word & LEAF_MASK, _status(word));
    }

    /// @notice The request tree's leaves start .. start + count - 1 (zero for a retired note), for a
    ///         rebuild of the tree from state. Reverts InvalidNoteRange unless start + count is at most
    ///         nextNoteId. A rebuild reads every page, nextNoteId() and currentRoot() at one block hash
    ///         (EIP-1898); pages of 2,048 leaves cost about 5.2M gas each.
    function noteLeaves(uint32 start, uint32 count) external view returns (uint256[] memory leaves) {
        if (uint256(start) + count > nextNoteId) revert Errors.InvalidNoteRange();
        leaves = new uint256[](count);
        for (uint256 i = 0; i < count;) {
            // casting to 'uint32' is safe because start + i < nextNoteId, a uint32
            // forge-lint: disable-next-line(unsafe-typecast)
            leaves[i] = _notes[uint32(start + i)] & LEAF_MASK;
            unchecked {
                ++i;
            }
        }
    }

    /// @notice nextNoteId and the request tree's frontier: nodes[t], t >= 1, is the complete left
    ///         subtree of height t, meaningful only where bit t of nextIndex is set (entries at clear
    ///         bits are stale subtrees already absorbed into higher ones; ignore them), and nodes[0]
    ///         is the last leaf when nextIndex is odd, else 0.
    function frontier() external view returns (uint32 nextIndex, uint256[32] memory nodes) {
        nextIndex = nextNoteId;
        nodes = _filledSubtrees;
        nodes[0] = nextIndex & 1 == 1 ? _notes[nextIndex - 1] & LEAF_MASK : 0;
    }

    /// @notice The block and note count recordRoot first recorded `root` at (zero if never).
    function recordedRoot(uint256 root) external view returns (uint32 noteCount, uint64 blockNumber) {
        uint256 record = _recordedRoots[root];
        // casting to 'uint32' and 'uint64' is safe because recordRoot packs exactly these widths
        // forge-lint: disable-next-line(unsafe-typecast)
        noteCount = uint32(record);
        // forge-lint: disable-next-line(unsafe-typecast)
        blockNumber = uint64(record >> 32);
    }

    /// @notice The paused time that preceded note `noteId`'s deposit (deposits never happen while
    ///         paused): the total of the latest pause epoch whose first note is at or below noteId.
    function pausedBefore(uint32 noteId) public view returns (uint64) {
        return _pausedBefore(noteId);
    }

    /// @notice Whether `nullifier` is consumed by an exit: a mutual close or a pending or finalized
    ///         escape (which consumes both its nullifiers). A defeat releases both.
    function usedNullifiers(uint256 nullifier) external view returns (bool) {
        return _nullifierWords[nullifier] & USED != 0;
    }

    /// @notice States an escape from which was defeated by successor evidence (a request proof at
    ///         the state's successor nullifier); they can never escape again, and the state just
    ///         below one reverts SupersededState. mutualClose does not consult it.
    function challengedNullifiers(uint256 nullifier) external view returns (bool) {
        return _nullifierWords[nullifier] & CHALLENGED != 0;
    }

    /// @notice A pending escape in revision 2's 6 words: exists, a zero word (revision 2's escape
    ///         proof activeRoot, which is not stored), withdrawalNullifier, the current payout
    ///         finalBalance, destination and challengeDeadline. All zero for a note without a
    ///         pending escape.
    function pendingWithdrawals(uint32 noteId)
        external
        view
        returns (
            bool exists,
            uint256 activeRoot,
            uint256 withdrawalNullifier,
            uint128 finalBalance,
            address destination,
            uint64 challengeDeadline
        )
    {
        Types.Escape storage escape = _escapes[noteId];
        challengeDeadline = escape.challengeDeadline;
        if (challengeDeadline == 0) return (false, 0, 0, 0, address(0), 0);
        exists = true;
        withdrawalNullifier = escape.withdrawalNullifier;
        finalBalance = escape.finalBalance;
        destination = _destinationOf(_nextNullifierOf(withdrawalNullifier));
    }

    /// @notice The concession side of a pending escape (3 words): nextNullifier N_{k+1}, the state
    ///         balance B_k = finalBalance + conceded, and conceded. All zero without a pending escape.
    function pendingConcessions(uint32 noteId)
        external
        view
        returns (uint256 nextNullifier, uint128 stateBalance, uint128 conceded)
    {
        Types.Escape storage escape = _escapes[noteId];
        if (escape.challengeDeadline == 0) return (0, 0, 0);
        nextNullifier = _nextNullifierOf(escape.withdrawalNullifier);
        conceded = escape.conceded;
        stateBalance = escape.finalBalance + conceded;
    }

    /// @notice Earliest wall-clock time claimExpired can succeed for the note with this commitment,
    ///         deposit and expiry, assuming no further pause.
    /// @dev Equals expiryTs plus all pause time since the deposit (at least challengePeriod of
    ///      unpaused time after a successful challenge), and never less than unpauseClaimGrace
    ///      after the latest unpause. While paused it projects an immediate unpause and keeps
    ///      increasing. Zero when (commitment, amount, expiryTs) is not the note's stored leaf: an
    ///      unknown or retired note, or wrong values.
    function effectiveExpiry(uint32 noteId, bytes32 commitment, uint128 amount, uint64 expiryTs)
        external
        view
        returns (uint64)
    {
        uint256 word = _notes[noteId];
        uint256 leaf = word & LEAF_MASK;
        if (
            leaf == 0
                || leaf != NoteLeafLib.computeLeaf(poseidon, commitment, NoteLeafLib.pack(noteId, amount, expiryTs))
        ) return 0;
        uint256 wallClock = _claimableAt(noteId, expiryTs);
        return wallClock > type(uint64).max ? type(uint64).max : uint64(wallClock);
    }

    /// @dev The exit checks, before any proof: noteFields below 2^224, the note Active, its stored
    ///      leaf equal to inputs.noteLeaf, and its deposit at most MAX_NATIVE_UNITS. The proof then
    ///      binds the leaf to the owner's registration and to these noteId, depositAmount and
    ///      expiryTs; the vault computed the stored leaf from the note's own, so they are the note's.
    function _activeNote(Types.WithdrawalPublicInputs calldata inputs)
        private
        view
        returns (uint32 noteId, uint128 depositAmount, uint64 expiryTs)
    {
        uint256 fields = inputs.noteFields;
        if (fields >> NoteLeafLib.FIELDS_BITS != 0) revert Errors.InvalidNoteFields();
        (noteId, depositAmount, expiryTs) = NoteLeafLib.unpack(fields);
        uint256 word = _notes[noteId];
        if (_status(word) != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (word & LEAF_MASK != inputs.noteLeaf) revert Errors.NoteLeafMismatch();
        // Every deposit is at most MAX_NATIVE_UNITS, so a larger D cannot match a stored leaf
        // unless the proof system is broken; refusing it bounds every amount below 2^53 before any
        // narrowing.
        if (depositAmount > MAX_NATIVE_UNITS) revert Errors.InvalidBalance();
    }

    function _transfer(address destination, uint128 amount) private {
        (bool success,) = payable(destination).call{value: uint256(amount) * nativeAssetWeiPerUnit}("");
        if (!success) revert Errors.NativeTransferFailed();
    }

    /// @dev Sends `amount` units with at most `gasLimit` execution gas and copies no return data.
    function _push(address recipient, uint128 amount, uint256 gasLimit) private returns (bool success) {
        uint256 value = uint256(amount) * nativeAssetWeiPerUnit;
        assembly ("memory-safe") {
            success := call(gasLimit, recipient, value, 0, 0, 0, 0)
        }
    }

    /// @dev A treasury that reverts or runs out of gas cannot freeze mutualClose and
    ///      finalizeEscapeWithdrawal payouts (or claimExpired): its share is retained in
    ///      treasuryArrears.
    function _payTreasury(uint128 amount) private {
        if (amount == 0) return;
        address recipient = treasury;
        if (!_push(recipient, amount, TREASURY_PAYOUT_GAS)) {
            treasuryArrears += amount;
            emit TreasuryPaymentDeferred(recipient, amount);
        }
    }

    /// @dev Neither zero nor the vault itself, which cannot receive ETH.
    function _requireDestination(address destination) private view {
        if (destination == address(0) || destination == address(this)) revert Errors.InvalidDestination();
    }

    /// @dev mutualClose's consumption of N, which keeps a CHALLENGED flag (G2: a close does not
    ///      consult it).
    function _consumeNullifier(uint256 nullifier) private {
        uint256 word = _nullifierWords[nullifier];
        _requireUnused(nullifier, word);
        _nullifierWords[nullifier] = word | USED;
    }

    /// @dev Only canonical field elements are consumed, whatever the adapter accepts: the nullifier
    ///      words and the escape records are keyed on the raw word, so N + r (the same scalar to a
    ///      verifier that reduced it) would otherwise slip past ChallengedNullifier, SupersededState
    ///      and ReplayedNullifier, or name a successor no defeat can match. Every nullifier with a
    ///      nonzero word passed this check first. `word` is _nullifierWords[nullifier].
    function _requireUnused(uint256 nullifier, uint256 word) private pure {
        if (nullifier >= MerkleUpdateLib.FIELD_MODULUS) revert Errors.InvalidFelt();
        if (word & USED != 0) revert Errors.ReplayedNullifier();
    }

    /// @dev N_{k+1} of the pending escape from N_k = `nullifier`, from N_k's word.
    function _nextNullifierOf(uint256 nullifier) private view returns (uint256) {
        return _nullifierWords[nullifier] >> PAYLOAD_SHIFT;
    }

    /// @dev The destination of the pending escape whose successor nullifier is `nextNullifier`,
    ///      from N_{k+1}'s word.
    function _destinationOf(uint256 nextNullifier) private view returns (address) {
        // casting to 'uint160' is safe because it keeps exactly the destination's 160 bits above the
        // flags (the expiryTs above them is dropped)
        // forge-lint: disable-next-line(unsafe-typecast)
        return address(uint160(_nullifierWords[nextNullifier] >> PAYLOAD_SHIFT));
    }

    /// @dev The note's word and the record of an escape that can still be challenged or raised.
    function _pendingEscape(uint32 noteId) private view returns (uint256 noteWord, Types.Escape storage escape) {
        noteWord = _notes[noteId];
        escape = _escapes[noteId];
        uint64 deadline = escape.challengeDeadline;
        if (_status(noteWord) != Types.NoteStatus.PendingWithdrawal || deadline == 0) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp >= deadline) revert Errors.ChallengeExpired();
    }

    /// @dev Delays, but does not prevent, an expiry sweep right after a defeat: the note keeps
    ///      at least challengePeriod of unpaused time to exit from its signed successor state, by
    ///      raising graceUntil when the note's active expiry max(expiryTs - pausedBefore, graceUntil)
    ///      is below that. pausedBefore(noteId) is at most totalPausedDuration, so when graceEnd is
    ///      at most max(expiryTs - totalPausedDuration, graceUntil) nothing needs writing and no
    ///      epoch is read: the common case, a defeat long before the expiry.
    function _grantChallengeGrace(uint32 noteId, uint64 expiryTs) private {
        uint256 graceEnd = _activeClock() + challengePeriod;
        uint256 grace = graceUntil[noteId];
        uint256 total = totalPausedDuration;
        uint256 lowerExpiry = expiryTs > total ? expiryTs - total : 0;
        if (graceEnd <= (lowerExpiry > grace ? lowerExpiry : grace)) return;
        uint256 activeExpiry = uint256(expiryTs) - _pausedBefore(noteId);
        if (grace > activeExpiry) activeExpiry = grace;
        if (graceEnd > activeExpiry) {
            graceUntil[noteId] = graceEnd > type(uint64).max ? type(uint64).max : uint64(graceEnd);
        }
    }

    /// @dev The total of the latest pause epoch whose firstNoteId is at or below noteId, 0 if none:
    ///      no read beyond the count without epochs, one read when noteId is in the latest epoch,
    ///      else a binary search over the earlier ones (at most one epoch per PAUSE_COOLDOWN).
    function _pausedBefore(uint32 noteId) private view returns (uint64) {
        uint32 count = pauseEpochCount;
        if (count == 0) return 0;
        uint256 last = _pauseEpochs[count - 1];
        if (noteId >= _epochFirst(last)) return _epochTotal(last);
        // The latest epoch with firstNoteId <= noteId among records [0, count - 1).
        uint256 low = 0;
        uint256 high = count - 1;
        uint256 found;
        while (low < high) {
            uint256 mid = (low + high) / 2;
            // casting to 'uint32' is safe because mid < count, a uint32
            // forge-lint: disable-next-line(unsafe-typecast)
            uint256 epoch = _pauseEpochs[uint32(mid)];
            if (_epochFirst(epoch) <= noteId) {
                found = epoch;
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return found == 0 ? 0 : _epochTotal(found);
    }

    function _epochFirst(uint256 epoch) private pure returns (uint32) {
        // casting to 'uint32' is safe because unpause packs a uint32 firstNoteId there
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(epoch >> EPOCH_FIRST_SHIFT);
    }

    function _epochTotal(uint256 epoch) private pure returns (uint64) {
        // casting to 'uint64' is safe because it keeps the 64-bit total below the firstNoteId
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(epoch);
    }

    function _pausedDuration() private view returns (uint256) {
        return paused ? uint256(totalPausedDuration) + (block.timestamp - pausedAt) : totalPausedDuration;
    }

    /// @dev Wall-clock time minus all paused time; frozen while paused.
    function _activeClock() private view returns (uint256) {
        return block.timestamp - _pausedDuration();
    }

    /// @dev Wall-clock time from which claimExpired may take the note, assuming no further pause:
    ///      its active-clock expiry plus all paused time, but no earlier than unpauseClaimGrace after
    ///      the latest unpause (an immediate unpause is assumed while paused). The grace means a
    ///      pause can never leave a note less than that to exit, however briefly it lasted.
    function _claimableAt(uint32 noteId, uint64 expiryTs) private view returns (uint256 claimableAt) {
        claimableAt = _noteActiveExpiry(noteId, expiryTs) + _pausedDuration();
        uint256 unpausedAt = paused ? block.timestamp : lastUnpausedAt;
        if (unpausedAt != 0 && unpausedAt + unpauseClaimGrace > claimableAt) {
            claimableAt = unpausedAt + unpauseClaimGrace;
        }
    }

    /// @dev max(expiryTs - pausedBefore(noteId), graceUntil(noteId)): the expiry on the active clock.
    function _noteActiveExpiry(uint32 noteId, uint64 expiryTs) private view returns (uint256 activeExpiry) {
        activeExpiry = uint256(expiryTs) - _pausedBefore(noteId);
        uint256 grace = graceUntil[noteId];
        if (grace > activeExpiry) activeExpiry = grace;
    }

    function _validateRequestBinding(Types.RequestPublicInputs calldata inputs) private view {
        if (
            inputs.protocolVersion != PROTOCOL_VERSION || inputs.chainId != block.chainid
                || inputs.contractAddress != address(this) || inputs.stateSigningKeyX != stateSigningKeyX
                || inputs.stateSigningKeyY != stateSigningKeyY
        ) revert Errors.InvalidDeploymentBinding();
    }

    function _validateWithdrawalBinding(Types.WithdrawalPublicInputs calldata inputs) private view {
        if (
            inputs.protocolVersion != PROTOCOL_VERSION || inputs.chainId != block.chainid
                || inputs.contractAddress != address(this) || inputs.stateSigningKeyX != stateSigningKeyX
                || inputs.stateSigningKeyY != stateSigningKeyY || inputs.clearanceSigningKeyX != clearanceSigningKeyX
                || inputs.clearanceSigningKeyY != clearanceSigningKeyY
        ) revert Errors.InvalidDeploymentBinding();
    }

    /// @dev A note's storage word.
    function _word(uint256 leaf, Types.NoteStatus status) private pure returns (uint256) {
        return leaf | (uint256(status) << STATUS_SHIFT);
    }

    function _status(uint256 word) private pure returns (Types.NoteStatus) {
        return Types.NoteStatus(word >> STATUS_SHIFT);
    }

    /// @dev A checked narrowing of an amount: reverts InvalidBalance above 2^64 - 1.
    function _toUint64(uint256 amount) private pure returns (uint64) {
        if (amount > type(uint64).max) revert Errors.InvalidBalance();
        return uint64(amount);
    }

    function _requireField(uint256 value) private pure {
        if (value >= MerkleUpdateLib.FIELD_MODULUS) revert Errors.InvalidFelt();
    }
}
