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

/// @title ZkApiVault
/// @notice Native ETH settlement in whole gwei with in-protocol BN254 Groth16 verification, for
///         circuit zkapi-v2-concession-v1 (vault revision 3).
/// @dev An escape names the nullifier N_k of the state it leaves and that state's derived successor
///      nullifier N_{k+1}, may concede an amount c, and pays B_k - c. Only a request proof at
///      N_{k+1} defeats it; a request proof at N_k can only raise c, to at most that request's
///      solvency bound. The note tree is append-only: deposits append leaves to its frontier (no
///      proof, so deposits never race each other) and only retireClosedLeaf changes one (a Closed
///      note's, back to zero), so exits do no Merkle work and every root the vault ever held stays
///      a valid proof root (knownRoots) for every note that was not retired.
///      Ownership transfers are two-step and stay open while paused, for incident key rotation:
///      transferOwnership only nominates pendingOwner, and the current owner keeps every power
///      (including unpause and replacing the nomination) until the nominee calls acceptOwnership.
///      A mistyped or unusable nominee therefore cannot leave a paused vault without an owner.
contract ZkApiVault is ReentrancyGuardTransient, Ownable2Step, Events {
    uint16 public constant PROTOCOL_VERSION = 2;
    /// @notice Capability marker of the concession exit (vault revision 3).
    uint16 public constant CONCESSION_ESCAPE_VERSION = 1;
    /// @notice Minimum unpaused time between an unpause and the next pause.
    uint64 public constant PAUSE_COOLDOWN = 1 days;
    uint64 public constant DEFAULT_CHALLENGE_PERIOD = 24 hours;
    uint64 public constant EXPIRY_BUCKET = 1 days;
    uint256 public constant MERKLE_DEPTH = 32;
    /// @notice The root window of off-chain services (the server's clearance check). The vault
    ///         itself accepts any root it ever held (isKnownRoot), however long ago it was replaced.
    uint64 public constant ROOT_HISTORY_WINDOW = 1 days;
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

    address public treasury;
    bool public paused;
    /// @notice Start of the current pause; zero while unpaused.
    uint64 public pausedAt;
    uint256 public currentRoot;
    uint32 public nextNoteId;
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

    mapping(uint32 => Types.Note) public notes;
    /// @dev The pending escapes; read through pendingWithdrawals and pendingConcessions.
    mapping(uint32 => Types.Escape) private _escapes;
    mapping(uint256 => bool) public usedNullifiers;
    /// @notice States an escape from which was defeated by successor evidence (a request proof at
    ///         the state's successor nullifier); they can never escape again, and the state just
    ///         below one reverts SupersededState. mutualClose does not consult it.
    mapping(uint256 => bool) public challengedNullifiers;
    /// @dev Expiry on the active (unpaused) clock. Zero means notes[noteId].expiryTs.
    mapping(uint32 => uint64) private _activeExpiry;
    /// @notice Escape payouts (gwei units) whose push to their destination failed, by destination;
    ///         see claimEscapePayout.
    mapping(address => uint128) public escapePayoutCredits;
    /// @notice Every root the vault ever set as currentRoot, including the empty tree's.
    mapping(uint256 => bool) public knownRoots;
    /// @dev The note tree's frontier: see MerkleUpdateLib.
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
        uint64 maxPauseDuration_
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

        if (requestChargeCap_ == 0 || requestChargeCap_ > MAX_NATIVE_UNITS) {
            revert Errors.InvalidBalance();
        }
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
        currentRoot = MerkleUpdateLib.EMPTY_ROOT;
        knownRoots[MerkleUpdateLib.EMPTY_ROOT] = true;
    }

    /// @notice Deposits `amount` gwei units under `commitment` as the next note, appending its leaf
    ///         to the tree. No Merkle proof is needed, so deposits never invalidate each other.
    function deposit(bytes32 commitment, uint128 amount) external payable nonReentrant whenNotPaused {
        if (amount > MAX_NATIVE_UNITS || msg.value != uint256(amount) * nativeAssetWeiPerUnit) {
            revert Errors.InvalidNativeValue();
        }
        if (amount == 0) revert Errors.ZeroAmount();
        if (commitment == bytes32(0)) revert Errors.InvalidCommitment();
        _requireField(uint256(commitment));

        uint32 noteId = nextNoteId;
        uint256 rawExpiry = block.timestamp + noteTtl;
        uint256 bucketedExpiry = ((rawExpiry + EXPIRY_BUCKET - 1) / EXPIRY_BUCKET) * EXPIRY_BUCKET;
        if (bucketedExpiry > type(uint64).max) revert Errors.InvalidFelt();
        uint64 expiryTs = uint64(bucketedExpiry);
        uint256 newLeaf = NoteLeafLib.computeLeaf(noteId, commitment, amount, expiryTs);
        uint256 newRoot = MerkleUpdateLib.insert(_filledSubtrees, noteId, newLeaf);

        _setCurrentRoot(newRoot);
        notes[noteId] = Types.Note(commitment, amount, expiryTs, Types.NoteStatus.Active);
        // Deposits cannot happen while paused, so only completed pauses precede this note.
        uint64 pausedBefore = totalPausedDuration;
        if (pausedBefore != 0) _activeExpiry[noteId] = expiryTs - pausedBefore;
        nextNoteId = noteId + 1;
        emit NoteDeposited(noteId, commitment, amount, expiryTs, newRoot);
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
        if (!isKnownRoot(inputs.activeRoot)) revert Errors.UnknownRoot();
        proofAdapter.assertValidWithdrawal(inputs, proof);
        _closeActive(inputs);
        emit MutualClose(inputs.noteId, inputs.withdrawalNullifier, inputs.finalBalance, inputs.destination);
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
        // A defeated escape stays defeated: its calldata is public, so anyone could replay it.
        if (challengedNullifiers[nullifier]) revert Errors.ChallengedNullifier();
        // The successor of this state was spent (it defeated an escape), so this state is stale.
        if (challengedNullifiers[nextNullifier]) revert Errors.SupersededState();
        if (!isKnownRoot(inputs.activeRoot)) revert Errors.UnknownRoot();
        proofAdapter.assertValidWithdrawal(inputs, proof);

        Types.Note storage note = notes[inputs.noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        uint256 total = uint256(inputs.finalBalance) + inputs.conceded;
        if (total > note.depositAmount) revert Errors.InvalidBalance();
        // casting to 'uint128' is safe because total is at most the uint128 depositAmount
        // forge-lint: disable-next-line(unsafe-typecast)
        uint128 stateBalance = uint128(total);
        _consumeNullifier(nullifier);
        _consumeNullifier(nextNullifier);

        uint64 deadline = uint64(block.timestamp) + challengePeriod;
        note.status = Types.NoteStatus.PendingWithdrawal;
        _escapes[inputs.noteId] = Types.Escape({
            withdrawalNullifier: nullifier,
            nextNullifier: nextNullifier,
            activeRoot: inputs.activeRoot,
            destination: inputs.destination,
            challengeDeadline: deadline,
            finalBalance: inputs.finalBalance,
            conceded: inputs.conceded
        });
        emit EscapeWithdrawalInitiated(
            inputs.noteId, nullifier, inputs.finalBalance, inputs.destination, deadline, currentRoot
        );
        emit EscapeConcessionRecorded(inputs.noteId, nextNullifier, stateBalance, inputs.conceded);
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
        (Types.Note storage note, Types.Escape storage escape) = _pendingEscape(noteId);
        _validateRequestBinding(inputs);
        uint256 nextNullifier = escape.nextNullifier;
        // A request at the escaped nullifier never defeats; it can only raise the concession.
        if (inputs.requestNullifier != nextNullifier) revert Errors.NotSuccessorEvidence();
        proofAdapter.assertValidRequest(inputs, proof);

        uint256 nullifier = escape.withdrawalNullifier;
        note.status = Types.NoteStatus.Active;
        delete _escapes[noteId];
        delete usedNullifiers[nullifier];
        delete usedNullifiers[nextNullifier];
        challengedNullifiers[nullifier] = true;
        _grantChallengeGrace(noteId, note);
        emit EscapeWithdrawalChallenged(noteId, nullifier, currentRoot);
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
        escape.conceded = raised;
        escape.finalBalance = finalBalance;
        emit EscapeConcessionRaised(noteId, nullifier, raised, finalBalance);
    }

    /// @notice Pays out an unchallenged escape after its deadline and closes the note. Neither
    ///         payee can block the other or the closure: finalBalance (as raised) goes to the
    ///         destination or, if that push fails, to escapePayoutCredits[destination]; the rest
    ///         of the deposit goes to the treasury or, if that push fails, to treasuryArrears.
    function finalizeEscapeWithdrawal(uint32 noteId) external nonReentrant {
        Types.Note storage note = notes[noteId];
        Types.Escape storage escape = _escapes[noteId];
        address destination = escape.destination;
        if (note.status != Types.NoteStatus.PendingWithdrawal || destination == address(0)) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp < escape.challengeDeadline) revert Errors.ChallengeNotExpired();

        uint256 nullifier = escape.withdrawalNullifier;
        uint128 finalBalance = escape.finalBalance;
        uint128 operatorShare = note.depositAmount - finalBalance;
        note.status = Types.NoteStatus.Closed;
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

    /// @notice Sweeps an Active note past its effective expiry to the treasury. The leaf stays:
    ///         the request circuit refuses requests after the note's expiryTs.
    function claimExpired(uint32 noteId) external nonReentrant whenNotPaused {
        Types.Note storage note = notes[noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (block.timestamp < _claimableAt(noteId, note)) revert Errors.NoteNotExpired();
        uint128 amount = note.depositAmount;
        note.status = Types.NoteStatus.Closed;
        _payTreasury(amount);
        emit ExpiredClaimed(noteId, amount, currentRoot);
    }

    /// @notice Removes a Closed note's leaf from the tree, so that proofs built on later roots no
    ///         longer contain it. Permissionless and open while paused; an operator tool.
    /// @dev Reverts StaleRoot when `siblings` do not reproduce currentRoot with the note's leaf,
    ///      including when the leaf was already retired.
    function retireClosedLeaf(uint32 noteId, uint256[32] calldata siblings) external nonReentrant {
        Types.Note storage note = notes[noteId];
        if (note.status != Types.NoteStatus.Closed) revert Errors.NoteNotClosed();
        uint256 newRoot =
            MerkleUpdateLib.retire(_filledSubtrees, nextNoteId, currentRoot, noteId, _leaf(noteId, note), siblings);
        _setCurrentRoot(newRoot);
        emit ClosedLeafRetired(noteId, newRoot);
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
    ///         flight resolve and credited payouts can be delivered, retireClosedLeaf, and
    ///         cancelTreasuryChange, transferOwnership and acceptOwnership. A pause needs
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

    function unpause() external onlyOwner {
        if (!paused) revert Errors.NotPaused();
        totalPausedDuration += uint64(block.timestamp) - pausedAt;
        paused = false;
        pausedAt = 0;
        lastUnpausedAt = uint64(block.timestamp);
        emit Unpaused(msg.sender);
    }

    /// @dev Prevents making a pause permanent by renouncing; renouncing also clears pendingOwner.
    ///      A pause that is never lifted blocks exits for at most maxPauseDuration, and nothing can
    ///      sweep notes while paused.
    function renounceOwnership() public override onlyOwner whenNotPaused {
        super.renounceOwnership();
    }

    /// @notice True for every root the vault ever held. The tree is append-only for every note
    ///         that is not Closed, so each root recorded since a note's deposit contains its leaf,
    ///         and a client can exit with the Merkle path it saved at deposit.
    function isKnownRoot(uint256 root) public view returns (bool) {
        return knownRoots[root];
    }

    /// @notice A pending escape as revision 2 exposed it (6 words): exists, the escape proof's
    ///         activeRoot, withdrawalNullifier, the current payout finalBalance, destination and
    ///         challengeDeadline. All zero for a note without a pending escape.
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
        destination = escape.destination;
        exists = destination != address(0);
        activeRoot = escape.activeRoot;
        withdrawalNullifier = escape.withdrawalNullifier;
        finalBalance = escape.finalBalance;
        challengeDeadline = escape.challengeDeadline;
    }

    /// @notice The concession side of a pending escape (3 words): nextNullifier N_{k+1}, the state
    ///         balance B_k = finalBalance + conceded, and conceded. All zero without a pending escape.
    function pendingConcessions(uint32 noteId)
        external
        view
        returns (uint256 nextNullifier, uint128 stateBalance, uint128 conceded)
    {
        Types.Escape storage escape = _escapes[noteId];
        nextNullifier = escape.nextNullifier;
        conceded = escape.conceded;
        stateBalance = escape.finalBalance + conceded;
    }

    /// @notice Earliest wall-clock time claimExpired can succeed, assuming no further pause.
    /// @dev Equals expiryTs plus all pause time since the deposit (at least challengePeriod of
    ///      unpaused time after a successful challenge), and never less than unpauseClaimGrace
    ///      after the latest unpause. While paused it projects an immediate unpause and keeps
    ///      increasing. Zero for unknown notes.
    function effectiveExpiry(uint32 noteId) external view returns (uint64) {
        Types.Note storage note = notes[noteId];
        if (note.status == Types.NoteStatus.Uninitialized) return 0;
        uint256 wallClock = _claimableAt(noteId, note);
        return wallClock > type(uint64).max ? type(uint64).max : uint64(wallClock);
    }

    function _closeActive(Types.WithdrawalPublicInputs calldata inputs) private {
        Types.Note storage note = notes[inputs.noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (inputs.finalBalance > note.depositAmount) revert Errors.InvalidBalance();
        _consumeNullifier(inputs.withdrawalNullifier);
        uint128 operatorShare = note.depositAmount - inputs.finalBalance;
        note.status = Types.NoteStatus.Closed;
        // The submitter chose this destination and can prove another, so a failed push reverts.
        if (inputs.finalBalance != 0) _transfer(inputs.destination, inputs.finalBalance);
        _payTreasury(operatorShare);
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

    /// @dev Only canonical field elements are consumed, whatever the adapter accepts: usedNullifiers,
    ///      challengedNullifiers and the escape records are keyed on the raw word, so N + r (the same
    ///      scalar to a verifier that reduced it) would otherwise slip past ChallengedNullifier,
    ///      SupersededState and ReplayedNullifier, or name a successor no defeat can match. Every
    ///      nullifier those mappings hold was consumed here first.
    function _consumeNullifier(uint256 nullifier) private {
        _requireField(nullifier);
        if (usedNullifiers[nullifier]) revert Errors.ReplayedNullifier();
        usedNullifiers[nullifier] = true;
    }

    function _setCurrentRoot(uint256 newRoot) private {
        currentRoot = newRoot;
        knownRoots[newRoot] = true;
    }

    /// @dev The note and record of an escape that can still be challenged or raised.
    function _pendingEscape(uint32 noteId) private view returns (Types.Note storage note, Types.Escape storage escape) {
        note = notes[noteId];
        escape = _escapes[noteId];
        if (note.status != Types.NoteStatus.PendingWithdrawal || escape.destination == address(0)) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp >= escape.challengeDeadline) revert Errors.ChallengeExpired();
    }

    /// @dev Delays, but does not prevent, an expiry sweep right after a defeat: the note keeps
    ///      at least challengePeriod of unpaused time to exit from its signed successor state.
    function _grantChallengeGrace(uint32 noteId, Types.Note storage note) private {
        uint256 graceEnd = _activeClock() + challengePeriod;
        if (graceEnd > _noteActiveExpiry(noteId, note)) {
            _activeExpiry[noteId] = graceEnd > type(uint64).max ? type(uint64).max : uint64(graceEnd);
        }
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
    function _claimableAt(uint32 noteId, Types.Note storage note) private view returns (uint256 claimableAt) {
        claimableAt = _noteActiveExpiry(noteId, note) + _pausedDuration();
        uint256 unpausedAt = paused ? block.timestamp : lastUnpausedAt;
        if (unpausedAt != 0 && unpausedAt + unpauseClaimGrace > claimableAt) {
            claimableAt = unpausedAt + unpauseClaimGrace;
        }
    }

    function _noteActiveExpiry(uint32 noteId, Types.Note storage note) private view returns (uint256) {
        uint64 adjusted = _activeExpiry[noteId];
        return adjusted == 0 ? note.expiryTs : adjusted;
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

    function _leaf(uint32 noteId, Types.Note storage note) private view returns (uint256) {
        return NoteLeafLib.computeLeaf(noteId, note.commitment, note.depositAmount, note.expiryTs);
    }

    function _requireField(uint256 value) private pure {
        if (value >= MerkleUpdateLib.FIELD_MODULUS) revert Errors.InvalidFelt();
    }
}
