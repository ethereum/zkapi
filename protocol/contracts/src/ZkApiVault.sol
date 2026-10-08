// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Types} from "./libraries/Types.sol";
import {Errors} from "./libraries/Errors.sol";
import {Events} from "./libraries/Events.sol";
import {MerkleUpdateLib} from "./libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "./libraries/NoteLeafLib.sol";
import {IZkApiProofAdapter} from "./interfaces/IZkApiProofAdapter.sol";

/// @title ZkApiVault
/// @notice Native ETH settlement in whole gwei with in-protocol BN254 Groth16 verification.
contract ZkApiVault is ReentrancyGuard, Ownable, Events {
    uint16 public constant PROTOCOL_VERSION = 2;
    uint64 public constant DEFAULT_CHALLENGE_PERIOD = 24 hours;
    uint64 public constant EXPIRY_BUCKET = 1 days;
    uint256 public constant MERKLE_DEPTH = 32;

    /// Native asset sentinel retained for deployment and client compatibility.
    address public constant billingToken = address(0);
    uint256 public constant nativeAssetWeiPerUnit = 1 gwei;
    uint128 public constant MAX_NATIVE_UNITS = 9_007_199_254_740_991;
    uint64 public immutable noteTtl;
    uint64 public immutable challengePeriod;
    uint128 public immutable requestChargeCap;
    IZkApiProofAdapter public immutable proofAdapter;
    uint256 public immutable stateSigningKeyX;
    uint256 public immutable stateSigningKeyY;
    uint256 public immutable clearanceSigningKeyX;
    uint256 public immutable clearanceSigningKeyY;

    address public treasury;
    bool public paused;
    /// @dev Sum of completed pause durations. Live pause time is added in `_pausedTimeNow`.
    uint64 public totalPausedTime;
    /// @dev Timestamp when the current pause started; 0 if not paused.
    uint64 public pausedAt;
    uint256 public currentRoot;
    uint32 public nextNoteId;

    mapping(uint32 => Types.Note) public notes;
    mapping(uint32 => Types.PendingWithdrawalData) public pendingWithdrawals;
    mapping(uint256 => bool) public usedNullifiers;

    modifier whenNotPaused() {
        if (paused) revert Errors.Paused();
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
        address owner_
    ) Ownable(owner_) {
        if (treasury_ == address(0) || proofAdapter_ == address(0) || challengePeriod_ == 0) {
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
        requestChargeCap = requestChargeCap_;
        proofAdapter = IZkApiProofAdapter(proofAdapter_);
        stateSigningKeyX = stateSigningKeyX_;
        stateSigningKeyY = stateSigningKeyY_;
        clearanceSigningKeyX = clearanceSigningKeyX_;
        clearanceSigningKeyY = clearanceSigningKeyY_;
        currentRoot = _computeEmptyTreeRoot();
    }

    function deposit(bytes32 commitment, uint128 amount, uint256[32] calldata siblings)
        external
        payable
        nonReentrant
        whenNotPaused
    {
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
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, 0, newLeaf, siblings);

        currentRoot = newRoot;
        notes[noteId] = Types.Note(commitment, amount, expiryTs, Types.NoteStatus.Active, _pausedTimeNow());
        nextNoteId = noteId + 1;
        emit NoteDeposited(noteId, commitment, amount, expiryTs, newRoot);
    }

    function mutualClose(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata proof,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        _validateWithdrawalBinding(inputs);
        if (!inputs.hasClearance) revert Errors.InvalidDeploymentBinding();
        if (inputs.activeRoot != currentRoot) revert Errors.StaleRoot();
        proofAdapter.assertValidWithdrawal(inputs, proof);
        _closeActive(inputs, siblings);
        emit MutualClose(inputs.noteId, inputs.withdrawalNullifier, inputs.finalBalance, inputs.destination);
    }

    function initiateEscapeWithdrawal(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata proof,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        _validateWithdrawalBinding(inputs);
        if (inputs.hasClearance) revert Errors.InvalidDeploymentBinding();
        if (inputs.activeRoot != currentRoot) revert Errors.StaleRoot();
        proofAdapter.assertValidWithdrawal(inputs, proof);

        Types.Note storage note = notes[inputs.noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (inputs.finalBalance > note.depositAmount) revert Errors.InvalidBalance();
        _consumeNullifier(inputs.withdrawalNullifier);

        uint256 oldRoot = currentRoot;
        uint256 leaf = _leaf(inputs.noteId, note);
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(oldRoot, inputs.noteId, leaf, 0, siblings);
        uint64 deadline = uint64(block.timestamp) + challengePeriod;
        currentRoot = newRoot;
        note.status = Types.NoteStatus.PendingWithdrawal;
        pendingWithdrawals[inputs.noteId] = Types.PendingWithdrawalData({
            exists: true,
            activeRoot: oldRoot,
            withdrawalNullifier: inputs.withdrawalNullifier,
            finalBalance: inputs.finalBalance,
            destination: inputs.destination,
            challengeDeadline: deadline
        });
        emit EscapeWithdrawalInitiated(
            inputs.noteId, inputs.withdrawalNullifier, inputs.finalBalance, inputs.destination, deadline, newRoot
        );
    }

    function challengeEscapeWithdrawal(
        uint32 noteId,
        Types.RequestPublicInputs calldata inputs,
        bytes calldata proof,
        uint256[32] calldata siblings
    ) external nonReentrant {
        Types.Note storage note = notes[noteId];
        Types.PendingWithdrawalData storage pending = pendingWithdrawals[noteId];
        if (note.status != Types.NoteStatus.PendingWithdrawal || !pending.exists) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp >= pending.challengeDeadline) revert Errors.ChallengeExpired();
        _validateRequestBinding(inputs);
        // Archived requests prove membership at the time of the request. Other
        // deposits or closes may change the root before this escape starts, so
        // the historical root must remain part of the original verified proof.
        // The matching nullifier binds that evidence to the withdrawn state.
        if (inputs.requestNullifier != pending.withdrawalNullifier) revert Errors.ReplayedNullifier();
        proofAdapter.assertValidRequest(inputs, proof);

        uint256 restoredRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, 0, _leaf(noteId, note), siblings);
        uint256 nullifier = pending.withdrawalNullifier;
        currentRoot = restoredRoot;
        note.status = Types.NoteStatus.Active;
        delete pendingWithdrawals[noteId];
        emit EscapeWithdrawalChallenged(noteId, nullifier, restoredRoot);
    }

    function finalizeEscapeWithdrawal(uint32 noteId) external nonReentrant {
        Types.Note storage note = notes[noteId];
        Types.PendingWithdrawalData storage pending = pendingWithdrawals[noteId];
        if (note.status != Types.NoteStatus.PendingWithdrawal || !pending.exists) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp < pending.challengeDeadline) revert Errors.ChallengeNotExpired();

        uint256 nullifier = pending.withdrawalNullifier;
        uint128 finalBalance = pending.finalBalance;
        address destination = pending.destination;
        uint128 operatorShare = note.depositAmount - finalBalance;
        note.status = Types.NoteStatus.Closed;
        delete pendingWithdrawals[noteId];
        _pay(destination, finalBalance, operatorShare);
        emit EscapeWithdrawalFinalized(noteId, nullifier, finalBalance, destination);
    }

    function claimExpired(uint32 noteId, uint256[32] calldata siblings) external nonReentrant {
        Types.Note storage note = notes[noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        uint64 extension = _pausedTimeNow() - note.pausedSnapshot;
        if (block.timestamp < uint256(note.expiryTs) + uint256(extension)) revert Errors.NoteNotExpired();
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, _leaf(noteId, note), 0, siblings);
        uint128 amount = note.depositAmount;
        currentRoot = newRoot;
        note.status = Types.NoteStatus.Closed;
        _transfer(treasury, amount);
        emit ExpiredClaimed(noteId, amount, newRoot);
    }

    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert Errors.Unauthorized();
        treasury = newTreasury;
        emit TreasurySet(newTreasury);
    }

    function pause() external onlyOwner {
        if (paused) revert Errors.Paused();
        paused = true;
        pausedAt = uint64(block.timestamp);
    }

    function unpause() external onlyOwner {
        if (!paused) revert Errors.NotPaused();
        totalPausedTime += uint64(block.timestamp) - pausedAt;
        pausedAt = 0;
        paused = false;
    }

    /// @dev Cumulative paused time including any in-progress pause.
    function _pausedTimeNow() private view returns (uint64) {
        return totalPausedTime + (paused ? uint64(block.timestamp) - pausedAt : 0);
    }

    function _closeActive(Types.WithdrawalPublicInputs calldata inputs, uint256[32] calldata siblings) private {
        Types.Note storage note = notes[inputs.noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (inputs.finalBalance > note.depositAmount) revert Errors.InvalidBalance();
        _consumeNullifier(inputs.withdrawalNullifier);
        uint256 newRoot =
            MerkleUpdateLib.verifyAndUpdate(currentRoot, inputs.noteId, _leaf(inputs.noteId, note), 0, siblings);
        uint128 operatorShare = note.depositAmount - inputs.finalBalance;
        currentRoot = newRoot;
        note.status = Types.NoteStatus.Closed;
        _pay(inputs.destination, inputs.finalBalance, operatorShare);
    }

    function _pay(address destination, uint128 balance, uint128 operatorShare) private {
        if (balance != 0) _transfer(destination, balance);
        if (operatorShare != 0) _transfer(treasury, operatorShare);
    }

    function _transfer(address destination, uint128 amount) private {
        (bool success,) = payable(destination).call{value: uint256(amount) * nativeAssetWeiPerUnit}("");
        if (!success) revert Errors.NativeTransferFailed();
    }

    function _consumeNullifier(uint256 nullifier) private {
        if (usedNullifiers[nullifier]) revert Errors.ReplayedNullifier();
        usedNullifiers[nullifier] = true;
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

    function _computeEmptyTreeRoot() private pure returns (uint256 root) {
        for (uint256 level = 0; level < MERKLE_DEPTH;) {
            root = MerkleUpdateLib.poseidonNodeHash(root, root);
            unchecked {
                ++level;
            }
        }
    }

    function _requireField(uint256 value) private pure {
        if (value >= MerkleUpdateLib.FIELD_MODULUS) revert Errors.InvalidFelt();
    }
}
