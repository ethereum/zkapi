// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254PoseidonReference} from "./reference/Bn254PoseidonReference.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";
import {LeafBindingMockAdapter} from "./mocks/MockProofAdapters.sol";
import {ToggleableDestination} from "./NativeEthVault.t.sol";
import {PoseidonRuntime, ReferenceHashes} from "./helpers/PoseidonRuntime.sol";

/// @dev Drives a vault (leaf-binding mock adapter) through random deposits, escapes with
///      concessions, raises, defeats, finalizations, closes, expiry claims, payout claims,
///      retirements, pauses, time, attempts to exit Closed notes again and exits whose fields or
///      leaf are not the note's, and keeps the ghost accounting and the ghost tree the invariants
///      check.
///      Note n's states have nullifiers N(n, i) = 1 + n * 1000 + i; an escape from S_i names
///      N(n, i + 1) as its successor.
contract VaultHandler is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint32 public constant MAX_NOTES = 8;
    uint256 constant STATES = 6;

    ZkApiVault public vault;
    LeafBindingMockAdapter public adapter;
    ToggleableDestination public treasury;
    address[3] public destinations;
    uint256[32] emptySiblings;

    // ghost state
    mapping(uint32 => bool) public retired;
    mapping(uint32 => uint256) public payouts; // completed exits per note
    mapping(uint32 => uint256) public paidToOwner; // gwei units pushed or credited
    mapping(uint32 => uint256) public paidToTreasury; // gwei units pushed or deferred
    uint256 public ghostCreditsClaimed;
    uint256 public calls;
    /// Successful operations, by kind: deposit, escape, raise, defeat, finalize, close, claim
    /// expired, claim payout, retire, refused exits of a Closed note, and refused exits with
    /// fields or a leaf that are not the note's.
    uint256[11] public done;
    /// What each deposit hashed into its leaf.
    mapping(uint32 => bytes32) public ghostCommitment;
    mapping(uint32 => uint128) public ghostAmount;
    mapping(uint32 => uint64) public ghostExpiry;

    constructor(
        ZkApiVault vault_,
        LeafBindingMockAdapter adapter_,
        ToggleableDestination treasury_,
        ToggleableDestination wallet
    ) {
        vault = vault_;
        adapter = adapter_;
        treasury = treasury_;
        destinations = [address(0xA11CE), address(wallet), address(0xB0B)];
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254PoseidonReference.compress(DOMAIN_NODE, zero, zero);
        }
        vm.deal(address(this), 1_000 ether);
    }

    /// The ghost leaf of note `id`: the reference leaf over its deposit, zero once retired or
    /// beyond nextNoteId.
    function ghostLeaf(uint32 id) public view returns (uint256) {
        if (id >= vault.nextNoteId() || retired[id]) return 0;
        return ReferenceHashes.leaf(id, ghostCommitment[id], ghostAmount[id], ghostExpiry[id]);
    }

    /// The full tree's root over the ghost leaves (at most MAX_NOTES = 8), by the reference Poseidon.
    function ghostRoot() external view returns (uint256 root) {
        uint256[8] memory level;
        for (uint32 i = 0; i < 8; ++i) {
            level[i] = ghostLeaf(i);
        }
        for (uint256 width = 4; width > 0; width /= 2) {
            for (uint256 i = 0; i < width; ++i) {
                level[i] = Bn254PoseidonReference.compress(DOMAIN_NODE, level[2 * i], level[2 * i + 1]);
            }
        }
        root = level[0];
        for (uint256 height = 3; height < 32; ++height) {
            root = Bn254PoseidonReference.compress(DOMAIN_NODE, root, emptySiblings[height]);
        }
    }

    // -------------------------------------------------------------------------- actions

    function deposit(uint128 amountSeed) external {
        uint32 id = vault.nextNoteId();
        if (id >= MAX_NOTES || vault.paused()) return;
        uint128 amount = uint128(bound(amountSeed, 1, 2_000_000));
        bytes32 commitment = bytes32(uint256(1000 + id));
        vault.deposit{value: uint256(amount) * 1 gwei}(commitment, amount);
        uint256 raw = vm.getBlockTimestamp() + vault.noteTtl();
        ghostCommitment[id] = commitment;
        ghostAmount[id] = amount;
        ghostExpiry[id] = uint64(((raw + 1 days - 1) / 1 days) * 1 days);
        adapter.register(id, commitment);
        ++calls;
        ++done[0];
    }

    function escape(uint32 noteSeed, uint256 stateSeed, uint128 balanceSeed, uint128 concededSeed, uint8 destSeed)
        external
    {
        (bool ok, uint32 id, uint128 deposit_) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint256 i = stateSeed % STATES;
        uint128 balance = uint128(bound(balanceSeed, 0, deposit_));
        uint128 conceded = uint128(bound(concededSeed, 0, balance));
        Types.WithdrawalPublicInputs memory inputs = _withdrawal(0, id, _n(id, i), _n(id, i + 1), balance - conceded);
        inputs.conceded = conceded;
        inputs.destination = destinations[destSeed % destinations.length];
        try vault.initiateEscapeWithdrawal(inputs, "") {
            ++calls;
            ++done[1];
        } catch {}
    }

    function raise(uint32 noteSeed, uint128 boundSeed, uint128 amountSeed) external {
        (bool ok, uint32 id,) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,, uint256 nullifier,,,) = vault.pendingWithdrawals(id);
        Types.RequestPublicInputs memory request = _request(nullifier, uint128(bound(boundSeed, 0, 2_000_000)));
        adapter.acceptRequest(request, "");
        try vault.raiseEscapeConcession(id, request, "", amountSeed) {
            ++calls;
            ++done[2];
        } catch {}
    }

    function defeat(uint32 noteSeed) external {
        (bool ok, uint32 id,) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (uint256 next,,) = vault.pendingConcessions(id);
        Types.RequestPublicInputs memory request = _request(next, 100_000);
        adapter.acceptRequest(request, "");
        try vault.challengeEscapeWithdrawal(id, request, "") {
            ++calls;
            ++done[3];
        } catch {}
    }

    function finalize(uint32 noteSeed) external {
        (bool ok, uint32 id, uint128 deposit_) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,,, uint128 finalBalance, address destination, uint64 deadline) = vault.pendingWithdrawals(id);
        if (vm.getBlockTimestamp() < deadline) vm.warp(deadline);
        uint256 before = destination.balance / 1 gwei + vault.escapePayoutCredits(destination);
        uint256 treasuryBefore = _treasuryHoldings();
        vault.finalizeEscapeWithdrawal(id);
        _recordExit(id, destination.balance / 1 gwei + vault.escapePayoutCredits(destination) - before, treasuryBefore);
        assertEq(paidToOwner[id], finalBalance);
        assertEq(paidToOwner[id] + paidToTreasury[id], deposit_);
        ++done[4];
    }

    function close(uint32 noteSeed, uint256 stateSeed, uint128 balanceSeed, uint8 destSeed) external {
        (bool ok, uint32 id, uint128 deposit_) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint256 i = stateSeed % STATES;
        uint128 balance = uint128(bound(balanceSeed, 0, deposit_));
        Types.WithdrawalPublicInputs memory inputs = _withdrawal(1, id, _n(id, i), 0, balance);
        // The rejecting wallet is not a close destination: a failed push reverts the close.
        address destination = destinations[destSeed % 2 == 0 ? 0 : 2];
        inputs.destination = destination;
        uint256 before = destination.balance / 1 gwei;
        uint256 treasuryBefore = _treasuryHoldings();
        try vault.mutualClose(inputs, "") {
            _recordExit(id, destination.balance / 1 gwei - before, treasuryBefore);
            ++done[5];
        } catch {}
    }

    function claimExpired(uint32 noteSeed) external {
        (bool ok, uint32 id,) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok || vault.paused()) return;
        uint64 at = vault.effectiveExpiry(id, ghostCommitment[id], ghostAmount[id], ghostExpiry[id]);
        if (vm.getBlockTimestamp() < at) vm.warp(at);
        uint256 treasuryBefore = _treasuryHoldings();
        vault.claimExpired(id, ghostCommitment[id], ghostAmount[id], ghostExpiry[id]);
        _recordExit(id, 0, treasuryBefore);
        ++done[6];
    }

    function claimPayout(uint8 destSeed) external {
        address destination = destinations[destSeed % destinations.length];
        uint128 credit = vault.escapePayoutCredits(destination);
        if (credit == 0) return;
        try vault.claimEscapePayout(destination) {
            ghostCreditsClaimed += credit;
            ++done[7];
        } catch {}
    }

    /// An escape or a close of a Closed note, from any of its states, with the note's leaf (an
    /// exit proof needs nothing else, so a closed note's leaf stays provable). It must revert:
    /// NoteNotActive, or for an escape ChallengedNullifier or SupersededState when a defeat
    /// flagged its state or the successor. A success is recorded as a second payout of the note,
    /// which invariant_onePayoutPerNoteSplittingItsDeposit refuses.
    function exitClosed(uint32 noteSeed, uint256 stateSeed, bool asClose, uint128 balanceSeed) external {
        (bool ok, uint32 id, uint128 deposit_) = _note(noteSeed, Types.NoteStatus.Closed);
        if (!ok) return;
        uint256 i = stateSeed % STATES;
        uint128 balance = uint128(bound(balanceSeed, 0, deposit_));
        Types.WithdrawalPublicInputs memory inputs =
            _withdrawal(asClose ? 1 : 0, id, _n(id, i), asClose ? 0 : _n(id, i + 1), balance);
        // The leaf the note had before any retirement: what its owner's proof carries.
        inputs.noteLeaf = ReferenceHashes.leaf(id, ghostCommitment[id], ghostAmount[id], ghostExpiry[id]);
        bytes4 expected = Errors.NoteNotActive.selector;
        if (vault.paused() && vm.getBlockTimestamp() < uint256(vault.pausedAt()) + vault.maxPauseDuration()) {
            expected = Errors.Paused.selector;
        } else if (!asClose && vault.challengedNullifiers(inputs.withdrawalNullifier)) {
            expected = Errors.ChallengedNullifier.selector;
        } else if (!asClose && vault.challengedNullifiers(inputs.nextNullifier)) {
            expected = Errors.SupersededState.selector;
        }
        bytes memory reason;
        if (asClose) {
            try vault.mutualClose(inputs, "") {
                ++payouts[id];
            } catch (bytes memory r) {
                reason = r;
            }
        } else {
            try vault.initiateEscapeWithdrawal(inputs, "") {
                ++payouts[id];
            } catch (bytes memory r) {
                reason = r;
            }
        }
        if (payouts[id] > 1) return;
        assertEq(reason, abi.encodeWithSelector(expected), "a closed note's exit failed for another reason");
        ++done[9];
    }

    /// An exit of an Active note whose statement is not the note's: its deposit raised (with the
    /// leaf of the raised fields, which the mock accepts as self-consistent), its expiry moved, or
    /// another note's leaf. The vault must refuse each before paying anything.
    function exitInconsistent(uint32 noteSeed, uint8 kindSeed, bool asClose) external {
        (bool ok, uint32 id, uint128 deposit_) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        if (vault.paused() && vm.getBlockTimestamp() < uint256(vault.pausedAt()) + vault.maxPauseDuration()) return;
        Types.WithdrawalPublicInputs memory inputs =
            _withdrawal(asClose ? 1 : 0, id, _n(id, 900), asClose ? 0 : _n(id, 901), deposit_ + 1);
        uint256 variant = kindSeed % 3;
        uint128 amount = variant == 0 ? deposit_ + 1 : deposit_;
        uint64 expiry = variant == 1 ? ghostExpiry[id] + 1 days : ghostExpiry[id];
        inputs.noteFields = NoteLeafLib.pack(id, amount, expiry);
        inputs.noteLeaf = ReferenceHashes.leaf(id, ghostCommitment[id], amount, expiry);
        if (variant == 2) {
            inputs.noteLeaf = ReferenceHashes.leaf(id ^ 1, bytes32(uint256(7)), deposit_, ghostExpiry[id]);
        }
        bytes memory reason;
        if (asClose) {
            try vault.mutualClose(inputs, "") {
                ++payouts[id];
            } catch (bytes memory r) {
                reason = r;
            }
        } else {
            try vault.initiateEscapeWithdrawal(inputs, "") {
                ++payouts[id];
            } catch (bytes memory r) {
                reason = r;
            }
        }
        if (payouts[id] > 1) return;
        assertEq(reason, abi.encodeWithSelector(Errors.NoteLeafMismatch.selector), "an inconsistent exit");
        ++done[10];
    }

    function retire(uint32 noteSeed) external {
        (bool ok, uint32 id,) = _note(noteSeed, Types.NoteStatus.Closed);
        if (!ok || retired[id]) return;
        uint256[32] memory path = _path(id);
        vault.retireClosedLeaf(id, path);
        retired[id] = true;
        ++done[8];
    }

    function toggleAcceptance(bool walletAccepts, bool treasuryAccepts) external {
        ToggleableDestination(payable(destinations[1])).setAccepting(walletAccepts);
        treasury.setAccepting(treasuryAccepts);
    }

    function pauseOrUnpause() external {
        if (vault.paused()) {
            vault.unpause();
        } else {
            try vault.pause() {} catch {}
        }
    }

    function warp(uint32 seconds_) external {
        vm.warp(vm.getBlockTimestamp() + bound(seconds_, 1, 10 days));
    }

    // -------------------------------------------------------------------------- helpers

    function _recordExit(uint32 id, uint256 toOwner, uint256 treasuryBefore) private {
        ++payouts[id];
        paidToOwner[id] += toOwner;
        paidToTreasury[id] += _treasuryHoldings() - treasuryBefore;
    }

    /// Treasury balance plus arrears, in gwei units.
    function _treasuryHoldings() private view returns (uint256) {
        return address(treasury).balance / 1 gwei + vault.treasuryArrears();
    }

    /// The first note at or after seed % count (cyclically) with status `wanted`.
    function _note(uint32 seed, Types.NoteStatus wanted) private view returns (bool, uint32, uint128) {
        uint32 count = vault.nextNoteId();
        for (uint32 k = 0; k < count; ++k) {
            uint32 id = uint32((uint256(seed) + k) % count);
            (, Types.NoteStatus status) = vault.noteRecord(id);
            if (status == wanted) return (true, id, ghostAmount[id]);
        }
        return (false, 0, 0);
    }

    function _n(uint32 id, uint256 i) private pure returns (uint256) {
        return 1 + uint256(id) * 1000 + i;
    }

    function _withdrawal(uint8 kind, uint32 id, uint256 nullifier, uint256 next, uint128 finalBalance)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            noteLeaf: ghostLeaf(id),
            stateSigningKeyX: 11,
            stateSigningKeyY: 12,
            clearanceSigningKeyX: 13,
            clearanceSigningKeyY: 14,
            noteFields: NoteLeafLib.pack(id, ghostAmount[id], ghostExpiry[id]),
            finalBalance: finalBalance,
            destination: destinations[0],
            withdrawalNullifier: nullifier,
            kind: kind,
            nextNullifier: next,
            conceded: 0,
            validUntil: uint64(vm.getBlockTimestamp()) + 3 hours
        });
    }

    function _request(uint256 nullifier, uint128 solvencyBound)
        private
        view
        returns (Types.RequestPublicInputs memory)
    {
        return Types.RequestPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: vault.currentRoot(),
            stateSigningKeyX: 11,
            stateSigningKeyY: 12,
            requestTime: uint64(vm.getBlockTimestamp()),
            solvencyBound: solvencyBound,
            requestNullifier: nullifier,
            authorizationTag: 1,
            anonymousCommitmentX: 2,
            anonymousCommitmentY: 3
        });
    }

    function _treeLeaf(uint32 index) private view returns (uint256) {
        return ghostLeaf(index);
    }

    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        siblings = emptySiblings;
        siblings[0] = _treeLeaf(index ^ 1);
        uint32 pair = (index >> 1) ^ 1;
        siblings[1] = Bn254PoseidonReference.compress(DOMAIN_NODE, _treeLeaf(pair * 2), _treeLeaf(pair * 2 + 1));
        uint32 quad = (index >> 2) ^ 1;
        siblings[2] = Bn254PoseidonReference.compress(
            DOMAIN_NODE,
            Bn254PoseidonReference.compress(DOMAIN_NODE, _treeLeaf(quad * 4), _treeLeaf(quad * 4 + 1)),
            Bn254PoseidonReference.compress(DOMAIN_NODE, _treeLeaf(quad * 4 + 2), _treeLeaf(quad * 4 + 3))
        );
    }

    receive() external payable {}
}

/// @dev Invariants of the concession exit under random operation sequences:
///      - balance accounting: the vault holds every Active and pending deposit, the treasury
///        arrears and the credited escape payouts, nothing more or less;
///      - every pending escape has finalBalance + conceded == stateBalance <= its deposit and a
///        nonzero successor nullifier, and no other note has a pending record;
///      - each note pays out at most once (an escape or close that a Closed note gets through
///        counts as a second payout), and each exit splits its deposit exactly between the owner
///        (pushed or credited) and the treasury (pushed or in arrears);
///      - the stored leaves are the ghost leaves (zero once retired) and the computed
///        currentRoot() is the ghost tree's root.
///      The handler expects every call it makes outside try/catch to succeed (and asserts each
///      exit's split as it happens), so a revert fails the campaign.
/// forge-config: default.invariant.fail-on-revert = true
contract ZkApiVaultInvariantTest is Test {
    ZkApiVault vault;
    VaultHandler handler;

    function setUp() public {
        vm.warp(1_700_000_000);
        LeafBindingMockAdapter adapter = new LeafBindingMockAdapter();
        ToggleableDestination treasury = new ToggleableDestination();
        treasury.setAccepting(true);
        ToggleableDestination wallet = new ToggleableDestination();
        vault = new ZkApiVault(
            address(treasury),
            30 days,
            24 hours,
            100_000,
            address(adapter),
            11,
            12,
            13,
            14,
            address(this),
            7 days,
            PoseidonRuntime.etch(),
            1
        );
        handler = new VaultHandler(vault, adapter, treasury, wallet);
        // The handler is the owner, so it can pause and unpause.
        vault.transferOwnership(address(handler));
        vm.prank(address(handler));
        vault.acceptOwnership();
        // Start every run with four notes of different sizes.
        for (uint128 i = 0; i < 4; ++i) {
            handler.deposit(250_000 * (i + 1));
        }
        targetContract(address(handler));
    }

    function invariant_balanceAccounting() public view {
        uint256 held;
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (, Types.NoteStatus status) = vault.noteRecord(id);
            uint128 amount = handler.ghostAmount(id);
            if (status == Types.NoteStatus.Active || status == Types.NoteStatus.PendingWithdrawal) held += amount;
        }
        held += vault.treasuryArrears();
        for (uint256 i = 0; i < 3; ++i) {
            held += vault.escapePayoutCredits(handler.destinations(i));
        }
        assertEq(address(vault).balance, held * 1 gwei);
    }

    function invariant_pendingConcessionsAreConsistent() public view {
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (, Types.NoteStatus status) = vault.noteRecord(id);
            uint128 amount = handler.ghostAmount(id);
            (
                bool exists,
                uint256 activeRoot,
                uint256 nullifier,
                uint128 finalBalance,
                address destination,
                uint64 deadline
            ) = vault.pendingWithdrawals(id);
            (uint256 next, uint128 stateBalance, uint128 conceded) = vault.pendingConcessions(id);
            // The proof's root is never stored.
            assertEq(activeRoot, 0);
            if (status == Types.NoteStatus.PendingWithdrawal) {
                assertTrue(exists);
                assertEq(uint256(finalBalance) + conceded, stateBalance);
                assertLe(stateBalance, amount);
                assertNotEq(next, 0);
                assertNotEq(next, nullifier);
                assertNotEq(destination, address(0));
                assertNotEq(deadline, 0);
                assertTrue(vault.usedNullifiers(nullifier));
                assertTrue(vault.usedNullifiers(next));
                assertFalse(vault.challengedNullifiers(nullifier));
                assertFalse(vault.challengedNullifiers(next));
            } else {
                assertFalse(exists);
                assertEq(nullifier, 0);
                assertEq(finalBalance, 0);
                assertEq(destination, address(0));
                assertEq(deadline, 0);
                assertEq(next, 0);
                assertEq(stateBalance, 0);
                assertEq(conceded, 0);
            }
        }
    }

    function invariant_onePayoutPerNoteSplittingItsDeposit() public view {
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (, Types.NoteStatus status) = vault.noteRecord(id);
            uint128 amount = handler.ghostAmount(id);
            uint256 payouts = handler.payouts(id);
            assertLe(payouts, 1);
            assertEq(payouts == 1, status == Types.NoteStatus.Closed);
            if (payouts == 1) assertEq(handler.paidToOwner(id) + handler.paidToTreasury(id), amount);
        }
    }

    function invariant_storedLeavesAndRootMatchTheGhostTree() public view {
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (uint256 leaf,) = vault.noteRecord(id);
            assertEq(leaf, handler.ghostLeaf(id));
        }
        assertEq(vault.currentRoot(), handler.ghostRoot());
        uint256[] memory leaves = vault.noteLeaves(0, count);
        for (uint32 id = 0; id < count; ++id) {
            assertEq(leaves[id], handler.ghostLeaf(id));
        }
    }
}
