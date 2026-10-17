// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";
import {MockProofAdapter} from "./mocks/MockProofAdapters.sol";
import {ToggleableDestination} from "./NativeEthVault.t.sol";

/// @dev Drives a vault (mock adapter) through random deposits, proved and on-chain activations
///      (and refused ones: proofs from a non-activator, the fallback before it opens), escapes with
///      concessions, raises, defeats, finalizations, closes, expiry claims, payout claims,
///      retirements, pauses, time and attempts to exit Closed notes again, and keeps the ghost
///      accounting and the ghost request tree the invariants check. The handler is the vault's
///      owner and its activator. Note n's states have nullifiers N(n, i) = 1 + n * 1000 + i; an
///      escape from S_i names N(n, i + 1) as its successor.
contract VaultHandler is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint32 public constant MAX_NOTES = 8;
    uint256 constant STATES = 6;

    ZkApiVault public vault;
    MockProofAdapter public adapter;
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
    /// expired, claim payout, retire, refused exits of a Closed note, proved activation, on-chain
    /// activation, refused stale activations or retirements of unactivated notes, refused
    /// on-chain activations before the fallback opens, and refused proofs from a non-activator.
    uint256[15] public done;
    /// Notes the handler activated: the ghost tree holds their recorded leaves, minus retired ones.
    uint32 public ghostCursor;

    constructor(
        ZkApiVault vault_,
        MockProofAdapter adapter_,
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
            zero = Bn254Poseidon.compress(DOMAIN_NODE, zero, zero);
        }
        vm.deal(address(this), 1_000 ether);
    }

    // -------------------------------------------------------------------------- actions

    function deposit(uint128 amountSeed) external {
        uint32 id = vault.nextNoteId();
        if (id >= MAX_NOTES || vault.paused()) return;
        uint128 amount = uint128(bound(amountSeed, 1, 2_000_000));
        vault.deposit{value: uint256(amount) * 1 gwei}(bytes32(uint256(1000 + id)), amount);
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
        (, uint256 nullifier,,,) = vault.pendingWithdrawals(id);
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
        (,, uint128 finalBalance, address destination, uint64 deadline) = vault.pendingWithdrawals(id);
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
        uint64 at = vault.effectiveExpiry(id);
        if (vm.getBlockTimestamp() < at) vm.warp(at);
        uint256 treasuryBefore = _treasuryHoldings();
        vault.claimExpired(id);
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

    /// An escape or a close of a Closed note, from any of its states, before or after its
    /// activation and retirement (closing changes no stored value it is bound by), possibly with a
    /// tampered registration commitment or metadata. It must revert: NoteNotActive (or
    /// NoteBindingMismatch when tampered), or for an escape ChallengedNullifier or SupersededState
    /// when a defeat flagged its state or the successor. A success is recorded as a second payout of
    /// the note, which invariant_onePayoutPerNoteSplittingItsDeposit refuses.
    function exitClosed(uint32 noteSeed, uint256 stateSeed, uint8 tamper, bool asClose, uint128 balanceSeed) external {
        (bool ok, uint32 id, uint128 deposit_) = _note(noteSeed, Types.NoteStatus.Closed);
        if (!ok) return;
        uint256 i = stateSeed % STATES;
        uint128 balance = uint128(bound(balanceSeed, 0, deposit_));
        Types.WithdrawalPublicInputs memory inputs =
            _withdrawal(asClose ? 1 : 0, id, _n(id, i), asClose ? 0 : _n(id, i + 1), balance);
        bytes4 expected = Errors.NoteNotActive.selector;
        if (tamper % 3 == 1) inputs.registrationCommitment ^= 1;
        if (tamper % 3 == 2) inputs.noteMetadata += 1;
        if (tamper % 3 != 0) expected = Errors.NoteBindingMismatch.selector;
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

    /// Retires a Closed, activated note's leaf with the ghost tree's path. A Closed note not yet
    /// activated is refused (NoteNotActivated) whatever the path.
    function retire(uint32 noteSeed) external {
        (bool ok, uint32 id,) = _note(noteSeed, Types.NoteStatus.Closed);
        if (!ok || retired[id]) return;
        uint256[32] memory path = _path(id);
        if (id >= ghostCursor) {
            vm.expectRevert(Errors.NoteNotActivated.selector);
            vault.retireClosedLeaf(id, path);
            ++done[12];
            return;
        }
        vault.retireClosedLeaf(id, path);
        retired[id] = true;
        ++done[8];
    }

    /// Activates the next 1, 4 or 16 recorded notes (by `countSeed`, among the aligned counts that
    /// fit), with a mock proof of the statement built from storage and the ghost tree's new root,
    /// or on-chain with the ghost tree's path, first waiting for the fallback to open if `wait`.
    /// Refused with Paused while paused, and on-chain with ActivationFallbackClosed before
    /// activationFallbackOpensAt.
    function activate(uint256 countSeed, bool onChain, bool wait) external {
        uint32 first = vault.activationCursor();
        uint256 pending = vault.nextNoteId() - first;
        uint256[3] memory sizes = [uint256(1), 4, 16];
        uint256 count = sizes[countSeed % 3];
        while (count > 1 && (first % count != 0 || pending < count)) {
            count /= 4;
        }
        if (pending < count) return;
        uint256 oldRoot = vault.currentRoot();
        (uint256 newRoot,) = ghostTree(uint256(first) + count, 0);
        uint256[32] memory siblings = _path(first);
        if (!onChain) adapter.acceptInsertion(count, _insertionInputs(first, count, oldRoot, newRoot), "");
        uint64 opensAt = vault.activationFallbackOpensAt();
        if (onChain && wait && vm.getBlockTimestamp() < opensAt) vm.warp(opensAt);
        bool paused = vault.paused();
        bool closed = onChain && vm.getBlockTimestamp() < opensAt;
        if (paused) vm.expectRevert(Errors.Paused.selector);
        else if (closed) vm.expectRevert(Errors.ActivationFallbackClosed.selector);
        if (onChain) vault.activateNotesOnChain(first, count, siblings);
        else vault.activateNotes(first, count, oldRoot, newRoot, "");
        if (paused) return;
        if (closed) {
            ++done[13];
            return;
        }
        ghostCursor = uint32(first + count);
        assertEq(vault.currentRoot(), newRoot);
        ++done[onChain ? 11 : 10];
    }

    /// A proof of the next note's activation that the adapter accepts, from anyone but the
    /// activator: NotActivator (Paused while paused).
    function activateAsOther(uint8 callerSeed) external {
        uint32 first = vault.activationCursor();
        if (vault.nextNoteId() == first) return;
        uint256 oldRoot = vault.currentRoot();
        (uint256 newRoot,) = ghostTree(uint256(first) + 1, 0);
        adapter.acceptInsertion(1, _insertionInputs(first, 1, oldRoot, newRoot), "");
        bool paused = vault.paused();
        vm.expectRevert(paused ? Errors.Paused.selector : Errors.NotActivator.selector);
        vm.prank(destinations[callerSeed % destinations.length]);
        vault.activateNotes(first, 1, oldRoot, newRoot, "");
        if (!paused) ++done[14];
    }

    /// An activation prepared against another root (a competing activation or a retirement landed
    /// first) reverts StaleActivation before any verification.
    function activateStale(uint256 rootDelta) external {
        uint32 first = vault.activationCursor();
        if (vault.nextNoteId() == first || vault.paused()) return;
        uint256 staleRoot = vault.currentRoot() + bound(rootDelta, 1, 1000);
        vm.expectRevert(Errors.StaleActivation.selector);
        vault.activateNotes(first, 1, staleRoot, 1, "");
        ++done[12];
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
            (, uint128 amount,, Types.NoteStatus status) = vault.notes(id);
            if (status == wanted) return (true, id, amount);
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
        (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(id);
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            registrationCommitment: uint256(commitment),
            stateSigningKeyX: 11,
            stateSigningKeyY: 12,
            clearanceSigningKeyX: 13,
            clearanceSigningKeyY: 14,
            noteId: id,
            finalBalance: finalBalance,
            destination: destinations[0],
            withdrawalNullifier: nullifier,
            kind: kind,
            nextNullifier: next,
            conceded: 0,
            validUntil: uint64(vm.getBlockTimestamp()) + 3 hours,
            noteMetadata: uint256(amount) | (uint256(expiry) << 128)
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

    function _leafOf(uint32 index) private view returns (uint256) {
        (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(index);
        return NoteLeafLib.computeLeaf(index, commitment, amount, expiry);
    }

    /// The ghost tree with notes 0 .. activated - 1 appended (retired leaves zero): its root and
    /// the siblings of slot `index`.
    function ghostTree(uint256 activated, uint32 index)
        public
        view
        returns (uint256 root, uint256[32] memory siblings)
    {
        uint256 width = activated > index ? activated : uint256(index) + 1;
        uint256[] memory nodes = new uint256[](width);
        for (uint256 i = 0; i < activated; ++i) {
            if (!retired[uint32(i)]) nodes[i] = _leafOf(uint32(i));
        }
        uint256 position = index;
        for (uint256 level = 0; level < 32; ++level) {
            siblings[level] = (position ^ 1) < width ? nodes[position ^ 1] : emptySiblings[level];
            uint256 parents = (width + 1) / 2;
            for (uint256 i = 0; i < parents; ++i) {
                uint256 right = 2 * i + 1 < width ? nodes[2 * i + 1] : emptySiblings[level];
                nodes[i] = Bn254Poseidon.compress(DOMAIN_NODE, nodes[2 * i], right);
            }
            width = parents;
            position >>= 1;
        }
        root = nodes[0];
    }

    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        (, siblings) = ghostTree(ghostCursor, index);
    }

    /// [oldRoot, newRoot, first, C_j, M_j, ...] read back from the vault's records.
    function _insertionInputs(uint32 first, uint256 count, uint256 oldRoot, uint256 newRoot)
        private
        view
        returns (uint256[] memory inputs)
    {
        inputs = new uint256[](3 + 2 * count);
        inputs[0] = oldRoot;
        inputs[1] = newRoot;
        inputs[2] = first;
        for (uint256 j = 0; j < count; ++j) {
            (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(uint32(first + j));
            inputs[3 + 2 * j] = uint256(commitment);
            inputs[4 + 2 * j] = uint256(amount) | (uint256(expiry) << 128);
        }
    }

    receive() external payable {}
}

/// @dev Invariants of the concession exit under random operation sequences:
///      - balance accounting: the vault holds every Active and pending deposit, the treasury
///        arrears and the credited escape payouts, nothing more or less;
///      - every pending escape has finalBalance + conceded == stateBalance <= its deposit and a
///        nonzero successor nullifier, and no other note has a pending record;
///      - each note pays out at most once (an escape or close that a Closed note gets through,
///        before or after its activation or retirement, counts as a second payout), and each exit
///        splits its deposit exactly between the owner (pushed or credited) and the treasury
///        (pushed or in arrears);
///      - the activation cursor never passes nextNoteId and equals the notes the handler
///        activated, and currentRoot is the root of the ghost tree: the recorded leaves of the
///        activated notes, minus the retired ones.
///      The handler expects every call it makes outside try/catch to succeed (and asserts each
///      exit's split as it happens), so a revert fails the campaign.
/// forge-config: default.invariant.fail-on-revert = true
contract ZkApiVaultInvariantTest is Test {
    ZkApiVault vault;
    VaultHandler handler;

    function setUp() public {
        vm.warp(1_700_000_000);
        MockProofAdapter adapter = new MockProofAdapter();
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
            address(this)
        );
        handler = new VaultHandler(vault, adapter, treasury, wallet);
        // The handler is the activator, and the owner, so it can pause and unpause.
        vault.setActivator(address(handler));
        vault.transferOwnership(address(handler));
        vm.prank(address(handler));
        vault.acceptOwnership();
        // Start every run with four notes of different sizes.
        for (uint128 i = 0; i < 4; ++i) {
            handler.deposit(250_000 * (i + 1));
        }
        targetContract(address(handler));
    }

    /// The handler does reach every activation path: a proved batch of four, an on-chain
    /// singleton refused before the fallback opens and landing once it has, a proof from a
    /// non-activator, a stale proved activation, the refused retirement of a Closed note not yet
    /// activated, a retirement and a tampered exit of a Closed note, and the invariants hold.
    function test_theHandlerReachesEveryActivationPath() public {
        handler.activate(1, false, false);
        handler.deposit(500_000);
        handler.activate(0, true, false);
        handler.activateAsOther(0);
        handler.activate(0, true, true);
        handler.deposit(600_000);
        handler.activateStale(7);
        handler.close(5, 0, 100_000, 0);
        handler.retire(5);
        handler.close(0, 0, 100_000, 0);
        handler.retire(0);
        handler.exitClosed(0, 0, 1, true, 0);
        assertEq(handler.done(10), 1, "proved activation");
        assertEq(handler.done(11), 1, "on-chain activation");
        assertEq(handler.done(12), 2, "stale activation and unactivated retirement refused");
        assertEq(handler.done(13), 1, "on-chain activation before the fallback opens refused");
        assertEq(handler.done(14), 1, "proof from a non-activator refused");
        assertEq(handler.done(8), 1, "retirement");
        assertEq(handler.done(9), 1, "tampered exit of a closed note refused");
        assertEq(vault.activationCursor(), 5);
        invariant_balanceAccounting();
        invariant_pendingConcessionsAreConsistent();
        invariant_onePayoutPerNoteSplittingItsDeposit();
        invariant_requestTreeIsTheGhostTree();
    }

    function invariant_balanceAccounting() public view {
        uint256 held;
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (, uint128 amount,, Types.NoteStatus status) = vault.notes(id);
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
            (, uint128 amount,, Types.NoteStatus status) = vault.notes(id);
            (bool exists, uint256 nullifier, uint128 finalBalance,,) = vault.pendingWithdrawals(id);
            (uint256 next, uint128 stateBalance, uint128 conceded) = vault.pendingConcessions(id);
            if (status == Types.NoteStatus.PendingWithdrawal) {
                assertTrue(exists);
                assertEq(uint256(finalBalance) + conceded, stateBalance);
                assertLe(stateBalance, amount);
                assertNotEq(next, 0);
                assertNotEq(next, nullifier);
                assertTrue(vault.usedNullifiers(nullifier));
                assertTrue(vault.usedNullifiers(next));
            } else {
                assertFalse(exists);
                assertEq(next, 0);
                assertEq(stateBalance, 0);
                assertEq(conceded, 0);
            }
        }
    }

    function invariant_onePayoutPerNoteSplittingItsDeposit() public view {
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (, uint128 amount,, Types.NoteStatus status) = vault.notes(id);
            uint256 payouts = handler.payouts(id);
            assertLe(payouts, 1);
            assertEq(payouts == 1, status == Types.NoteStatus.Closed);
            if (payouts == 1) assertEq(handler.paidToOwner(id) + handler.paidToTreasury(id), amount);
        }
    }

    function invariant_requestTreeIsTheGhostTree() public view {
        uint32 cursor = vault.activationCursor();
        assertLe(cursor, vault.nextNoteId());
        assertEq(cursor, handler.ghostCursor());
        (uint256 root,) = handler.ghostTree(cursor, 0);
        assertEq(vault.currentRoot(), root);
        if (cursor != 0) assertTrue(vault.isActivated(cursor - 1));
        assertFalse(vault.isActivated(cursor));
    }
}
