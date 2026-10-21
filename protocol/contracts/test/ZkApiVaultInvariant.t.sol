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

/// @dev Drives a vault (mock adapter) through random deposits, escapes with concessions, raises,
///      defeats, finalizations, closes, expiry claims, payout claims, retirements, pauses, time and
///      attempts to exit Closed notes again, and keeps the ghost accounting the invariants check.
///      Note n's states have nullifiers N(n, i) = 1 + n * 1000 + i; an escape from S_i names
///      N(n, i + 1) as its successor.
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
    /// expired, claim payout, retire, and refused exits of a Closed note.
    uint256[10] public done;
    /// Every root the vault set: the empty tree's, then each deposit's and retirement's.
    uint256[] public roots;

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
        roots.push(vault_.currentRoot());
    }

    function rootCount() external view returns (uint256) {
        return roots.length;
    }

    // -------------------------------------------------------------------------- actions

    function deposit(uint128 amountSeed) external {
        uint32 id = vault.nextNoteId();
        if (id >= MAX_NOTES || vault.paused()) return;
        uint128 amount = uint128(bound(amountSeed, 1, 2_000_000));
        vault.deposit{value: uint256(amount) * 1 gwei}(bytes32(uint256(1000 + id)), amount);
        roots.push(vault.currentRoot());
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

    /// An escape or a close of a Closed note, from any of its states, at any root the vault ever
    /// held (Amendment A1 keeps them all valid, so a closed note's leaf stays provable). It must
    /// revert: NoteNotActive, or for an escape ChallengedNullifier or SupersededState when a defeat
    /// flagged its state or the successor. A success is recorded as a second payout of the note,
    /// which invariant_onePayoutPerNoteSplittingItsDeposit refuses.
    function exitClosed(uint32 noteSeed, uint256 stateSeed, uint256 rootSeed, bool asClose, uint128 balanceSeed)
        external
    {
        (bool ok, uint32 id, uint128 deposit_) = _note(noteSeed, Types.NoteStatus.Closed);
        if (!ok) return;
        uint256 i = stateSeed % STATES;
        uint128 balance = uint128(bound(balanceSeed, 0, deposit_));
        Types.WithdrawalPublicInputs memory inputs =
            _withdrawal(asClose ? 1 : 0, id, _n(id, i), asClose ? 0 : _n(id, i + 1), balance);
        inputs.activeRoot = roots[rootSeed % roots.length];
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

    function retire(uint32 noteSeed) external {
        (bool ok, uint32 id,) = _note(noteSeed, Types.NoteStatus.Closed);
        if (!ok || retired[id]) return;
        uint256[32] memory path = _path(id);
        vault.retireClosedLeaf(id, path);
        retired[id] = true;
        roots.push(vault.currentRoot());
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
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: vault.currentRoot(),
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
        if (index >= vault.nextNoteId() || retired[index]) return 0;
        (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(index);
        return NoteLeafLib.computeLeaf(index, commitment, amount, expiry);
    }

    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        siblings = emptySiblings;
        siblings[0] = _treeLeaf(index ^ 1);
        uint32 pair = (index >> 1) ^ 1;
        siblings[1] = Bn254Poseidon.compress(DOMAIN_NODE, _treeLeaf(pair * 2), _treeLeaf(pair * 2 + 1));
        uint32 quad = (index >> 2) ^ 1;
        siblings[2] = Bn254Poseidon.compress(
            DOMAIN_NODE,
            Bn254Poseidon.compress(DOMAIN_NODE, _treeLeaf(quad * 4), _treeLeaf(quad * 4 + 1)),
            Bn254Poseidon.compress(DOMAIN_NODE, _treeLeaf(quad * 4 + 2), _treeLeaf(quad * 4 + 3))
        );
    }

    receive() external payable {}
}

/// @dev Invariants of the concession exit under random operation sequences:
///      - balance accounting: the vault holds every Active and pending deposit, the treasury
///        arrears and the credited escape payouts, nothing more or less;
///      - every pending escape has finalBalance + conceded == stateBalance <= its deposit and a
///        nonzero successor nullifier, and no other note has a pending record;
///      - each note pays out at most once (an escape or close that a Closed note gets through,
///        at any root the vault held, counts as a second payout), and each exit splits its
///        deposit exactly between the owner (pushed or credited) and the treasury (pushed or in
///        arrears);
///      - every root the vault held stays known.
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
            address(treasury), 30 days, 24 hours, 100_000, address(adapter), 11, 12, 13, 14, address(this), 7 days
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
            (bool exists,, uint256 nullifier, uint128 finalBalance,,) = vault.pendingWithdrawals(id);
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

    function invariant_everyRootTheVaultHeldStaysKnown() public view {
        uint256 count = handler.rootCount();
        assertEq(handler.roots(count - 1), vault.currentRoot());
        for (uint256 i = 0; i < count; ++i) {
            assertTrue(vault.isKnownRoot(handler.roots(i)));
        }
    }
}
