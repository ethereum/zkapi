// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {IEntryPoint, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {ToggleableDestination} from "../NativeEthVault.t.sol";
import {GaslessTestBase, SelfFundedAccount} from "./GaslessTestBase.sol";

/// @dev Owns a whole gasless deployment and drives it: sponsored and direct closes, sponsored and
///      direct escapes, raises, defeats, sponsored and direct finalizations, forwards, sweeps, credit
///      claims, policy changes, write-offs and time. Two payees (an EOA and a wallet that may refuse
///      ETH) give two transit accounts. Every sponsored operation goes through handleOps; refusals
///      and reverted executions are expected outcomes, not failures. Some actions bundle an
///      operation ahead of a sponsored one that makes its execution revert after validation (a
///      self-funded replay of the close or the finalization, or S's own unsponsored operation), so
///      the reverted, stranded and credit-on-revert paths of postOp run too. Ghost sums, read from
///      the EntryPoint's and the paymaster's events, track what the float actually paid and
///      charged.
contract GaslessHandler is GaslessTestBase {
    uint256 public constant NOTE_AMOUNT = 100_000_000; // 0.1 ether in gwei units
    uint32 public constant MAX_NOTES = 8;

    ToggleableDestination public wallet;
    address[2] public payees;
    address[2] public accounts;
    uint256 public writtenOff;
    uint256 public ghostCreditsClaimed;
    uint256 public nullifierSeq = 10_000;
    uint256 public sponsoredOps;
    uint256 public revertedOps;
    uint256 public refusedOps;
    uint256 public postOpReverts;
    /// What the EntryPoint took from the float for sponsored operations that settled, and for those
    /// whose execution reverted (UserOperationEvent.actualGasCost, the final cost).
    uint256 public ghostSettledGas;
    uint256 public ghostRevertedGas;
    /// Settled.charged summed, and the part of it the float did not get (charged to a payout that
    /// could not cover it).
    uint256 public ghostCharged;
    uint256 public ghostUncollected;
    SelfFundedAccount public replayer;

    constructor() {
        _setUpGasless();
        replayer = new SelfFundedAccount(ENTRY_POINT);
        vm.deal(address(replayer), 1000 ether);
        wallet = new ToggleableDestination();
        payees = [address(0x9A7EE), address(wallet)];
        accounts = [_transit(ownerAddr, payees[0]), _transit(ownerAddr, payees[1])];
    }

    function paymasterAddress() external view returns (address) {
        return address(paymaster);
    }

    function vaultAddress() external view returns (address) {
        return address(vault);
    }

    function initialDeposit() external pure returns (uint256) {
        return INITIAL_DEPOSIT;
    }

    function userAddress() external view returns (address) {
        return user;
    }

    // ------------------------------------------------------------------------------ actions

    function deposit() external {
        if (vault.nextNoteId() >= MAX_NOTES || vault.paused()) return;
        _depositUnits(1000 + vault.nextNoteId(), uint128(NOTE_AMOUNT));
    }

    function sponsoredClose(uint32 noteSeed, uint128 balanceSeed, uint8 payeeSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        address payee_ = payees[payeeSeed % 2];
        uint256 nullifier = ++nullifierSeq;
        (PackedUserOperation memory op,) = _closeOpFor(payee_, id, nullifier, balance);
        _sponsored(op);
    }

    function directClose(uint32 noteSeed, uint128 balanceSeed, uint8 destSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        address destination = destSeed % 3 == 2 ? user : accounts[destSeed % 2];
        Types.WithdrawalPublicInputs memory inputs = _close(id, ++nullifierSeq, balance);
        inputs.destination = destination;
        vm.prank(user);
        try vault.mutualClose(inputs, PROOF) {} catch {}
    }

    function sponsoredEscape(uint32 noteSeed, uint128 balanceSeed, uint128 concededSeed, uint8 payeeSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        uint128 conceded = uint128(bound(concededSeed, 0, balance));
        uint256 nullifier = ++nullifierSeq;
        (PackedUserOperation memory op,) =
            _escapeOpFor(payees[payeeSeed % 2], id, nullifier, nullifier + 500_000, balance - conceded, conceded);
        _sponsored(op);
    }

    function directEscape(uint32 noteSeed, uint128 balanceSeed, uint8 destSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        uint256 nullifier = ++nullifierSeq;
        Types.WithdrawalPublicInputs memory inputs = _escape(id, nullifier, nullifier + 500_000, balance, 0);
        inputs.destination = destSeed % 3 == 2 ? user : accounts[destSeed % 2];
        vm.prank(user);
        try vault.initiateEscapeWithdrawal(inputs, PROOF) {} catch {}
    }

    function raise(uint32 noteSeed, uint128 amountSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,, uint256 nullifier,,,) = vault.pendingWithdrawals(id);
        uint128 amount = uint128(bound(amountSeed, 0, NOTE_AMOUNT));
        Types.RequestPublicInputs memory request = _evidence(nullifier, amount);
        vm.prank(challenger);
        try vault.raiseEscapeConcession(id, request, PROOF, amount) {} catch {}
    }

    function defeat(uint32 noteSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (uint256 next,,) = vault.pendingConcessions(id);
        Types.RequestPublicInputs memory request = _evidence(next, 100_000);
        vm.prank(challenger);
        try vault.challengeEscapeWithdrawal(id, request, PROOF) {} catch {}
    }

    function sponsoredFinalize(uint32 noteSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,,,, address destination, uint64 deadline) = vault.pendingWithdrawals(id);
        uint8 which = destination == accounts[0] ? 0 : destination == accounts[1] ? 1 : 2;
        if (which == 2) return;
        if (vm.getBlockTimestamp() < deadline) vm.warp(deadline);
        _sponsored(_finalizeOpFor(payees[which], id));
    }

    function directFinalize(uint32 noteSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        if (vm.getBlockTimestamp() < deadline) vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(id);
    }

    /// A self-funded account replays the close on the vault in the operation before the sponsored
    /// one: the sponsored execution reverts, S is stranded with the payout.
    function sponsoredCloseAfterReplay(uint32 noteSeed, uint128 balanceSeed, uint8 payeeSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _closeOpFor(payees[payeeSeed % 2], id, ++nullifierSeq, balance);
        _replayAhead(op, abi.encodeCall(ZkApiVault.mutualClose, (inputs, proof256)));
    }

    /// A self-funded account finalizes the escape directly in the operation before the sponsored
    /// finalization: the sponsored execution reverts, S is stranded with the payout.
    function sponsoredFinalizeAfterReplay(uint32 noteSeed) external {
        (bool ok, uint32 id, uint8 which) = _pendingOfAccount(noteSeed);
        if (!ok) return;
        _replayAhead(_finalizeOpFor(payees[which], id), abi.encodeCall(ZkApiVault.finalizeEscapeWithdrawal, (id)));
    }

    /// S's own unsponsored operation (its EntryPoint deposit pays) closes the note ahead of the
    /// sponsored close: the payout reaches the paymaster while the sponsorship is in flight, the
    /// sponsored execution reverts, and its postOp credits the payout to the payee.
    function unsponsoredCloseAhead(uint32 noteSeed, uint128 balanceSeed, uint8 payeeSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint8 which = payeeSeed % 2;
        _fundAccount(which);
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _closeOpFor(payees[which], id, ++nullifierSeq, balance);
        _unsponsoredAhead(which, op, _callData(_closeCall(inputs)));
    }

    /// The same with a finalization: the postOp deducts S's escape debt from the payout first.
    function unsponsoredFinalizeAhead(uint32 noteSeed) external {
        (bool ok, uint32 id, uint8 which) = _pendingOfAccount(noteSeed);
        if (!ok) return;
        _fundAccount(which);
        _unsponsoredAhead(which, _finalizeOpFor(payees[which], id), _callData(_finalizeCall(id)));
    }

    function forward(uint8 which) external {
        which = which % 2;
        if (accounts[which].code.length == 0 && accounts[which].balance == 0) return;
        _sponsored(_forwardOpFor(payees[which]));
    }

    function sweep(uint8 which) external {
        which = which % 2;
        address s = accounts[which];
        if (s.code.length == 0) factory.createAccount(ownerAddr, payees[which]);
        if (s.balance == 0) return;
        vm.prank(user);
        ZkApiWithdrawalAccount(payable(s)).sweep();
        assertEq(s.balance, 0, "swept");
    }

    function claimCredit(uint8 which) external {
        address payee_ = payees[which % 2];
        uint256 amount = paymaster.credits(payee_);
        if (amount == 0) return;
        vm.prank(user);
        try paymaster.claimCredit(payee_) {
            ghostCreditsClaimed += amount;
        } catch {}
    }

    function toggleWallet(bool accepting) external {
        wallet.setAccepting(accepting);
    }

    function setPolicy(uint64 flatFeeSeed, bool escapes, bool paused) external {
        ZkApiWithdrawalPaymaster.Policy memory p = _defaultPolicy();
        p.flatFeeWei = uint64(bound(flatFeeSeed, 0, 0.001 ether));
        p.escapesEnabled = escapes;
        p.sponsorshipPaused = paused;
        paymaster.setPolicy(p);
    }

    function writeOff(uint8 which) external {
        address s = accounts[which % 2];
        uint256 amount = paymaster.owed(s);
        if (amount == 0) return;
        paymaster.writeOffDebt(s);
        writtenOff += amount;
    }

    function allowForward(uint8 which) external {
        paymaster.allowForward(accounts[which % 2]);
    }

    function warp(uint32 seconds_) external {
        vm.warp(vm.getBlockTimestamp() + bound(seconds_, 1, 2 days));
    }

    // ------------------------------------------------------------------------------ helpers

    function _sponsored(PackedUserOperation memory op) internal {
        _bundle(_single(op));
    }

    function _replayAhead(PackedUserOperation memory op, bytes memory vaultCalldata) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _selfFundedOp(replayer, address(vault), vaultCalldata);
        ops[1] = op;
        _bundle(ops);
    }

    /// S deployed (before its sponsored operation is built, so that carries no initCode) and with an
    /// EntryPoint deposit of its own for its unsponsored operation.
    function _fundAccount(uint8 which) internal {
        address s = accounts[which];
        if (s.code.length == 0) factory.createAccount(ownerAddr, payees[which]);
        if (entryPoint.balanceOf(s) < 0.1 ether) {
            vm.deal(address(this), 1 ether);
            entryPoint.depositTo{value: 1 ether}(s);
        }
    }

    function _unsponsoredAhead(uint8 which, PackedUserOperation memory op, bytes memory callData) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _unsponsoredOp(accounts[which], 7, callData);
        ops[1] = op;
        _bundle(ops);
    }

    /// handleOps(ops) from the bundler, reading the outcome of every sponsored operation from the
    /// logs. A bundle that fails validation changes nothing and counts as refused.
    function _bundle(PackedUserOperation[] memory ops) internal {
        vm.recordLogs();
        (bool ok,) = _tryHandleOps(ops);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        if (!ok) {
            ++refusedOps;
            return;
        }
        for (uint256 i = 0; i < logs.length; ++i) {
            Vm.Log memory l = logs[i];
            if (l.emitter == ENTRY_POINT) {
                if (
                    l.topics[0] == IEntryPoint.UserOperationEvent.selector
                        && address(uint160(uint256(l.topics[3]))) == address(paymaster)
                ) {
                    (, bool success, uint256 actualGasCost,) = abi.decode(l.data, (uint256, bool, uint256, uint256));
                    ++sponsoredOps;
                    if (success) {
                        ghostSettledGas += actualGasCost;
                    } else {
                        ++revertedOps;
                        ghostRevertedGas += actualGasCost;
                    }
                } else if (l.topics[0] == IEntryPoint.PostOpRevertReason.selector) {
                    ++postOpReverts;
                }
            } else if (l.emitter == address(paymaster) && l.topics[0] == ZkApiWithdrawalPaymaster.Settled.selector) {
                (uint8 kind,, uint256 received, uint256 charged, uint256 owedPaid, uint256 paidOut) =
                    abi.decode(l.data, (uint8, uint32, uint256, uint256, uint256, uint256));
                // An escape's charge joins the debt in full (what S held settles part of it); any
                // other kind keeps what the payout covered: received - paidOut, less the debt paid.
                uint256 collected = kind == ESCAPE ? charged : received - paidOut - owedPaid;
                ghostCharged += charged;
                ghostUncollected += charged - collected;
            }
        }
    }

    /// A pending escape whose destination is one of the two transit accounts, at its deadline.
    function _pendingOfAccount(uint32 seed) internal returns (bool ok, uint32 id, uint8 which) {
        (ok, id) = _note(seed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return (false, 0, 0);
        (,,,, address destination, uint64 deadline) = vault.pendingWithdrawals(id);
        if (destination != accounts[0] && destination != accounts[1]) return (false, 0, 0);
        which = destination == accounts[0] ? 0 : 1;
        if (vm.getBlockTimestamp() < deadline) vm.warp(deadline);
    }

    function _note(uint32 seed, Types.NoteStatus wanted) internal view returns (bool ok, uint32 id) {
        uint32 count = vault.nextNoteId();
        if (count == 0) return (false, 0);
        for (uint32 i = 0; i < count; ++i) {
            id = uint32((uint256(seed) + i) % count);
            if (_status(id) == wanted) return (true, id);
        }
        return (false, 0);
    }
}

/// @dev Invariants of the paymaster under random sequences of sponsored and direct exits:
///      - the paymaster's own balance is exactly the credited payouts;
///      - the float's ledger is exact: deposit + open debts + written-off debts equals the initial
///        deposit plus the revenue (every charge less the final gas cost of the operations that
///        settled), less the final gas cost of the sponsored operations that reverted and the
///        charges no payout covered;
///      - the float loses only what it records: lostWei covers the reverted operations' final
///        cost, shortfallWei the uncovered charges, and postOp never reverts;
///      - a transit account holds nothing after a forward or a sweep (asserted as they happen);
///      - the vault's own balance accounting still holds.
/// forge-config: default.invariant.fail-on-revert = true
contract GaslessInvariantTest is Test {
    GaslessHandler handler;
    ZkApiWithdrawalPaymaster paymaster;
    ZkApiVault vault;
    IEntryPoint entryPoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);

    function setUp() public {
        handler = new GaslessHandler();
        paymaster = ZkApiWithdrawalPaymaster(handler.paymasterAddress());
        vault = ZkApiVault(handler.vaultAddress());
        for (uint256 i = 0; i < 4; ++i) {
            handler.deposit();
        }
        targetContract(address(handler));
    }

    function invariant_paymasterBalanceIsTheCredits() public view {
        assertEq(address(paymaster).balance, paymaster.totalCredits());
        assertEq(paymaster.totalCredits(), paymaster.credits(handler.payees(0)) + paymaster.credits(handler.payees(1)));
    }

    function invariant_theFloatLedgerIsExact() public view {
        uint256 held = entryPoint.balanceOf(address(paymaster)) + paymaster.owed(handler.accounts(0))
            + paymaster.owed(handler.accounts(1)) + handler.writtenOff();
        int256 revenue = int256(handler.ghostCharged()) - int256(handler.ghostSettledGas());
        int256 expected = int256(handler.initialDeposit()) + revenue - int256(handler.ghostRevertedGas())
            - int256(handler.ghostUncollected());
        assertEq(int256(held), expected);
    }

    function invariant_theFloatLosesOnlyWhatItRecords() public view {
        assertGe(paymaster.lostWei(), handler.ghostRevertedGas(), "lostWei covers every reverted operation");
        assertGe(paymaster.shortfallWei(), handler.ghostUncollected(), "shortfallWei covers every uncovered charge");
        assertEq(handler.postOpReverts(), 0, "postOp never reverts");
    }

    /// The handler's bundles do reach the reverted-execution paths: a replayed close, a replayed
    /// finalization, and S's own close and finalization ahead of the sponsored ones each revert
    /// after validation, and the invariants hold over them.
    function test_theHandlerReachesRevertedSponsorships() public {
        handler.sponsoredCloseAfterReplay(0, uint128(handler.NOTE_AMOUNT() / 2), 0);
        handler.unsponsoredCloseAhead(0, uint128(handler.NOTE_AMOUNT() / 2), 1);
        handler.sponsoredEscape(0, uint128(handler.NOTE_AMOUNT()), 0, 0);
        handler.sponsoredEscape(0, uint128(handler.NOTE_AMOUNT()), 0, 1);
        handler.sponsoredFinalizeAfterReplay(0);
        handler.unsponsoredFinalizeAhead(0);
        assertEq(handler.revertedOps(), 4, "four sponsored executions reverted");
        assertEq(handler.refusedOps(), 0);
        assertGt(paymaster.lostWei(), 0);
        assertGt(paymaster.totalCredits(), 0, "credit-on-revert reached");
        assertTrue(paymaster.stranded(handler.accounts(0)), "stranded reached");
        invariant_paymasterBalanceIsTheCredits();
        invariant_theFloatLedgerIsExact();
        invariant_theFloatLosesOnlyWhatItRecords();
    }

    function invariant_vaultBalanceAccounting() public view {
        uint256 held;
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (, uint128 amount,, Types.NoteStatus status) = vault.notes(id);
            if (status == Types.NoteStatus.Active || status == Types.NoteStatus.PendingWithdrawal) held += amount;
        }
        held += vault.treasuryArrears();
        held += vault.escapePayoutCredits(handler.accounts(0)) + vault.escapePayoutCredits(handler.accounts(1))
        + vault.escapePayoutCredits(handler.userAddress());
        assertEq(address(vault).balance, held * 1 gwei);
    }
}
