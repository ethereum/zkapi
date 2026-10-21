// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ReentrancyGuardTransient} from "../src/libraries/ReentrancyGuardTransient.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {MockAdapterIdentity} from "./mocks/MockProofAdapters.sol";

/// Accepts every proof. It has no receive function, so it also serves as a non-payable payee.
contract NativeProofFixture is MockAdapterIdentity {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

contract RejectNativePayout {
    receive() external payable {
        revert();
    }
}

/// Rejects ETH until switched on, like a wallet fixed after an escape to it.
contract ToggleableDestination {
    bool public accepting;

    function setAccepting(bool value) external {
        accepting = value;
    }

    receive() external payable {
        if (!accepting) revert();
    }
}

/// Once it accepts ETH, re-enters claimEscapePayout from its receive hook.
contract ReenteringClaimant {
    ZkApiVault public vault;
    bool public accepting;
    bool public reentered;
    bytes4 public reentryError;

    constructor(ZkApiVault target) {
        vault = target;
    }

    function setAccepting(bool value) external {
        accepting = value;
    }

    receive() external payable {
        if (!accepting) revert();
        (bool ok, bytes memory reason) = address(vault).call(abi.encodeCall(vault.claimEscapePayout, (address(this))));
        reentered = ok;
        reentryError = bytes4(reason);
    }
}

/// Accepts ETH, but only with more than ESCAPE_PAYOUT_GAS: its receive writes seven fresh slots
/// (about 155k gas), like a wallet that books every incoming payment.
contract HeavyReceiveDestination {
    uint256 public payments;
    mapping(uint256 => uint256) private receipts;

    receive() external payable {
        for (uint256 i; i < 6; ++i) {
            receipts[payments * 6 + i] = msg.value + i + 1;
        }
        ++payments;
    }
}

contract ReenterNativePayout {
    ZkApiVault public vault;
    bool public reentered;

    constructor(ZkApiVault target) {
        vault = target;
    }

    receive() external payable {
        (reentered,) = address(vault).call(abi.encodeCall(vault.finalizeEscapeWithdrawal, (0)));
    }
}

contract NativeEthVaultTest is Test {
    uint128 constant UNITS = 1_000_000;
    /// EscapeWithdrawalFinalized(uint32,uint256,uint128,address), as clients match it.
    bytes32 constant ESCAPE_FINALIZED_TOPIC = 0x163f2e46c4004f0ed9682e2db8c84efac31310720266b17ea9904ba348c26504;
    /// EscapePayoutDeferred(uint32,address,uint128), as clients match it.
    bytes32 constant ESCAPE_PAYOUT_DEFERRED_TOPIC = 0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942;
    address user = address(0x1234);
    address treasury = address(0x5678);
    ZkApiVault vault;
    NativeProofFixture adapter;
    uint256[32] siblings;

    function setUp() public {
        uint256 zero;
        for (uint256 level; level < 32; ++level) {
            siblings[level] = zero;
            zero = Bn254Poseidon.compress(0x7a6b6170692e76322e6e6f6465, zero, zero);
        }
        adapter = new NativeProofFixture();
        vault = new ZkApiVault(
            treasury, 30 days, 24 hours, 100_000, address(adapter), 11, 12, 13, 14, address(this), 7 days
        );
        vm.deal(user, 1 ether);
    }

    function deposit() internal {
        vm.prank(user);
        vault.deposit{value: uint256(UNITS) * 1 gwei}(bytes32(uint256(42)), UNITS);
    }

    /// A close (kind 1) or an escape (kind 0, successor nullifier 100) from the state at
    /// nullifier 99 with a 700,000 payout.
    function withdrawal(address destination, bool clearance)
        internal
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return Types.WithdrawalPublicInputs(
            2,
            uint64(block.chainid),
            address(vault),
            vault.currentRoot(),
            11,
            12,
            13,
            14,
            0,
            700_000,
            destination,
            99,
            clearance ? 1 : 0,
            clearance ? 0 : 100,
            0,
            uint64(vm.getBlockTimestamp()) + 3 hours
        );
    }

    function test_nativeDepositAndMutualPayout() public {
        uint256 gasBefore = gasleft();
        deposit();
        emit log_named_uint("Native deposit gas (cold fixture account)", gasBefore - gasleft());
        assertEq(address(vault.billingToken()), address(0));
        assertEq(vault.nativeAssetWeiPerUnit(), 1 gwei);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        uint256 initial = user.balance;
        vault.mutualClose(withdrawal(user, true), "");
        assertEq(user.balance - initial, 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
        assertEq(address(vault).balance, 0);
        assertTrue(vault.usedNullifiers(99));
    }

    function test_nativeRejectsWrongOrMissingValue() public {
        vm.startPrank(user);
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit(bytes32(uint256(42)), UNITS);
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit{value: uint256(UNITS) * 1 gwei + 1}(bytes32(uint256(42)), UNITS);
        vm.stopPrank();
        assertEq(vault.nextNoteId(), 0);
        assertEq(address(vault).balance, 0);
    }

    function test_nativeRejectsUnsafeLedgerAmount() public {
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit(bytes32(uint256(42)), 9_007_199_254_740_992);
    }

    function test_nativeRejectsInvalidRequestChargeCap() public {
        uint128 unsafeCap = vault.MAX_NATIVE_UNITS() + 1;
        vm.expectRevert(Errors.InvalidBalance.selector);
        new ZkApiVault(treasury, 30 days, 24 hours, 0, address(adapter), 11, 12, 13, 14, address(this), 7 days);
        vm.expectRevert(Errors.InvalidBalance.selector);
        new ZkApiVault(treasury, 30 days, 24 hours, unsafeCap, address(adapter), 11, 12, 13, 14, address(this), 7 days);
    }

    function test_rejectedPayoutPreservesNoteAndFunds() public {
        deposit();
        RejectNativePayout recipient = new RejectNativePayout();
        Types.WithdrawalPublicInputs memory inputs = withdrawal(address(recipient), true);
        uint256 root = vault.currentRoot();
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.mutualClose(inputs, "");
        assertEq(vault.currentRoot(), root);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        assertFalse(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
    }

    function test_rejectedTreasuryPayoutAccruesWithoutBlockingUser() public {
        deposit();
        address rejecting = address(new RejectNativePayout());
        vault.setTreasury(rejecting);
        vm.warp(block.timestamp + vault.treasuryChangeDelay());
        vault.acceptTreasury();
        uint256 userBalance = user.balance;
        Types.WithdrawalPublicInputs memory inputs = withdrawal(user, true);
        vm.expectEmit(address(vault));
        emit Events.TreasuryPaymentDeferred(rejecting, 300_000);
        vault.mutualClose(inputs, "");
        assertEq(user.balance - userBalance, 700_000 gwei);
        assertEq(vault.treasuryArrears(), 300_000);
        assertEq(address(vault).balance, 300_000 gwei);
        assertTrue(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.withdrawTreasuryArrears();
        vault.setTreasury(treasury);
        vm.warp(block.timestamp + vault.treasuryChangeDelay());
        vault.acceptTreasury();
        vault.withdrawTreasuryArrears();
        assertEq(treasury.balance, 300_000 gwei);
        assertEq(vault.treasuryArrears(), 0);
        assertEq(address(vault).balance, 0);
    }

    /// A destination that rejects ETH cannot lock the note or the operator's share: the escape
    /// closes, the treasury is paid, and the balance waits for the destination as a credit.
    function test_rejectedEscapePayoutIsCreditedAndTreasuryPaid() public {
        deposit();
        ToggleableDestination recipient = new ToggleableDestination();
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "");
        uint256 root = vault.currentRoot();
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline);
        vm.expectEmit(address(vault));
        emit Events.EscapePayoutDeferred(0, address(recipient), 700_000);
        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalFinalized(0, 99, 700_000, address(recipient));
        vm.prank(address(0xBEEF));
        vault.finalizeEscapeWithdrawal(0);
        assertEq(treasury.balance, 300_000 gwei);
        assertEq(vault.treasuryArrears(), 0);
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);
        assertEq(address(vault).balance, 700_000 gwei);
        assertEq(vault.currentRoot(), root);
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);

        // While the destination still rejects ETH, a claim reverts and keeps the credit.
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.claimEscapePayout(address(recipient));
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);

        // Once it accepts, anyone can push the whole credit to it, once.
        recipient.setAccepting(true);
        vm.expectEmit(address(vault));
        emit Events.EscapePayoutClaimed(address(recipient), 700_000);
        vm.prank(address(0xBEEF));
        vault.claimEscapePayout(address(recipient));
        assertEq(address(recipient).balance, 700_000 gwei);
        assertEq(address(0xBEEF).balance, 0);
        assertEq(vault.escapePayoutCredits(address(recipient)), 0);
        assertEq(address(vault).balance, 0);
        vm.expectRevert(Errors.ZeroAmount.selector);
        vault.claimEscapePayout(address(recipient));
    }

    /// The reviewed griefing attack: spend the note down to one unit, then escape it to a
    /// contract that has no receive function. The operator's share is still paid at the deadline.
    function test_spentDownEscapeToNonPayableContractPaysOperatorShare() public {
        deposit();
        Types.WithdrawalPublicInputs memory inputs = withdrawal(address(adapter), false);
        inputs.finalBalance = 1;
        vault.initiateEscapeWithdrawal(inputs, "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(treasury.balance, uint256(UNITS - 1) * 1 gwei);
        assertEq(vault.treasuryArrears(), 0);
        assertEq(vault.escapePayoutCredits(address(adapter)), 1);
        assertEq(address(vault).balance, 1 gwei);
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
    }

    /// When both payees reject ETH, each share is kept for its own payee.
    function test_rejectedEscapeAndTreasuryPayoutsAreBothKept() public {
        deposit();
        address rejecting = address(new RejectNativePayout());
        vault.setTreasury(rejecting);
        vm.warp(block.timestamp + vault.treasuryChangeDelay());
        vault.acceptTreasury();
        RejectNativePayout recipient = new RejectNativePayout();
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);
        assertEq(vault.treasuryArrears(), 300_000);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
    }

    function test_claimEscapePayoutIsNotReentrant() public {
        deposit();
        ReenteringClaimant recipient = new ReenteringClaimant(vault);
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);
        recipient.setAccepting(true);
        vault.claimEscapePayout(address(recipient));
        assertFalse(recipient.reentered());
        assertEq(recipient.reentryError(), ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        assertEq(address(recipient).balance, 700_000 gwei);
        assertEq(vault.escapePayoutCredits(address(recipient)), 0);
        assertEq(address(vault).balance, 0);
    }

    /// EscapeWithdrawalFinalized is identical whether the destination was paid or credited, so a
    /// client must tell the two apart by the EscapePayoutDeferred log that precedes it in the
    /// same receipt, matched on the vault address and topics [topic0, noteId, destination].
    function test_finalizeReceiptTellsPaidFromCreditedPayout() public {
        deposit();
        uint256 snapshot = vm.snapshotState();
        Vm.Log[] memory paid = _finalizeEscapeLogs(user);
        vm.revertToState(snapshot);
        address rejecting = address(new RejectNativePayout());
        Vm.Log[] memory credited = _finalizeEscapeLogs(rejecting);

        assertEq(paid.length, 1);
        _assertFinalizedLog(paid[0], user);
        assertEq(credited.length, 2);
        Vm.Log memory deferred = credited[0];
        assertEq(deferred.emitter, address(vault));
        assertEq(deferred.topics.length, 3);
        assertEq(deferred.topics[0], ESCAPE_PAYOUT_DEFERRED_TOPIC);
        assertEq(deferred.topics[1], bytes32(uint256(0)));
        assertEq(deferred.topics[2], bytes32(uint256(uint160(rejecting))));
        assertEq(deferred.data, abi.encode(uint128(700_000)));
        _assertFinalizedLog(credited[1], rejecting);
        assertEq(vault.escapePayoutCredits(rejecting), 700_000);
        assertEq(rejecting.balance, 0);
    }

    /// Clients hard-code these in calldata and receipt parsing (the SDK's wallet.js ABI table,
    /// zkapi-clientd, the challenger, the signer allowlist and the indexer). Pinned so that a
    /// signature change fails here instead of silently in a client. Values from the design
    /// (circuit zkapi-v2-concession-v1, vault revision 3).
    function test_clientFacingSelectorsAndTopicsArePinned() public view {
        assertEq(vault.deposit.selector, bytes4(0x56d2e1ea));
        assertEq(vault.mutualClose.selector, bytes4(0x72cd2e44));
        assertEq(vault.initiateEscapeWithdrawal.selector, bytes4(0xa38d62aa));
        assertEq(vault.challengeEscapeWithdrawal.selector, bytes4(0xda0ce43d));
        assertEq(vault.raiseEscapeConcession.selector, bytes4(0xdd0064ba));
        assertEq(vault.finalizeEscapeWithdrawal.selector, bytes4(0xff8f5585));
        assertEq(vault.claimExpired.selector, bytes4(0xa940507e));
        assertEq(vault.retireClosedLeaf.selector, bytes4(0xe41f4c31));
        assertEq(vault.claimEscapePayout.selector, bytes4(0x88c10aee));
        assertEq(vault.pendingWithdrawals.selector, bytes4(0xa2f9f1ce));
        assertEq(vault.pendingConcessions.selector, bytes4(0xf8ffe6e0));
        assertEq(vault.usedNullifiers.selector, bytes4(0xaad24061));
        assertEq(vault.challengedNullifiers.selector, bytes4(0x6cda756a));
        assertEq(vault.knownRoots.selector, bytes4(0x12ad7381));
        assertEq(vault.isKnownRoot.selector, bytes4(0xa6232a93));
        assertEq(vault.effectiveExpiry.selector, bytes4(0x7cb4a03c));
        assertEq(vault.CONCESSION_ESCAPE_VERSION.selector, bytes4(0x5e00b426));
        assertEq(vault.ROOT_HISTORY_WINDOW.selector, bytes4(0x1fe72de0));
        assertEq(vault.PAUSE_COOLDOWN.selector, bytes4(0xb5acb567));
        assertEq(vault.maxPauseDuration.selector, bytes4(0x64433d27));
        assertEq(vault.proofAdapter.selector, bytes4(0xefc91e58));
        assertEq(vault.challengePeriod.selector, bytes4(0xf3f480d9));
        assertEq(vault.currentRoot.selector, bytes4(0xfdab463d));
        assertEq(vault.nextNoteId.selector, bytes4(0x7a2043a3));
        assertEq(vault.notes.selector, bytes4(0x9f18e4ed));
        assertEq(vault.escapePayoutCredits.selector, bytes4(0x91f6e93a));
        assertEq(IZkApiProofAdapter.CIRCUIT_ID_HASH.selector, bytes4(0xda0e8385));
        assertEq(IZkApiProofAdapter.REQUEST_VK_HASH.selector, bytes4(0xfe351488));
        assertEq(IZkApiProofAdapter.WITHDRAWAL_VK_HASH.selector, bytes4(0x7fcd0926));
        assertEq(IZkApiProofAdapter.assertValidRequest.selector, bytes4(0x69078eaf));
        assertEq(IZkApiProofAdapter.assertValidWithdrawal.selector, bytes4(0x9ea31c77));
        assertEq(Events.NoteDeposited.selector, 0x7c83dba8534bea9e30d6444f9ca6462dc906897f9938d220dbbe4358c1f7a063);
        assertEq(Events.MutualClose.selector, 0x1f43fa4711ca18e1d26398f26bf598bd3a62992cdd0e84f055f2bb506e9d7031);
        assertEq(
            Events.EscapeWithdrawalInitiated.selector,
            0xb0d1eb7131bcf3c6dd53517f6fa90bf7cc94178eb0eb5e0a1f204abe3b839cdf
        );
        assertEq(
            Events.EscapeWithdrawalChallenged.selector,
            0x5cc5343b84cd949969f3ccc4ea44315630280857b9e591cc1ab48dbb9e6a3581
        );
        assertEq(
            Events.EscapeConcessionRecorded.selector, 0x2254ee827bce198564720fe77733ebfab1a49361cd4f050f107445241b560b4d
        );
        assertEq(
            Events.EscapeConcessionRaised.selector, 0x3faf5608f821061643ff6fdfe6dd0f6d7fb074bb565f35e3537a86ac08f0897c
        );
        assertEq(Events.ClosedLeafRetired.selector, 0x64572cec8ef079a5baa4f2860f8b65efb52a96f64ee679d315fd2a0541ea28b3);
        assertEq(Events.ExpiredClaimed.selector, 0x5534ce4a9fb7fe545375064cc186660ac10ba2152cb1592b29b244d2fe169ae4);
        assertEq(Events.EscapeWithdrawalFinalized.selector, ESCAPE_FINALIZED_TOPIC);
        assertEq(Events.EscapePayoutDeferred.selector, ESCAPE_PAYOUT_DEFERRED_TOPIC);
        assertEq(
            Events.EscapePayoutClaimed.selector, 0x6bf75371d42e9753c0913bf8fcecb651e8db173d99d7da0e4d836e91512bbe27
        );
        assertEq(Groth16ProofAdapter(address(0)).CIRCUIT_ID_HASH.selector, bytes4(0xda0e8385));
    }

    /// The exit calldata sizes the Go and JS encoders reproduce: 16 tuple words, then the proof's
    /// offset and length and 8 proof words for a withdrawal; noteId, 12 words, offset (and the
    /// raise's amount), length and 8 proof words for a defeat or raise.
    function test_exitCalldataSizesArePinned() public view {
        bytes memory proof = new bytes(256);
        Types.WithdrawalPublicInputs memory w = withdrawal(user, false);
        Types.RequestPublicInputs memory r;
        assertEq(abi.encodeCall(vault.initiateEscapeWithdrawal, (w, proof)).length, 836);
        assertEq(abi.encodeCall(vault.mutualClose, (w, proof)).length, 836);
        assertEq(abi.encodeCall(vault.challengeEscapeWithdrawal, (0, r, proof)).length, 740);
        assertEq(abi.encodeCall(vault.raiseEscapeConcession, (0, r, proof, 1)).length, 772);
        // The proof offset follows the static tuple: 17 words for a withdrawal.
        bytes memory escape = abi.encodeCall(vault.initiateEscapeWithdrawal, (w, proof));
        uint256 offset;
        assembly ("memory-safe") {
            offset := mload(add(escape, add(0x20, add(4, mul(16, 32)))))
        }
        assertEq(offset, 17 * 32);
    }

    /// A destination that accepts ETH but needs more than ESCAPE_PAYOUT_GAS is not paid at
    /// finalization, however much gas the finalizer sends: the receipt carries the credit marker,
    /// and claimEscapePayout, which forwards all gas, then pays the whole balance. So the cap can
    /// delay such a wallet's payout but never strand it.
    function test_heavyReceiveDestinationIsCreditedAndClaimsInFull() public {
        deposit();
        HeavyReceiveDestination recipient = new HeavyReceiveDestination();
        (bool acceptedWithinCap,) = address(recipient).call{value: 1, gas: vault.ESCAPE_PAYOUT_GAS()}("");
        assertFalse(acceptedWithinCap, "the fixture must need more than the cap");

        Vm.Log[] memory logs = _finalizeEscapeLogs(address(recipient));
        assertEq(recipient.payments(), 0);
        assertEq(logs.length, 2);
        assertEq(logs[0].emitter, address(vault));
        assertEq(logs[0].topics[0], ESCAPE_PAYOUT_DEFERRED_TOPIC);
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(address(recipient)))));
        _assertFinalizedLog(logs[1], address(recipient));
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);
        assertEq(treasury.balance, 300_000 gwei);

        vm.prank(address(0xBEEF));
        vault.claimEscapePayout(address(recipient));
        assertEq(recipient.payments(), 1);
        assertEq(address(recipient).balance, 700_000 gwei);
        assertEq(vault.escapePayoutCredits(address(recipient)), 0);
        assertEq(address(vault).balance, 0);
    }

    function _finalizeEscapeLogs(address destination) private returns (Vm.Log[] memory) {
        vault.initiateEscapeWithdrawal(withdrawal(destination, false), "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline);
        vm.recordLogs();
        vault.finalizeEscapeWithdrawal(0);
        return vm.getRecordedLogs();
    }

    function _assertFinalizedLog(Vm.Log memory log, address destination) private view {
        assertEq(log.emitter, address(vault));
        assertEq(log.topics.length, 2);
        assertEq(log.topics[0], ESCAPE_FINALIZED_TOPIC);
        assertEq(log.topics[1], bytes32(uint256(0)));
        assertEq(log.data, abi.encode(uint256(99), uint128(700_000), destination));
    }

    function test_nativeEscapeAndReentrancyGuard() public {
        deposit();
        ReenterNativePayout recipient = new ReenterNativePayout(vault);
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "");
        (bool exists,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        assertTrue(exists);
        vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(0);
        assertFalse(recipient.reentered());
        assertEq(address(recipient).balance, 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
    }

    function test_nativeExpiryPayout() public {
        deposit();
        (,, uint64 expiry,) = vault.notes(0);
        vm.warp(expiry);
        vault.claimExpired(0);
        assertEq(treasury.balance, uint256(UNITS) * 1 gwei);
        assertEq(address(vault).balance, 0);
    }
}
