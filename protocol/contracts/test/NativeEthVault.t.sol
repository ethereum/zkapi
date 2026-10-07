// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";

contract NativeProofFixture is IZkApiProofAdapter {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

contract RejectNativePayout {
    receive() external payable {
        revert();
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
    address user = address(0x1234);
    address treasury = address(0x5678);
    ZkApiVault vault;
    NativeProofFixture adapter;
    uint256[32] siblings;

    function setUp() public {
        uint256 zero;
        for (uint256 level; level < 32; ++level) {
            siblings[level] = zero;
            zero = Bn254Poseidon.hash3(0x7a6b6170692e76322e6e6f6465, zero, zero);
        }
        adapter = new NativeProofFixture();
        vault = new ZkApiVault(treasury, 30 days, 24 hours, 100_000, address(adapter), 11, 12, 13, 14, address(this));
        vm.deal(user, 1 ether);
    }

    function deposit() internal {
        vm.prank(user);
        vault.deposit{value: uint256(UNITS) * 1 gwei}(bytes32(uint256(42)), UNITS, siblings);
    }

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
            clearance,
            100
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
        vault.mutualClose(withdrawal(user, true), "", siblings);
        assertEq(user.balance - initial, 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
        assertEq(address(vault).balance, 0);
        assertTrue(vault.usedNullifiers(99));
    }

    function test_nativeRejectsWrongOrMissingValue() public {
        vm.startPrank(user);
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit(bytes32(uint256(42)), UNITS, siblings);
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit{value: uint256(UNITS) * 1 gwei + 1}(bytes32(uint256(42)), UNITS, siblings);
        vm.stopPrank();
        assertEq(vault.nextNoteId(), 0);
        assertEq(address(vault).balance, 0);
    }

    function test_nativeRejectsUnsafeLedgerAmount() public {
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit(bytes32(uint256(42)), 9_007_199_254_740_992, siblings);
    }

    function test_nativeRejectsInvalidRequestChargeCap() public {
        uint128 unsafeCap = vault.MAX_NATIVE_UNITS() + 1;
        vm.expectRevert(Errors.InvalidBalance.selector);
        new ZkApiVault(treasury, 30 days, 24 hours, 0, address(adapter), 11, 12, 13, 14, address(this));
        vm.expectRevert(Errors.InvalidBalance.selector);
        new ZkApiVault(treasury, 30 days, 24 hours, unsafeCap, address(adapter), 11, 12, 13, 14, address(this));
    }

    function test_rejectedPayoutPreservesNoteAndFunds() public {
        deposit();
        RejectNativePayout recipient = new RejectNativePayout();
        Types.WithdrawalPublicInputs memory inputs = withdrawal(address(recipient), true);
        uint256 root = vault.currentRoot();
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.mutualClose(inputs, "", siblings);
        assertEq(vault.currentRoot(), root);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        assertFalse(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
    }

    function test_rejectedTreasuryPayoutRollsBackUserPayout() public {
        deposit();
        vault.setTreasury(address(new RejectNativePayout()));
        uint256 root = vault.currentRoot();
        uint256 userBalance = user.balance;
        Types.WithdrawalPublicInputs memory inputs = withdrawal(user, true);
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.mutualClose(inputs, "", siblings);
        assertEq(user.balance, userBalance);
        assertEq(vault.currentRoot(), root);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        assertFalse(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
    }

    function test_rejectedEscapePayoutPreservesPendingWithdrawal() public {
        deposit();
        RejectNativePayout recipient = new RejectNativePayout();
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "", siblings);
        uint256 root = vault.currentRoot();
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline);
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(vault.currentRoot(), root);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        assertEq(treasury.balance, 0);
        assertTrue(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.PendingWithdrawal));
        (bool exists,, uint256 nullifier, uint128 balance, address destination, uint64 retainedDeadline) =
            vault.pendingWithdrawals(0);
        assertTrue(exists);
        assertEq(nullifier, 99);
        assertEq(balance, 700_000);
        assertEq(destination, address(recipient));
        assertEq(retainedDeadline, deadline);
    }

    function test_nativeEscapeAndReentrancyGuard() public {
        deposit();
        ReenterNativePayout recipient = new ReenterNativePayout(vault);
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "", siblings);
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
        (,, uint64 expiry,,) = vault.notes(0);
        vm.warp(expiry);
        vault.claimExpired(0, siblings);
        assertEq(treasury.balance, uint256(UNITS) * 1 gwei);
        assertEq(address(vault).balance, 0);
    }
}
