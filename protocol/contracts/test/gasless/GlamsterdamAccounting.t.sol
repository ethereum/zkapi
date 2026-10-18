// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {GaslessTestBase} from "./GaslessTestBase.sol";

/// Accounting invariants for the repriced policy. Cancun execution here tests accounting, not
/// Glamsterdam gas consumption; the published gas limits also require live-chain measurements.
contract GlamsterdamAccountingTest is GaslessTestBase {
    function setUp() public {
        _setUpGasless(ZkApiWithdrawalPaymaster.GasSchedule.Glamsterdam);
    }

    function testFuzz_attemptKeyEncodingPreservesTheFourDomains(uint256 nullifier, uint32 noteId, address sender) public view {
        assertEq(paymaster.keyFor(CLOSE, nullifier, noteId, sender), keccak256(abi.encode("close", nullifier)));
        assertEq(paymaster.keyFor(ESCAPE, nullifier, noteId, sender), keccak256(abi.encode("escape", noteId)));
        assertEq(paymaster.keyFor(FINALIZE, nullifier, noteId, sender), keccak256(abi.encode("finalize", noteId)));
        assertEq(paymaster.keyFor(FORWARD, nullifier, noteId, sender), keccak256(abi.encode("forward", sender)));
    }

    function test_unknownAttemptKindKeepsItsErrorSelector() public {
        vm.expectRevert(ZkApiWithdrawalPaymaster.InvalidKind.selector);
        paymaster.keyFor(0, 0, 0, address(0));
        vm.expectRevert(ZkApiWithdrawalPaymaster.InvalidKind.selector);
        paymaster.keyFor(5, 0, 0, address(0));
    }

    function testFuzz_repeatEscapeConservesDebtAndRespectsApprovedMaximum(uint256 balanceSeed) public {
        uint32 firstId = _bigNote(42);
        (PackedUserOperation memory first,) =
            _escapeOp(firstId, 2001, 2002, BIG - 2_000_000, 1_000_000);
        Vm.Log[] memory firstLogs = _handle(first);
        (bool success,,) = _userOpEvent(firstLogs);
        assertTrue(success);
        uint256 priorDebt = paymaster.owed(first.sender);
        assertGt(priorDebt, 0);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(firstId, _evidence(2002, 100_000), PROOF);

        // Exercise an empty sender, tiny unsolicited balances, partial repayment and full repayment.
        uint256 forwarded = balanceSeed % 4 == 0 ? 0 : balanceSeed % 4 == 1 ? 1 : bound(balanceSeed, 2, 1 ether);
        vm.deal(first.sender, forwarded);
        uint32 nextId = _bigNote(43);
        (PackedUserOperation memory next,) =
            _escapeOp(nextId, 3001, 3002, BIG - 2_000_000, 1_000_000);
        Vm.Log[] memory logs = _handle(next);
        (success,,) = _userOpEvent(logs);
        assertTrue(success, "a defeated escape permits another sponsorship");
        SettledEvent memory settled = _settled(logs);
        assertTrue(settled.found);
        assertLe(settled.charged, _maxCostOf(next) + FLAT_FEE, "the signed maximum is universal");
        assertEq(settled.received, forwarded);
        assertEq(paymaster.owed(next.sender) + settled.owedPaid, priorDebt + settled.charged);
        assertEq(paymaster.credits(payee) + settled.owedPaid, forwarded);
        assertEq(paymaster.totalCredits(), address(paymaster).balance);
        assertEq(next.sender.balance, 0);
        assertEq(paymaster.escapeNotePlusOne(next.sender), uint256(nextId) + 1);
        assertTrue(paymaster.escapeSponsored(nextId));
    }
}
