// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {IEntryPoint, IPaymaster, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {GaslessTestBase, GasBurner, SelfFundedAccount} from "./GaslessTestBase.sol";

/// @dev postOp never reverts within its gas floor on any path: fuzzed down to the floor with a
///      payee that burns every unit it is given and every slot cold, the finalization-with-debt path,
///      the shortfall path (a sweep front-run inside the bundle), and preVerificationGas at its
///      floor; the paymaster has no receive.
contract PostOpTest is GaslessTestBase {
    function setUp() public {
        _setUpGasless();
    }

    function _assertSettledCleanly(Vm.Log[] memory logs) internal pure {
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success, "success");
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.PostOpRevertReason.selector), "no PostOpRevertReason");
        assertFalse(
            _has(logs, ENTRY_POINT, IEntryPoint.UserOperationPrefundTooLow.selector), "no UserOperationPrefundTooLow"
        );
    }

    /// A first-use close with a gas-burning payee (every slot cold, the first credit ever) settles
    /// with any paymasterPostOpGasLimit from the floor up.
    function testFuzz_postOpSettlesDownToTheFloor(uint256 limitSeed) public {
        uint256 limit = bound(limitSeed, gp.postOpFloor, gp.postOpCap);
        GasBurner burner = new GasBurner();
        uint32 id = _bigNote(42);
        address s = _transit(ownerAddr, address(burner));
        Types.WithdrawalPublicInputs memory inputs = _closeTo(id, 1001, BIG - 1_000_000, s);
        OpGas memory g = _gas(CLOSE, true);
        g.postOp = limit;
        PackedUserOperation memory op =
            _op(s, _nonce(s, 1001), _initCode(ownerAddr, address(burner)), _callData(_closeCall(inputs)), g);
        op = _sign(op, OWNER_KEY);
        Vm.Log[] memory logs = _handle(op);
        _assertSettledCleanly(logs);
        assertTrue(_has(logs, address(paymaster), ZkApiWithdrawalPaymaster.PayoutCredited.selector), "credited");
        assertEq(paymaster.totalCredits(), address(paymaster).balance);
    }

    /// The most expensive settling path at the floor: a finalization that deducts a debt, pushes to
    /// a burning payee and credits it.
    function test_finalizeWithDebtAndBurningPayeeAtTheFloor() public {
        GasBurner burner = new GasBurner();
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _escapeOpFor(address(burner), id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _handle(op);
        address s = op.sender;
        assertGt(paymaster.owed(s), 0);
        vm.warp(_deadline(id));
        op = _finalizeOpFor(address(burner), id);
        OpGas memory g = _gas(FINALIZE, false);
        g.postOp = gp.postOpFloor;
        op.accountGasLimits = bytes32((g.verification << 128) | g.call);
        op.paymasterAndData = _paymasterAndData(g);
        op = _sign(op, OWNER_KEY);
        Vm.Log[] memory logs = _handle(op);
        _assertSettledCleanly(logs);
        SettledEvent memory e = _settled(logs);
        assertGt(e.owedPaid, 0, "the debt was deducted");
        assertEq(paymaster.owed(s), 0);
        assertEq(paymaster.credits(address(burner)), e.paidOut);
    }

    /// A sweep front-run inside the bundle empties S before the forward executes: the shortfall path
    /// settles without a revert and records what the payout could not cover.
    function test_shortfallPathAtTheFloor() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory close, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, 1001, BIG - 1_000_000);
        address s = close.sender;
        // the close is replayed inside the bundle: the payout sits in S, the sponsored close is stranded
        _bundledWithReplay(close, abi.encodeCall(ZkApiVault.mutualClose, (inputs, proof256)));
        assertTrue(paymaster.stranded(s));
        assertEq(s.balance, uint256(BIG - 1_000_000) * 1 gwei);
        // a bundle: another account sweeps S, then the sponsored forward finds nothing
        SelfFundedAccount other = new SelfFundedAccount(ENTRY_POINT);
        vm.deal(address(other), 1 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _selfFundedOp(other, s, abi.encodeCall(ZkApiWithdrawalAccount.sweep, ()));
        PackedUserOperation memory forward = _forwardOp();
        OpGas memory g = _gas(FORWARD, false);
        g.postOp = gp.postOpFloor;
        forward.paymasterAndData = _paymasterAndData(g);
        ops[1] = _sign(forward, OWNER_KEY);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        Vm.Log[] memory logs = _handleOps(ops);
        assertEq(_count(logs, ENTRY_POINT, IEntryPoint.UserOperationEvent.selector), 2);
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.PostOpRevertReason.selector));
        assertTrue(_has(logs, address(paymaster), ZkApiWithdrawalPaymaster.Collected.selector), "swept to the payee");
        assertTrue(_has(logs, address(paymaster), ZkApiWithdrawalPaymaster.Shortfall.selector), "shortfall recorded");
        SettledEvent memory e = _settled(logs);
        assertTrue(e.found);
        assertEq(e.kind, FORWARD);
        assertEq(e.received, 0);
        assertEq(e.paidOut, 0);
        assertEq(paymaster.shortfallWei(), e.charged, "the whole charge was short");
        assertEq(payee.balance, uint256(BIG - 1_000_000) * 1 gwei, "the sweep paid the payee");
        assertLt(entryPoint.balanceOf(address(paymaster)), depositBefore, "the float paid the forward");
        assertFalse(paymaster.stranded(s), "evidence consumed");
    }

    /// Every field at its floor: the prefund still covers the real cost.
    function test_everyGasFieldAtItsFloor() public {
        factory.createAccount(ownerAddr, payee);
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOp(id, 1001, BIG - 1_000_000);
        OpGas memory g = _gas(CLOSE, false);
        g.pvg = gp.pvgFloor;
        g.verification = gp.verificationFloor;
        g.call = gp.callFloor[0];
        g.pmVerification = gp.pmVerificationFloor;
        g.postOp = gp.postOpFloor;
        op.accountGasLimits = bytes32((g.verification << 128) | g.call);
        op.preVerificationGas = g.pvg;
        op.paymasterAndData = _paymasterAndData(g);
        op = _sign(op, OWNER_KEY);
        Vm.Log[] memory logs = _handle(op);
        _assertSettledCleanly(logs);
        // and with initCode at its own floor
        address other = address(0x0A11);
        uint32 id2 = _bigNote(43);
        (op,) = _closeOpFor(other, id2, 1002, BIG - 1_000_000);
        g.verification = gp.verificationFloorInit;
        op.accountGasLimits = bytes32((g.verification << 128) | g.call);
        op.preVerificationGas = g.pvg;
        op.paymasterAndData = _paymasterAndData(g);
        op = _sign(op, OWNER_KEY);
        logs = _handle(op);
        _assertSettledCleanly(logs);
    }

    function test_theOtherModesAreFailures() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOp(id, 1001, BIG - 1_000_000);
        factory.createAccount(ownerAddr, payee);
        op.initCode = "";
        op = _sign(op, OWNER_KEY);
        (, bytes memory context,) = _validateDirect(op);
        uint256 lostBefore = paymaster.lostWei();
        uint256 gasUsed = driver.postOpReverted(paymaster, context, 1e15, 11 gwei);
        assertLe(gasUsed, 70_000, "the failure path is within FAILURE_POSTOP_GAS");
        OpGas memory g = _gas(CLOSE, false);
        assertEq(paymaster.lostWei() - lostBefore, 1e15 + ((g.call + g.postOp) / 10 + 70_000) * 11 gwei, "bounded loss");
        assertTrue(paymaster.stranded(op.sender));
    }

    function test_strayTransfersRevert() public {
        (bool ok,) = address(paymaster).call{value: 1}("");
        assertFalse(ok, "no receive");
        (ok,) = address(paymaster).call{value: 1}(abi.encodeWithSelector(bytes4(0x12345678)));
        assertFalse(ok, "no fallback");
        uint256 before = entryPoint.balanceOf(address(paymaster));
        (ok,) = address(paymaster).call{value: 1 ether}(abi.encodeCall(ZkApiWithdrawalPaymaster.deposit, ()));
        assertTrue(ok);
        assertEq(entryPoint.balanceOf(address(paymaster)) - before, 1 ether);
        assertEq(address(paymaster).balance, 0);
    }

    function test_postOpOnlyFromTheEntryPoint() public {
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotEntryPoint.selector);
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, "", 0, 0);
    }
}
