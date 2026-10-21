// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Events} from "../../src/libraries/Events.sol";
import {Types} from "../../src/libraries/Types.sol";
import {IEntryPoint, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {ToggleableDestination} from "../NativeEthVault.t.sol";
import {GaslessTestBase, GasBurner, Acceptor} from "./GaslessTestBase.sol";

/// @dev Sponsored closes end to end: the first use with initCode, repeats, the payee kinds, and the
///      charge property (never below the real cost, never more than the margin above it) fuzzed over
///      the signed gas fields, the fees, the payout and the payee.
contract CloseTest is GaslessTestBase {
    function setUp() public {
        _setUpGasless();
    }

    function test_firstUseCloseCreatesTheAccountAndPaysThePayee() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, 1001, BIG - 1_000_000);
        address s = op.sender;
        assertEq(s.code.length, 0, "fresh");
        assertEq(payee.balance, 0, "the payee holds no ETH");
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        uint256 beneficiaryBefore = beneficiary.balance;
        uint256 maxCost = _maxCost(_gas(CLOSE, true));

        Vm.Log[] memory logs = _handle(op);

        (bool success, uint256 actualGasCost, uint256 actualGasUsed) = _userOpEvent(logs);
        assertTrue(success, "success");
        assertTrue(_has(logs, ENTRY_POINT, IEntryPoint.AccountDeployed.selector), "AccountDeployed");
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.UserOperationRevertReason.selector));
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.PostOpRevertReason.selector));
        (bool found, Vm.Log memory closeLog) = _find(logs, address(vault), Events.MutualClose.selector);
        assertTrue(found, "MutualClose");
        (,, address destination) = abi.decode(closeLog.data, (uint256, uint128, address));
        assertEq(destination, s, "the vault paid S");
        (found, closeLog) = _find(logs, address(paymaster), ZkApiWithdrawalPaymaster.Sponsored.selector);
        assertTrue(found, "Sponsored");
        assertEq(closeLog.topics[1], _closeKey(1001));
        (uint8 kind, uint32 noteId, uint256 sponsoredMaxCost) = abi.decode(closeLog.data, (uint8, uint32, uint256));
        assertEq(kind, CLOSE);
        assertEq(noteId, id);
        assertEq(sponsoredMaxCost, maxCost);

        SettledEvent memory e = _settled(logs);
        assertTrue(e.found, "Settled");
        assertEq(e.key, _closeKey(1001));
        assertEq(e.sender, s);
        assertEq(e.payee, payee);
        assertEq(e.kind, CLOSE);
        assertEq(e.noteId, id);
        assertEq(e.received, uint256(inputs.finalBalance) * 1 gwei, "the whole payout went through S");
        assertGe(e.charged, actualGasCost + FLAT_FEE, "never below the real cost plus the flat fee");
        assertLe(
            e.charged,
            actualGasCost + FLAT_FEE + gp.marginGas * _gasPrice(_gas(CLOSE, true)),
            "at most the margin above"
        );
        assertLe(e.charged, maxCost + FLAT_FEE, "at most the prefund plus the flat fee");
        assertEq(e.owedPaid, 0);
        assertEq(e.paidOut, e.received - e.charged);

        assertEq(payee.balance, e.paidOut, "the payee received P - charged");
        assertEq(s.balance, 0, "nothing stays in S");
        assertEq(s.code.length, 221, "S exists");
        assertEq(paymaster.received(s), 0);
        assertEq(paymaster.receivedGas(s), 0);
        assertEq(address(paymaster).balance, 0, "the paymaster holds only credits");
        assertEq(
            entryPoint.balanceOf(address(paymaster)) - depositBefore,
            e.charged - actualGasCost,
            "the float grew by the overcharge and the fee"
        );
        assertGe(entryPoint.balanceOf(address(paymaster)) - depositBefore, FLAT_FEE);
        assertEq(beneficiary.balance - beneficiaryBefore, actualGasCost, "the bundler was paid the operation's cost");
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        assertEq(paymaster.attempts(_closeKey(1001)), 1);
        assertEq(entryPoint.getNonce(s, uint192(1001)), (uint256(uint192(1001)) << 64) | 1, "the nonce advanced");
        assertEq(actualGasUsed, actualGasCost / _gasPrice(_gas(CLOSE, true)));
    }

    function test_repeatCloseWithoutInitCode() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOp(id, 1001, BIG - 1_000_000);
        _handle(op);
        uint32 id2 = _bigNote(43);
        (op,) = _closeOp(id2, 1002, BIG - 500_000);
        assertEq(op.initCode.length, 0, "no initCode");
        uint256 payeeBefore = payee.balance;
        Vm.Log[] memory logs = _handle(op);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.AccountDeployed.selector));
        SettledEvent memory e = _settled(logs);
        assertEq(e.received, uint256(BIG - 500_000) * 1 gwei);
        assertEq(payee.balance - payeeBefore, e.paidOut);
        assertEq(paymaster.attempts(_closeKey(1002)), 1);
        assertEq(paymaster.attempts(_closeKey(1001)), 1);
    }

    function test_theOwnerMayBeThePayee() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOpFor(ownerAddr, id, 1001, BIG - 1_000_000);
        Vm.Log[] memory logs = _handle(op);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertEq(ownerAddr.balance, e.paidOut);
    }

    function test_rejectingPayeeIsCreditedAndAnyoneMayClaimForIt() public {
        ToggleableDestination wallet = new ToggleableDestination();
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOpFor(address(wallet), id, 1001, BIG - 1_000_000);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        Vm.Log[] memory logs = _handle(op);
        (bool success, uint256 actualGasCost,) = _userOpEvent(logs);
        assertTrue(success, "the push failure does not fail the operation");
        assertTrue(_has(logs, address(paymaster), ZkApiWithdrawalPaymaster.PayoutCredited.selector));
        SettledEvent memory e = _settled(logs);
        uint256 price = _gasPrice(_gas(CLOSE, true));
        assertGe(e.charged, actualGasCost + FLAT_FEE + gp.creditGas * price, "the credit bookkeeping is charged");
        assertEq(paymaster.credits(address(wallet)), e.paidOut, "credited");
        assertEq(paymaster.totalCredits(), e.paidOut);
        assertEq(address(paymaster).balance, e.paidOut, "the credit is held by the paymaster");
        assertEq(address(wallet).balance, 0);
        assertGe(entryPoint.balanceOf(address(paymaster)), depositBefore);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NativeTransferFailed.selector);
        paymaster.claimCredit(address(wallet));
        assertEq(paymaster.credits(address(wallet)), e.paidOut, "the credit is kept");
        wallet.setAccepting(true);
        vm.recordLogs();
        vm.prank(user);
        paymaster.claimCredit(address(wallet));
        assertTrue(_has(vm.getRecordedLogs(), address(paymaster), ZkApiWithdrawalPaymaster.CreditClaimed.selector));
        assertEq(address(wallet).balance, e.paidOut);
        assertEq(paymaster.credits(address(wallet)), 0);
        assertEq(paymaster.totalCredits(), 0);
        assertEq(address(paymaster).balance, 0);
    }

    function test_gasBurningPayeeIsCreditedAndChargedForTheBurn() public {
        GasBurner burner = new GasBurner();
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOpFor(address(burner), id, 1001, BIG - 1_000_000);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        Vm.Log[] memory logs = _handle(op);
        (bool success, uint256 actualGasCost,) = _userOpEvent(logs);
        assertTrue(success);
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.PostOpRevertReason.selector));
        SettledEvent memory e = _settled(logs);
        uint256 price = _gasPrice(_gas(CLOSE, true));
        assertGe(e.charged, actualGasCost + FLAT_FEE, "the burn never costs the float");
        assertGe(
            e.charged,
            (gp.payoutPushGas + gp.eoaPushGas + gp.creditGas) * price,
            "forwarded gas, push and credit charged"
        );
        assertEq(paymaster.credits(address(burner)), e.paidOut);
        assertGe(entryPoint.balanceOf(address(paymaster)), depositBefore + FLAT_FEE);
    }

    /// Over every signed gas field within the caps, every fee under the ceilings, every payout that
    /// covers the cost and every payee kind (a never-used address, a funded EOA, a used and drained
    /// EOA that EIP-161 no longer holds empty, a payee with code that accepts, one that burns the
    /// push): the float never pays, and an EOA payee is overcharged by at most MARGIN_GAS (a payee
    /// with code by at most the forwarded push gas and the credit bookkeeping on top, which the push
    /// cannot measure).
    function testFuzz_chargeStaysWithinTheMargin(
        uint256 callSeed,
        uint256 postOpSeed,
        uint256 verificationSeed,
        uint256 maxFeeSeed,
        uint256 prioritySeed,
        uint8 payeeKind,
        uint128 payoutSeed
    ) public {
        payeeKind = payeeKind % 5;
        address payee_;
        if (payeeKind == 0) payee_ = address(uint160(uint256(keccak256(abi.encode("empty", payoutSeed, callSeed)))));
        if (payeeKind == 1) {
            payee_ = address(uint160(uint256(keccak256(abi.encode("funded", payoutSeed, callSeed)))));
            vm.deal(payee_, 1 ether);
        }
        if (payeeKind == 2) payee_ = address(new Acceptor());
        if (payeeKind == 3) payee_ = address(new GasBurner());
        if (payeeKind == 4) {
            payee_ = address(uint160(uint256(keccak256(abi.encode("drained", payoutSeed, callSeed)))));
            vm.setNonce(payee_, uint64(1 + payoutSeed % 7));
        }
        bool eoaPayee = payeeKind <= 1 || payeeKind == 4;
        OpGas memory g = _gas(CLOSE, true);
        g.call = bound(callSeed, gp.callFloor[0], gp.callHardCap[0]);
        g.postOp = bound(postOpSeed, gp.postOpFloor, gp.postOpCap);
        g.verification = bound(verificationSeed, gp.verificationFloorInit, gp.verificationCap);
        // the note must be able to pay: the fee is bounded so that maxCost stays under the payout range
        uint256 maxGas = g.pvg + g.verification + g.call + g.pmVerification + g.postOp;
        uint256 feeRoof = (uint256(BIG) * 1 gwei - FLAT_FEE - 1 gwei) / maxGas;
        g.maxFee = bound(maxFeeSeed, 1 gwei, feeRoof < MAX_FEE_CEILING ? feeRoof : MAX_FEE_CEILING);
        g.priority = bound(prioritySeed, 0.1 gwei, g.maxFee < PRIORITY_CEILING ? g.maxFee : PRIORITY_CEILING);
        uint256 required = _maxCost(g) + FLAT_FEE;
        uint128 payout = uint128(bound(payoutSeed, required / 1 gwei + 1, BIG));
        uint32 id = _bigNote(42);
        address s = _transit(ownerAddr, payee_);
        Types.WithdrawalPublicInputs memory inputs = _closeTo(id, 1001, payout, s);
        PackedUserOperation memory op =
            _op(s, _nonce(s, 1001), _initCode(ownerAddr, payee_), _callData(_closeCall(inputs)), g);
        op = _sign(op, OWNER_KEY);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));

        Vm.Log[] memory logs = _handle(op);

        (bool success, uint256 actualGasCost, uint256 actualGasUsed) = _userOpEvent(logs);
        assertTrue(success, "success");
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.PostOpRevertReason.selector), "postOp never reverts");
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.UserOperationPrefundTooLow.selector), "prefund covers the cost");
        SettledEvent memory e = _settled(logs);
        uint256 price = _gasPrice(g);
        assertEq(actualGasCost, actualGasUsed * price, "price");
        assertEq(e.received, uint256(payout) * 1 gwei);
        assertGe(entryPoint.balanceOf(address(paymaster)), depositBefore + FLAT_FEE, "the float never pays");
        assertGe(e.charged, actualGasCost + FLAT_FEE, "charged at least the real cost");
        uint256 overcharge = (e.charged - actualGasCost - FLAT_FEE) / price;
        if (eoaPayee) {
            assertLe(overcharge, gp.marginGas, "EOA payee: within the margin");
        } else {
            assertLe(
                overcharge,
                gp.marginGas + gp.payoutPushGas + gp.creditGas,
                "payee with code: the forwarded push and credit on top"
            );
        }
        if (payeeKind == 3) {
            assertEq(paymaster.credits(payee_), e.paidOut, "a burning payee is credited");
        } else {
            assertEq(payee_.balance - (payeeKind == 1 ? 1 ether : 0), e.paidOut, "paid out");
        }
        assertEq(s.balance, 0);
    }

    function test_chargeForFormula() public view {
        uint256 fee = 3 gwei;
        uint256 base = gp.postOpBaseGas + gp.eoaPushGas;
        uint256 limit = 700_000 + 260_000;
        // a funded EOA: base push; the penalty is 10% of the unused limits; the margin on top
        uint256 used = 100_000 + gp.accountCallOverheadGas + base;
        uint256 expected = (200_000 + base + (limit - used) / 10 + gp.marginGas) * fee;
        assertEq(paymaster.chargeFor(CLOSE, 200_000, 100_000, 700_000, 260_000, false, false, fee), expected);
        // an empty payee adds the new-account surcharge; a payee with code the forwarded push gas
        uint256 withNew = base + gp.newAccountGas;
        used = 100_000 + gp.accountCallOverheadGas + withNew;
        assertEq(
            paymaster.chargeFor(CLOSE, 200_000, 100_000, 700_000, 260_000, false, true, fee),
            (200_000 + withNew + (limit - used) / 10 + gp.marginGas) * fee
        );
        uint256 withCode = base + gp.payoutPushGas;
        used = 100_000 + gp.accountCallOverheadGas + withCode;
        assertEq(
            paymaster.chargeFor(CLOSE, 200_000, 100_000, 700_000, 260_000, true, true, fee),
            (200_000 + withCode + (limit - used) / 10 + gp.marginGas) * fee
        );
        // a finalize adds its extra; an escape has its own postOp and overhead
        uint256 finalize = base + gp.postOpFinalizeExtraGas;
        used = 100_000 + gp.accountCallOverheadGas + finalize;
        assertEq(
            paymaster.chargeFor(FINALIZE, 200_000, 100_000, 700_000, 260_000, false, false, fee),
            (200_000 + finalize + (limit - used) / 10 + gp.marginGas) * fee
        );
        used = 100_000 + gp.accountCallOverheadEscapeGas + gp.postOpEscapeGas;
        assertEq(
            paymaster.chargeFor(ESCAPE, 200_000, 100_000, 700_000, 260_000, true, true, fee),
            (200_000 + gp.postOpEscapeGas + (limit - used) / 10 + gp.marginGas) * fee
        );
        // the reported execution gas is clamped to the call limit; no penalty below the limits
        assertEq(
            paymaster.chargeFor(CLOSE, 200_000, 5_000_000, 700_000, 260_000, false, false, fee),
            paymaster.chargeFor(CLOSE, 200_000, 700_000, 700_000, 260_000, false, false, fee)
        );
        assertEq(
            paymaster.chargeFor(CLOSE, 200_000, 700_000, 700_000, 0, false, false, fee),
            (200_000 + base + gp.marginGas) * fee
        );
        // estimation: a zero fee charges nothing
        assertEq(paymaster.chargeFor(CLOSE, 200_000, 100_000, 700_000, 260_000, false, false, 0), 0);
    }
}
