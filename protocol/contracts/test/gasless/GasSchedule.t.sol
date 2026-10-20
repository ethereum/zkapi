// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {IEntryPoint, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {GaslessTestBase} from "./GaslessTestBase.sol";

/// @dev The paymaster with its fresh-slot probe exposed, and a switch that makes the probe read
///      what a fresh slot costs under EIP-8037 (Forge runs one schedule only, so the tests stand in
///      for the fork): off at construction, so it deploys as on the measured schedule.
contract ForkablePaymaster is ZkApiWithdrawalPaymaster {
    /// What a hand-assembled equivalent of the probe measured on Sepolia in October 2026.
    uint256 public constant EIP_8037_FRESH_SLOT_GAS = 110_027;
    bool public forked;

    constructor(
        IEntryPoint entryPoint_,
        ZkApiVault vault_,
        address owner_,
        Policy memory policy_,
        uint256 maxFeeCeiling_,
        uint256 priorityFeeCeiling_
    ) ZkApiWithdrawalPaymaster(entryPoint_, vault_, owner_, policy_, maxFeeCeiling_, priorityFeeCeiling_) {}

    function fork() external {
        forked = true;
    }

    function probe() external returns (uint256) {
        return _freshSlotGas();
    }

    function _freshSlotGas() internal override returns (uint256) {
        if (forked) return EIP_8037_FRESH_SLOT_GAS;
        return super._freshSlotGas();
    }
}

/// @dev A paymaster deployed on a chain that already prices state creation as EIP-8037 does.
contract RepricedChainPaymaster is ZkApiWithdrawalPaymaster {
    constructor(
        IEntryPoint entryPoint_,
        ZkApiVault vault_,
        address owner_,
        Policy memory policy_,
        uint256 maxFeeCeiling_,
        uint256 priorityFeeCeiling_
    ) ZkApiWithdrawalPaymaster(entryPoint_, vault_, owner_, policy_, maxFeeCeiling_, priorityFeeCeiling_) {}

    /// @dev Not a constant, so the compiler cannot see the constructor revert on every path (it
    ///      refuses to compile a contract whose immutables are never assigned).
    function _freshSlotGas() internal view override returns (uint256) {
        return block.chainid != 0 ? 110_027 : 0;
    }
}

/// @dev The gas-schedule guard: every constant of the paymaster was measured under EIP-2929 storage
///      pricing, so the constructor refuses a chain that prices a fresh slot above
///      FRESH_SLOT_GAS_BOUND, and checkGasSchedule lets anyone retire sponsorship once a fork
///      reprices it under a deployed paymaster. The probe's measurement under Forge's schedule is
///      pinned in snapshots/gasless-gas.json (freshSlotProbe).
contract GasScheduleTest is GaslessTestBase {
    ForkablePaymaster forkable;

    function setUp() public {
        _setUpGasless();
        forkable = new ForkablePaymaster(
            entryPoint, vault, address(this), _defaultPolicy(), MAX_FEE_CEILING, PRIORITY_CEILING
        );
    }

    /// One fresh SSTORE as the probe reads it: EIP-2929's cold zero-to-nonzero write (22,100) and
    /// the probe's own opcodes, under the bound.
    function test_probeMeasuresTheScheduleTheConstantsAssume() public {
        uint256 measured = forkable.probe();
        assertGe(measured, 22_100, "a cold zero-to-nonzero SSTORE");
        assertLt(measured, 22_100 + 100, "and the probe's few opcodes");
        assertLe(measured, paymaster.FRESH_SLOT_GAS_BOUND(), "under the bound");
        assertEq(paymaster.FRESH_SLOT_GAS_BOUND(), 25_000);
        vm.snapshotValue("gasless-gas", "freshSlotProbe", measured);
    }

    function test_constructorRefusesAChainThatRepricesStateCreation() public {
        vm.expectRevert(abi.encodeWithSelector(ZkApiWithdrawalPaymaster.UnsupportedGasSchedule.selector, 110_027));
        new RepricedChainPaymaster(
            entryPoint, vault, address(this), _defaultPolicy(), MAX_FEE_CEILING, PRIORITY_CEILING
        );
    }

    /// Under the measured schedule the check changes nothing, whoever calls it.
    function test_checkGasScheduleKeepsSponsorshipOnTheMeasuredSchedule() public {
        vm.recordLogs();
        vm.prank(address(0xCAFE));
        assertFalse(paymaster.checkGasSchedule());
        assertEq(vm.getRecordedLogs().length, 0, "no event");
        assertFalse(paymaster.scheduleRepriced());
        (,,,, bool paused) = paymaster.policy();
        assertFalse(paused);
        paymaster.setPolicy(_defaultPolicy());
    }

    /// After a fork that reprices state creation, anyone's check pauses sponsorship for good:
    /// validation refuses every operation first, and the owner can no longer resume it.
    function test_aRepricingForkRetiresSponsorshipForGood() public {
        forkable.fork();
        vm.expectEmit(address(forkable));
        emit ZkApiWithdrawalPaymaster.ScheduleRepriced(110_027);
        vm.prank(address(0xCAFE));
        assertTrue(forkable.checkGasSchedule());
        assertTrue(forkable.scheduleRepriced());
        (uint128 maxCost, uint64 flatFee,, bool escapes, bool paused) = forkable.policy();
        assertTrue(paused, "paused");
        ZkApiWithdrawalPaymaster.Policy memory pol = _defaultPolicy();
        assertEq(maxCost, pol.maxSponsoredCost, "the rest of the policy is kept");
        assertEq(flatFee, pol.flatFeeWei);
        assertEq(escapes, pol.escapesEnabled);
        vm.expectRevert(ZkApiWithdrawalPaymaster.SponsorshipRetired.selector);
        forkable.setPolicy(pol);
        pol.sponsorshipPaused = true;
        pol.flatFeeWei = 0;
        forkable.setPolicy(pol);
        vm.recordLogs();
        assertTrue(forkable.checkGasSchedule(), "still repriced");
        assertEq(vm.getRecordedLogs().length, 0, "reported once");
        (PackedUserOperation memory op,) = _closeOp(_bigNote(42), 1001, BIG - 1_000_000);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(ZkApiWithdrawalPaymaster.SponsorshipPaused.selector);
        forkable.validatePaymasterUserOp(op, bytes32(0), 1);
    }
}
