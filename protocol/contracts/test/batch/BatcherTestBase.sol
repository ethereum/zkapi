// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {ZkApiExitBatcher} from "../../src/periphery/ZkApiExitBatcher.sol";
import {PoseidonRuntime} from "../helpers/PoseidonRuntime.sol";
import {BatchTestBase} from "./BatchTestBase.sol";

/// @dev The batch fixture's deployment: the vault CREATEd by 0xf00d at nonce 0 with the generated
///      adapter folded for it, the 16 notes deposited at the fixture's time (so that its root is the
///      proofs'), and a ZkApiExitBatcher with the mainnet-schedule caps.
abstract contract BatcherTestBase is BatchTestBase {
    uint128 internal constant DEPOSIT = 1_000_000;
    uint128 internal constant RAISE = 60_000;
    address internal constant TREASURY = address(0xbeef);
    address internal constant DEPOSITOR = address(0xd0d0);
    address internal constant RELAYER = address(0x7e1a);

    /// The caps under the mainnet schedule (Deploy.s.sol's defaults), kind order close, escape,
    /// defeat, raise, finalize.
    uint256 internal constant CLOSE_GAS = 250_000;
    uint256 internal constant ESCAPE_GAS = 250_000;
    uint256 internal constant DEFEAT_GAS = 150_000;
    uint256 internal constant RAISE_GAS = 150_000;
    uint256 internal constant FINALIZE_GAS = 300_000;

    ZkApiVault internal vault;
    ZkApiExitBatcher internal batcher;

    function _caps() internal pure returns (uint256[5] memory) {
        return [CLOSE_GAS, ESCAPE_GAS, DEFEAT_GAS, RAISE_GAS, FINALIZE_GAS];
    }

    function _deployVaultAndBatcher(bool fundDestinations) internal {
        _loadBatchFixtures();
        vm.warp(vm.parseJsonUint(exits, ".timestamp"));
        adapter = _deployAdapter();
        address poseidon = PoseidonRuntime.etch();
        vm.setNonce(DEPLOYER, 0);
        vm.prank(DEPLOYER);
        vault = new ZkApiVault(
            TREASURY,
            30 days,
            24 hours,
            100_000,
            address(adapter),
            w[0].stateSigningKeyX,
            w[0].stateSigningKeyY,
            w[0].clearanceSigningKeyX,
            w[0].clearanceSigningKeyY,
            address(this),
            7 days,
            poseidon
        );
        assertEq(address(vault), vaultAddress);
        vm.deal(DEPOSITOR, 100 ether);
        vm.startPrank(DEPOSITOR);
        for (uint256 i = 0; i < N; ++i) {
            bytes32 registration =
                bytes32(vm.parseJsonUint(exits, string.concat(".notes[", vm.toString(i), "].registration")));
            vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(registration, DEPOSIT);
        }
        vm.stopPrank();
        assertEq(vault.currentRoot(), vm.parseJsonUint(exits, ".root"), "the proofs' root");
        vm.deal(TREASURY, 1 wei);
        if (fundDestinations) {
            for (uint256 i = 0; i < N; ++i) {
                vm.deal(_destination(i), 1 wei);
            }
        }
        batcher = new ZkApiExitBatcher(vault, _caps());
    }

    function _destination(uint256 i) internal view returns (address) {
        return w[i].destination;
    }

    function _status(uint256 i) internal view returns (Types.NoteStatus status) {
        (,,, status) = vault.notes(uint32(i));
    }

    /// Closes (the first 16 withdrawals) or escapes (the next 16) of notes [from, from + n).
    function _closes(uint256 from, uint256 n)
        internal
        view
        returns (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs)
    {
        return _w(from, n);
    }

    function _escapes(uint256 from, uint256 n)
        internal
        view
        returns (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs)
    {
        return _w(N + from, n);
    }

    /// Defeats (successor requests, amount 0) or raises (state requests, amount RAISE) of notes
    /// [from, from + n).
    function _challenges(uint256 from, uint256 n, bool raise)
        internal
        view
        returns (
            uint32[] memory ids,
            uint128[] memory amounts,
            Types.RequestPublicInputs[] memory ins,
            bytes memory prs
        )
    {
        (ins, prs) = _q(raise ? from : N + from, n);
        ids = new uint32[](n);
        amounts = new uint128[](n);
        for (uint256 i = 0; i < n; ++i) {
            ids[i] = uint32(from + i);
            amounts[i] = raise ? RAISE : 0;
        }
    }

    function _initiateAll(uint256 n) internal {
        for (uint256 i = 0; i < n; ++i) {
            vault.initiateEscapeWithdrawal(w[N + i], wp[N + i]);
        }
    }

    function _coolAll() internal {
        vm.cool(address(vault));
        vm.cool(address(adapter));
        vm.cool(TREASURY);
        for (uint256 i = 0; i < N; ++i) {
            vm.cool(_destination(i));
        }
    }

    /// The transaction gas of `data` sent to `target` by RELAYER with every account cold: 21,000 +
    ///      calldata + execution, refunds capped at a fifth, at least EIP-7623's floor (the method of
    ///      test/GasBaseline.t.sol).
    function _txGas(address target, bytes memory data) internal returns (uint256 net) {
        uint256 zeros;
        for (uint256 i = 0; i < data.length; ++i) {
            if (data[i] == 0) ++zeros;
        }
        uint256 nonzeros = data.length - zeros;
        uint256 floorGas = 21_000 + 10 * (zeros + 4 * nonzeros);
        vm.cool(address(vault));
        vm.cool(address(adapter));
        vm.cool(address(batcher));
        vm.cool(TREASURY);
        vm.cool(RELAYER);
        for (uint256 i = 0; i < N; ++i) {
            vm.cool(_destination(i));
        }
        vm.prank(RELAYER, RELAYER);
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        Vm.Gas memory g = vm.lastCallGas();
        uint256 refund = g.gasRefunded > 0 ? uint256(int256(g.gasRefunded)) : 0;
        uint256 txGas = 21_000 + 4 * zeros + 16 * nonzeros + g.gasTotalUsed;
        uint256 cap = txGas / 5;
        net = txGas - (refund < cap ? refund : cap);
        if (net < floorGas) net = floorGas;
    }
}
