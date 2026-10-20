// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Groth16ProofAdapter} from "../../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";

/// @dev The batch fixtures of zkapi-proof/examples/batch_fixture.rs: test/fixtures/batch-exits.json
///      (16 notes of the vault CREATEd by 0xf00d at nonce 0 on chain 31337, each with a close, an
///      escape, the request at the escaped state and the request at its successor, plus four
///      withdrawals and four requests of another vault, which take the generic path) and
///      test/fixtures/batch-verifier-vectors.json (batches with the reference verifier's
///      transcript, outcome and pairing input). Regenerate both with
///        cargo run --release -p zkapi-proof --example batch_fixture -- ../setup/v2-concession-dev \
///          ../contracts/test/fixtures/batch-exits.json ../contracts/test/fixtures/batch-verifier-vectors.json
abstract contract BatchTestBase is Test {
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant N = 16;
    uint256 internal constant FOREIGN = 4;
    address internal constant DEPLOYER = address(0xf00d);
    /// ZkApiExitBatcher's VERIFY_BASE_GAS and VERIFY_ITEM_GAS, which BatchGasTest checks against the
    /// worst case it measures and ExitBatcherTest against the contract's.
    uint256 internal constant BATCHER_VERIFY_BASE_GAS = 330_000;
    uint256 internal constant BATCHER_VERIFY_ITEM_GAS = 60_000;

    string internal exits;
    address internal vaultAddress;
    Groth16ProofAdapter internal adapter;

    /// Withdrawals: the 16 closes then the 16 escapes. Requests: the 16 state requests then the 16
    /// successor requests. Foreign: another vault's statements.
    Types.WithdrawalPublicInputs[] internal w;
    bytes[] internal wp;
    Types.RequestPublicInputs[] internal q;
    bytes[] internal qp;
    Types.WithdrawalPublicInputs[] internal fw;
    bytes[] internal fwp;
    Types.RequestPublicInputs[] internal fq;
    bytes[] internal fqp;

    function _loadBatchFixtures() internal {
        vm.chainId(31_337);
        exits = vm.readFile("test/fixtures/batch-exits.json");
        assertEq(vm.parseJsonString(exits, ".circuit_id"), "zkapi-v2-concession-v1");
        vaultAddress = vm.parseJsonAddress(exits, ".vault");
        assertEq(vm.computeCreateAddress(DEPLOYER, 0), vaultAddress, "the fixture vault is CREATE(0xf00d, 0)");
        string[2] memory wk = ["close", "escape"];
        string[2] memory qk = ["req_state", "req_succ"];
        for (uint256 k = 0; k < 2; ++k) {
            for (uint256 i = 0; i < N; ++i) {
                (Types.WithdrawalPublicInputs memory wi, bytes memory pi) = _withdrawal(wk[k], i);
                w.push(wi);
                wp.push(pi);
                (Types.RequestPublicInputs memory qi, bytes memory pq) = _request(qk[k], i);
                q.push(qi);
                qp.push(pq);
            }
        }
        for (uint256 i = 0; i < FOREIGN; ++i) {
            string memory at = string.concat(".foreign.withdrawals[", vm.toString(i), "]");
            fw.push(
                abi.decode(vm.parseJsonBytes(exits, string.concat(at, ".inputs_abi")), (Types.WithdrawalPublicInputs))
            );
            fwp.push(vm.parseJsonBytes(exits, string.concat(at, ".proof_hex")));
            at = string.concat(".foreign.requests[", vm.toString(i), "]");
            fq.push(abi.decode(vm.parseJsonBytes(exits, string.concat(at, ".inputs_abi")), (Types.RequestPublicInputs)));
            fqp.push(vm.parseJsonBytes(exits, string.concat(at, ".proof_hex")));
        }
    }

    function _withdrawal(string memory name, uint256 i)
        internal
        view
        returns (Types.WithdrawalPublicInputs memory inputs, bytes memory proof)
    {
        string memory at = string.concat(".notes[", vm.toString(i), "].", name);
        inputs = abi.decode(vm.parseJsonBytes(exits, string.concat(at, ".inputs_abi")), (Types.WithdrawalPublicInputs));
        proof = vm.parseJsonBytes(exits, string.concat(at, ".proof_hex"));
    }

    function _request(string memory name, uint256 i)
        internal
        view
        returns (Types.RequestPublicInputs memory inputs, bytes memory proof)
    {
        string memory at = string.concat(".notes[", vm.toString(i), "].", name);
        inputs = abi.decode(vm.parseJsonBytes(exits, string.concat(at, ".inputs_abi")), (Types.RequestPublicInputs));
        proof = vm.parseJsonBytes(exits, string.concat(at, ".proof_hex"));
    }

    /// The adapter folded for the fixture vault (its statements take the folded path).
    function _deployAdapter() internal returns (Groth16ProofAdapter a) {
        a = new Groth16ProofAdapter(
            vaultAddress,
            w[0].stateSigningKeyX,
            w[0].stateSigningKeyY,
            w[0].clearanceSigningKeyX,
            w[0].clearanceSigningKeyY
        );
    }

    /// Withdrawals [from, from + n) of w.
    function _w(uint256 from, uint256 n)
        internal
        view
        returns (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs)
    {
        ins = new Types.WithdrawalPublicInputs[](n);
        for (uint256 i = 0; i < n; ++i) {
            ins[i] = w[from + i];
            prs = bytes.concat(prs, wp[from + i]);
        }
    }

    /// Requests [from, from + n) of q.
    function _q(uint256 from, uint256 n)
        internal
        view
        returns (Types.RequestPublicInputs[] memory ins, bytes memory prs)
    {
        ins = new Types.RequestPublicInputs[](n);
        for (uint256 i = 0; i < n; ++i) {
            ins[i] = q[from + i];
            prs = bytes.concat(prs, qp[from + i]);
        }
    }

    function _concat(bytes[] memory ps) internal pure returns (bytes memory out) {
        for (uint256 i = 0; i < ps.length; ++i) {
            out = bytes.concat(out, ps[i]);
        }
    }

    function _copy(bytes memory b) internal pure returns (bytes memory) {
        return bytes.concat(b);
    }

    function _word(bytes memory p, uint256 k) internal pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := mload(add(add(p, 0x20), mul(k, 0x20)))
        }
    }

    function _setWord(bytes memory p, uint256 k, uint256 v) internal pure {
        assembly ("memory-safe") {
            mstore(add(add(p, 0x20), mul(k, 0x20)), v)
        }
    }

    function _isInvalidProof(bytes memory ret) internal pure returns (bool) {
        return ret.length == 4 && bytes4(ret) == Errors.InvalidProof.selector;
    }

    function _calldataGas(bytes memory data) internal pure returns (uint256 g) {
        for (uint256 i = 0; i < data.length; ++i) {
            g += data[i] == 0 ? 4 : 16;
        }
    }

    /// A call with the target cold; returns (ok, frame gas, revert data).
    function _call(address target, bytes memory data) internal returns (bool ok, uint256 frame, bytes memory ret) {
        vm.cool(target);
        (ok, ret) = target.call(data);
        frame = vm.lastCallGas().gasTotalUsed;
    }

    /// verifyWithdrawalBatch as raw calldata built from raw input words (which need not decode): the
    /// ABI head (two offsets), the array (length, n · 16 words) and the bytes (length, data, padding).
    function _rawBatchCall(bytes4 selector, uint256 stride, bytes memory inputs, bytes memory proofs)
        internal
        pure
        returns (bytes memory data)
    {
        uint256 n = inputs.length / stride;
        uint256 padded = (proofs.length + 31) / 32 * 32;
        data = bytes.concat(
            selector,
            abi.encode(uint256(0x40), uint256(0x60 + inputs.length), n),
            inputs,
            abi.encode(proofs.length),
            proofs,
            new bytes(padded - proofs.length)
        );
    }

    /// The setup's manifest.json: ZKAPI_SETUP_DIR, absolute or relative to protocol/rust, as
    ///      Groth16ProofAdapterTest reads it; empty, the development setup.
    function _setupManifest() internal view returns (string memory) {
        string memory dir = vm.envOr("ZKAPI_SETUP_DIR", string(""));
        if (bytes(dir).length == 0) dir = string.concat(vm.projectRoot(), "/../setup/v2-concession-dev");
        else if (bytes(dir)[0] != "/") dir = string.concat(vm.projectRoot(), "/../rust/", dir);
        return vm.readFile(string.concat(dir, "/manifest.json"));
    }

    function _ecAdd(uint256 ax, uint256 ay, uint256 bx, uint256 by) internal view returns (uint256 x, uint256 y) {
        uint256[4] memory input = [ax, ay, bx, by];
        uint256[2] memory out;
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 6, input, 0x80, out, 0x40)
        }
        require(ok, "ecAdd");
        (x, y) = (out[0], out[1]);
    }
}
