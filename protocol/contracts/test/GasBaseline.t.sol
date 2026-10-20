// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {MerkleUpdateLib} from "../src/libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

/// @dev Gas baseline of the vault, its Poseidon library and its Groth16 adapter. Logs only (no
///      snapshot files). Run: forge test --match-path test/GasBaseline.t.sol -vv
///
///      Methodology. Every measured call goes from the test contract to the vault with the vault,
///      the adapter, the Poseidon library, the treasury and USER marked cold (vm.cool), as at the
///      start of a real transaction; the pranked sender is warm, as tx.origin is. Each line logs:
///        frame   vm.lastCallGas().gasTotalUsed, the callee's execution gas before refunds: what a
///                real transaction spends after its intrinsic cost.
///        tx      21,000 + calldata (16 per nonzero byte, 4 per zero byte) + frame, before refunds;
///                the EIP-7623 floor (21,000 + 40 / 10 per byte) never binds here.
///        net     tx - min(refund, tx / 5) (EIP-3529).
///        delta   gasleft() before minus after the CALL in the test contract: the frame plus the
///                CALL's own costs (2,600 cold vault, 9,000 for a value transfer less the unused
///                2,300 stipend) and the test's ABI encoding. Informational.
///      Foundry runs a whole test function as one transaction, so an SSTORE to a slot written
///      earlier in the same test function is priced as a dirty write (100 instead of 2,900 / 20,000)
///      and a delete of it refunds as a restore. Every measured call therefore runs against state
///      committed in setUp (one contract per starting state), never after another write of the
///      same test. test_snapshotMethodologyReplica reproduces the pinned
///      snapshots/concession-exit-gas.json method (deposits inside the test, no treasury account)
///      to show the difference. The EVM rules are Foundry's (Prague): no Glamsterdam state gas.
abstract contract GasBaselineBase is Test {
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465; // "zkapi.v2.node"
    uint256 internal constant DOMAIN_LEAF = 0x7a6b6170692e76322e6c656166; // "zkapi.v2.leaf"
    uint256 internal constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint128 internal constant DEPOSIT = 1_000_000;
    uint128 internal constant SB2 = 100_000;
    address internal constant DEPLOYER = address(0xf00d);
    address internal constant USER = 0x1111111111111111111111111111111111111111;
    address internal constant TREASURY = address(0xbeef);
    address internal constant OPERATOR = address(0x0D0D);
    /// Storage layout (forge inspect ZkApiVault storageLayout).
    uint256 internal constant SLOT_CURRENT_ROOT = 3;
    uint256 internal constant SLOT_NEXT_NOTE_ID = 4;
    uint256 internal constant SLOT_FILLED = 13;

    Groth16ProofAdapter internal adapter;
    ZkApiVault internal vault;
    string internal fixtures;
    address internal poseidon;

    struct Measured {
        uint256 frame;
        uint256 calldataGas;
        uint256 txGas;
        uint256 refund;
        uint256 net;
        uint256 delta;
    }

    /// The vault of test/fixtures/vault-challenge.json (its proofs bind chain 31337 and the address
    /// DEPLOYER creates at nonce 0), with the real Groth16 adapter. treasuryExists funds the
    /// treasury so that payouts to it do not create an account (+25,000), as on a live deployment.
    function _deploy(bool treasuryExists) internal {
        vm.chainId(31_337);
        fixtures = vm.readFile("test/fixtures/vault-challenge.json");
        vm.warp(vm.parseJsonUint(fixtures, ".timestamp"));
        (Types.WithdrawalPublicInputs memory parameters,) = _withdrawal("escape_a2");
        // Folded for the vault DEPLOYER creates at nonce 0, the address the proofs bind.
        adapter = new Groth16ProofAdapter(
            vm.computeCreateAddress(DEPLOYER, 0),
            parameters.stateSigningKeyX,
            parameters.stateSigningKeyY,
            parameters.clearanceSigningKeyX,
            parameters.clearanceSigningKeyY
        );
        vm.setNonce(DEPLOYER, 0);
        vm.prank(DEPLOYER);
        vault = new ZkApiVault(
            TREASURY,
            30 days,
            24 hours,
            100_000,
            address(adapter),
            parameters.stateSigningKeyX,
            parameters.stateSigningKeyY,
            parameters.clearanceSigningKeyX,
            parameters.clearanceSigningKeyY,
            address(this),
            7 days
        );
        assertEq(address(vault), parameters.contractAddress);
        vm.deal(USER, 100_000 ether);
        if (treasuryExists) vm.deal(TREASURY, 1 wei);
        poseidon = address(Bn254Poseidon);
    }

    function _coolAll() internal {
        vm.cool(address(vault));
        vm.cool(address(adapter));
        vm.cool(poseidon);
        vm.cool(TREASURY);
        vm.cool(USER);
    }

    function _calldataGas(bytes memory data) internal pure returns (uint256 gas) {
        for (uint256 i = 0; i < data.length; ++i) {
            gas += data[i] == 0 ? 4 : 16;
        }
    }

    /// Calls the vault from `sender` with everything cold (sender warm) and logs the costs.
    function _measure(address sender, uint256 value, bytes memory data, string memory label)
        internal
        returns (Measured memory m)
    {
        m.calldataGas = _calldataGas(data);
        _coolAll();
        vm.prank(sender);
        uint256 before = gasleft();
        (bool ok, bytes memory ret) = address(vault).call{value: value}(data);
        m.delta = before - gasleft();
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        Vm.Gas memory g = vm.lastCallGas();
        m.frame = g.gasTotalUsed;
        m.refund = g.gasRefunded > 0 ? uint256(int256(g.gasRefunded)) : 0;
        m.txGas = 21_000 + m.calldataGas + m.frame;
        uint256 cap = m.txGas / 5;
        m.net = m.txGas - (m.refund < cap ? m.refund : cap);
        _log(label, m);
    }

    function _log(string memory label, Measured memory m) internal {
        emit log_named_uint(string.concat(label, " | frame"), m.frame);
        emit log_named_uint(string.concat(label, " | calldata"), m.calldataGas);
        emit log_named_uint(string.concat(label, " | tx (pre-refund)"), m.txGas);
        emit log_named_uint(string.concat(label, " | refund"), m.refund);
        emit log_named_uint(string.concat(label, " | tx (net)"), m.net);
        emit log_named_uint(string.concat(label, " | gasleft delta"), m.delta);
    }

    /// Execution gas of a direct (non-delegate) static call, e.g. into a pure library function.
    function _staticFrame(address target, bytes memory data, bool cold) internal returns (uint256, bytes memory) {
        if (cold) vm.cool(target);
        (bool ok, bytes memory ret) = target.staticcall(data);
        require(ok, "staticcall");
        return (vm.lastCallGas().gasTotalUsed, ret);
    }

    function _depositData(uint256 commitment) internal pure returns (bytes memory) {
        return abi.encodeCall(ZkApiVault.deposit, (bytes32(commitment), DEPOSIT));
    }

    /// A field element with no zero byte, as a random commitment almost always is.
    function _commitment(uint256 i) internal pure returns (uint256 c) {
        c = uint256(keccak256(abi.encode("gas-baseline", i))) % SCALAR_MODULUS;
        // Make every byte nonzero (keeps calldata gas comparable across commitments).
        for (uint256 b = 0; b < 31; ++b) {
            if ((c >> (8 * b)) & 0xff == 0) c |= uint256(1) << (8 * b);
        }
    }

    function _plainDeposit(uint256 commitment) internal {
        vm.prank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(commitment), DEPOSIT);
    }

    function _depositAB() internal {
        vm.startPrank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(vm.parseJsonBytes32(fixtures, ".note_a_registration"), DEPOSIT);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(vm.parseJsonBytes32(fixtures, ".note_b_registration"), DEPOSIT);
        vm.stopPrank();
        assertEq(vault.currentRoot(), vm.parseJsonUint(fixtures, ".root_ab"));
    }

    function _leafOf(uint32 noteId) internal view returns (uint256) {
        (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(noteId);
        return NoteLeafLib.computeLeaf(noteId, commitment, amount, expiry);
    }

    function _request(string memory name) internal view returns (Types.RequestPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.RequestPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    function _withdrawal(string memory name) internal view returns (Types.WithdrawalPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.WithdrawalPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    function _deadline(uint32 noteId) internal view returns (uint64 deadline) {
        (,,,,, deadline) = vault.pendingWithdrawals(noteId);
    }

    /// Scalar multiplications and additions the adapter performs for these input words.
    function _msmOps(uint256[] memory values) internal pure returns (uint256 muls, uint256 adds) {
        for (uint256 i = 0; i < values.length; ++i) {
            uint256 v = values[i];
            if (v == 0) continue;
            adds += 1; // accumulator + term
            if (v == 2) adds += 1; // point + point
            else if (v != 1) muls += 1;
        }
    }

    function _withdrawalWords(Types.WithdrawalPublicInputs memory w) internal pure returns (uint256[] memory v) {
        v = new uint256[](16);
        v[0] = w.protocolVersion;
        v[1] = w.chainId;
        v[2] = uint160(w.contractAddress);
        v[3] = w.activeRoot;
        v[4] = w.stateSigningKeyX;
        v[5] = w.stateSigningKeyY;
        v[6] = w.clearanceSigningKeyX;
        v[7] = w.clearanceSigningKeyY;
        v[8] = w.noteId;
        v[9] = w.finalBalance;
        v[10] = uint160(w.destination);
        v[11] = w.withdrawalNullifier;
        v[12] = w.kind;
        v[13] = w.nextNullifier;
        v[14] = w.conceded;
        v[15] = w.validUntil;
    }

    function _requestWords(Types.RequestPublicInputs memory r) internal pure returns (uint256[] memory v) {
        v = new uint256[](12);
        v[0] = r.protocolVersion;
        v[1] = r.chainId;
        v[2] = uint160(r.contractAddress);
        v[3] = r.activeRoot;
        v[4] = r.stateSigningKeyX;
        v[5] = r.stateSigningKeyY;
        v[6] = r.requestTime;
        v[7] = r.solvencyBound;
        v[8] = r.requestNullifier;
        v[9] = r.authorizationTag;
        v[10] = r.anonymousCommitmentX;
        v[11] = r.anonymousCommitmentY;
    }

    /// The words the adapter multiplies: on its folded path (every folded word, the first
    /// `foldedCount` of `foldedIndices`, equal to the constants it was deployed with) the folded
    /// words cost nothing, so they count as 0.
    function _multiplied(uint256[] memory words, uint256[7] memory foldedIndices, uint256 foldedCount)
        internal
        view
        returns (uint256[] memory out)
    {
        uint256[7] memory constants = [
            uint256(2),
            adapter.foldedChainId(),
            uint160(adapter.foldedVault()),
            adapter.foldedStateSigningKeyX(),
            adapter.foldedStateSigningKeyY(),
            adapter.foldedClearanceSigningKeyX(),
            adapter.foldedClearanceSigningKeyY()
        ];
        out = new uint256[](words.length);
        bool folded = true;
        for (uint256 i = 0; i < words.length; ++i) {
            out[i] = words[i];
        }
        for (uint256 k = 0; k < foldedCount; ++k) {
            if (words[foldedIndices[k]] != constants[k]) folded = false;
        }
        if (!folded) return out;
        for (uint256 k = 0; k < foldedCount; ++k) {
            out[foldedIndices[k]] = 0;
        }
    }

    /// Logs the adapter's frame, its precompile share and the rest (decoding, checks, memory).
    function _logAdapter(string memory label, uint256 frame, uint256[] memory words) internal {
        (uint256 muls, uint256 adds) = _msmOps(words);
        // ECMUL 6,000, ECADD 150, a 4-pair pairing 45,000 + 4 * 34,000; each precompile STATICCALL
        // costs 100 (precompiles are always warm).
        uint256 precompile = muls * 6_000 + adds * 150 + 181_000 + (muls + adds + 1) * 100;
        emit log_named_uint(string.concat(label, " | adapter frame"), frame);
        emit log_named_uint(string.concat(label, " | ECMULs"), muls);
        emit log_named_uint(string.concat(label, " | ECADDs"), adds);
        emit log_named_uint(string.concat(label, " | precompiles incl. call overhead"), precompile);
        emit log_named_uint(string.concat(label, " | adapter non-precompile"), frame - precompile);
    }
}

// ============================================================================ deposits by index

/// A deposit at index N, measured against a committed tree of N leaves. N <= 64: real deposits
/// in setUp. N > 64: nextNoteId and the frontier written with vm.store in setUp, for a tree of
/// synthetic nonzero leaves (Poseidon cost does not depend on the values; the SSTORE costs depend
/// only on which slots are zero, which the synthetic frontier reproduces exactly).
abstract contract DepositAtBase is GasBaselineBase {
    function _n() internal pure virtual returns (uint32);

    function setUp() public {
        _deploy(true);
        uint32 n = _n();
        if (n <= 64) {
            for (uint32 i = 0; i < n; ++i) {
                _plainDeposit(_commitment(1_000 + i));
            }
        } else {
            _seed(n);
        }
    }

    function _seed(uint32 n) internal {
        uint256[32] memory frontier;
        for (uint32 j = 0; j < n; ++j) {
            uint256 node = uint256(keccak256(abi.encode("leaf", j))) % SCALAR_MODULUS;
            for (uint256 level = 0; level < 32; ++level) {
                if ((j >> level) & 1 == 0) {
                    frontier[level] = node;
                    break;
                }
                node = Bn254Poseidon.compress(DOMAIN_NODE, frontier[level], node);
            }
        }
        for (uint256 level = 0; level < 32; ++level) {
            vm.store(address(vault), bytes32(SLOT_FILLED + level), bytes32(frontier[level]));
        }
        vm.store(address(vault), bytes32(SLOT_NEXT_NOTE_ID), bytes32(uint256(n)));
        // Any nonzero root: the deposit overwrites it (nonzero to nonzero, as live).
        vm.store(address(vault), bytes32(SLOT_CURRENT_ROOT), bytes32(uint256(0x1234)));
    }

    function test_depositAtIndex() public {
        uint32 n = _n();
        assertEq(vault.nextNoteId(), n);
        uint256[32] memory frontier;
        for (uint256 level = 0; level < 32; ++level) {
            frontier[level] = uint256(vm.load(address(vault), bytes32(SLOT_FILLED + level)));
        }
        uint256 commitment = _commitment(n);
        Measured memory m = _measure(
            USER,
            uint256(DEPOSIT) * 1 gwei,
            _depositData(commitment),
            string.concat("deposit #", vm.toString(uint256(n)))
        );
        // The deposit appended the expected leaf to the expected tree.
        uint256 node = _leafOf(n);
        for (uint256 level = 0; level < 32; ++level) {
            node = ((n >> level) & 1) == 1
                ? Bn254Poseidon.compress(DOMAIN_NODE, frontier[level], node)
                : Bn254Poseidon.compress(DOMAIN_NODE, node, MerkleUpdateLib.zeroHash(level));
        }
        assertEq(vault.currentRoot(), node, "root");
        assertEq(vault.nextNoteId(), n + 1);

        // Vault-own execution: frame minus the two library frames and their DELEGATECALL access
        // (2,600 cold, then 100 warm). The library frames are data independent.
        (uint256 hash5Frame,) = _staticFrame(
            poseidon,
            abi.encodeWithSelector(
                Bn254Poseidon.hash5.selector, DOMAIN_LEAF, uint256(n), commitment, uint256(DEPOSIT), uint256(1)
            ),
            false
        );
        uint256[32] memory siblings;
        (uint256 insertFrame,) = _staticFrame(
            poseidon, abi.encodeWithSelector(Bn254Poseidon.insertPath32.selector, DOMAIN_NODE, n, node, siblings), false
        );
        uint256 own = m.frame - hash5Frame - insertFrame - 2_700;
        emit log_named_uint(string.concat("deposit #", vm.toString(uint256(n)), " | vault-own (frame - hashing)"), own);
        emit log_named_uint(
            string.concat("deposit #", vm.toString(uint256(n)), " | popcount(N) frontier SLOADs"), _popcount(n)
        );
    }

    function _popcount(uint32 x) internal pure returns (uint256 c) {
        while (x != 0) {
            c += x & 1;
            x >>= 1;
        }
    }
}

contract GasBaselineDeposit0 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 0;
    }
}

contract GasBaselineDeposit1 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 1;
    }
}

contract GasBaselineDeposit2 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 2;
    }
}

contract GasBaselineDeposit3 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 3;
    }
}

contract GasBaselineDeposit7 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 7;
    }
}

contract GasBaselineDeposit8 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 8;
    }
}

contract GasBaselineDeposit255 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 255;
    }
}

contract GasBaselineDeposit1023 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 1023;
    }
}

// ================================================================ components, adapter, averages

contract GasBaselineComponents is GasBaselineBase {
    function setUp() public {
        _deploy(true);
    }

    /// One compress, hash5, insertPath32 and compressPairPath32: the library frame alone (direct
    /// STATICCALL, cold and warm), and as the vault reaches it (a Solidity library call, i.e. a
    /// DELEGATECALL, measured as a gasleft() delta that includes access, ABI encoding and decoding).
    function test_poseidonComponents() public {
        (uint256 compressCold, bytes memory r1) = _staticFrame(
            poseidon, abi.encodeWithSelector(Bn254Poseidon.compress.selector, DOMAIN_NODE, uint256(1), uint256(2)), true
        );
        assertEq(abi.decode(r1, (uint256)), 0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1);
        (uint256 compressWarm,) = _staticFrame(
            poseidon,
            abi.encodeWithSelector(Bn254Poseidon.compress.selector, DOMAIN_NODE, uint256(1), uint256(2)),
            false
        );
        emit log_named_uint("compress | library frame", compressCold);
        emit log_named_uint("compress | library frame (warm library)", compressWarm);

        vm.cool(poseidon);
        uint256 before = gasleft();
        uint256 h = Bn254Poseidon.compress(DOMAIN_NODE, 1, 2);
        emit log_named_uint("compress | library call from Solidity, cold (gasleft delta)", before - gasleft());
        before = gasleft();
        h = Bn254Poseidon.compress(DOMAIN_NODE, h, 2);
        emit log_named_uint("compress | library call from Solidity, warm (gasleft delta)", before - gasleft());

        (uint256 hash5Frame, bytes memory r2) = _staticFrame(
            poseidon,
            abi.encodeWithSelector(
                Bn254Poseidon.hash5.selector, uint256(1), uint256(2), uint256(3), uint256(4), uint256(5)
            ),
            true
        );
        assertEq(abi.decode(r2, (uint256)), 0x26081ccbe44f775603e118e5d9152fbbff51c9d7af1a96c9d25ddc7cbed55457);
        emit log_named_uint("hash5 | library frame (3 permutations)", hash5Frame);

        vm.cool(poseidon);
        before = gasleft();
        h = NoteLeafLib.computeLeaf(7, bytes32(_commitment(7)), DEPOSIT, 1_800_000_000);
        emit log_named_uint("NoteLeafLib.computeLeaf | cold library (gasleft delta)", before - gasleft());

        uint256[32] memory siblings;
        for (uint256 level = 0; level < 32; ++level) {
            siblings[level] = MerkleUpdateLib.zeroHash(level);
        }
        (uint256 insertFrame,) = _staticFrame(
            poseidon,
            abi.encodeWithSelector(Bn254Poseidon.insertPath32.selector, DOMAIN_NODE, uint32(5), h, siblings),
            true
        );
        emit log_named_uint("insertPath32 | library frame (32 compressions)", insertFrame);
        emit log_named_uint("insertPath32 | per compression", insertFrame / 32);

        (uint256 pairFrame,) = _staticFrame(
            poseidon,
            abi.encodeWithSelector(
                Bn254Poseidon.compressPairPath32.selector, DOMAIN_NODE, uint32(5), h, uint256(0), siblings, uint256(3)
            ),
            true
        );
        emit log_named_uint("compressPairPath32 | library frame (64 compressions)", pairFrame);

        // The permutation alone: the difference between hash5 (3 permutations) and compress (1),
        // both paying one entry (constants copy, ABI) each.
        emit log_named_uint("permutation | marginal ((hash5 - compress) / 2)", (hash5Frame - compressWarm) / 2);
        emit log_named_uint(
            "library entry overhead | compress - permutation", compressWarm - (hash5Frame - compressWarm) / 2
        );
    }

    /// The Groth16 adapter alone, cold, with the real vault-challenge proofs, and its precompile
    /// share. The adapter only reads its inputs, so the vault state does not matter.
    function test_adapterIsolated() public {
        string[3] memory withdrawals = ["close_a2", "escape_a2", "escape_a2_concede"];
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            (Types.WithdrawalPublicInputs memory w, bytes memory p) = _withdrawal(withdrawals[i]);
            vm.cool(address(adapter));
            uint256 before = gasleft();
            adapter.assertValidWithdrawal(w, p);
            uint256 delta = before - gasleft();
            uint256 frame = vm.lastCallGas().gasTotalUsed;
            _logAdapter(
                string.concat("assertValidWithdrawal(", withdrawals[i], ")"),
                frame,
                _multiplied(_withdrawalWords(w), [uint256(0), 1, 2, 4, 5, 6, 7], 7)
            );
            emit log_named_uint(string.concat("assertValidWithdrawal(", withdrawals[i], ") | gasleft delta"), delta);
        }
        string[3] memory requests = ["request_a1", "request_a2", "request_a3"];
        for (uint256 i = 0; i < requests.length; ++i) {
            (Types.RequestPublicInputs memory r, bytes memory p) = _request(requests[i]);
            vm.cool(address(adapter));
            uint256 before = gasleft();
            adapter.assertValidRequest(r, p);
            uint256 delta = before - gasleft();
            uint256 frame = vm.lastCallGas().gasTotalUsed;
            _logAdapter(
                string.concat("assertValidRequest(", requests[i], ")"),
                frame,
                _multiplied(_requestWords(r), [uint256(0), 1, 2, 4, 5, 0, 0], 5)
            );
            emit log_named_uint(string.concat("assertValidRequest(", requests[i], ") | gasleft delta"), delta);
        }
    }

    /// The average over the first 64 deposits, each as its own transaction: the test runs
    /// isolated (every top-level call a separate transaction, so slots start clean and cold). In
    /// isolation vm.lastCallGas() reports the whole transaction (21,000 + calldata + execution);
    /// the frame is that less the intrinsic part. The values equal the per-index contracts above
    /// (deposit #0, #1, #2, #3, #7, #8).
    /// forge-config: default.isolate = true
    function test_depositAverageFirst64Isolated() public {
        uint256 totalTx;
        uint256 totalFrame;
        for (uint256 i = 0; i < 64; ++i) {
            bytes memory data = _depositData(_commitment(5_000 + i));
            vm.prank(USER);
            (bool ok,) = address(vault).call{value: uint256(DEPOSIT) * 1 gwei}(data);
            require(ok, "deposit");
            uint256 txGas = vm.lastCallGas().gasTotalUsed;
            totalTx += txGas;
            totalFrame += txGas - 21_000 - _calldataGas(data);
            if (i < 9 || i == 15 || i == 16 || i == 31 || i == 63) {
                emit log_named_uint(string.concat("isolated deposit #", vm.toString(uint256(i)), " | tx"), txGas);
            }
        }
        emit log_named_uint("first 64 deposits (isolated) | average tx", totalTx / 64);
        emit log_named_uint("first 64 deposits (isolated) | average frame", totalFrame / 64);
    }

    /// The same loop without isolation, to show the dirty-slot discount a single test transaction
    /// gives repeated deposits (currentRoot, nextNoteId and frontier rewrites priced at 100).
    function test_depositAverageFirst64SameTx() public {
        uint256 total;
        for (uint256 i = 0; i < 64; ++i) {
            bytes memory data = _depositData(_commitment(5_000 + i));
            _coolAll();
            vm.prank(USER);
            (bool ok,) = address(vault).call{value: uint256(DEPOSIT) * 1 gwei}(data);
            require(ok, "deposit");
            total += vm.lastCallGas().gasTotalUsed;
        }
        emit log_named_uint("first 64 deposits (one test tx, dirty slots) | average frame", total / 64);
    }
}

/// Returns constants for the two library entry points deposit uses, at the library's selectors,
/// so a deposit through it costs the vault's own work only (plus two trivial frames). Payable:
/// the vault DELEGATECALLs it inside a payable deposit, and a library has no callvalue check.
contract PoseidonStub {
    function hash5(uint256, uint256, uint256, uint256, uint256) external payable returns (uint256) {
        return 0x1111;
    }

    function insertPath32(uint256, uint32, uint256, uint256[32] memory) external payable returns (uint256, uint256) {
        return (0x2222, 0x3333);
    }
}

/// Deposit #2 with the Poseidon library replaced by PoseidonStub (vm.etch): the vault's own
/// execution (storage, event, calldata and memory work) measured directly, not by subtraction.
contract GasBaselineDepositStubbedHashing is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _plainDeposit(_commitment(1_000));
        _plainDeposit(_commitment(1_001));
    }

    function test_depositWithoutHashing() public {
        assertEq(PoseidonStub.hash5.selector, Bn254Poseidon.hash5.selector);
        assertEq(PoseidonStub.insertPath32.selector, Bn254Poseidon.insertPath32.selector);
        vm.etch(poseidon, address(new PoseidonStub()).code);
        Measured memory m =
            _measure(USER, uint256(DEPOSIT) * 1 gwei, _depositData(_commitment(2)), "deposit #2, stubbed Poseidon");
        assertEq(vault.currentRoot(), 0x2222);
        uint256[32] memory siblings;
        (bool ok,) = poseidon.call(abi.encodeWithSelector(PoseidonStub.hash5.selector, 1, 2, 3, 4, uint256(5)));
        require(ok, "stub hash5");
        uint256 stubHash5 = vm.lastCallGas().gasTotalUsed;
        (ok,) = poseidon.call(abi.encodeWithSelector(PoseidonStub.insertPath32.selector, 1, uint32(2), 3, siblings));
        require(ok, "stub insertPath32");
        uint256 stubInsert = vm.lastCallGas().gasTotalUsed;
        emit log_named_uint("deposit #2, stubbed Poseidon | stub frames", stubHash5 + stubInsert);
        emit log_named_uint(
            "deposit #2, stubbed Poseidon | vault-own (frame - stub frames - 2,700 access)",
            m.frame - stubHash5 - stubInsert - 2_700
        );
    }
}

// ===================================================================== exits with real proofs

/// Notes A (id 0) and B (id 1) of the vault-challenge fixture, committed in setUp; treasury live.
contract GasBaselineExits is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
    }

    /// Submitted by a relayer: destination (USER) and treasury cold.
    function test_mutualCloseRelayed() public {
        (Types.WithdrawalPublicInputs memory close, bytes memory proof) = _withdrawal("close_a2");
        Measured memory m =
            _measure(OPERATOR, 0, abi.encodeCall(ZkApiVault.mutualClose, (close, proof)), "mutualClose (relayed)");
        _vaultOverhead("mutualClose (relayed)", m.frame, close, proof);
    }

    /// Submitted by the destination itself (as the Sepolia close was): destination warm.
    function test_mutualCloseSelf() public {
        (Types.WithdrawalPublicInputs memory close, bytes memory proof) = _withdrawal("close_a2");
        _measure(USER, 0, abi.encodeCall(ZkApiVault.mutualClose, (close, proof)), "mutualClose (self)");
    }

    function test_initiateEscape() public {
        (Types.WithdrawalPublicInputs memory escape, bytes memory proof) = _withdrawal("escape_a2");
        Measured memory m = _measure(
            USER, 0, abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (escape, proof)), "initiateEscapeWithdrawal"
        );
        _vaultOverhead("initiateEscapeWithdrawal", m.frame, escape, proof);
    }

    function test_claimExpired() public {
        vm.warp(vault.effectiveExpiry(0));
        _measure(OPERATOR, 0, abi.encodeCall(ZkApiVault.claimExpired, (0)), "claimExpired");
    }

    /// The vault's own share of an exit: its frame minus the adapter frame (measured on the same
    /// statement, cold) and the adapter access (EXTCODESIZE 2,600 cold, then the STATICCALL 100).
    function _vaultOverhead(string memory label, uint256 frame, Types.WithdrawalPublicInputs memory w, bytes memory p)
        internal
    {
        vm.cool(address(adapter));
        adapter.assertValidWithdrawal(w, p);
        uint256 adapterFrame = vm.lastCallGas().gasTotalUsed;
        emit log_named_uint(string.concat(label, " | adapter frame"), adapterFrame);
        emit log_named_uint(
            string.concat(label, " | vault-own (frame - adapter - 2,700 access)"), frame - adapterFrame - 2_700
        );
    }
}

/// An escape from a2 pending, committed in setUp.
contract GasBaselinePendingEscape is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
        (Types.WithdrawalPublicInputs memory escape, bytes memory proof) = _withdrawal("escape_a2");
        vm.prank(USER);
        vault.initiateEscapeWithdrawal(escape, proof);
    }

    function test_raiseEscapeConcession() public {
        (Types.RequestPublicInputs memory r2, bytes memory proof) = _request("request_a2");
        Measured memory m = _measure(
            OPERATOR, 0, abi.encodeCall(ZkApiVault.raiseEscapeConcession, (0, r2, proof, SB2)), "raiseEscapeConcession"
        );
        _requestOverhead("raiseEscapeConcession", m.frame, r2, proof);
    }

    function test_challengeEscapeWithdrawal() public {
        (Types.RequestPublicInputs memory r3, bytes memory proof) = _request("request_a3");
        Measured memory m = _measure(
            OPERATOR,
            0,
            abi.encodeCall(ZkApiVault.challengeEscapeWithdrawal, (0, r3, proof)),
            "challengeEscapeWithdrawal"
        );
        _requestOverhead("challengeEscapeWithdrawal", m.frame, r3, proof);
    }

    function test_finalizeEscapeWithdrawal() public {
        vm.warp(_deadline(0));
        _measure(OPERATOR, 0, abi.encodeCall(ZkApiVault.finalizeEscapeWithdrawal, (0)), "finalizeEscapeWithdrawal");
    }

    function _requestOverhead(string memory label, uint256 frame, Types.RequestPublicInputs memory r, bytes memory p)
        internal
    {
        vm.cool(address(adapter));
        adapter.assertValidRequest(r, p);
        uint256 adapterFrame = vm.lastCallGas().gasTotalUsed;
        emit log_named_uint(string.concat(label, " | adapter frame"), adapterFrame);
        emit log_named_uint(
            string.concat(label, " | vault-own (frame - adapter - 2,700 access)"), frame - adapterFrame - 2_700
        );
    }
}

/// Note A closed (mutual close), committed in setUp.
contract GasBaselineRetire is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
        (Types.WithdrawalPublicInputs memory close, bytes memory proof) = _withdrawal("close_a2");
        vault.mutualClose(close, proof);
    }

    function test_retireClosedLeaf() public {
        uint256[32] memory siblings;
        siblings[0] = _leafOf(1);
        for (uint256 level = 1; level < 32; ++level) {
            siblings[level] = MerkleUpdateLib.zeroHash(level);
        }
        _measure(OPERATOR, 0, abi.encodeCall(ZkApiVault.retireClosedLeaf, (0, siblings)), "retireClosedLeaf");
        uint256 node = Bn254Poseidon.compress(DOMAIN_NODE, 0, siblings[0]);
        for (uint256 level = 1; level < 32; ++level) {
            node = Bn254Poseidon.compress(DOMAIN_NODE, node, siblings[level]);
        }
        assertEq(vault.currentRoot(), node, "retired root");
    }
}

/// The pinned snapshot's method (test/ZkApiVaultGroth16.t.sol test_realExitGasSnapshot): deposits
/// inside the measured test transaction and a treasury with no account. Logged next to the
/// pinned values, for comparison with the committed-state measurements above.
contract GasBaselineSnapshotReplica is GasBaselineBase {
    function setUp() public {
        _deploy(false);
    }

    function test_snapshotMethodologyReplica() public {
        _depositAB();
        string memory pinned = vm.readFile("snapshots/concession-exit-gas.json");
        uint256 snapshot = vm.snapshotState();

        (Types.WithdrawalPublicInputs memory escape, bytes memory escapeProof) = _withdrawal("escape_a2");
        _replica(
            "initiateEscapeWithdrawal",
            abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (escape, escapeProof)),
            pinned
        );
        (Types.RequestPublicInputs memory r2, bytes memory r2Proof) = _request("request_a2");
        _replica(
            "raiseEscapeConcession", abi.encodeCall(ZkApiVault.raiseEscapeConcession, (0, r2, r2Proof, SB2)), pinned
        );
        (Types.RequestPublicInputs memory r3, bytes memory r3Proof) = _request("request_a3");
        _replica(
            "challengeEscapeWithdrawal", abi.encodeCall(ZkApiVault.challengeEscapeWithdrawal, (0, r3, r3Proof)), pinned
        );
        vm.revertToState(snapshot);

        vm.prank(USER);
        vault.initiateEscapeWithdrawal(escape, escapeProof);
        vm.warp(_deadline(0));
        _replica("finalizeEscapeWithdrawal", abi.encodeCall(ZkApiVault.finalizeEscapeWithdrawal, (0)), pinned);
        vm.revertToState(snapshot);

        (Types.WithdrawalPublicInputs memory close, bytes memory closeProof) = _withdrawal("close_a2");
        _replica("mutualClose", abi.encodeCall(ZkApiVault.mutualClose, (close, closeProof)), pinned);
        vm.revertToState(snapshot);

        vm.warp(vault.effectiveExpiry(0));
        _replica("claimExpired", abi.encodeCall(ZkApiVault.claimExpired, (0)), pinned);
    }

    function _replica(string memory label, bytes memory data, string memory pinned) internal {
        vm.cool(address(vault));
        vm.cool(address(adapter));
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(data);
        assertTrue(ok, label);
        uint256 txGas = 21_000 + _calldataGas(data) + vm.lastCallGas().gasTotalUsed;
        emit log_named_uint(string.concat("snapshot replica ", label, " | tx"), txGas);
        emit log_named_uint(
            string.concat("snapshot replica ", label, " | pinned"),
            vm.parseUint(vm.parseJsonString(pinned, string.concat(".", label)))
        );
    }
}
