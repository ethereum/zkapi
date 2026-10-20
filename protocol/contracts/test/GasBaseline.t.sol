// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Bn254PoseidonReference} from "./reference/Bn254PoseidonReference.sol";
import {MerkleUpdateLib} from "../src/libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";
import {IBn254Poseidon} from "../src/interfaces/IBn254Poseidon.sol";
import {PoseidonRuntime, ReferenceHashes} from "./helpers/PoseidonRuntime.sol";
import {VaultStorage} from "./helpers/VaultStorage.sol";

/// @dev Gas baseline of the vault (revision 4, leaf-bound exits), its Poseidon runtime and its
///      Groth16 adapter. Logs only (no snapshot files). Run:
///      forge test --match-path test/GasBaseline.t.sol -vv
///
///      Methodology. Every measured call goes from the test contract to the vault with the vault,
///      the adapter, the Poseidon runtime, the treasury and USER marked cold (vm.cool), as at the
///      start of a real transaction; the pranked sender is warm, as tx.origin is. Each line logs:
///        frame   vm.lastCallGas().gasTotalUsed, the callee's execution gas before refunds: what a
///                real transaction spends after its intrinsic cost.
///        tx      21,000 + calldata (16 per nonzero byte, 4 per zero byte) + frame, before refunds,
///                or the EIP-7623 floor (21,000 + 10 per zero byte and 40 per nonzero byte) when
///                that is higher (only a retirement with full siblings at a low level reaches it).
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
///      to show the difference. The EVM rules are Foundry's (Prague): no Glamsterdam state gas, so
///      a fresh slot costs 22,100 here and about 110,000 under EIP-8037 (count them with the
///      fresh-slot lines).
abstract contract GasBaselineBase is Test {
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465; // "zkapi.v2.node"
    uint256 internal constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint128 internal constant DEPOSIT = 1_000_000;
    uint128 internal constant SB2 = 100_000;
    address internal constant DEPLOYER = address(0xf00d);
    address internal constant USER = 0x1111111111111111111111111111111111111111;
    address internal constant TREASURY = address(0xbeef);
    address internal constant OPERATOR = address(0x0D0D);

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
            7 days,
            PoseidonRuntime.etch(),
            1
        );
        assertEq(address(vault), parameters.contractAddress);
        vm.deal(USER, 100_000 ether);
        if (treasuryExists) vm.deal(TREASURY, 1 wei);
        poseidon = address(vault.poseidon());
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

    /// The EIP-7623 floor of a transaction carrying `data` to a contract.
    function _floorGas(bytes memory data) internal pure returns (uint256 tokens) {
        for (uint256 i = 0; i < data.length; ++i) {
            tokens += data[i] == 0 ? 1 : 4;
        }
        tokens = 21_000 + 10 * tokens;
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
        uint256 floor = _floorGas(data);
        if (floor > m.net) m.net = floor;
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

    /// Execution gas of a static call, as the vault calls its Poseidon runtime.
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

    function _storedLeaf(uint32 noteId) internal view returns (uint256 leaf) {
        (leaf,) = vault.noteRecord(noteId);
    }

    /// The fixture's expiry, which notes A and B carry.
    function _expiry() internal view returns (uint64) {
        // casting to 'uint64' is safe because the fixture's expiry is a bucketed uint64 time
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(vm.parseJsonUint(fixtures, ".expiry"));
    }

    function _claimData() internal view returns (bytes memory) {
        return abi.encodeCall(
            ZkApiVault.claimExpired, (0, vm.parseJsonBytes32(fixtures, ".note_a_registration"), DEPOSIT, _expiry())
        );
    }

    function _effectiveExpiryA() internal view returns (uint64) {
        return vault.effectiveExpiry(0, vm.parseJsonBytes32(fixtures, ".note_a_registration"), DEPOSIT, _expiry());
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
        v[3] = w.noteLeaf;
        v[4] = w.stateSigningKeyX;
        v[5] = w.stateSigningKeyY;
        v[6] = w.clearanceSigningKeyX;
        v[7] = w.clearanceSigningKeyY;
        v[8] = w.noteFields;
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

    /// Writes a synthetic request tree of `n` notes (frontier, last note word, nextNoteId) as the
    /// vault would hold it after n deposits: every frontier level written by an index below n
    /// holds a nonzero node, as on a live vault (stale entries included), so the SSTOREs of the
    /// next deposit are priced exactly. The leaves are synthetic nonzero words; the Poseidon cost
    /// does not depend on them.
    function _seedTree(uint32 n) internal {
        uint256[32] memory filled;
        uint256 previous;
        for (uint32 j = 0; j < n; ++j) {
            uint256 leaf = uint256(keccak256(abi.encode("leaf", j))) % SCALAR_MODULUS;
            if (j & 1 == 1) {
                uint256 node = Bn254PoseidonReference.compress(DOMAIN_NODE, previous, leaf);
                uint256 level = 1;
                while ((j >> level) & 1 == 1) {
                    node = Bn254PoseidonReference.compress(DOMAIN_NODE, filled[level], node);
                    ++level;
                }
                filled[level] = node;
            }
            previous = leaf;
        }
        for (uint256 level = 1; level < 32; ++level) {
            if (filled[level] != 0) VaultStorage.setFilled(address(vault), level, filled[level]);
        }
        if (n != 0) VaultStorage.setNote(address(vault), n - 1, previous, VaultStorage.ACTIVE);
        VaultStorage.setNextNoteId(address(vault), n);
    }

    /// A synthetic state of `n` notes of any size: nonzero frontier entries at every level some
    /// index below n wrote (2^l - 1 < n), the last note's word and nextNoteId. Its root is not a
    /// real tree's; the gas of what reads it (the computed root, recordRoot) does not depend on
    /// the values.
    function _seedSynthetic(uint32 n) internal {
        for (uint256 level = 1; level < 32; ++level) {
            if ((uint256(1) << level) - 1 >= n) break;
            VaultStorage.setFilled(
                address(vault), level, uint256(keccak256(abi.encode("synthetic", level))) % SCALAR_MODULUS
            );
        }
        if (n != 0) VaultStorage.setNote(address(vault), n - 1, 0x1234, VaultStorage.ACTIVE);
        VaultStorage.setNextNoteId(address(vault), n);
    }

    /// Slots of the vault that a call writes from zero to nonzero (fresh slots). The state is left
    /// as before the call.
    function _freshSlots(bytes memory data, uint256 value, address sender) internal returns (uint256 fresh) {
        uint256 before = vm.snapshotState();
        vm.record();
        vm.prank(sender);
        (bool ok,) = address(vault).call{value: value}(data);
        require(ok, "fresh-slot call");
        (, bytes32[] memory writes) = vm.accesses(address(vault));
        bytes32[] memory values = new bytes32[](writes.length);
        for (uint256 i = 0; i < writes.length; ++i) {
            values[i] = vm.load(address(vault), writes[i]);
        }
        vm.revertToState(before);
        for (uint256 i = 0; i < writes.length; ++i) {
            bool counted;
            for (uint256 j = 0; j < i; ++j) {
                if (writes[j] == writes[i]) counted = true;
            }
            if (!counted && values[i] != 0 && vm.load(address(vault), writes[i]) == 0) ++fresh;
        }
    }
}

// ============================================================================ deposits by index

/// A deposit at index N against a committed tree of N notes: N <= 64 real deposits in setUp, larger
/// N the synthetic tree _seedTree writes. Deposit gas depends on N through trailing_ones(N)
/// compressions and, at N = 2^t - 1, the first write of the frontier entry of level t.
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
            _seedTree(n);
        }
    }

    function test_depositAtIndex() public {
        uint32 n = _n();
        assertEq(vault.nextNoteId(), n);
        uint256 commitment = _commitment(n);
        string memory label = string.concat("deposit #", vm.toString(uint256(n)));
        uint256 fresh = _freshSlots(_depositData(commitment), uint256(DEPOSIT) * 1 gwei, USER);
        Measured memory m = _measure(USER, uint256(DEPOSIT) * 1 gwei, _depositData(commitment), label);
        assertEq(vault.nextNoteId(), n + 1);
        // casting to 'uint64' is safe because the bucketed expiry of a test time fits
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 expiry = uint64(((vm.getBlockTimestamp() + 30 days + 1 days - 1) / 1 days) * 1 days);
        assertEq(_storedLeaf(n), ReferenceHashes.leaf(n, bytes32(commitment), DEPOSIT, expiry), "stored leaf");
        // One fresh slot (the note's word), plus the frontier entry of level t at N = 2^t - 1.
        uint256 t = _trailingOnes(n);
        bool firstWrite = t >= 1 && uint256(n) == (uint256(1) << t) - 1;
        assertEq(fresh, firstWrite ? 2 : 1, "fresh slots");
        emit log_named_uint(string.concat(label, " | trailing ones (compressions beyond the pair)"), t);
        emit log_named_uint(string.concat(label, " | fresh slots"), fresh);
        emit log_named_uint(string.concat(label, " | frame per compression (t >= 1)"), t == 0 ? 0 : m.frame / (t + 1));
    }

    function _trailingOnes(uint32 x) internal pure returns (uint256 c) {
        while (x & 1 == 1) {
            ++c;
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

/// N = 1,535 (t = 1) and 1,791 (t = 8): levels already written, the common case at those depths.
contract GasBaselineDeposit1535 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 1535;
    }
}

contract GasBaselineDeposit1791 is DepositAtBase {
    function _n() internal pure override returns (uint32) {
        return 1791;
    }
}

/// The deepest append: N = 2^31 - 1 (t = 31, the first write of level 31). The NatSpec gas floors
/// (650,000 mainnet, 850,000 under EIP-8037 pricing) must cover it.
contract GasBaselineDepositDeepest is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        // Every level below 31 written, as after 2^31 - 1 deposits.
        for (uint256 level = 1; level < 31; ++level) {
            VaultStorage.setFilled(
                address(vault), level, uint256(keccak256(abi.encode("node", level))) % SCALAR_MODULUS
            );
        }
        uint32 n = uint32((uint256(1) << 31) - 1);
        VaultStorage.setNote(address(vault), n - 1, 0x1234, VaultStorage.ACTIVE);
        VaultStorage.setNextNoteId(address(vault), n);
    }

    function test_deepestDepositFitsTheStaticFloors() public {
        uint32 n = vault.nextNoteId();
        Measured memory m =
            _measure(USER, uint256(DEPOSIT) * 1 gwei, _depositData(_commitment(n)), "deposit #2^31-1 (t = 31)");
        // Two fresh slots (the note and filled[31]); at 110,000 each under EIP-8037.
        uint256 glamsterdam = m.txGas + 2 * (110_000 - 22_100);
        emit log_named_uint("deposit #2^31-1 | tx with 110,000-gas fresh slots", glamsterdam);
        assertLt(m.txGas, 650_000, "mainnet floor");
        assertLt(glamsterdam, 850_000, "EIP-8037 floor");
    }
}

// ================================================================ components, adapter, averages

contract GasBaselineComponents is GasBaselineBase {
    function setUp() public {
        _deploy(true);
    }

    /// One compress: the runtime frame alone (direct STATICCALL, cold and warm), and as the vault
    /// reaches it (MerkleUpdateLib.compress, measured as a gasleft() delta that includes access
    /// and the call). NoteLeafLib.computeLeaf is one compress.
    function test_poseidonComponents() public {
        (uint256 compressCold, bytes memory r1) = _staticFrame(
            poseidon,
            abi.encodeWithSelector(IBn254Poseidon.compress.selector, DOMAIN_NODE, uint256(1), uint256(2)),
            true
        );
        assertEq(abi.decode(r1, (uint256)), 0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1);
        (uint256 compressWarm,) = _staticFrame(
            poseidon,
            abi.encodeWithSelector(IBn254Poseidon.compress.selector, DOMAIN_NODE, uint256(1), uint256(2)),
            false
        );
        emit log_named_uint("compress | runtime frame", compressCold);
        emit log_named_uint("compress | runtime frame (warm runtime)", compressWarm);

        vm.cool(poseidon);
        uint256 before = gasleft();
        uint256 h = MerkleUpdateLib.compress(IBn254Poseidon(poseidon), DOMAIN_NODE, 1, 2);
        emit log_named_uint("compress | MerkleUpdateLib.compress, cold (gasleft delta)", before - gasleft());
        before = gasleft();
        h = MerkleUpdateLib.compress(IBn254Poseidon(poseidon), DOMAIN_NODE, h, 2);
        emit log_named_uint("compress | MerkleUpdateLib.compress, warm (gasleft delta)", before - gasleft());

        uint256 fields = NoteLeafLib.pack(7, DEPOSIT, 1_800_000_000);
        vm.cool(poseidon);
        before = gasleft();
        h = NoteLeafLib.computeLeaf(IBn254Poseidon(poseidon), bytes32(_commitment(7)), fields);
        emit log_named_uint("NoteLeafLib.computeLeaf | cold runtime (gasleft delta)", before - gasleft());
        assertEq(h, ReferenceHashes.leaf(7, bytes32(_commitment(7)), DEPOSIT, 1_800_000_000));

        address oracle = address(Bn254PoseidonReference);
        (uint256 refCompress,) = _staticFrame(
            oracle, abi.encodeWithSelector(IBn254Poseidon.compress.selector, DOMAIN_NODE, uint256(1), uint256(2)), false
        );
        emit log_named_uint("reference | compress frame (warm)", refCompress);
    }

    /// The Groth16 adapter alone, cold, with the real vault-challenge proofs, and its precompile
    /// share. The adapter only reads its inputs, so the vault state does not matter. Inputs 3
    /// (noteLeaf) and 8 (noteFields) always take a full scalar multiplication.
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
    /// gives repeated deposits (nextNoteId and frontier rewrites priced at 100).
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
        bytes memory data = abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (escape, proof));
        uint256 fresh = _freshSlots(data, 0, USER);
        assertEq(fresh, 4, "the escape record (2 slots) and both nullifier words");
        emit log_named_uint("initiateEscapeWithdrawal | fresh slots", fresh);
        Measured memory m = _measure(USER, 0, data, "initiateEscapeWithdrawal");
        _vaultOverhead("initiateEscapeWithdrawal", m.frame, escape, proof);
    }

    /// No pause ever: no pause epoch to read.
    function test_claimExpired() public {
        vm.warp(_effectiveExpiryA());
        _measure(OPERATOR, 0, _claimData(), "claimExpired (no pause epochs)");
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

/// claimExpired of note A after pause epochs: one epoch (A in the latest one: the one-read fast
/// path), and 32 epochs with A before the latest (the binary search).
contract GasBaselineClaimAfterEpochs is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
    }

    function _pauseRound() internal {
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        vault.unpause();
        vm.warp(vm.getBlockTimestamp() + 1 days);
    }

    function test_claimExpiredAfterOneEpoch() public {
        _pauseRound();
        assertEq(vault.pauseEpochCount(), 1);
        vm.warp(_effectiveExpiryA());
        _measure(OPERATOR, 0, _claimData(), "claimExpired (1 epoch, latest-epoch fast path)");
    }

    function test_claimExpiredAfterThirtyTwoEpochs() public {
        for (uint256 i = 0; i < 32; ++i) {
            _plainDeposit(_commitment(9_000 + i));
            _pauseRound();
        }
        assertEq(vault.pauseEpochCount(), 32);
        assertEq(vault.pausedBefore(0), 0);
        vm.warp(_effectiveExpiryA() + 1);
        _measure(OPERATOR, 0, _claimData(), "claimExpired (32 epochs, binary search)");
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

    /// The defeat far from the note's expiry: the fast path (no grace, no epoch read).
    function test_challengeEscapeWithdrawal() public {
        (Types.RequestPublicInputs memory r3, bytes memory proof) = _request("request_a3");
        Measured memory m = _measure(
            OPERATOR,
            0,
            abi.encodeCall(ZkApiVault.challengeEscapeWithdrawal, (0, r3, proof)),
            "challengeEscapeWithdrawal (fast path)"
        );
        assertEq(vault.graceUntil(0), 0);
        _requestOverhead("challengeEscapeWithdrawal (fast path)", m.frame, r3, proof);
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

/// The defeat's slow path: an escape initiated within a challenge period of the note's expiry,
/// after one pause epoch, defeated at its deadline: the exact pausedBefore lookup and a fresh
/// graceUntil slot.
contract GasBaselineDefeatNearExpiry is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        vault.unpause();
        vm.warp(uint256(_expiry()) - 1 hours);
        (Types.WithdrawalPublicInputs memory escape, bytes memory proof) = _withdrawal("escape_a2_late");
        vm.prank(USER);
        vault.initiateEscapeWithdrawal(escape, proof);
        vm.warp(_deadline(0) - 1);
    }

    function test_challengeNearExpiry() public {
        (Types.RequestPublicInputs memory r3, bytes memory proof) = _request("request_a3");
        _measure(
            OPERATOR,
            0,
            abi.encodeCall(ZkApiVault.challengeEscapeWithdrawal, (0, r3, proof)),
            "challengeEscapeWithdrawal (slow path: grace written)"
        );
        assertGt(vault.graceUntil(0), 0);
    }
}

/// retireClosedLeaf at a chosen level: the retired note's word, the frontier entry of its subtree
/// and nextNoteId written so that the leaf's level is `level` (note 0 against nextNoteId 2^level,
/// or the last leaf of an odd count for level 0), with real siblings below the level. Measured
/// with the unused siblings zero-filled (what the challenger sends) and full.
abstract contract RetireAtBase is GasBaselineBase {
    uint256 internal constant LEAF = 0x0a11ce;
    uint256[32] internal path;
    uint32 internal retired;

    function _level() internal pure virtual returns (uint256);

    function setUp() public {
        _deploy(true);
        uint256 level = _level();
        // casting to 'uint32' is safe because the levels measured are below 32
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 next = level == 0 ? 3 : uint32(uint256(1) << level);
        retired = level == 0 ? 2 : 0;
        uint256 node = LEAF;
        for (uint256 h = 0; h < level; ++h) {
            path[h] = uint256(keccak256(abi.encode("sibling", h))) % SCALAR_MODULUS;
            node = Bn254PoseidonReference.compress(DOMAIN_NODE, node, path[h]);
        }
        if (level > 0) VaultStorage.setFilled(address(vault), level, node);
        // The other levels hold live-looking nonzero entries too.
        for (uint256 l = 1; l < level; ++l) {
            VaultStorage.setFilled(address(vault), l, uint256(keccak256(abi.encode("stale", l))) % SCALAR_MODULUS);
        }
        VaultStorage.setNote(address(vault), retired, LEAF, VaultStorage.CLOSED);
        if (level == 0) VaultStorage.setNote(address(vault), 0, 0x1234, VaultStorage.ACTIVE);
        VaultStorage.setNextNoteId(address(vault), next);
    }

    function test_retireZeroFilled() public {
        string memory label = string.concat("retireClosedLeaf (level ", vm.toString(_level()), ", zero-filled)");
        _measure(OPERATOR, 0, abi.encodeCall(ZkApiVault.retireClosedLeaf, (retired, path)), label);
        assertEq(_storedLeaf(retired), 0);
    }

    function test_retireFullSiblings() public {
        uint256[32] memory full = path;
        for (uint256 h = _level(); h < 32; ++h) {
            full[h] = uint256(keccak256(abi.encode("unused", h))) % SCALAR_MODULUS;
        }
        string memory label = string.concat("retireClosedLeaf (level ", vm.toString(_level()), ", full siblings)");
        bytes memory data = abi.encodeCall(ZkApiVault.retireClosedLeaf, (retired, full));
        _measure(OPERATOR, 0, data, label);
        emit log_named_uint(string.concat(label, " | EIP-7623 floor"), _floorGas(data));
    }
}

contract GasBaselineRetire0 is RetireAtBase {
    function _level() internal pure override returns (uint256) {
        return 0;
    }
}

contract GasBaselineRetire4 is RetireAtBase {
    function _level() internal pure override returns (uint256) {
        return 4;
    }
}

contract GasBaselineRetire8 is RetireAtBase {
    function _level() internal pure override returns (uint256) {
        return 8;
    }
}

contract GasBaselineRetire16 is RetireAtBase {
    function _level() internal pure override returns (uint256) {
        return 16;
    }
}

/// The retirement the old baseline measured: note A closed next to B (level 1), real path.
contract GasBaselineRetire is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
        _plainDeposit(_commitment(77));
        (Types.WithdrawalPublicInputs memory close, bytes memory proof) = _withdrawal("close_a2");
        vault.mutualClose(close, proof);
    }

    function test_retireClosedLeaf() public {
        uint256[32] memory siblings;
        siblings[0] = _storedLeaf(1);
        // Level msb(0 ^ 3) = 1: only siblings[0] is read.
        _measure(
            OPERATOR, 0, abi.encodeCall(ZkApiVault.retireClosedLeaf, (0, siblings)), "retireClosedLeaf (A, level 1)"
        );
        uint256 node = Bn254PoseidonReference.compress(
            DOMAIN_NODE,
            Bn254PoseidonReference.compress(DOMAIN_NODE, 0, siblings[0]),
            Bn254PoseidonReference.compress(DOMAIN_NODE, _storedLeaf(2), 0)
        );
        for (uint256 level = 2; level < 32; ++level) {
            node = Bn254PoseidonReference.compress(DOMAIN_NODE, node, MerkleUpdateLib.zeroHash(level));
        }
        assertEq(vault.currentRoot(), node, "retired root");
    }
}

/// recordRoot and the computed views: at 2 notes (two compressions below the top) and at a full
/// 31-bit pattern (32 compressions), and a noteLeaves page of 2,048 leaves.
contract GasBaselineViews is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
    }

    function test_recordRootAtTwoNotes() public {
        _measure(OPERATOR, 0, abi.encodeCall(ZkApiVault.recordRoot, ()), "recordRoot (2 notes)");
        (uint32 count, uint64 blockNumber) = vault.recordedRoot(vault.currentRoot());
        assertEq(count, 2);
        assertEq(blockNumber, block.number);
    }

    function test_recordRootAtFullPattern() public {
        _seedSynthetic(uint32((uint256(1) << 31) - 1));
        _measure(OPERATOR, 0, abi.encodeCall(ZkApiVault.recordRoot, ()), "recordRoot (2^31 - 1 notes)");
    }

    function test_viewsAsEthCalls() public {
        _seedSynthetic(uint32((uint256(1) << 31) - 1));
        _coolAll();
        uint256 before = gasleft();
        vault.currentRoot();
        emit log_named_uint("currentRoot() eth_call (2^31 - 1 notes) | gasleft delta", before - gasleft());
        _seedSynthetic(2_048);
        _coolAll();
        before = gasleft();
        vault.noteLeaves(0, 2_048);
        emit log_named_uint("noteLeaves(0, 2048) eth_call | gasleft delta", before - gasleft());
    }
}

/// unpause: a new pause epoch (a fresh slot), and one that overwrites the previous epoch (no
/// deposit since).
contract GasBaselineUnpause is GasBaselineBase {
    function setUp() public {
        _deploy(true);
        _depositAB();
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
    }

    function test_unpauseNewEpoch() public {
        _measureOwner(abi.encodeCall(ZkApiVault.unpause, ()), "unpause (new epoch)");
        assertEq(vault.pauseEpochCount(), 1);
    }

    function test_unpauseOverwritingTheEpoch() public {
        vault.unpause();
        vm.warp(vm.getBlockTimestamp() + 1 days);
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        // Committed above in this test, so measured warm: a lower bound; logged for comparison.
        _measureOwner(abi.encodeCall(ZkApiVault.unpause, ()), "unpause (overwrite, same tx: lower bound)");
        assertEq(vault.pauseEpochCount(), 1);
    }

    function _measureOwner(bytes memory data, string memory label) internal {
        _coolAll();
        (bool ok,) = address(vault).call(data);
        require(ok, label);
        emit log_named_uint(string.concat(label, " | frame"), vm.lastCallGas().gasTotalUsed);
        emit log_named_uint(string.concat(label, " | tx"), 21_000 + _calldataGas(data) + vm.lastCallGas().gasTotalUsed);
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

        vm.warp(_effectiveExpiryA());
        _replica("claimExpired", _claimData(), pinned);
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
