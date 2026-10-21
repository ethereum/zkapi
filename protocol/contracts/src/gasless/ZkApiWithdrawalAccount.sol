// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount, PackedUserOperation} from "./IERC4337.sol";

/// @dev The two execution-phase entry points of ZkApiWithdrawalPaymaster that a transit account
///      calls. Declared here, not imported, so the account depends on nothing but the ABI.
interface IZkApiWithdrawalPaymaster {
    function repay(uint256 executionGasUsed) external payable;
    function collect() external payable;
}

/// @title ZkApiWithdrawalAccount – The logic of every transit account S of a gasless withdrawal
/// @notice A transit account is a 221-byte proxy the factory deploys with CREATE2: 61 bytes that
///         delegate every call here with the account's five immutable arguments (entryPoint, vault,
///         paymaster, owner, payee; abi-encoded, 160 bytes) appended to the calldata, and those 160
///         bytes. Its address therefore commits to its payee: a withdrawal proof that names S as its
///         destination binds the final payout address, and nobody (the owner key, the paymaster
///         operator, a bundler) can redirect it. S holds no storage and no amounts; it only forwards
///         whatever it receives to the paymaster, which keeps the measured gas charge and pushes the
///         rest to `payee`. One copy of this logic serves every account, so creating one costs the
///         deposit of 221 bytes rather than of this contract.
/// @dev Validation reads only the calldata, the appended arguments and the ecrecover precompile: as
///      an unstaked sender under ERC-7562 it touches no storage, no balance and no other contract.
///      `withdraw` and `sweep` are execution-phase code. The paymaster trusts the gas S reports
///      because it verifies, in validation, that the sender is a factory-created proxy of this
///      logic (its arguments reproduce its CREATE2 address). Called on this contract itself rather
///      than through a proxy, every function reverts NotProxy, whatever the calldata carries: the
///      logic never relays a call or holds a balance of its own.
contract ZkApiWithdrawalAccount is IAccount {
    /// @notice The only sponsored entry point's selector; the paymaster accepts no other callData.
    bytes4 public constant SELECTOR_WITHDRAW = bytes4(keccak256("withdraw(bytes)"));
    /// @notice abi.encode(entryPoint, vault, paymaster, owner, payee): what the proxy appends.
    uint256 public constant ARGS_LENGTH = 160;
    /// @dev secp256k1n / 2: signatures with a higher s are rejected so that every operation has one
    ///      signature, as EIP-2 requires of transactions.
    uint256 private constant SECP256K1N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    /// @dev This contract's own address: a delegatecall from a proxy sees the proxy's address
    ///      instead, which is how a direct call is told apart from a proxied one.
    address private immutable self;

    constructor() {
        self = address(this);
    }

    struct Args {
        address entryPoint;
        address vault;
        address paymaster;
        address owner;
        address payee;
    }

    error NotEntryPoint();
    error NotProxy();
    /// @notice The vault call inside a sponsored operation reverted; carries the vault's revert bytes.
    error VaultCallFailed(bytes reason);
    error NothingToSweep();
    error UnknownCall();

    /// @dev The vault's full-gas push on a close and its 100,000-gas push on a finalization arrive
    ///      through the proxy as a call carrying only the arguments, so this must accept them and
    ///      cost nothing; any other unknown call is refused.
    fallback() external payable {
        if (address(this) == self) revert NotProxy();
        if (msg.data.length != ARGS_LENGTH) revert UnknownCall();
    }

    /// @dev Only a direct transfer to the logic contract itself has empty calldata; refuse it.
    receive() external payable {
        revert UnknownCall();
    }

    function entryPoint() external view returns (address) {
        return _args().entryPoint;
    }

    function vault() external view returns (address) {
        return _args().vault;
    }

    function paymaster() external view returns (address) {
        return _args().paymaster;
    }

    /// @notice The key that signs this account's operations (EIP-191 over the userOpHash).
    function owner() external view returns (address) {
        return _args().owner;
    }

    /// @notice The only address the paymaster ever pays S's funds to.
    function payee() external view returns (address) {
        return _args().payee;
    }

    /// @notice ERC-4337 validation: the owner's personal_sign over the 32 raw bytes of the userOpHash.
    ///         Returns SIG_VALIDATION_FAILED instead of reverting for every malformed or foreign
    ///         signature, as bundler estimation relies on. No validUntil/validAfter window is set
    ///         here; the paymaster carries the time bounds.
    /// @dev missingAccountFunds is always 0 when a paymaster sponsors the operation, and the
    ///      EntryPoint refuses an unsponsored one from an account without a deposit (AA21).
    function validateUserOp(PackedUserOperation calldata op, bytes32 userOpHash, uint256)
        external
        view
        returns (uint256)
    {
        Args memory a = _args();
        if (msg.sender != a.entryPoint) revert NotEntryPoint();
        if (op.signature.length != 65) return SIG_VALIDATION_FAILED;
        bytes32 r = bytes32(op.signature[0:32]);
        bytes32 s = bytes32(op.signature[32:64]);
        uint8 v = uint8(op.signature[64]);
        if (v < 27) v += 27;
        if (uint256(s) > SECP256K1N_HALF || (v != 27 && v != 28)) return SIG_VALIDATION_FAILED;
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        address signer = ecrecover(digest, v, r, s);
        return (signer != address(0) && signer == a.owner) ? 0 : SIG_VALIDATION_FAILED;
    }

    /// @notice The only sponsored entry point. `vaultCall` is empty (a forward of S's balance) or the
    ///         exact calldata of a vault exit whose destination is S. Whatever S holds afterwards goes
    ///         to the paymaster with the execution gas S measured; the paymaster keeps its measured
    ///         charge and pushes the rest to `payee`.
    /// @dev A failed vault call reverts with the vault's error bytes, so the EntryPoint reports them
    ///      in UserOperationRevertReason and the paymaster's postOp sees mode opReverted with the
    ///      vault state rolled back. `repay` is called even with a zero balance (an escape initiation
    ///      pays nothing yet) so the paymaster always has the gas measurement.
    function withdraw(bytes calldata vaultCall) external {
        uint256 g0 = gasleft();
        Args memory a = _args();
        if (msg.sender != a.entryPoint) revert NotEntryPoint();
        if (vaultCall.length != 0) {
            (bool ok, bytes memory ret) = a.vault.call(vaultCall);
            if (!ok) revert VaultCallFailed(ret);
        }
        uint256 used = g0 - gasleft();
        IZkApiWithdrawalPaymaster(a.paymaster).repay{value: address(this).balance}(used);
    }

    /// @notice Permissionless: forwards S's whole balance to the paymaster outside an operation. The
    ///         paymaster collects what S owes first and pushes the rest to `payee`, so a payout that
    ///         reached S by a direct vault call (a replayed close, a third-party finalization) is never
    ///         stuck and never dodges S's debt.
    function sweep() external {
        Args memory a = _args();
        uint256 bal = address(this).balance;
        if (bal == 0) revert NothingToSweep();
        IZkApiWithdrawalPaymaster(a.paymaster).collect{value: bal}();
    }

    /// @dev The five arguments the proxy appends to every call, in abi.encode layout. A call that
    ///      reaches this contract directly is refused before its calldata is looked at, so a tail
    ///      crafted to look like arguments cannot make the logic relay a call or send its balance.
    function _args() private view returns (Args memory a) {
        if (address(this) == self || msg.data.length < ARGS_LENGTH) revert NotProxy();
        assembly ("memory-safe") {
            let base := sub(calldatasize(), ARGS_LENGTH)
            let mask := 0xffffffffffffffffffffffffffffffffffffffff
            mstore(a, and(calldataload(base), mask))
            mstore(add(a, 0x20), and(calldataload(add(base, 0x20)), mask))
            mstore(add(a, 0x40), and(calldataload(add(base, 0x40)), mask))
            mstore(add(a, 0x60), and(calldataload(add(base, 0x60)), mask))
            mstore(add(a, 0x80), and(calldataload(add(base, 0x80)), mask))
        }
    }
}
