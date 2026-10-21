// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IERC4337 – The ERC-4337 EntryPoint v0.7.0 ABI subset the gasless withdrawal contracts use
/// @notice An original declaration written from EIP-4337 and the v0.7.0 interface signatures, not a
///         copy of any eth-infinitism file (those are GPL-3.0). It is ABI-identical to the canonical
///         EntryPoint at 0x0000000071727De22E5E9d8BAf0edAc6f37da032: the same struct layout, function
///         selectors, event topics and error selectors, which the tests check against the etched
///         runtime. Nothing here is compiled into a deployed EntryPoint; the paymaster pins the
///         canonical one by codehash.

/// @dev The v0.7 packed user operation: accountGasLimits = verificationGasLimit << 128 | callGasLimit,
///      gasFees = maxPriorityFeePerGas << 128 | maxFeePerGas, paymasterAndData = paymaster (20 bytes)
///      ‖ paymasterVerificationGasLimit (16) ‖ paymasterPostOpGasLimit (16) ‖ paymasterData.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

interface IAccount {
    /// @notice Returns packed validation data: 0 for success, 1 for a failed signature, with optional
    ///         validUntil (bits 160..207) and validAfter (bits 208..255) windows.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}

interface IPaymaster {
    enum PostOpMode {
        opSucceeded,
        opReverted,
        postOpReverted
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData);

    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        external;
}

interface IEntryPoint {
    struct DepositInfo {
        uint256 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    event AccountDeployed(bytes32 indexed userOpHash, address indexed sender, address factory, address paymaster);

    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    event PostOpRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason);

    event UserOperationPrefundTooLow(bytes32 indexed userOpHash, address indexed sender, uint256 nonce);

    event Deposited(address indexed account, uint256 totalDeposit);

    error FailedOp(uint256 opIndex, string reason);

    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

    error PostOpReverted(bytes returnData);

    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;

    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);

    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);

    function depositTo(address account) external payable;

    function balanceOf(address account) external view returns (uint256);

    function addStake(uint32 unstakeDelaySec) external payable;

    function unlockStake() external;

    function withdrawStake(address payable withdrawAddress) external;

    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;

    function getDepositInfo(address account) external view returns (DepositInfo memory info);
}

/// @dev Field unpacking of a v0.7 packed operation; the offsets are those of UserOperationLib.
library UserOpGas {
    uint256 internal constant PAYMASTER_VALIDATION_GAS_OFFSET = 20;
    uint256 internal constant PAYMASTER_POSTOP_GAS_OFFSET = 36;
    uint256 internal constant PAYMASTER_DATA_OFFSET = 52;

    function verificationGasLimit(PackedUserOperation calldata op) internal pure returns (uint256) {
        return uint256(op.accountGasLimits) >> 128;
    }

    function callGasLimit(PackedUserOperation calldata op) internal pure returns (uint256) {
        return uint128(uint256(op.accountGasLimits));
    }

    function maxPriorityFeePerGas(PackedUserOperation calldata op) internal pure returns (uint256) {
        return uint256(op.gasFees) >> 128;
    }

    function maxFeePerGas(PackedUserOperation calldata op) internal pure returns (uint256) {
        return uint128(uint256(op.gasFees));
    }

    function paymasterVerificationGasLimit(PackedUserOperation calldata op) internal pure returns (uint256) {
        return uint128(bytes16(op.paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET:PAYMASTER_POSTOP_GAS_OFFSET]));
    }

    function paymasterPostOpGasLimit(PackedUserOperation calldata op) internal pure returns (uint256) {
        return uint128(bytes16(op.paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:PAYMASTER_DATA_OFFSET]));
    }
}
