// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../libraries/Types.sol";

interface IZkApiProofAdapter {
    function CIRCUIT_ID_HASH() external view returns (bytes32);
    function REQUEST_VK_HASH() external view returns (bytes32);
    function WITHDRAWAL_VK_HASH() external view returns (bytes32);
    function INSERTION1_VK_HASH() external view returns (bytes32);
    function INSERTION4_VK_HASH() external view returns (bytes32);
    function INSERTION16_VK_HASH() external view returns (bytes32);
    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external view;
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof) external view;
    function assertValidInsertion(uint256 count, uint256[] calldata inputs, bytes calldata proof) external view;
}
