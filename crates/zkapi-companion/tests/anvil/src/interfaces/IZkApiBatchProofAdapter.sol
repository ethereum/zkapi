// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../libraries/Types.sol";

interface IZkApiBatchProofAdapter {
    function verifyWithdrawalBatch(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs) external view;
    function verifyRequestBatch(Types.RequestPublicInputs[] calldata inputs, bytes calldata proofs) external view;
    function verifyWithdrawalBatchOnce(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs) external;
    function verifyRequestBatchOnce(Types.RequestPublicInputs[] calldata inputs, bytes calldata proofs) external;
}
