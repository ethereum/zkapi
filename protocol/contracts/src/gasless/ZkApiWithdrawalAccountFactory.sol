// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IEntryPoint} from "./IERC4337.sol";
import {ZkApiWithdrawalAccount} from "./ZkApiWithdrawalAccount.sol";

/// @title ZkApiWithdrawalAccountFactory – Deterministic deployment of transit accounts
/// @notice Deployed by the paymaster's constructor; deploys the account logic once and every transit
///         account as a 221-byte proxy of it. `S = CREATE2(factory, salt 0, accountCreationCode() ‖
///         abi.encode(entryPoint, vault, paymaster, owner, payee))`, so a client computes S locally
///         from the pinned 74-byte creation code and cross-checks it with `getAddress`. Creating
///         someone else's S early is harmless: the account's behaviour depends only on its arguments.
/// @dev The deployment frame reads no storage and performs exactly one CREATE2 (ERC-7562 OP-031);
///      inspecting the sender's code is allowed there (OP-042). The factory is staked only to lift
///      the public mempool's per-factory limits; its stake's terms are set by the paymaster's owner.
///
///      The proxy's runtime (61 bytes, then the 160 argument bytes) copies the calldata, appends the
///      arguments from its own code, delegatecalls the logic and returns or reverts with its output:
///        36 6000 6000 37            calldatacopy(0, 0, calldatasize)
///        60a0 603d 36 39            codecopy(calldatasize, 61, 160)
///        6000 6000 60a0 36 01 6000  (retSize 0, retOffset 0, argsSize calldatasize + 160, argsOffset 0)
///        73 <logic> 5a f4           delegatecall(gas, logic, ...)
///        3d 6000 6000 3e            returndatacopy(0, 0, returndatasize)
///        3d 6000 82 603b 57         jump to 59 when it succeeded
///        fd                         revert(0, returndatasize)
///        5b f3                      return(0, returndatasize)
///      The creation code is a 13-byte stub that returns everything after itself:
///        600d 80 38 03 80 91 6000 39 6000 f3   codecopy(0, 13, codesize − 13); return(0, codesize − 13)
contract ZkApiWithdrawalAccountFactory {
    bytes private constant CREATION_STUB = hex"600d80380380916000396000f3";
    bytes private constant PROXY_HEAD = hex"36600060003760a0603d36396000600060a03601600073";
    bytes private constant PROXY_TAIL = hex"5af43d600060003e3d600082603b57fd5bf3";

    address public immutable entryPoint;
    address public immutable vault;
    address public immutable paymaster;
    /// @notice The one logic contract every transit account delegates to.
    ZkApiWithdrawalAccount public immutable implementation;
    /// @notice keccak256 of accountCreationCode(): a client cross-check of the creation code it carries.
    bytes32 public immutable accountCreationCodeHash;

    event AccountCreated(address indexed account, address indexed owner, address indexed payee);

    error NotPaymasterOwner();
    /// @notice Only the paymaster's owner may set the stake's terms: a first stake, a longer unstake
    ///         delay or a re-lock after unlockStake.
    error StakeTermsLocked();
    error InvalidPayee();
    error CreateFailed();

    /// @dev Only the paymaster's current owner may move the factory's stake.
    modifier onlyPaymasterOwner() {
        if (msg.sender != Ownable(paymaster).owner()) revert NotPaymasterOwner();
        _;
    }

    constructor(address entryPoint_, address vault_) {
        entryPoint = entryPoint_;
        vault = vault_;
        paymaster = msg.sender;
        ZkApiWithdrawalAccount implementation_ = new ZkApiWithdrawalAccount();
        implementation = implementation_;
        accountCreationCodeHash = keccak256(_creationCode(address(implementation_)));
    }

    /// @notice Creates the transit account of (owner, payee) or returns it if it exists. Permissionless.
    /// @dev `payee` may not be an address that cannot or must not hold a payout: zero, the vault, the
    ///      paymaster, the EntryPoint or this factory. The owner may not be zero because ecrecover
    ///      returns zero for an invalid signature.
    function createAccount(address owner, address payee) external returns (address account) {
        if (
            payee == address(0) || payee == vault || payee == paymaster || payee == entryPoint || payee == address(this)
                || owner == address(0)
        ) revert InvalidPayee();
        account = getAddress(owner, payee);
        if (account.code.length != 0) return account;
        bytes memory initCode = _initCode(owner, payee);
        address created;
        assembly ("memory-safe") {
            created := create2(0, add(initCode, 0x20), mload(initCode), 0)
        }
        if (created != account) revert CreateFailed();
        emit AccountCreated(account, owner, payee);
    }

    /// @notice The CREATE2 address of the transit account of (owner, payee), deployed or not.
    function getAddress(address owner, address payee) public view returns (address) {
        bytes32 initCodeHash = keccak256(_initCode(owner, payee));
        return
            address(
                uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), bytes32(0), initCodeHash))))
            );
    }

    /// @notice The 74-byte creation code every transit account's init code starts with; the init code
    ///         is this followed by abi.encode(entryPoint, vault, paymaster, owner, payee).
    function accountCreationCode() external view returns (bytes memory) {
        return _creationCode(address(implementation));
    }

    /// @notice Stakes the factory with the EntryPoint, under the paymaster's rule: the paymaster's
    ///         owner sets the terms, anyone else may only add to a locked stake at its current delay
    ///         (the EntryPoint would otherwise let a stranger raise the delay or cancel an unlock).
    function addStake(uint32 unstakeDelaySec) external payable {
        if (msg.sender != Ownable(paymaster).owner()) {
            IEntryPoint.DepositInfo memory info = IEntryPoint(entryPoint).getDepositInfo(address(this));
            if (!info.staked || info.unstakeDelaySec != unstakeDelaySec) revert StakeTermsLocked();
        }
        IEntryPoint(entryPoint).addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyPaymasterOwner {
        IEntryPoint(entryPoint).unlockStake();
    }

    function withdrawStake(address payable to) external onlyPaymasterOwner {
        IEntryPoint(entryPoint).withdrawStake(to);
    }

    function _initCode(address owner, address payee) private view returns (bytes memory) {
        return abi.encodePacked(
            _creationCode(address(implementation)), abi.encode(entryPoint, vault, paymaster, owner, payee)
        );
    }

    function _creationCode(address logic) private pure returns (bytes memory) {
        return abi.encodePacked(CREATION_STUB, PROXY_HEAD, logic, PROXY_TAIL);
    }
}
