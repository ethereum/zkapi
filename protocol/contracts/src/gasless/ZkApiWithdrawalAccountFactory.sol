// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IEntryPoint} from "./IERC4337.sol";
import {ZkApiWithdrawalAccount} from "./ZkApiWithdrawalAccount.sol";

/// @title ZkApiWithdrawalAccountFactory – Deterministic deployment of transit accounts
/// @notice Deploys one account implementation and 93-byte proxies. The CREATE2 preimage remains
///         accountCreationCode() || abi.encode(entryPoint, vault, paymaster, owner, payee), so
///         clients use the same address derivation. The implementation pins the first three values;
///         the creation stub retains only the packed 20-byte owner/payee addresses in each proxy.
/// @dev The factory performs one CREATE2 and reads no storage during account deployment. The
///      runtime is 53 bytes of forwarding code followed by 40 bytes of owner/payee data, appended
///      to each delegatecall. The 24-byte creation stub copies forwarding code from offset 24,
///      owner from offset 185 and payee from offset 217 of the full init code, returning 93 bytes.
contract ZkApiWithdrawalAccountFactory {
    bytes private constant CREATION_STUB = hex"603560185f39601460b9603539601460d9604939605d5ff3";
    bytes private constant PROXY_HEAD = hex"365f5f376028603536395f5f602836015f73";
    bytes private constant PROXY_TAIL = hex"5af43d5f5f3e3d5f82603357fd5bf3";

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
        ZkApiWithdrawalAccount implementation_ = new ZkApiWithdrawalAccount(entryPoint_, vault_, msg.sender);
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

    /// @notice The 77-byte creation code every transit account's init code starts with; the init code
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
            CREATION_STUB, PROXY_HEAD, address(implementation), PROXY_TAIL,
            uint256(uint160(entryPoint)), uint256(uint160(vault)), uint256(uint160(paymaster)),
            uint256(uint160(owner)), uint256(uint160(payee))
        );
    }

    function _creationCode(address logic) private pure returns (bytes memory) {
        return abi.encodePacked(CREATION_STUB, PROXY_HEAD, logic, PROXY_TAIL);
    }
}
