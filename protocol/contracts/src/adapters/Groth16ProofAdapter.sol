// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiBatchProofAdapter} from "../interfaces/IZkApiBatchProofAdapter.sol";
import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";

/// @title Groth16ProofAdapter
/// @notice zkAPI verifier for circuit zkapi-v2-concession-v1, setup dev, generated from its
///         verifying keys. Verification is standard Groth16 over the 12 request and 16 withdrawal
///         public inputs, in the order of Types.RequestPublicInputs and Types.WithdrawalPublicInputs;
///         inputs of 0, 1 and 2 skip the scalar multiplication.
///         A deployment serves one vault: the constructor folds the inputs every proof of that
///         vault shares (protocol version 2, the chain ID, the vault's address and its signing
///         keys) into the first IC point, and a statement whose words equal them all skips their
///         scalar multiplications. Any other statement is verified over every input, so the
///         adapter accepts exactly the proofs of these keys, whatever it was folded for; a wrong
///         fold only costs gas.
///         verifyWithdrawalOnce, the gasless paymaster's verification in validation, records the
///         statement and proof it verified for the rest of the transaction (EIP-1153), and
///         assertValidWithdrawal of the same bytes, the vault's in the execution phase, then
///         returns without verifying them again.
///         The batch entry points (IZkApiBatchProofAdapter) verify n statements of one kind at
///         once, all or nothing, with one random linear combination of their equations: n + 3
///         pairings and one shared multi-scalar multiplication instead of 4n pairings and n. The
///         Once variants then write, for every item, the record a single verification would have
///         left (withdrawals: the record of verifyWithdrawalOnce; requests: a record under
///         REQUEST_RECORD that assertValidRequest consults), for ZkApiExitBatcher's vault calls.
/// @dev Every word is read from calldata as Solidity's ABI decoder reads it: the narrow fields
///      must be clean (an empty revert otherwise), the proof is 256 bytes and every input and
///      proof word must be canonical; any other failure reverts InvalidProof().
contract Groth16ProofAdapter is IZkApiProofAdapter, IZkApiBatchProofAdapter {
    /// @notice keccak256("zkapi-v2-concession-v1"): the statement this adapter verifies.
    bytes32 public constant CIRCUIT_ID_HASH = 0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687;
    /// @notice keccak256 of the request verifying key (arkworks compressed bytes of request.vk
    ///         without its header). Identifies the setup.
    bytes32 public constant REQUEST_VK_HASH = 0x346b3c1414685205ebe8f7d6a1533cc2936be5f7922e90b24bf46d556d8a3790;
    /// @notice keccak256 of the withdrawal verifying key (withdrawal.vk without its header).
    bytes32 public constant WITHDRAWAL_VK_HASH = 0xfe768c9fed820772e0ccc6015a82b6d5387183d1241e8b1d6361d865f30f2ae1;

    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant BASE_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    /// @dev The protocol version every statement carries.
    uint256 private constant PROTOCOL_VERSION = 2;
    /// @dev keccak256("zkapi.groth16.batch.v1"): the first word of a batch's Fiat-Shamir transcript.
    uint256 private constant BATCH_DOMAIN = 0xca80fe9779d18ee0b63d605d88a5b66c8270acd425592d10473e2ebee417e6c8;
    /// @dev keccak256("zkapi.groth16.request-record.v1"), at or above 2^160: the first word of a request
    ///      record's slot preimage, where a withdrawal record has its destination (below 2^160), so
    ///      that no record of one kind can be read as one of the other.
    uint256 private constant REQUEST_RECORD = 0xe8b8fb47a0b8117907fcaea5c18794512eebbf818b8c203f2a5875f17da985bb;

    /// @notice The chain ID the fold binds: block.chainid at construction.
    uint256 public immutable foldedChainId;
    /// @notice The vault address the fold binds (the statements' contractAddress).
    address public immutable foldedVault;
    /// @notice The state signing key the fold binds.
    uint256 public immutable foldedStateSigningKeyX;
    uint256 public immutable foldedStateSigningKeyY;
    /// @notice The clearance signing key the withdrawal fold binds.
    uint256 public immutable foldedClearanceSigningKeyX;
    uint256 public immutable foldedClearanceSigningKeyY;
    /// @notice IC0 + 2 · IC1 + chainId · IC2 + vault · IC3 + stateX · IC5 + stateY · IC6 of the
    ///         request key, with the constants above.
    uint256 public immutable foldedRequestIc0X;
    uint256 public immutable foldedRequestIc0Y;
    /// @notice The same for the withdrawal key, plus clearanceX · IC7 + clearanceY · IC8.
    uint256 public immutable foldedWithdrawalIc0X;
    uint256 public immutable foldedWithdrawalIc0Y;

    // The verifying keys. G2 coordinates are named by their arkworks coefficients: c0 (real)
    // and c1 (imaginary), which EIP-197 takes first.
    uint256 private constant REQUEST_ALPHA_X = 0x0e41d816cbcc39b947acbbec578a240d71f6f0d84baa1b4055db06b0005c3793;
    uint256 private constant REQUEST_ALPHA_Y = 0x2cd0915dbb7599f0393714c1c388deb83f43bb5d2f610777ee30a9c47da131b5;
    uint256 private constant REQUEST_BETA_X_C0 = 0x123603df7a4dcdbfc69e74856a3b4c9cd4b4798df54f4fd34a68635bfebab38e;
    uint256 private constant REQUEST_BETA_X_C1 = 0x0e67a3f707f1e7cd3ca0587602f5ecfb487a4150aaed074b8d17b9e1917713e2;
    uint256 private constant REQUEST_BETA_Y_C0 = 0x14c71c77cf6f6d4e55e8a957830f4ee88d19cd21ec897db31b0aad4ba6fa6f43;
    uint256 private constant REQUEST_BETA_Y_C1 = 0x1eb225694e7bdf9e06a4afe8825787b8203289fdc512a18c89530f5398bb19db;
    uint256 private constant REQUEST_GAMMA_X_C0 = 0x243c8ae4b6d9020f398be9a4c6e7d861e9d6be0eedd09664dee2670cac521085;
    uint256 private constant REQUEST_GAMMA_X_C1 = 0x1026ecf1c3b7c5131bb928553af0dcd45f3e37e23ae971f2ff862540bd7f7126;
    uint256 private constant REQUEST_GAMMA_Y_C0 = 0x1594c00bdef3d8c7bf8301e896a7bfae32d2c15dd72cc5f5554b9e6e57e7e4ec;
    uint256 private constant REQUEST_GAMMA_Y_C1 = 0x0c9bdd6c7adea26d6d70793f9fdc2a9d16ece6365ff8434eac63c681dd920fc1;
    uint256 private constant REQUEST_DELTA_X_C0 = 0x23885d6c3f54f3117c570ae2d1abcbbc1d5393089490edfd2d740b9c97c07e7e;
    uint256 private constant REQUEST_DELTA_X_C1 = 0x0a352eb74c0c3f7dfb312b5f220e6055b0eaecd101cec6e592578419a2540970;
    uint256 private constant REQUEST_DELTA_Y_C0 = 0x19ed0aa007774000f64282f29f33ee10cc6490e13f3bd46cf7cbec49b538cc36;
    uint256 private constant REQUEST_DELTA_Y_C1 = 0x21a121ac7037f98ae762c17ca81422e8d5866b38dd113e2a57a8cee63e94c736;
    uint256 private constant REQUEST_IC0_X = 0x29dc866da7e243c657d0de1583ef137c2d83404a5e6d764c1c129e1d0b81ae51;
    uint256 private constant REQUEST_IC0_Y = 0x13faa0669073c6aaefb44d0d09733e979f2608815c3af7c914050c23e7f114f3;
    uint256 private constant REQUEST_IC1_X = 0x022adf9c9a3d89a4b5a3343699aa144e3ac9dce9c69f405a716ca9c410ae3995;
    uint256 private constant REQUEST_IC1_Y = 0x29a1c4d8d8d0586bd5e61fe41b3baf494ee1f1de531c1d0dddbb81aaa7930672;
    uint256 private constant REQUEST_IC2_X = 0x1f0362d0d3eee2d8c8d22631870473db15fa7f5e6dfc589c268ed96fc1a79263;
    uint256 private constant REQUEST_IC2_Y = 0x15c569522a31fa817bed8d71a87a1d8da079a4f4ce986235f77d64b1c8bf172f;
    uint256 private constant REQUEST_IC3_X = 0x18ce1bc5a9a174cc79b506bc9f6f1f2a0330d9f9f51e7998e6a51b666b9e7cca;
    uint256 private constant REQUEST_IC3_Y = 0x0e317817e9d2acddf74671564e07a4648ba607fe88827f423196128c7ad06b16;
    uint256 private constant REQUEST_IC4_X = 0x0d1a49f5e4c81cfb0f0d247633f484f88af77fd06db5791139a85affd48c0755;
    uint256 private constant REQUEST_IC4_Y = 0x2d564d3ea7a8a4ebfb7f0445fe5ff38ffe1b45280c31f9dda40a9116a93f88d8;
    uint256 private constant REQUEST_IC5_X = 0x05f880e80c12c1e3b012a391b0d70e74d948bd9fbcca126185eb9b5ad70648df;
    uint256 private constant REQUEST_IC5_Y = 0x0cec3847f4aecb37b1cbc76ec29518b39c0085edcbaf2e4a58461c017ac7ceb4;
    uint256 private constant REQUEST_IC6_X = 0x27867bc2d456b2ee366b63178e06e854afb34c2c4199f184cac66570e205f97e;
    uint256 private constant REQUEST_IC6_Y = 0x1788a58831198d51f512afb565b974bd2727dd6a24116a8dc72bfa27d138e6c9;
    uint256 private constant REQUEST_IC7_X = 0x105643c3617ee640173bfc9dcc8bb31a5f841208fd5558ce916a34e97898ba98;
    uint256 private constant REQUEST_IC7_Y = 0x0ba033fda0d9d3667eafec10f8b2d68c895d711f80e1380e3f8c67239bda206b;
    uint256 private constant REQUEST_IC8_X = 0x302ea3ae838cc65fcf32badd1663e6a8d3a217ac7a60c56b39da231c7927bb6f;
    uint256 private constant REQUEST_IC8_Y = 0x06b38b47dc9b092877faba06e2092e6492645fc34d5934681b15bb7bbdc65371;
    uint256 private constant REQUEST_IC9_X = 0x2d1867a697640bf25b0afd7d5713f904ce4a4c81ba438f937a1abb1e38d0ad77;
    uint256 private constant REQUEST_IC9_Y = 0x13169463799390d1b98a933b5968026e926ce668a132224e825caeec4d557749;
    uint256 private constant REQUEST_IC10_X = 0x083c8ee4ccbdaddc98e1b62d62a44253bd660155e548ba64c061e7c74a7fef5d;
    uint256 private constant REQUEST_IC10_Y = 0x0090449d3855502cebdb187662d8ef7864c3c8dc52a8432a45a7e1ea559ebbe8;
    uint256 private constant REQUEST_IC11_X = 0x2ddd41710cda2c8e86f936094a98a4ed8da149b0006c41e30cbb2514fe6e1698;
    uint256 private constant REQUEST_IC11_Y = 0x106857485c6108b9c2612bd85f3b6b8c841ead5981033ec02cd4648bf0cbcc4a;
    uint256 private constant REQUEST_IC12_X = 0x0d6d874d429871f52ecc07d253c69d43ce59f191496025735267b772ab9af505;
    uint256 private constant REQUEST_IC12_Y = 0x10f7e6181cd8620740ba6137212a7c7cb0241dd4344c706d8d581d76fe70e16c;

    uint256 private constant WITHDRAWAL_ALPHA_X = 0x2166ed9bdbd9c61a47a6f602c0ac5cfbef17ca98b350205323f9f94608a6db18;
    uint256 private constant WITHDRAWAL_ALPHA_Y = 0x277a08955c058c4fb5fd53c08e7a094d1a336221446b14724f1f31e3f1a8f476;
    uint256 private constant WITHDRAWAL_BETA_X_C0 = 0x1416fa0b9fdf0482bf1b96163bb664573a7859c6613ee2485d5e4272f776e23d;
    uint256 private constant WITHDRAWAL_BETA_X_C1 = 0x088a2dc33a5cb675d136ea487f615651da57178ff9bfa29346fb8d536e1646ab;
    uint256 private constant WITHDRAWAL_BETA_Y_C0 = 0x0849883a5afb3e2ef3c7271d372c3732c12fb3e578a542b6f086e5bb52297ece;
    uint256 private constant WITHDRAWAL_BETA_Y_C1 = 0x0d8c1091ed12401dc07e373bb67de5e856321d24ee4948262c3b424ac6c4ce1e;
    uint256 private constant WITHDRAWAL_GAMMA_X_C0 = 0x2e7ff8f53da4536307c816b4c40d1decd534ac06aacc95de2109a4a6c5457d07;
    uint256 private constant WITHDRAWAL_GAMMA_X_C1 = 0x1b5f2d8441eefd7a9e62d380a18a5631a5f711aa1e1441d691325fb5a1af59c9;
    uint256 private constant WITHDRAWAL_GAMMA_Y_C0 = 0x22fc60802258f0cab10fffbe417e717a7838b2634385b79e6cb63440f5882ab7;
    uint256 private constant WITHDRAWAL_GAMMA_Y_C1 = 0x02b447f81d2e5a532d15703f8d17ef25ecb51fb0a75d26e22a0ebd2c94f462fd;
    uint256 private constant WITHDRAWAL_DELTA_X_C0 = 0x1ed8e7b749cd67d171bf587bcf59fc867596c452ef776ad72c11fea946c41914;
    uint256 private constant WITHDRAWAL_DELTA_X_C1 = 0x1cd6a44736e1a1b9246c6716674af675ce70afb8a0719e17a1fa95fc80dde590;
    uint256 private constant WITHDRAWAL_DELTA_Y_C0 = 0x27a63e18cba604245976b2f10bd1b3a447f206086c71c1872b2839b715056586;
    uint256 private constant WITHDRAWAL_DELTA_Y_C1 = 0x2875c65bd2df8477b746c7b3bf8e1115c03a304e447a8a80ff7dee11c10e93bc;
    uint256 private constant WITHDRAWAL_IC0_X = 0x01ec9065d8749e451c78a4bddb0e87ef97640c665609bbba06350412ba759dae;
    uint256 private constant WITHDRAWAL_IC0_Y = 0x1f2389ff9e07f10296766db544d47d1852bbb00d800b2c5488c948cb6ab1aea4;
    uint256 private constant WITHDRAWAL_IC1_X = 0x2f65d6796ce1e6547fb96295af051d0c4a31dc2a2f83f9d1c8b3ccb50504faac;
    uint256 private constant WITHDRAWAL_IC1_Y = 0x1cea1a47577772cc688918a353feef0d6bb7677bebe77e23b76d0f07a542247b;
    uint256 private constant WITHDRAWAL_IC2_X = 0x1a4d60a242e61bf0fb8aad7a1679095b5402f6b429f3f380162180e05672e7a2;
    uint256 private constant WITHDRAWAL_IC2_Y = 0x13af3c5a6e34d7c633f484d251a803d11de9be3eccde2860d87378aae31bf20d;
    uint256 private constant WITHDRAWAL_IC3_X = 0x1912aed3bcd481ca13c200fd68526a4e5b6bfa817d854dd5dd80f302e7ceb4d3;
    uint256 private constant WITHDRAWAL_IC3_Y = 0x200fc8c19651b067d3ef51686231aa30c383871322726c30c4028776a2021a58;
    uint256 private constant WITHDRAWAL_IC4_X = 0x209837ed55b2f0b1a214d96bda695a3512cb62113d3a47d22b7507282d37bdfd;
    uint256 private constant WITHDRAWAL_IC4_Y = 0x0c7bf70fd82347f7febd5790a01623228ea01bc1d57e23dae9d56a5d10954a2a;
    uint256 private constant WITHDRAWAL_IC5_X = 0x24c0111c44fa9790bbd28f7c9e1e425f2ff19b0b7109e47c63414679e44aaaa6;
    uint256 private constant WITHDRAWAL_IC5_Y = 0x0deabc62c530c11773096d9278f7f0170094db78dbf65b09b08fda90d7d6e271;
    uint256 private constant WITHDRAWAL_IC6_X = 0x097d1c378f329568048ff32f8b4606d6a519e1f3039195f483ce320ff9165f1d;
    uint256 private constant WITHDRAWAL_IC6_Y = 0x048fcefd36e381acdf4b30c7578837e1f8364980cfe0d980c3f9c3e77ef0c7f0;
    uint256 private constant WITHDRAWAL_IC7_X = 0x2debd0053005c26c54bb11f2ad71c140377c501e1064dfa512e1208d10d84b97;
    uint256 private constant WITHDRAWAL_IC7_Y = 0x2612b6f613b96fa0439207ff674ccfb292cf04fc795b4c38e628a2fde3580df8;
    uint256 private constant WITHDRAWAL_IC8_X = 0x2c560d9a316a2236832e3eb1058dcdc9747d3f6809a749369924e94540313511;
    uint256 private constant WITHDRAWAL_IC8_Y = 0x13665025be7dbcd2425ec777a3cc7045c53bdbd7436c8342355e23d7826070fa;
    uint256 private constant WITHDRAWAL_IC9_X = 0x2431a5a30f78dfbbcb11c74eba15e4c972b85eec0f168311c6f6a051d54d061b;
    uint256 private constant WITHDRAWAL_IC9_Y = 0x1ab3e0357014c15112d7702505ec50a83fbed56536e0fbcbffb22e067703c079;
    uint256 private constant WITHDRAWAL_IC10_X = 0x1f8142c40f9b09b2541186da50bfb5968645ab171e93356f440bf9629ee0cb90;
    uint256 private constant WITHDRAWAL_IC10_Y = 0x0ec00bf558849de8cc8444456c231ec73892975780786d3d9e86192f99b83068;
    uint256 private constant WITHDRAWAL_IC11_X = 0x0e1ba5b47631a18c9523f0cf0a4ebe45196455dc3028090883197400240c6606;
    uint256 private constant WITHDRAWAL_IC11_Y = 0x02fe5e8016e77949b4a1f075c33849206460cc218ebefd0d9f8f82f3d07471a4;
    uint256 private constant WITHDRAWAL_IC12_X = 0x0f03e68245000a851f410ab4aadd0d1fbd9add7691818f881ddc4e84b7f4ede6;
    uint256 private constant WITHDRAWAL_IC12_Y = 0x2376f78eb5abddf5460be7594b09f737780c335113cf9e2fedcd60be3962d146;
    uint256 private constant WITHDRAWAL_IC13_X = 0x29a4616c6a8f099cd56dff3df9c44f52d8c679ddfba79ab204d8695c6115d14b;
    uint256 private constant WITHDRAWAL_IC13_Y = 0x0ee4013d135b902d0fa7ab4c71000dc4e8dc3e568de9dfb5fb474a1ff025aa04;
    uint256 private constant WITHDRAWAL_IC14_X = 0x100816372bf2241443e779c9ab6ba4804bc008bb988899e5719c4feb24b11d0c;
    uint256 private constant WITHDRAWAL_IC14_Y = 0x02a6815d85e3d6fa76238823da04cd26fe54475a6eabce200000bb2a2d7af1bd;
    uint256 private constant WITHDRAWAL_IC15_X = 0x0db9c30a3a638f825fe883a6e717447b3014c7a26954c6a356d0f246aa93f7d0;
    uint256 private constant WITHDRAWAL_IC15_Y = 0x15cc2bb91e77add5eb87ecdd3041b42c1497713cae8fbf57ec8e8e4c6f927948;
    uint256 private constant WITHDRAWAL_IC16_X = 0x09754e506956548f40dcc9511c046745d99563fb0e857828653d49a3669c2733;
    uint256 private constant WITHDRAWAL_IC16_Y = 0x24a803af39ef324b406b5bbd43d51a06c06471dac27d3caf6e2e314b56c7872b;

    /// @param vault The vault whose proofs take the folded path: its address, predicted before it
    ///        exists (the deployer's CREATE nonce, or CREATE2).
    /// @param stateSigningKeyX The vault's state and clearance signing keys. A coordinate at or
    ///        above the scalar field order reverts InvalidProof(): no proof can carry it.
    constructor(
        address vault,
        uint256 stateSigningKeyX,
        uint256 stateSigningKeyY,
        uint256 clearanceSigningKeyX,
        uint256 clearanceSigningKeyY
    ) {
        foldedChainId = block.chainid;
        foldedVault = vault;
        foldedStateSigningKeyX = stateSigningKeyX;
        foldedStateSigningKeyY = stateSigningKeyY;
        foldedClearanceSigningKeyX = clearanceSigningKeyX;
        foldedClearanceSigningKeyY = clearanceSigningKeyY;
        (foldedRequestIc0X, foldedRequestIc0Y, foldedWithdrawalIc0X, foldedWithdrawalIc0Y) = _fold(
            block.chainid,
            uint256(uint160(vault)),
            stateSigningKeyX,
            stateSigningKeyY,
            clearanceSigningKeyX,
            clearanceSigningKeyY
        );
    }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external
        view
        override
    {
        if (_requestVerifiedEarlier(inputs, proof)) return;
        _verifyRequest(inputs, proof);
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        view
        override
    {
        if (_verifiedEarlier(inputs, proof)) return;
        _verifyWithdrawal(inputs, proof);
    }

    function verifyWithdrawalOnce(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        override
    {
        _verifyWithdrawal(inputs, proof);
        bytes32 slot = _verifiedSlot(inputs, proof);
        assembly ("memory-safe") {
            tstore(slot, 1)
        }
    }

    function verifyWithdrawalBatch(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs)
        external
        view
        override
    {
        _verifyWithdrawalBatch(inputs, proofs);
    }

    function verifyRequestBatch(Types.RequestPublicInputs[] calldata inputs, bytes calldata proofs)
        external
        view
        override
    {
        _verifyRequestBatch(inputs, proofs);
    }

    /// @dev The batch verification, then every item's record exactly as verifyWithdrawalOnce writes
    ///      it (_verifiedSlot).
    function verifyWithdrawalBatchOnce(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs)
        external
        override
    {
        _verifyWithdrawalBatch(inputs, proofs);
        assembly ("memory-safe") {
            let m := mload(0x40)
            for { let i := 0 } lt(i, inputs.length) { i := add(i, 1) } {
                let w := add(inputs.offset, mul(i, 0x200))
                calldatacopy(m, w, 0x200)
                calldatacopy(add(m, 0x200), add(proofs.offset, mul(i, 0x100)), 0x100)
                mstore(0x00, calldataload(add(w, 0x140)))
                mstore(0x20, keccak256(m, 0x300))
                tstore(keccak256(0x00, 0x40), 1)
            }
        }
    }

    /// @dev The batch verification, then every item's request record (_requestVerifiedEarlier).
    function verifyRequestBatchOnce(Types.RequestPublicInputs[] calldata inputs, bytes calldata proofs)
        external
        override
    {
        _verifyRequestBatch(inputs, proofs);
        assembly ("memory-safe") {
            let m := mload(0x40)
            for { let i := 0 } lt(i, inputs.length) { i := add(i, 1) } {
                calldatacopy(m, add(inputs.offset, mul(i, 0x180)), 0x180)
                calldatacopy(add(m, 0x180), add(proofs.offset, mul(i, 0x100)), 0x100)
                mstore(0x00, REQUEST_RECORD)
                mstore(0x20, keccak256(m, 0x280))
                tstore(keccak256(0x00, 0x40), 1)
            }
        }
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IZkApiProofAdapter).interfaceId
            || interfaceId == type(IZkApiBatchProofAdapter).interfaceId || interfaceId == 0x01ffc9a7;
    }

    /// @dev Whether verifyWithdrawalOnce verified exactly these inputs and proof earlier in this
    ///      transaction. Only a full verification writes a record and none is ever erased, so a
    ///      record means these bytes verified; a proof that is not 256 bytes never does.
    function _verifiedEarlier(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        private
        view
        returns (bool verified)
    {
        if (proof.length != 0x100) return false;
        bytes32 slot = _verifiedSlot(inputs, proof);
        assembly ("memory-safe") {
            verified := iszero(iszero(tload(slot)))
        }
    }

    /// @dev The transient slot of a verified withdrawal: keccak256(destination ‖ h), h the
    ///      keccak256 of the 16 input words and the 256 proof bytes as the call carries them. Only
    ///      these exact bytes name it, and it is associated with the destination in the ERC-7562
    ///      sense (STO-021): the paymaster records it in validation for an operation whose sender
    ///      is the destination.
    function _verifiedSlot(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        private
        pure
        returns (bytes32 slot)
    {
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, inputs, 0x200)
            calldatacopy(add(m, 0x200), proof.offset, 0x100)
            mstore(0x00, calldataload(add(inputs, 0x140)))
            mstore(0x20, keccak256(m, 0x300))
            slot := keccak256(0x00, 0x40)
        }
    }

    /// @dev Whether verifyRequestBatchOnce verified exactly these inputs and proof earlier in this
    ///      transaction: keccak256(REQUEST_RECORD ‖ h), h the keccak256 of the 12 input words and the
    ///      256 proof bytes as the call carries them. Only a full batch verification writes a record
    ///      and none is ever erased; a proof that is not 256 bytes never has one.
    function _requestVerifiedEarlier(Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        private
        view
        returns (bool verified)
    {
        if (proof.length != 0x100) return false;
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, inputs, 0x180)
            calldatacopy(add(m, 0x180), proof.offset, 0x100)
            mstore(0x00, REQUEST_RECORD)
            mstore(0x20, keccak256(m, 0x280))
            verified := iszero(iszero(tload(keccak256(0x00, 0x40))))
        }
    }

    /// @dev The Groth16 verification of a request statement; reverts unless it holds. The
    ///      checks run in the order of the ABI decoder and the plain verifier: the narrow fields,
    ///      the proof's length and words, then each input as it enters the multi-scalar
    ///      multiplication. The pairing input (24 words) is built in place at the free memory
    ///      pointer m: the multiplication accumulates at its third G1 point (m + 0x180), with the
    ///      four words gamma takes afterwards as scratch.
    function _verifyRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) private view {
        uint256 foldedX = foldedRequestIc0X;
        uint256 foldedY = foldedRequestIc0Y;
        uint256 chainId = foldedChainId;
        uint256 vault = uint256(uint160(foldedVault));
        uint256 stateX = foldedStateSigningKeyX;
        uint256 stateY = foldedStateSigningKeyY;
        assembly ("memory-safe") {
            // Reverts InvalidProof().
            function fail() {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }
            // Adds s · (x, y) to the G1 point at l, with the four words after it as scratch. A
            // scalar at or above the field order is refused. 0 · P is the identity, the neutral
            // element of the sum: skipped. 1 · P and 2 · P need no scalar multiplication (6,000
            // gas) either: the point itself, and one addition. The protocol version (2), a
            // close's kind (1), an escape's kind (0) and an exit's zero nextNullifier and conceded
            // take these paths.
            function addTerm(l, x, y, s) {
                if iszero(lt(s, SCALAR_MODULUS)) { fail() }
                if s {
                    let t := add(l, 0x40)
                    mstore(t, x)
                    mstore(add(t, 0x20), y)
                    switch s
                    case 1 {}
                    case 2 {
                        mstore(add(t, 0x40), x)
                        mstore(add(t, 0x60), y)
                        if iszero(staticcall(gas(), 0x06, t, 0x80, t, 0x40)) { fail() }
                    }
                    default {
                        mstore(add(t, 0x40), s)
                        if iszero(staticcall(gas(), 0x07, t, 0x60, t, 0x40)) { fail() }
                    }
                    if iszero(staticcall(gas(), 0x06, l, 0x80, l, 0x40)) { fail() }
                }
            }
            // The narrow fields, as Solidity's ABI decoder checks them (an empty revert):
            // protocolVersion (16), chainId (64), contractAddress (160), requestTime (64),
            // solvencyBound (128).
            if or(
                or(
                    or(shr(16, calldataload(inputs)), shr(64, calldataload(add(inputs, 0x20)))),
                    shr(160, calldataload(add(inputs, 0x40)))
                ),
                or(shr(64, calldataload(add(inputs, 0xc0))), shr(128, calldataload(add(inputs, 0xe0))))
            ) { revert(0x00, 0x00) }
            // The proof: 256 bytes, every word a canonical base-field element.
            if iszero(eq(proof.length, 0x100)) { fail() }
            let o := proof.offset
            if iszero(
                and(
                    and(
                        and(lt(calldataload(o), BASE_MODULUS), lt(calldataload(add(o, 0x20)), BASE_MODULUS)),
                        and(lt(calldataload(add(o, 0x40)), BASE_MODULUS), lt(calldataload(add(o, 0x60)), BASE_MODULUS))
                    ),
                    and(
                        and(lt(calldataload(add(o, 0x80)), BASE_MODULUS), lt(calldataload(add(o, 0xa0)), BASE_MODULUS)),
                        and(lt(calldataload(add(o, 0xc0)), BASE_MODULUS), lt(calldataload(add(o, 0xe0)), BASE_MODULUS))
                    )
                )
            ) { fail() }
            let m := mload(0x40)
            let l := add(m, 0x180)
            switch and(
                and(
                    and(eq(calldataload(inputs), PROTOCOL_VERSION), eq(calldataload(add(inputs, 0x20)), chainId)),
                    eq(calldataload(add(inputs, 0x40)), vault)
                ),
                and(eq(calldataload(add(inputs, 0x80)), stateX), eq(calldataload(add(inputs, 0xa0)), stateY))
            )
            case 0 {
                // Another vault, chain, key or version: IC0 and every input.
                mstore(l, REQUEST_IC0_X)
                mstore(add(l, 0x20), REQUEST_IC0_Y)
                addTerm(l, REQUEST_IC1_X, REQUEST_IC1_Y, calldataload(inputs))
                addTerm(l, REQUEST_IC2_X, REQUEST_IC2_Y, calldataload(add(inputs, 0x20)))
                addTerm(l, REQUEST_IC3_X, REQUEST_IC3_Y, calldataload(add(inputs, 0x40)))
                addTerm(l, REQUEST_IC5_X, REQUEST_IC5_Y, calldataload(add(inputs, 0x80)))
                addTerm(l, REQUEST_IC6_X, REQUEST_IC6_Y, calldataload(add(inputs, 0xa0)))
            }
            default {
                // The folded constants: their sum is the constructor's.
                mstore(l, foldedX)
                mstore(add(l, 0x20), foldedY)
            }
            addTerm(l, REQUEST_IC4_X, REQUEST_IC4_Y, calldataload(add(inputs, 0x60)))
            addTerm(l, REQUEST_IC7_X, REQUEST_IC7_Y, calldataload(add(inputs, 0xc0)))
            addTerm(l, REQUEST_IC8_X, REQUEST_IC8_Y, calldataload(add(inputs, 0xe0)))
            addTerm(l, REQUEST_IC9_X, REQUEST_IC9_Y, calldataload(add(inputs, 0x100)))
            addTerm(l, REQUEST_IC10_X, REQUEST_IC10_Y, calldataload(add(inputs, 0x120)))
            addTerm(l, REQUEST_IC11_X, REQUEST_IC11_Y, calldataload(add(inputs, 0x140)))
            addTerm(l, REQUEST_IC12_X, REQUEST_IC12_Y, calldataload(add(inputs, 0x160)))
            // The pairing: (-A, B), (alpha, beta), (L, gamma), (C, delta).
            mstore(m, calldataload(o))
            mstore(add(m, 0x20), mod(sub(BASE_MODULUS, calldataload(add(o, 0x20))), BASE_MODULUS))
            mstore(add(m, 0x40), calldataload(add(o, 0x60)))
            mstore(add(m, 0x60), calldataload(add(o, 0x40)))
            mstore(add(m, 0x80), calldataload(add(o, 0xa0)))
            mstore(add(m, 0xa0), calldataload(add(o, 0x80)))
            mstore(add(m, 0xc0), REQUEST_ALPHA_X)
            mstore(add(m, 0xe0), REQUEST_ALPHA_Y)
            mstore(add(m, 0x100), REQUEST_BETA_X_C1)
            mstore(add(m, 0x120), REQUEST_BETA_X_C0)
            mstore(add(m, 0x140), REQUEST_BETA_Y_C1)
            mstore(add(m, 0x160), REQUEST_BETA_Y_C0)
            mstore(add(m, 0x1c0), REQUEST_GAMMA_X_C1)
            mstore(add(m, 0x1e0), REQUEST_GAMMA_X_C0)
            mstore(add(m, 0x200), REQUEST_GAMMA_Y_C1)
            mstore(add(m, 0x220), REQUEST_GAMMA_Y_C0)
            calldatacopy(add(m, 0x240), add(o, 0xc0), 0x40)
            mstore(add(m, 0x280), REQUEST_DELTA_X_C1)
            mstore(add(m, 0x2a0), REQUEST_DELTA_X_C0)
            mstore(add(m, 0x2c0), REQUEST_DELTA_Y_C1)
            mstore(add(m, 0x2e0), REQUEST_DELTA_Y_C0)
            let ok := staticcall(gas(), 0x08, m, 0x300, 0x00, 0x20)
            if iszero(and(ok, eq(mload(0x00), 1))) { fail() }
        }
    }

    /// @dev The Groth16 verification of a withdrawal statement; reverts unless it holds. The
    ///      checks run in the order of the ABI decoder and the plain verifier: the narrow fields,
    ///      the proof's length and words, then each input as it enters the multi-scalar
    ///      multiplication. The pairing input (24 words) is built in place at the free memory
    ///      pointer m: the multiplication accumulates at its third G1 point (m + 0x180), with the
    ///      four words gamma takes afterwards as scratch.
    function _verifyWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof) private view {
        uint256 foldedX = foldedWithdrawalIc0X;
        uint256 foldedY = foldedWithdrawalIc0Y;
        uint256 chainId = foldedChainId;
        uint256 vault = uint256(uint160(foldedVault));
        uint256 stateX = foldedStateSigningKeyX;
        uint256 stateY = foldedStateSigningKeyY;
        uint256 clearanceX = foldedClearanceSigningKeyX;
        uint256 clearanceY = foldedClearanceSigningKeyY;
        assembly ("memory-safe") {
            // Reverts InvalidProof().
            function fail() {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }
            // Adds s · (x, y) to the G1 point at l, with the four words after it as scratch. A
            // scalar at or above the field order is refused. 0 · P is the identity, the neutral
            // element of the sum: skipped. 1 · P and 2 · P need no scalar multiplication (6,000
            // gas) either: the point itself, and one addition. The protocol version (2), a
            // close's kind (1), an escape's kind (0) and an exit's zero nextNullifier and conceded
            // take these paths.
            function addTerm(l, x, y, s) {
                if iszero(lt(s, SCALAR_MODULUS)) { fail() }
                if s {
                    let t := add(l, 0x40)
                    mstore(t, x)
                    mstore(add(t, 0x20), y)
                    switch s
                    case 1 {}
                    case 2 {
                        mstore(add(t, 0x40), x)
                        mstore(add(t, 0x60), y)
                        if iszero(staticcall(gas(), 0x06, t, 0x80, t, 0x40)) { fail() }
                    }
                    default {
                        mstore(add(t, 0x40), s)
                        if iszero(staticcall(gas(), 0x07, t, 0x60, t, 0x40)) { fail() }
                    }
                    if iszero(staticcall(gas(), 0x06, l, 0x80, l, 0x40)) { fail() }
                }
            }
            // The narrow fields, as Solidity's ABI decoder checks them (an empty revert):
            // protocolVersion (16), chainId (64), contractAddress (160), noteId (32),
            // finalBalance (128), destination (160), kind (8), conceded (128), validUntil (64).
            if or(
                or(
                    or(
                        or(shr(16, calldataload(inputs)), shr(64, calldataload(add(inputs, 0x20)))),
                        shr(160, calldataload(add(inputs, 0x40)))
                    ),
                    or(shr(32, calldataload(add(inputs, 0x100))), shr(128, calldataload(add(inputs, 0x120))))
                ),
                or(
                    or(shr(160, calldataload(add(inputs, 0x140))), shr(8, calldataload(add(inputs, 0x180)))),
                    or(shr(128, calldataload(add(inputs, 0x1c0))), shr(64, calldataload(add(inputs, 0x1e0))))
                )
            ) { revert(0x00, 0x00) }
            // The proof: 256 bytes, every word a canonical base-field element.
            if iszero(eq(proof.length, 0x100)) { fail() }
            let o := proof.offset
            if iszero(
                and(
                    and(
                        and(lt(calldataload(o), BASE_MODULUS), lt(calldataload(add(o, 0x20)), BASE_MODULUS)),
                        and(lt(calldataload(add(o, 0x40)), BASE_MODULUS), lt(calldataload(add(o, 0x60)), BASE_MODULUS))
                    ),
                    and(
                        and(lt(calldataload(add(o, 0x80)), BASE_MODULUS), lt(calldataload(add(o, 0xa0)), BASE_MODULUS)),
                        and(lt(calldataload(add(o, 0xc0)), BASE_MODULUS), lt(calldataload(add(o, 0xe0)), BASE_MODULUS))
                    )
                )
            ) { fail() }
            let m := mload(0x40)
            let l := add(m, 0x180)
            switch and(
                and(
                    and(eq(calldataload(inputs), PROTOCOL_VERSION), eq(calldataload(add(inputs, 0x20)), chainId)),
                    and(eq(calldataload(add(inputs, 0x40)), vault), eq(calldataload(add(inputs, 0x80)), stateX))
                ),
                and(
                    and(eq(calldataload(add(inputs, 0xa0)), stateY), eq(calldataload(add(inputs, 0xc0)), clearanceX)),
                    eq(calldataload(add(inputs, 0xe0)), clearanceY)
                )
            )
            case 0 {
                // Another vault, chain, key or version: IC0 and every input.
                mstore(l, WITHDRAWAL_IC0_X)
                mstore(add(l, 0x20), WITHDRAWAL_IC0_Y)
                addTerm(l, WITHDRAWAL_IC1_X, WITHDRAWAL_IC1_Y, calldataload(inputs))
                addTerm(l, WITHDRAWAL_IC2_X, WITHDRAWAL_IC2_Y, calldataload(add(inputs, 0x20)))
                addTerm(l, WITHDRAWAL_IC3_X, WITHDRAWAL_IC3_Y, calldataload(add(inputs, 0x40)))
                addTerm(l, WITHDRAWAL_IC5_X, WITHDRAWAL_IC5_Y, calldataload(add(inputs, 0x80)))
                addTerm(l, WITHDRAWAL_IC6_X, WITHDRAWAL_IC6_Y, calldataload(add(inputs, 0xa0)))
                addTerm(l, WITHDRAWAL_IC7_X, WITHDRAWAL_IC7_Y, calldataload(add(inputs, 0xc0)))
                addTerm(l, WITHDRAWAL_IC8_X, WITHDRAWAL_IC8_Y, calldataload(add(inputs, 0xe0)))
            }
            default {
                // The folded constants: their sum is the constructor's.
                mstore(l, foldedX)
                mstore(add(l, 0x20), foldedY)
            }
            addTerm(l, WITHDRAWAL_IC4_X, WITHDRAWAL_IC4_Y, calldataload(add(inputs, 0x60)))
            addTerm(l, WITHDRAWAL_IC9_X, WITHDRAWAL_IC9_Y, calldataload(add(inputs, 0x100)))
            addTerm(l, WITHDRAWAL_IC10_X, WITHDRAWAL_IC10_Y, calldataload(add(inputs, 0x120)))
            addTerm(l, WITHDRAWAL_IC11_X, WITHDRAWAL_IC11_Y, calldataload(add(inputs, 0x140)))
            addTerm(l, WITHDRAWAL_IC12_X, WITHDRAWAL_IC12_Y, calldataload(add(inputs, 0x160)))
            addTerm(l, WITHDRAWAL_IC13_X, WITHDRAWAL_IC13_Y, calldataload(add(inputs, 0x180)))
            addTerm(l, WITHDRAWAL_IC14_X, WITHDRAWAL_IC14_Y, calldataload(add(inputs, 0x1a0)))
            addTerm(l, WITHDRAWAL_IC15_X, WITHDRAWAL_IC15_Y, calldataload(add(inputs, 0x1c0)))
            addTerm(l, WITHDRAWAL_IC16_X, WITHDRAWAL_IC16_Y, calldataload(add(inputs, 0x1e0)))
            // The pairing: (-A, B), (alpha, beta), (L, gamma), (C, delta).
            mstore(m, calldataload(o))
            mstore(add(m, 0x20), mod(sub(BASE_MODULUS, calldataload(add(o, 0x20))), BASE_MODULUS))
            mstore(add(m, 0x40), calldataload(add(o, 0x60)))
            mstore(add(m, 0x60), calldataload(add(o, 0x40)))
            mstore(add(m, 0x80), calldataload(add(o, 0xa0)))
            mstore(add(m, 0xa0), calldataload(add(o, 0x80)))
            mstore(add(m, 0xc0), WITHDRAWAL_ALPHA_X)
            mstore(add(m, 0xe0), WITHDRAWAL_ALPHA_Y)
            mstore(add(m, 0x100), WITHDRAWAL_BETA_X_C1)
            mstore(add(m, 0x120), WITHDRAWAL_BETA_X_C0)
            mstore(add(m, 0x140), WITHDRAWAL_BETA_Y_C1)
            mstore(add(m, 0x160), WITHDRAWAL_BETA_Y_C0)
            mstore(add(m, 0x1c0), WITHDRAWAL_GAMMA_X_C1)
            mstore(add(m, 0x1e0), WITHDRAWAL_GAMMA_X_C0)
            mstore(add(m, 0x200), WITHDRAWAL_GAMMA_Y_C1)
            mstore(add(m, 0x220), WITHDRAWAL_GAMMA_Y_C0)
            calldatacopy(add(m, 0x240), add(o, 0xc0), 0x40)
            mstore(add(m, 0x280), WITHDRAWAL_DELTA_X_C1)
            mstore(add(m, 0x2a0), WITHDRAWAL_DELTA_X_C0)
            mstore(add(m, 0x2c0), WITHDRAWAL_DELTA_Y_C1)
            mstore(add(m, 0x2e0), WITHDRAWAL_DELTA_Y_C0)
            let ok := staticcall(gas(), 0x08, m, 0x300, 0x00, 0x20)
            if iszero(and(ok, eq(mload(0x00), 1))) { fail() }
        }
    }

    /// @dev The batch Groth16 verification of n ≥ 1 request statements, all or nothing: reverts
    ///      unless every one holds. Each item gets the single verification's checks in its order
    ///      (narrow fields: an empty revert; proof words, then inputs, canonical: InvalidProof()),
    ///      and the equations are combined with r_0 = 1 and 128-bit Fiat-Shamir challenges r_i =
    ///      keccak256(seed ‖ i) >> 128 (i ≥ 1), seed = keccak256(BATCH_DOMAIN ‖ REQUEST_VK_HASH ‖ n ‖
    ///      every input word ‖ every proof word), the bytes the loop reads: Π e(-r_i A_i, B_i) ·
    ///      e(Σ r_i alpha, beta) · e(Σ r_i L_i, gamma) · e(Σ r_i C_i, delta) == 1, n + 3 pairs, where
    ///      Σ r_i L_i = (Σ_folded r_i) IC0' + (Σ_other r_i) IC0 + Σ_j (Σ_i r_i x_ij) IC_j is one
    ///      shared multi-scalar multiplication over the folded and generic items alike. An empty
    ///      batch and a proofs length other than 256 · n revert InvalidProof(). Memory from the free
    ///      pointer m: first the transcript (n ≥ 2), then the pairing input ((n + 3) · 0xc0 bytes),
    ///      the scalars s (14 words), Σ r L with its four scratch words, and Σ r C with its.
    function _verifyRequestBatch(Types.RequestPublicInputs[] calldata inputs, bytes calldata proofs) private view {
        uint256 foldedX = foldedRequestIc0X;
        uint256 foldedY = foldedRequestIc0Y;
        uint256 chainId = foldedChainId;
        uint256 vault = uint256(uint160(foldedVault));
        uint256 stateX = foldedStateSigningKeyX;
        uint256 stateY = foldedStateSigningKeyY;
        assembly ("memory-safe") {
            // Reverts InvalidProof().
            function fail() {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }
            // Adds s · (x, y) to the G1 point at l, with the four words after it as scratch. A
            // scalar at or above the field order is refused. 0 · P is the identity, the neutral
            // element of the sum: skipped. 1 · P and 2 · P need no scalar multiplication (6,000
            // gas) either: the point itself, and one addition. The protocol version (2), a
            // close's kind (1), an escape's kind (0) and an exit's zero nextNullifier and conceded
            // take these paths.
            function addTerm(l, x, y, s) {
                if iszero(lt(s, SCALAR_MODULUS)) { fail() }
                if s {
                    let t := add(l, 0x40)
                    mstore(t, x)
                    mstore(add(t, 0x20), y)
                    switch s
                    case 1 {}
                    case 2 {
                        mstore(add(t, 0x40), x)
                        mstore(add(t, 0x60), y)
                        if iszero(staticcall(gas(), 0x06, t, 0x80, t, 0x40)) { fail() }
                    }
                    default {
                        mstore(add(t, 0x40), s)
                        if iszero(staticcall(gas(), 0x07, t, 0x60, t, 0x40)) { fail() }
                    }
                    if iszero(staticcall(gas(), 0x06, l, 0x80, l, 0x40)) { fail() }
                }
            }
            // Adds r · x to the scalar at p, modulo the field order. An input at or above it is
            // refused, as the single verification's addTerm refuses it, so no statement verifies
            // in a non-canonical form (x + r).
            function accumulate(p, x, r) {
                if iszero(lt(x, SCALAR_MODULUS)) { fail() }
                if x { mstore(p, addmod(mload(p), mulmod(r, x, SCALAR_MODULUS), SCALAR_MODULUS)) }
            }
            let n := inputs.length
            if iszero(n) { fail() }
            if iszero(eq(proofs.length, mul(n, 0x100))) { fail() }
            let m := mload(0x40)
            // The Fiat-Shamir seed over every byte the loop reads. One statement needs none: r_0 = 1.
            let seed := 0
            if gt(n, 1) {
                mstore(m, BATCH_DOMAIN)
                mstore(add(m, 0x20), REQUEST_VK_HASH)
                mstore(add(m, 0x40), n)
                calldatacopy(add(m, 0x60), inputs.offset, mul(n, 0x180))
                calldatacopy(add(m, add(0x60, mul(n, 0x180))), proofs.offset, mul(n, 0x100))
                seed := keccak256(m, add(0x60, mul(n, 0x280)))
            }
            let s := add(m, mul(add(n, 3), 0xc0))
            let l := add(s, 0x1c0)
            let c := add(l, 0xc0)
            for { let k := 0 } lt(k, 0x1c0) { k := add(k, 0x20) } { mstore(add(s, k), 0) }
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let w := add(inputs.offset, mul(i, 0x180))
                let o := add(proofs.offset, mul(i, 0x100))
                // The narrow fields, as Solidity's ABI decoder checks them (an empty revert):
                // protocolVersion (16), chainId (64), contractAddress (160), requestTime (64),
                // solvencyBound (128).
                if or(
                    or(
                        or(shr(16, calldataload(w)), shr(64, calldataload(add(w, 0x20)))),
                        shr(160, calldataload(add(w, 0x40)))
                    ),
                    or(shr(64, calldataload(add(w, 0xc0))), shr(128, calldataload(add(w, 0xe0))))
                ) { revert(0x00, 0x00) }
                // The proof: every word a canonical base-field element.
                if iszero(
                    and(
                        and(
                            and(lt(calldataload(o), BASE_MODULUS), lt(calldataload(add(o, 0x20)), BASE_MODULUS)),
                            and(
                                lt(calldataload(add(o, 0x40)), BASE_MODULUS),
                                lt(calldataload(add(o, 0x60)), BASE_MODULUS)
                            )
                        ),
                        and(
                            and(
                                lt(calldataload(add(o, 0x80)), BASE_MODULUS),
                                lt(calldataload(add(o, 0xa0)), BASE_MODULUS)
                            ),
                            and(
                                lt(calldataload(add(o, 0xc0)), BASE_MODULUS),
                                lt(calldataload(add(o, 0xe0)), BASE_MODULUS)
                            )
                        )
                    )
                ) { fail() }
                // The challenge: 1 for the first statement, the top 128 bits of keccak256(seed ‖ i)
                // after it.
                let r := 1
                if i {
                    mstore(0x00, seed)
                    mstore(0x20, i)
                    r := shr(128, keccak256(0x00, 0x40))
                }
                switch and(
                    and(
                        and(eq(calldataload(w), PROTOCOL_VERSION), eq(calldataload(add(w, 0x20)), chainId)),
                        eq(calldataload(add(w, 0x40)), vault)
                    ),
                    and(eq(calldataload(add(w, 0x80)), stateX), eq(calldataload(add(w, 0xa0)), stateY))
                )
                case 0 {
                    // Another vault, chain, key or version: IC0 and every input.
                    mstore(add(s, 0x20), addmod(mload(add(s, 0x20)), r, SCALAR_MODULUS))
                    accumulate(add(s, 0x40), calldataload(w), r)
                    accumulate(add(s, 0x60), calldataload(add(w, 0x20)), r)
                    accumulate(add(s, 0x80), calldataload(add(w, 0x40)), r)
                    accumulate(add(s, 0xc0), calldataload(add(w, 0x80)), r)
                    accumulate(add(s, 0xe0), calldataload(add(w, 0xa0)), r)
                }
                default {
                    // The folded constants: IC0'.
                    mstore(s, addmod(mload(s), r, SCALAR_MODULUS))
                }
                accumulate(add(s, 0xa0), calldataload(add(w, 0x60)), r)
                accumulate(add(s, 0x100), calldataload(add(w, 0xc0)), r)
                accumulate(add(s, 0x120), calldataload(add(w, 0xe0)), r)
                accumulate(add(s, 0x140), calldataload(add(w, 0x100)), r)
                accumulate(add(s, 0x160), calldataload(add(w, 0x120)), r)
                accumulate(add(s, 0x180), calldataload(add(w, 0x140)), r)
                accumulate(add(s, 0x1a0), calldataload(add(w, 0x160)), r)
                // Pair i: (-r A, B), A negated in place, then scaled; and r C into the sum at c.
                let q := add(m, mul(i, 0xc0))
                mstore(q, calldataload(o))
                mstore(add(q, 0x20), mod(sub(BASE_MODULUS, calldataload(add(o, 0x20))), BASE_MODULUS))
                switch i
                case 0 { calldatacopy(c, add(o, 0xc0), 0x40) }
                default {
                    mstore(add(q, 0x40), r)
                    if iszero(staticcall(gas(), 0x07, q, 0x60, q, 0x40)) { fail() }
                    calldatacopy(add(c, 0x40), add(o, 0xc0), 0x40)
                    mstore(add(c, 0x80), r)
                    if iszero(staticcall(gas(), 0x07, add(c, 0x40), 0x60, add(c, 0x40), 0x40)) { fail() }
                    if iszero(staticcall(gas(), 0x06, c, 0x80, c, 0x40)) { fail() }
                }
                mstore(add(q, 0x40), calldataload(add(o, 0x60)))
                mstore(add(q, 0x60), calldataload(add(o, 0x40)))
                mstore(add(q, 0x80), calldataload(add(o, 0xa0)))
                mstore(add(q, 0xa0), calldataload(add(o, 0x80)))
            }
            // Σ r_i L_i: the shared multi-scalar multiplication, from the identity.
            mstore(l, 0)
            mstore(add(l, 0x20), 0)
            addTerm(l, foldedX, foldedY, mload(s))
            addTerm(l, REQUEST_IC0_X, REQUEST_IC0_Y, mload(add(s, 0x20)))
            addTerm(l, REQUEST_IC1_X, REQUEST_IC1_Y, mload(add(s, 0x40)))
            addTerm(l, REQUEST_IC2_X, REQUEST_IC2_Y, mload(add(s, 0x60)))
            addTerm(l, REQUEST_IC3_X, REQUEST_IC3_Y, mload(add(s, 0x80)))
            addTerm(l, REQUEST_IC4_X, REQUEST_IC4_Y, mload(add(s, 0xa0)))
            addTerm(l, REQUEST_IC5_X, REQUEST_IC5_Y, mload(add(s, 0xc0)))
            addTerm(l, REQUEST_IC6_X, REQUEST_IC6_Y, mload(add(s, 0xe0)))
            addTerm(l, REQUEST_IC7_X, REQUEST_IC7_Y, mload(add(s, 0x100)))
            addTerm(l, REQUEST_IC8_X, REQUEST_IC8_Y, mload(add(s, 0x120)))
            addTerm(l, REQUEST_IC9_X, REQUEST_IC9_Y, mload(add(s, 0x140)))
            addTerm(l, REQUEST_IC10_X, REQUEST_IC10_Y, mload(add(s, 0x160)))
            addTerm(l, REQUEST_IC11_X, REQUEST_IC11_Y, mload(add(s, 0x180)))
            addTerm(l, REQUEST_IC12_X, REQUEST_IC12_Y, mload(add(s, 0x1a0)))
            // The last three pairs: ((Σ r) alpha, beta), (Σ r L, gamma), (Σ r C, delta).
            let q := add(m, mul(n, 0xc0))
            let sum := addmod(mload(s), mload(add(s, 0x20)), SCALAR_MODULUS)
            mstore(q, REQUEST_ALPHA_X)
            mstore(add(q, 0x20), REQUEST_ALPHA_Y)
            if iszero(eq(sum, 1)) {
                mstore(add(q, 0x40), sum)
                if iszero(staticcall(gas(), 0x07, q, 0x60, q, 0x40)) { fail() }
            }
            mstore(add(q, 0x40), REQUEST_BETA_X_C1)
            mstore(add(q, 0x60), REQUEST_BETA_X_C0)
            mstore(add(q, 0x80), REQUEST_BETA_Y_C1)
            mstore(add(q, 0xa0), REQUEST_BETA_Y_C0)
            mstore(add(q, 0xc0), mload(l))
            mstore(add(q, 0xe0), mload(add(l, 0x20)))
            mstore(add(q, 0x100), REQUEST_GAMMA_X_C1)
            mstore(add(q, 0x120), REQUEST_GAMMA_X_C0)
            mstore(add(q, 0x140), REQUEST_GAMMA_Y_C1)
            mstore(add(q, 0x160), REQUEST_GAMMA_Y_C0)
            mstore(add(q, 0x180), mload(c))
            mstore(add(q, 0x1a0), mload(add(c, 0x20)))
            mstore(add(q, 0x1c0), REQUEST_DELTA_X_C1)
            mstore(add(q, 0x1e0), REQUEST_DELTA_X_C0)
            mstore(add(q, 0x200), REQUEST_DELTA_Y_C1)
            mstore(add(q, 0x220), REQUEST_DELTA_Y_C0)
            let ok := staticcall(gas(), 0x08, m, mul(add(n, 3), 0xc0), 0x00, 0x20)
            if iszero(and(ok, eq(mload(0x00), 1))) { fail() }
        }
    }

    /// @dev The batch Groth16 verification of n ≥ 1 withdrawal statements, all or nothing: reverts
    ///      unless every one holds. Each item gets the single verification's checks in its order
    ///      (narrow fields: an empty revert; proof words, then inputs, canonical: InvalidProof()),
    ///      and the equations are combined with r_0 = 1 and 128-bit Fiat-Shamir challenges r_i =
    ///      keccak256(seed ‖ i) >> 128 (i ≥ 1), seed = keccak256(BATCH_DOMAIN ‖ WITHDRAWAL_VK_HASH ‖ n ‖
    ///      every input word ‖ every proof word), the bytes the loop reads: Π e(-r_i A_i, B_i) ·
    ///      e(Σ r_i alpha, beta) · e(Σ r_i L_i, gamma) · e(Σ r_i C_i, delta) == 1, n + 3 pairs, where
    ///      Σ r_i L_i = (Σ_folded r_i) IC0' + (Σ_other r_i) IC0 + Σ_j (Σ_i r_i x_ij) IC_j is one
    ///      shared multi-scalar multiplication over the folded and generic items alike. An empty
    ///      batch and a proofs length other than 256 · n revert InvalidProof(). Memory from the free
    ///      pointer m: first the transcript (n ≥ 2), then the pairing input ((n + 3) · 0xc0 bytes),
    ///      the scalars s (18 words), Σ r L with its four scratch words, and Σ r C with its.
    function _verifyWithdrawalBatch(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs)
        private
        view
    {
        uint256 foldedX = foldedWithdrawalIc0X;
        uint256 foldedY = foldedWithdrawalIc0Y;
        uint256 chainId = foldedChainId;
        uint256 vault = uint256(uint160(foldedVault));
        uint256 stateX = foldedStateSigningKeyX;
        uint256 stateY = foldedStateSigningKeyY;
        uint256 clearanceX = foldedClearanceSigningKeyX;
        uint256 clearanceY = foldedClearanceSigningKeyY;
        assembly ("memory-safe") {
            // Reverts InvalidProof().
            function fail() {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }
            // Adds s · (x, y) to the G1 point at l, with the four words after it as scratch. A
            // scalar at or above the field order is refused. 0 · P is the identity, the neutral
            // element of the sum: skipped. 1 · P and 2 · P need no scalar multiplication (6,000
            // gas) either: the point itself, and one addition. The protocol version (2), a
            // close's kind (1), an escape's kind (0) and an exit's zero nextNullifier and conceded
            // take these paths.
            function addTerm(l, x, y, s) {
                if iszero(lt(s, SCALAR_MODULUS)) { fail() }
                if s {
                    let t := add(l, 0x40)
                    mstore(t, x)
                    mstore(add(t, 0x20), y)
                    switch s
                    case 1 {}
                    case 2 {
                        mstore(add(t, 0x40), x)
                        mstore(add(t, 0x60), y)
                        if iszero(staticcall(gas(), 0x06, t, 0x80, t, 0x40)) { fail() }
                    }
                    default {
                        mstore(add(t, 0x40), s)
                        if iszero(staticcall(gas(), 0x07, t, 0x60, t, 0x40)) { fail() }
                    }
                    if iszero(staticcall(gas(), 0x06, l, 0x80, l, 0x40)) { fail() }
                }
            }
            // Adds r · x to the scalar at p, modulo the field order. An input at or above it is
            // refused, as the single verification's addTerm refuses it, so no statement verifies
            // in a non-canonical form (x + r).
            function accumulate(p, x, r) {
                if iszero(lt(x, SCALAR_MODULUS)) { fail() }
                if x { mstore(p, addmod(mload(p), mulmod(r, x, SCALAR_MODULUS), SCALAR_MODULUS)) }
            }
            let n := inputs.length
            if iszero(n) { fail() }
            if iszero(eq(proofs.length, mul(n, 0x100))) { fail() }
            let m := mload(0x40)
            // The Fiat-Shamir seed over every byte the loop reads. One statement needs none: r_0 = 1.
            let seed := 0
            if gt(n, 1) {
                mstore(m, BATCH_DOMAIN)
                mstore(add(m, 0x20), WITHDRAWAL_VK_HASH)
                mstore(add(m, 0x40), n)
                calldatacopy(add(m, 0x60), inputs.offset, mul(n, 0x200))
                calldatacopy(add(m, add(0x60, mul(n, 0x200))), proofs.offset, mul(n, 0x100))
                seed := keccak256(m, add(0x60, mul(n, 0x300)))
            }
            let s := add(m, mul(add(n, 3), 0xc0))
            let l := add(s, 0x240)
            let c := add(l, 0xc0)
            for { let k := 0 } lt(k, 0x240) { k := add(k, 0x20) } { mstore(add(s, k), 0) }
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let w := add(inputs.offset, mul(i, 0x200))
                let o := add(proofs.offset, mul(i, 0x100))
                // The narrow fields, as Solidity's ABI decoder checks them (an empty revert):
                // protocolVersion (16), chainId (64), contractAddress (160), noteId (32),
                // finalBalance (128), destination (160), kind (8), conceded (128), validUntil (64).
                if or(
                    or(
                        or(
                            or(shr(16, calldataload(w)), shr(64, calldataload(add(w, 0x20)))),
                            shr(160, calldataload(add(w, 0x40)))
                        ),
                        or(shr(32, calldataload(add(w, 0x100))), shr(128, calldataload(add(w, 0x120))))
                    ),
                    or(
                        or(shr(160, calldataload(add(w, 0x140))), shr(8, calldataload(add(w, 0x180)))),
                        or(shr(128, calldataload(add(w, 0x1c0))), shr(64, calldataload(add(w, 0x1e0))))
                    )
                ) { revert(0x00, 0x00) }
                // The proof: every word a canonical base-field element.
                if iszero(
                    and(
                        and(
                            and(lt(calldataload(o), BASE_MODULUS), lt(calldataload(add(o, 0x20)), BASE_MODULUS)),
                            and(
                                lt(calldataload(add(o, 0x40)), BASE_MODULUS),
                                lt(calldataload(add(o, 0x60)), BASE_MODULUS)
                            )
                        ),
                        and(
                            and(
                                lt(calldataload(add(o, 0x80)), BASE_MODULUS),
                                lt(calldataload(add(o, 0xa0)), BASE_MODULUS)
                            ),
                            and(
                                lt(calldataload(add(o, 0xc0)), BASE_MODULUS),
                                lt(calldataload(add(o, 0xe0)), BASE_MODULUS)
                            )
                        )
                    )
                ) { fail() }
                // The challenge: 1 for the first statement, the top 128 bits of keccak256(seed ‖ i)
                // after it.
                let r := 1
                if i {
                    mstore(0x00, seed)
                    mstore(0x20, i)
                    r := shr(128, keccak256(0x00, 0x40))
                }
                switch and(
                    and(
                        and(eq(calldataload(w), PROTOCOL_VERSION), eq(calldataload(add(w, 0x20)), chainId)),
                        and(eq(calldataload(add(w, 0x40)), vault), eq(calldataload(add(w, 0x80)), stateX))
                    ),
                    and(
                        and(eq(calldataload(add(w, 0xa0)), stateY), eq(calldataload(add(w, 0xc0)), clearanceX)),
                        eq(calldataload(add(w, 0xe0)), clearanceY)
                    )
                )
                case 0 {
                    // Another vault, chain, key or version: IC0 and every input.
                    mstore(add(s, 0x20), addmod(mload(add(s, 0x20)), r, SCALAR_MODULUS))
                    accumulate(add(s, 0x40), calldataload(w), r)
                    accumulate(add(s, 0x60), calldataload(add(w, 0x20)), r)
                    accumulate(add(s, 0x80), calldataload(add(w, 0x40)), r)
                    accumulate(add(s, 0xc0), calldataload(add(w, 0x80)), r)
                    accumulate(add(s, 0xe0), calldataload(add(w, 0xa0)), r)
                    accumulate(add(s, 0x100), calldataload(add(w, 0xc0)), r)
                    accumulate(add(s, 0x120), calldataload(add(w, 0xe0)), r)
                }
                default {
                    // The folded constants: IC0'.
                    mstore(s, addmod(mload(s), r, SCALAR_MODULUS))
                }
                accumulate(add(s, 0xa0), calldataload(add(w, 0x60)), r)
                accumulate(add(s, 0x140), calldataload(add(w, 0x100)), r)
                accumulate(add(s, 0x160), calldataload(add(w, 0x120)), r)
                accumulate(add(s, 0x180), calldataload(add(w, 0x140)), r)
                accumulate(add(s, 0x1a0), calldataload(add(w, 0x160)), r)
                accumulate(add(s, 0x1c0), calldataload(add(w, 0x180)), r)
                accumulate(add(s, 0x1e0), calldataload(add(w, 0x1a0)), r)
                accumulate(add(s, 0x200), calldataload(add(w, 0x1c0)), r)
                accumulate(add(s, 0x220), calldataload(add(w, 0x1e0)), r)
                // Pair i: (-r A, B), A negated in place, then scaled; and r C into the sum at c.
                let q := add(m, mul(i, 0xc0))
                mstore(q, calldataload(o))
                mstore(add(q, 0x20), mod(sub(BASE_MODULUS, calldataload(add(o, 0x20))), BASE_MODULUS))
                switch i
                case 0 { calldatacopy(c, add(o, 0xc0), 0x40) }
                default {
                    mstore(add(q, 0x40), r)
                    if iszero(staticcall(gas(), 0x07, q, 0x60, q, 0x40)) { fail() }
                    calldatacopy(add(c, 0x40), add(o, 0xc0), 0x40)
                    mstore(add(c, 0x80), r)
                    if iszero(staticcall(gas(), 0x07, add(c, 0x40), 0x60, add(c, 0x40), 0x40)) { fail() }
                    if iszero(staticcall(gas(), 0x06, c, 0x80, c, 0x40)) { fail() }
                }
                mstore(add(q, 0x40), calldataload(add(o, 0x60)))
                mstore(add(q, 0x60), calldataload(add(o, 0x40)))
                mstore(add(q, 0x80), calldataload(add(o, 0xa0)))
                mstore(add(q, 0xa0), calldataload(add(o, 0x80)))
            }
            // Σ r_i L_i: the shared multi-scalar multiplication, from the identity.
            mstore(l, 0)
            mstore(add(l, 0x20), 0)
            addTerm(l, foldedX, foldedY, mload(s))
            addTerm(l, WITHDRAWAL_IC0_X, WITHDRAWAL_IC0_Y, mload(add(s, 0x20)))
            addTerm(l, WITHDRAWAL_IC1_X, WITHDRAWAL_IC1_Y, mload(add(s, 0x40)))
            addTerm(l, WITHDRAWAL_IC2_X, WITHDRAWAL_IC2_Y, mload(add(s, 0x60)))
            addTerm(l, WITHDRAWAL_IC3_X, WITHDRAWAL_IC3_Y, mload(add(s, 0x80)))
            addTerm(l, WITHDRAWAL_IC4_X, WITHDRAWAL_IC4_Y, mload(add(s, 0xa0)))
            addTerm(l, WITHDRAWAL_IC5_X, WITHDRAWAL_IC5_Y, mload(add(s, 0xc0)))
            addTerm(l, WITHDRAWAL_IC6_X, WITHDRAWAL_IC6_Y, mload(add(s, 0xe0)))
            addTerm(l, WITHDRAWAL_IC7_X, WITHDRAWAL_IC7_Y, mload(add(s, 0x100)))
            addTerm(l, WITHDRAWAL_IC8_X, WITHDRAWAL_IC8_Y, mload(add(s, 0x120)))
            addTerm(l, WITHDRAWAL_IC9_X, WITHDRAWAL_IC9_Y, mload(add(s, 0x140)))
            addTerm(l, WITHDRAWAL_IC10_X, WITHDRAWAL_IC10_Y, mload(add(s, 0x160)))
            addTerm(l, WITHDRAWAL_IC11_X, WITHDRAWAL_IC11_Y, mload(add(s, 0x180)))
            addTerm(l, WITHDRAWAL_IC12_X, WITHDRAWAL_IC12_Y, mload(add(s, 0x1a0)))
            addTerm(l, WITHDRAWAL_IC13_X, WITHDRAWAL_IC13_Y, mload(add(s, 0x1c0)))
            addTerm(l, WITHDRAWAL_IC14_X, WITHDRAWAL_IC14_Y, mload(add(s, 0x1e0)))
            addTerm(l, WITHDRAWAL_IC15_X, WITHDRAWAL_IC15_Y, mload(add(s, 0x200)))
            addTerm(l, WITHDRAWAL_IC16_X, WITHDRAWAL_IC16_Y, mload(add(s, 0x220)))
            // The last three pairs: ((Σ r) alpha, beta), (Σ r L, gamma), (Σ r C, delta).
            let q := add(m, mul(n, 0xc0))
            let sum := addmod(mload(s), mload(add(s, 0x20)), SCALAR_MODULUS)
            mstore(q, WITHDRAWAL_ALPHA_X)
            mstore(add(q, 0x20), WITHDRAWAL_ALPHA_Y)
            if iszero(eq(sum, 1)) {
                mstore(add(q, 0x40), sum)
                if iszero(staticcall(gas(), 0x07, q, 0x60, q, 0x40)) { fail() }
            }
            mstore(add(q, 0x40), WITHDRAWAL_BETA_X_C1)
            mstore(add(q, 0x60), WITHDRAWAL_BETA_X_C0)
            mstore(add(q, 0x80), WITHDRAWAL_BETA_Y_C1)
            mstore(add(q, 0xa0), WITHDRAWAL_BETA_Y_C0)
            mstore(add(q, 0xc0), mload(l))
            mstore(add(q, 0xe0), mload(add(l, 0x20)))
            mstore(add(q, 0x100), WITHDRAWAL_GAMMA_X_C1)
            mstore(add(q, 0x120), WITHDRAWAL_GAMMA_X_C0)
            mstore(add(q, 0x140), WITHDRAWAL_GAMMA_Y_C1)
            mstore(add(q, 0x160), WITHDRAWAL_GAMMA_Y_C0)
            mstore(add(q, 0x180), mload(c))
            mstore(add(q, 0x1a0), mload(add(c, 0x20)))
            mstore(add(q, 0x1c0), WITHDRAWAL_DELTA_X_C1)
            mstore(add(q, 0x1e0), WITHDRAWAL_DELTA_X_C0)
            mstore(add(q, 0x200), WITHDRAWAL_DELTA_Y_C1)
            mstore(add(q, 0x220), WITHDRAWAL_DELTA_Y_C0)
            let ok := staticcall(gas(), 0x08, m, mul(add(n, 3), 0xc0), 0x00, 0x20)
            if iszero(and(ok, eq(mload(0x00), 1))) { fail() }
        }
    }

    /// @dev IC0 + Σ c · IC over the constants every proof of the vault carries, for both keys,
    ///      by the routine the verification uses: a constant at or above the scalar field order
    ///      reverts InvalidProof().
    function _fold(
        uint256 chainId,
        uint256 vault,
        uint256 stateX,
        uint256 stateY,
        uint256 clearanceX,
        uint256 clearanceY
    ) private view returns (uint256 requestX, uint256 requestY, uint256 withdrawalX, uint256 withdrawalY) {
        assembly ("memory-safe") {
            // Reverts InvalidProof().
            function fail() {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }
            // Adds s · (x, y) to the G1 point at l, with the four words after it as scratch. A
            // scalar at or above the field order is refused. 0 · P is the identity, the neutral
            // element of the sum: skipped. 1 · P and 2 · P need no scalar multiplication (6,000
            // gas) either: the point itself, and one addition. The protocol version (2), a
            // close's kind (1), an escape's kind (0) and an exit's zero nextNullifier and conceded
            // take these paths.
            function addTerm(l, x, y, s) {
                if iszero(lt(s, SCALAR_MODULUS)) { fail() }
                if s {
                    let t := add(l, 0x40)
                    mstore(t, x)
                    mstore(add(t, 0x20), y)
                    switch s
                    case 1 {}
                    case 2 {
                        mstore(add(t, 0x40), x)
                        mstore(add(t, 0x60), y)
                        if iszero(staticcall(gas(), 0x06, t, 0x80, t, 0x40)) { fail() }
                    }
                    default {
                        mstore(add(t, 0x40), s)
                        if iszero(staticcall(gas(), 0x07, t, 0x60, t, 0x40)) { fail() }
                    }
                    if iszero(staticcall(gas(), 0x06, l, 0x80, l, 0x40)) { fail() }
                }
            }
            let l := mload(0x40)
            mstore(l, REQUEST_IC0_X)
            mstore(add(l, 0x20), REQUEST_IC0_Y)
            addTerm(l, REQUEST_IC1_X, REQUEST_IC1_Y, PROTOCOL_VERSION)
            addTerm(l, REQUEST_IC2_X, REQUEST_IC2_Y, chainId)
            addTerm(l, REQUEST_IC3_X, REQUEST_IC3_Y, vault)
            addTerm(l, REQUEST_IC5_X, REQUEST_IC5_Y, stateX)
            addTerm(l, REQUEST_IC6_X, REQUEST_IC6_Y, stateY)
            requestX := mload(l)
            requestY := mload(add(l, 0x20))
            mstore(l, WITHDRAWAL_IC0_X)
            mstore(add(l, 0x20), WITHDRAWAL_IC0_Y)
            addTerm(l, WITHDRAWAL_IC1_X, WITHDRAWAL_IC1_Y, PROTOCOL_VERSION)
            addTerm(l, WITHDRAWAL_IC2_X, WITHDRAWAL_IC2_Y, chainId)
            addTerm(l, WITHDRAWAL_IC3_X, WITHDRAWAL_IC3_Y, vault)
            addTerm(l, WITHDRAWAL_IC5_X, WITHDRAWAL_IC5_Y, stateX)
            addTerm(l, WITHDRAWAL_IC6_X, WITHDRAWAL_IC6_Y, stateY)
            addTerm(l, WITHDRAWAL_IC7_X, WITHDRAWAL_IC7_Y, clearanceX)
            addTerm(l, WITHDRAWAL_IC8_X, WITHDRAWAL_IC8_Y, clearanceY)
            withdrawalX := mload(l)
            withdrawalY := mload(add(l, 0x20))
        }
    }
}
