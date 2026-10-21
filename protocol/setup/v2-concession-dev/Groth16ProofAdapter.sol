// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title Groth16ProofAdapter
/// @notice zkAPI verifier for circuit zkapi-v2-concession-v1, setup dev, generated from its
///         verifying keys. Verification is standard Groth16 over the 12 request and 16 withdrawal
///         public inputs, in the order of Types.RequestPublicInputs and Types.WithdrawalPublicInputs;
///         inputs of 0, 1 and 2 skip the scalar multiplication.
contract Groth16ProofAdapter is IZkApiProofAdapter {
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

    struct G1Point { uint256 x; uint256 y; }
    // Coordinates use arkworks order: c0 (real), then c1 (imaginary).
    struct G2Point { uint256[2] x; uint256[2] y; }
    struct Proof { G1Point a; G2Point b; G1Point c; }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[12] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            uint256(inputs.requestTime),
            uint256(inputs.solvencyBound),
            inputs.requestNullifier,
            inputs.authorizationTag,
            inputs.anonymousCommitmentX,
            inputs.anonymousCommitmentY
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyRequest(values, parsed)) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[16] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            inputs.clearanceSigningKeyX,
            inputs.clearanceSigningKeyY,
            uint256(inputs.noteId),
            uint256(inputs.finalBalance),
            uint256(uint160(inputs.destination)),
            inputs.withdrawalNullifier,
            uint256(inputs.kind),
            inputs.nextNullifier,
            uint256(inputs.conceded),
            uint256(inputs.validUntil)
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyWithdrawal(values, parsed)) revert Errors.InvalidProof();
    }

    function _verifyRequest(uint256[12] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _requestIc(0);
        for (uint256 i = 0; i < 12; ++i) {
            uint256 value = values[i];
            if (value >= SCALAR_MODULUS) return false;
            // 0 · IC is the point at infinity, the neutral element of the sum: skipped. 1 · IC and
            // 2 · IC need no scalar multiplication (6,000 gas) either: the point itself, and one
            // addition. The protocol version (2), a close's kind (1), an escape's kind (0) and an
            // exit's zero nextNullifier and conceded take these paths.
            if (value == 0) continue;
            G1Point memory point = _requestIc(i + 1);
            G1Point memory term = point;
            bool ok;
            if (value == 2) {
                (term, ok) = _add(point, point);
                if (!ok) return false;
            } else if (value != 1) {
                (term, ok) = _scalarMul(point, value);
                if (!ok) return false;
            }
            (accumulator, ok) = _add(accumulator, term);
            if (!ok) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _requestAlpha(), _requestBeta(),
            accumulator, _requestGamma(),
            proof.c, _requestDelta()
        );
    }

    function _verifyWithdrawal(uint256[16] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _withdrawalIc(0);
        for (uint256 i = 0; i < 16; ++i) {
            uint256 value = values[i];
            if (value >= SCALAR_MODULUS) return false;
            // 0 · IC is the point at infinity, the neutral element of the sum: skipped. 1 · IC and
            // 2 · IC need no scalar multiplication (6,000 gas) either: the point itself, and one
            // addition. The protocol version (2), a close's kind (1), an escape's kind (0) and an
            // exit's zero nextNullifier and conceded take these paths.
            if (value == 0) continue;
            G1Point memory point = _withdrawalIc(i + 1);
            G1Point memory term = point;
            bool ok;
            if (value == 2) {
                (term, ok) = _add(point, point);
                if (!ok) return false;
            } else if (value != 1) {
                (term, ok) = _scalarMul(point, value);
                if (!ok) return false;
            }
            (accumulator, ok) = _add(accumulator, term);
            if (!ok) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _withdrawalAlpha(), _withdrawalBeta(),
            accumulator, _withdrawalGamma(),
            proof.c, _withdrawalDelta()
        );
    }

    function _decodeProof(bytes calldata encoded) private pure returns (Proof memory proof, bool valid) {
        if (encoded.length != 256) return (proof, false);
        uint256[8] memory words;
        assembly ("memory-safe") {
            let start := encoded.offset
            mstore(words, calldataload(start))
            mstore(add(words, 0x20), calldataload(add(start, 0x20)))
            mstore(add(words, 0x40), calldataload(add(start, 0x40)))
            mstore(add(words, 0x60), calldataload(add(start, 0x60)))
            mstore(add(words, 0x80), calldataload(add(start, 0x80)))
            mstore(add(words, 0xa0), calldataload(add(start, 0xa0)))
            mstore(add(words, 0xc0), calldataload(add(start, 0xc0)))
            mstore(add(words, 0xe0), calldataload(add(start, 0xe0)))
        }
        for (uint256 i = 0; i < 8; ++i) if (words[i] >= BASE_MODULUS) return (proof, false);
        proof.a = G1Point(words[0], words[1]);
        proof.b = G2Point([words[2], words[3]], [words[4], words[5]]);
        proof.c = G1Point(words[6], words[7]);
        return (proof, true);
    }

    function _negate(G1Point memory point) private pure returns (G1Point memory) {
        if (point.x == 0 && point.y == 0) return G1Point(0, 0);
        return G1Point(point.x, BASE_MODULUS - (point.y % BASE_MODULUS));
    }

    function _add(G1Point memory a, G1Point memory b) private view returns (G1Point memory result, bool ok) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        assembly ("memory-safe") { ok := staticcall(gas(), 6, input, 0x80, result, 0x40) }
    }

    function _scalarMul(G1Point memory point, uint256 scalar)
        private view returns (G1Point memory result, bool ok)
    {
        uint256[3] memory input = [point.x, point.y, scalar];
        assembly ("memory-safe") { ok := staticcall(gas(), 7, input, 0x60, result, 0x40) }
    }

    function _pairing(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) private view returns (bool) {
        uint256[24] memory input;
        _writePair(input, 0, a1, a2);
        _writePair(input, 6, b1, b2);
        _writePair(input, 12, c1, c2);
        _writePair(input, 18, d1, d2);
        uint256[1] memory output;
        bool ok;
        assembly ("memory-safe") { ok := staticcall(gas(), 8, input, 0x300, output, 0x20) }
        return ok && output[0] == 1;
    }

    function _writePair(uint256[24] memory input, uint256 offset, G1Point memory g1, G2Point memory g2)
        private pure
    {
        input[offset] = g1.x;
        input[offset + 1] = g1.y;
        // EIP-197 expects the imaginary coefficient before the real coefficient.
        input[offset + 2] = g2.x[1];
        input[offset + 3] = g2.x[0];
        input[offset + 4] = g2.y[1];
        input[offset + 5] = g2.y[0];
    }

    function _requestAlpha() private pure returns (G1Point memory) {
        return G1Point(0x0e41d816cbcc39b947acbbec578a240d71f6f0d84baa1b4055db06b0005c3793, 0x2cd0915dbb7599f0393714c1c388deb83f43bb5d2f610777ee30a9c47da131b5);
    }

    function _requestBeta() private pure returns (G2Point memory) {
        return G2Point([0x123603df7a4dcdbfc69e74856a3b4c9cd4b4798df54f4fd34a68635bfebab38e, 0x0e67a3f707f1e7cd3ca0587602f5ecfb487a4150aaed074b8d17b9e1917713e2], [0x14c71c77cf6f6d4e55e8a957830f4ee88d19cd21ec897db31b0aad4ba6fa6f43, 0x1eb225694e7bdf9e06a4afe8825787b8203289fdc512a18c89530f5398bb19db]);
    }

    function _requestGamma() private pure returns (G2Point memory) {
        return G2Point([0x243c8ae4b6d9020f398be9a4c6e7d861e9d6be0eedd09664dee2670cac521085, 0x1026ecf1c3b7c5131bb928553af0dcd45f3e37e23ae971f2ff862540bd7f7126], [0x1594c00bdef3d8c7bf8301e896a7bfae32d2c15dd72cc5f5554b9e6e57e7e4ec, 0x0c9bdd6c7adea26d6d70793f9fdc2a9d16ece6365ff8434eac63c681dd920fc1]);
    }

    function _requestDelta() private pure returns (G2Point memory) {
        return G2Point([0x23885d6c3f54f3117c570ae2d1abcbbc1d5393089490edfd2d740b9c97c07e7e, 0x0a352eb74c0c3f7dfb312b5f220e6055b0eaecd101cec6e592578419a2540970], [0x19ed0aa007774000f64282f29f33ee10cc6490e13f3bd46cf7cbec49b538cc36, 0x21a121ac7037f98ae762c17ca81422e8d5866b38dd113e2a57a8cee63e94c736]);
    }

    function _requestIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x29dc866da7e243c657d0de1583ef137c2d83404a5e6d764c1c129e1d0b81ae51, 0x13faa0669073c6aaefb44d0d09733e979f2608815c3af7c914050c23e7f114f3);
        if (index == 1) return G1Point(0x022adf9c9a3d89a4b5a3343699aa144e3ac9dce9c69f405a716ca9c410ae3995, 0x29a1c4d8d8d0586bd5e61fe41b3baf494ee1f1de531c1d0dddbb81aaa7930672);
        if (index == 2) return G1Point(0x1f0362d0d3eee2d8c8d22631870473db15fa7f5e6dfc589c268ed96fc1a79263, 0x15c569522a31fa817bed8d71a87a1d8da079a4f4ce986235f77d64b1c8bf172f);
        if (index == 3) return G1Point(0x18ce1bc5a9a174cc79b506bc9f6f1f2a0330d9f9f51e7998e6a51b666b9e7cca, 0x0e317817e9d2acddf74671564e07a4648ba607fe88827f423196128c7ad06b16);
        if (index == 4) return G1Point(0x0d1a49f5e4c81cfb0f0d247633f484f88af77fd06db5791139a85affd48c0755, 0x2d564d3ea7a8a4ebfb7f0445fe5ff38ffe1b45280c31f9dda40a9116a93f88d8);
        if (index == 5) return G1Point(0x05f880e80c12c1e3b012a391b0d70e74d948bd9fbcca126185eb9b5ad70648df, 0x0cec3847f4aecb37b1cbc76ec29518b39c0085edcbaf2e4a58461c017ac7ceb4);
        if (index == 6) return G1Point(0x27867bc2d456b2ee366b63178e06e854afb34c2c4199f184cac66570e205f97e, 0x1788a58831198d51f512afb565b974bd2727dd6a24116a8dc72bfa27d138e6c9);
        if (index == 7) return G1Point(0x105643c3617ee640173bfc9dcc8bb31a5f841208fd5558ce916a34e97898ba98, 0x0ba033fda0d9d3667eafec10f8b2d68c895d711f80e1380e3f8c67239bda206b);
        if (index == 8) return G1Point(0x302ea3ae838cc65fcf32badd1663e6a8d3a217ac7a60c56b39da231c7927bb6f, 0x06b38b47dc9b092877faba06e2092e6492645fc34d5934681b15bb7bbdc65371);
        if (index == 9) return G1Point(0x2d1867a697640bf25b0afd7d5713f904ce4a4c81ba438f937a1abb1e38d0ad77, 0x13169463799390d1b98a933b5968026e926ce668a132224e825caeec4d557749);
        if (index == 10) return G1Point(0x083c8ee4ccbdaddc98e1b62d62a44253bd660155e548ba64c061e7c74a7fef5d, 0x0090449d3855502cebdb187662d8ef7864c3c8dc52a8432a45a7e1ea559ebbe8);
        if (index == 11) return G1Point(0x2ddd41710cda2c8e86f936094a98a4ed8da149b0006c41e30cbb2514fe6e1698, 0x106857485c6108b9c2612bd85f3b6b8c841ead5981033ec02cd4648bf0cbcc4a);
        if (index == 12) return G1Point(0x0d6d874d429871f52ecc07d253c69d43ce59f191496025735267b772ab9af505, 0x10f7e6181cd8620740ba6137212a7c7cb0241dd4344c706d8d581d76fe70e16c);
        revert Errors.InvalidProof();
    }

    function _withdrawalAlpha() private pure returns (G1Point memory) {
        return G1Point(0x2166ed9bdbd9c61a47a6f602c0ac5cfbef17ca98b350205323f9f94608a6db18, 0x277a08955c058c4fb5fd53c08e7a094d1a336221446b14724f1f31e3f1a8f476);
    }

    function _withdrawalBeta() private pure returns (G2Point memory) {
        return G2Point([0x1416fa0b9fdf0482bf1b96163bb664573a7859c6613ee2485d5e4272f776e23d, 0x088a2dc33a5cb675d136ea487f615651da57178ff9bfa29346fb8d536e1646ab], [0x0849883a5afb3e2ef3c7271d372c3732c12fb3e578a542b6f086e5bb52297ece, 0x0d8c1091ed12401dc07e373bb67de5e856321d24ee4948262c3b424ac6c4ce1e]);
    }

    function _withdrawalGamma() private pure returns (G2Point memory) {
        return G2Point([0x2e7ff8f53da4536307c816b4c40d1decd534ac06aacc95de2109a4a6c5457d07, 0x1b5f2d8441eefd7a9e62d380a18a5631a5f711aa1e1441d691325fb5a1af59c9], [0x22fc60802258f0cab10fffbe417e717a7838b2634385b79e6cb63440f5882ab7, 0x02b447f81d2e5a532d15703f8d17ef25ecb51fb0a75d26e22a0ebd2c94f462fd]);
    }

    function _withdrawalDelta() private pure returns (G2Point memory) {
        return G2Point([0x1ed8e7b749cd67d171bf587bcf59fc867596c452ef776ad72c11fea946c41914, 0x1cd6a44736e1a1b9246c6716674af675ce70afb8a0719e17a1fa95fc80dde590], [0x27a63e18cba604245976b2f10bd1b3a447f206086c71c1872b2839b715056586, 0x2875c65bd2df8477b746c7b3bf8e1115c03a304e447a8a80ff7dee11c10e93bc]);
    }

    function _withdrawalIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x01ec9065d8749e451c78a4bddb0e87ef97640c665609bbba06350412ba759dae, 0x1f2389ff9e07f10296766db544d47d1852bbb00d800b2c5488c948cb6ab1aea4);
        if (index == 1) return G1Point(0x2f65d6796ce1e6547fb96295af051d0c4a31dc2a2f83f9d1c8b3ccb50504faac, 0x1cea1a47577772cc688918a353feef0d6bb7677bebe77e23b76d0f07a542247b);
        if (index == 2) return G1Point(0x1a4d60a242e61bf0fb8aad7a1679095b5402f6b429f3f380162180e05672e7a2, 0x13af3c5a6e34d7c633f484d251a803d11de9be3eccde2860d87378aae31bf20d);
        if (index == 3) return G1Point(0x1912aed3bcd481ca13c200fd68526a4e5b6bfa817d854dd5dd80f302e7ceb4d3, 0x200fc8c19651b067d3ef51686231aa30c383871322726c30c4028776a2021a58);
        if (index == 4) return G1Point(0x209837ed55b2f0b1a214d96bda695a3512cb62113d3a47d22b7507282d37bdfd, 0x0c7bf70fd82347f7febd5790a01623228ea01bc1d57e23dae9d56a5d10954a2a);
        if (index == 5) return G1Point(0x24c0111c44fa9790bbd28f7c9e1e425f2ff19b0b7109e47c63414679e44aaaa6, 0x0deabc62c530c11773096d9278f7f0170094db78dbf65b09b08fda90d7d6e271);
        if (index == 6) return G1Point(0x097d1c378f329568048ff32f8b4606d6a519e1f3039195f483ce320ff9165f1d, 0x048fcefd36e381acdf4b30c7578837e1f8364980cfe0d980c3f9c3e77ef0c7f0);
        if (index == 7) return G1Point(0x2debd0053005c26c54bb11f2ad71c140377c501e1064dfa512e1208d10d84b97, 0x2612b6f613b96fa0439207ff674ccfb292cf04fc795b4c38e628a2fde3580df8);
        if (index == 8) return G1Point(0x2c560d9a316a2236832e3eb1058dcdc9747d3f6809a749369924e94540313511, 0x13665025be7dbcd2425ec777a3cc7045c53bdbd7436c8342355e23d7826070fa);
        if (index == 9) return G1Point(0x2431a5a30f78dfbbcb11c74eba15e4c972b85eec0f168311c6f6a051d54d061b, 0x1ab3e0357014c15112d7702505ec50a83fbed56536e0fbcbffb22e067703c079);
        if (index == 10) return G1Point(0x1f8142c40f9b09b2541186da50bfb5968645ab171e93356f440bf9629ee0cb90, 0x0ec00bf558849de8cc8444456c231ec73892975780786d3d9e86192f99b83068);
        if (index == 11) return G1Point(0x0e1ba5b47631a18c9523f0cf0a4ebe45196455dc3028090883197400240c6606, 0x02fe5e8016e77949b4a1f075c33849206460cc218ebefd0d9f8f82f3d07471a4);
        if (index == 12) return G1Point(0x0f03e68245000a851f410ab4aadd0d1fbd9add7691818f881ddc4e84b7f4ede6, 0x2376f78eb5abddf5460be7594b09f737780c335113cf9e2fedcd60be3962d146);
        if (index == 13) return G1Point(0x29a4616c6a8f099cd56dff3df9c44f52d8c679ddfba79ab204d8695c6115d14b, 0x0ee4013d135b902d0fa7ab4c71000dc4e8dc3e568de9dfb5fb474a1ff025aa04);
        if (index == 14) return G1Point(0x100816372bf2241443e779c9ab6ba4804bc008bb988899e5719c4feb24b11d0c, 0x02a6815d85e3d6fa76238823da04cd26fe54475a6eabce200000bb2a2d7af1bd);
        if (index == 15) return G1Point(0x0db9c30a3a638f825fe883a6e717447b3014c7a26954c6a356d0f246aa93f7d0, 0x15cc2bb91e77add5eb87ecdd3041b42c1497713cae8fbf57ec8e8e4c6f927948);
        if (index == 16) return G1Point(0x09754e506956548f40dcc9511c046745d99563fb0e857828653d49a3669c2733, 0x24a803af39ef324b406b5bbd43d51a06c06471dac27d3caf6e2e314b56c7872b);
        revert Errors.InvalidProof();
    }
}
