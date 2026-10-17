// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title Groth16ProofAdapter
/// @notice zkAPI verifier for circuit zkapi-v2-concession-v2, setup dev, generated from its
///         verifying keys. Verification is standard Groth16 over the 12 request and 17 withdrawal
///         public inputs, in the order of Types.RequestPublicInputs and Types.WithdrawalPublicInputs,
///         and over the 3 + 2K inputs of the K-note insertion statement (K = 1, 4 or 16); inputs of
///         0, 1 and 2 skip the scalar multiplication.
contract Groth16ProofAdapter is IZkApiProofAdapter {
    /// @notice keccak256("zkapi-v2-concession-v2"): the statement this adapter verifies.
    bytes32 public constant CIRCUIT_ID_HASH = 0xcbe7e9ff73a9d6e589b63f04856d01d48cc2306851a024a7621aab30a50488c1;
    /// @notice keccak256 of the request verifying key (arkworks compressed bytes of request.vk
    ///         without its header). Identifies the setup.
    bytes32 public constant REQUEST_VK_HASH = 0x78ee5bb1fd0d0eeedfc36e769a24e36b9df6e6464154344e57824f4812fd4496;
    /// @notice keccak256 of the withdrawal verifying key (withdrawal.vk without its header).
    bytes32 public constant WITHDRAWAL_VK_HASH = 0x8ea30a21c1727fdc919a895dcd76c968f869055539e9212066988f1678d0ac30;
    /// @notice keccak256 of the 1-, 4- and 16-note insertion verifying keys.
    bytes32 public constant INSERTION1_VK_HASH = 0xbfe4bbfa7e02e038151d9cbfd804bbed7d3778cea9e235698da7af9bd08ead38;
    bytes32 public constant INSERTION4_VK_HASH = 0x2b2aec8bfe7f9bb89197afbf0956a72f93ddc8fff3618fa4b2e4dbb38da69414;
    bytes32 public constant INSERTION16_VK_HASH = 0x2433029b1c075abbd406f222554051dd40cbad992ca650c3d7f0f3ba8839aa9a;

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
        uint256[17] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.registrationCommitment,
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
            uint256(inputs.validUntil),
            inputs.noteMetadata
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyWithdrawal(values, parsed)) revert Errors.InvalidProof();
    }

    function assertValidInsertion(uint256 count, uint256[] calldata inputs, bytes calldata proof)
        external view override
    {
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyInsertion(count, inputs, parsed)) revert Errors.InvalidProof();
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

    function _verifyWithdrawal(uint256[17] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _withdrawalIc(0);
        for (uint256 i = 0; i < 17; ++i) {
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

    /// @dev The K-note insertion statement: [oldRoot, newRoot, firstNoteId, C_0, M_0, ...].
    function _verifyInsertion(uint256 count, uint256[] calldata values, Proof memory proof)
        private view returns (bool)
    {
        if (count != 1 && count != 4 && count != 16) return false;
        if (values.length != 3 + 2 * count) return false;
        G1Point memory accumulator = _insertionIc(count, 0);
        for (uint256 i = 0; i < values.length; ++i) {
            uint256 value = values[i];
            if (value >= SCALAR_MODULUS) return false;
            // 0 · IC is the point at infinity, the neutral element of the sum: skipped. 1 · IC and
            // 2 · IC need no scalar multiplication (6,000 gas) either: the point itself, and one
            // addition. The protocol version (2), a close's kind (1), an escape's kind (0) and an
            // exit's zero nextNullifier and conceded take these paths.
            if (value == 0) continue;
            G1Point memory point = _insertionIc(count, i + 1);
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
            _insertionAlpha(count), _insertionBeta(count),
            accumulator, _insertionGamma(count),
            proof.c, _insertionDelta(count)
        );
    }

    function _insertionIc(uint256 count, uint256 index) private pure returns (G1Point memory) {
        if (count == 1) return _insertion1Ic(index);
        if (count == 4) return _insertion4Ic(index);
        return _insertion16Ic(index);
    }

    function _insertionAlpha(uint256 count) private pure returns (G1Point memory) {
        if (count == 1) return _insertion1Alpha();
        if (count == 4) return _insertion4Alpha();
        return _insertion16Alpha();
    }

    function _insertionBeta(uint256 count) private pure returns (G2Point memory) {
        if (count == 1) return _insertion1Beta();
        if (count == 4) return _insertion4Beta();
        return _insertion16Beta();
    }

    function _insertionGamma(uint256 count) private pure returns (G2Point memory) {
        if (count == 1) return _insertion1Gamma();
        if (count == 4) return _insertion4Gamma();
        return _insertion16Gamma();
    }

    function _insertionDelta(uint256 count) private pure returns (G2Point memory) {
        if (count == 1) return _insertion1Delta();
        if (count == 4) return _insertion4Delta();
        return _insertion16Delta();
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
        return G1Point(0x269c0676bb9a380ecb7915a3be60622829c825e9e2f2958f8cb95082bd42585d, 0x00b1233e834c43adc5887fc245b92d29a36d03f4b831db61c139e0c91e714ba6);
    }

    function _requestBeta() private pure returns (G2Point memory) {
        return G2Point([0x2c89093f48e9c799456f2364577e9fe00f3a96dae65b0efd488a5ca5fdbfbac8, 0x25376a78731130126c4298e75810029fbcbe272bca32842d8442bb1169d092c3], [0x1f1d882597adcf44b2af3db54318f6be66accaa2a445a2142ff9aa212a685da8, 0x1340e1f48449bcb895291e7060aa88243c4c3d528c2ad157a733f9a6d67cccf9]);
    }

    function _requestGamma() private pure returns (G2Point memory) {
        return G2Point([0x1f13c26cfdd5d27cae8a54295276b81d0fb66606783447e7a1c49feeae5592ad, 0x15ccbf19d2db7f3c342e260df595bccb59f04fe208d33c0603fd72993278b51e], [0x1c46838e78fe81ee0ab89c20162b90cb99f283101b029324bd445fa71e36bec8, 0x1b247adf53d9644d2d38a8e82e05c753b432425026b144b5a171893bf5260b68]);
    }

    function _requestDelta() private pure returns (G2Point memory) {
        return G2Point([0x1d2d98162e6b8c17a6a36c692aa2e4f69f90ad328b6efa85d090c82b75075d1e, 0x1453e84644a9bf33fa7b057daa115d496608adc7fdbc7b751452bd2795b80c8c], [0x166a0bf73c0fb57466efd832314b1dfc7491e5a303c32249fd8ddc76629c1cd2, 0x2db0612a3d5e0d671a5fd5700cd746d94d501ae3e1f1667c8c40c4a4df62ce0a]);
    }

    function _requestIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x2e04b3b04360cf863b9c968725e7d73bfdb419ff9db1a91c377c647462e805e9, 0x2e0c21b186a8bbb34006a8eead4727a1051ad08354bfb1482f04fd6779bf4e25);
        if (index == 1) return G1Point(0x04c27a8e4a6529d2f242f575150a820275c77ba36d55f5a583c231bd7e62f04a, 0x03f6d1ab054d5296ade5bae8530bd7b56a6933382ac1715b4a471ee833ad809d);
        if (index == 2) return G1Point(0x02d116b32c45c911428d4316b9047d9aca54a88a24298ba2d80cfe21ed5056ce, 0x233c8463c92af6813c454b2e3b9e533d9fbb4e7c6c402858137bce5f6ceec9d1);
        if (index == 3) return G1Point(0x06d9e214ffb6317410401d1655eea12c5584f59d1993be6722f11a25a4b25794, 0x297543826d391572d50255d20b03df427e75fb219fd7340afd16f9c90aea97ef);
        if (index == 4) return G1Point(0x07d8756db0e70d960334c710326afd40a4c5b526a20a919534aa7f08cc00c2a0, 0x10268869c15d954bcfa6a5823b5d860a794e152dc84b94306ce325a5258bc428);
        if (index == 5) return G1Point(0x208e1fee847f789dd63bb8911674392a9818040f598c1184632eea2ff3a76ba5, 0x249a0304670f9282731b5ff8ca12c6f2f9c94f464d9a357a8116c09667862d12);
        if (index == 6) return G1Point(0x300c34b50bc87412326fa5e2426b1f9f6b4c33e0760d1754315b0123b849c666, 0x2f10e1fbe468e58c1a48877052b9c28372b74b3263df1ca4ed168da96df36e5e);
        if (index == 7) return G1Point(0x02e34e79ab8089db4f3b2eb97b4608f5d9ba26b92b1a66b11cdc352d41367882, 0x297b895db384a8eb92cf41e80948b2d396e1748f7aa31f13f8105283d86e2c96);
        if (index == 8) return G1Point(0x2b3c18860c49a6ce9b9e92d41ce0d1b6b86251c7cc43845bb1045cf2b6ffd94f, 0x16080e28cf46832c1e6c6be084b92b0d482fd3ff6077e14e5c11b4053ecd07b8);
        if (index == 9) return G1Point(0x1af871188a9431d884ec651430dd1517b49858fd69da272f521dd631a819aae0, 0x183f9dcde6eaf912da24b67cc0cc46dbd91f957cfca92ccbf5e71bc303c94dc0);
        if (index == 10) return G1Point(0x0ac6ed3732df97b8996d0a1e22802cbd9d4b56d613b8c41ca458ec4aeb38abb6, 0x12e84ab2db98bf93c507ace6e98f45c2ef31534abc4eae729270925f2da5771a);
        if (index == 11) return G1Point(0x2c46b132cf7498fa44cbda6a1cce884beade78cd3ce0014c984302d0aeaa715a, 0x10bc355b8077ebb17556de976cd7de36fcc2075c34e1d3f6c1f39779c49fdee0);
        if (index == 12) return G1Point(0x1380b5c5df3e4a1815f8e2be8ec87a8f58cf1bcd72d278cd06403330fec0ccd0, 0x10079cc2906142b83fd2f68fff9b7a00ae8edae6e3b959b46daea0eaebcd2740);
        revert Errors.InvalidProof();
    }

    function _withdrawalAlpha() private pure returns (G1Point memory) {
        return G1Point(0x22b7c70519b2dc5e316010871583207b737016d64a9e6657d8a6b26d78a6e9f8, 0x0d8c0bc5f1954ef4f1f7ce79609d91b28d1eaae0500ee794fdc1332cdb26e098);
    }

    function _withdrawalBeta() private pure returns (G2Point memory) {
        return G2Point([0x13bc867595144ccae3716c7fbb3e1465a6aeacebc9431c64cb754a637f6a2ce8, 0x2d9c8396b42fe7787a26521f70b65b3e61882141e4b9760c1299344b8ad9c808], [0x2b6452607703aa237292c392f4affdccd08edfb1e89cb72fab9c61776bbf40c0, 0x036109d3e98ca779da09e5980ee65b8d735d73a4a5d8d9fa235ab35eb43085c2]);
    }

    function _withdrawalGamma() private pure returns (G2Point memory) {
        return G2Point([0x22ac490aea790e97ee0870b37b04ff2ad419e2ebe0c1859e31fd359ea8ccfdeb, 0x191d1b53571c119900db95efb029bf90c17090a1d62a9f9eb1c996b00d3f044b], [0x13713b68985399895b65cedbe3bffba5c73ea8a9cd6f9cbd99ec253e68f925f7, 0x12ed5daec9cdc2ba8c9e319594f91c11049d3e3cfd815d0d8f888d461b3310cc]);
    }

    function _withdrawalDelta() private pure returns (G2Point memory) {
        return G2Point([0x175e4ec273cd64d802e6b7d08917e4a5a6170b530239b87f09a6b2c7c1e209e5, 0x283d0aad835015a7f7ccbc130c6b072d7ade727d820d1cab09e480b458d519f0], [0x01835279cd99bda7eb4fa12ef276549d44b4ffda89d565c4d216de228d65ef0f, 0x154b813673406b0397857dc6fc757241cd7d598ebad1be19b0a761ce12d0f617]);
    }

    function _withdrawalIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x075f2803b2b98614736cd66067ffc3e6a9459caff8bf738b03e3acb94be1c6e9, 0x2064f88b9787d2881b629ad0b619c415a3473b088f54c3b5d4a5a118e5cfa852);
        if (index == 1) return G1Point(0x28ce752bde79ba68191e7c3779adbb1d292a9e936dedbacc6deb9a37faf478b7, 0x169d33ebdd227394d73ffbd7b826a2365b7c419058c93c42233b3a2fb55fa84c);
        if (index == 2) return G1Point(0x24572f1c7fc3cf988bb5a273611dc70c20eba9fbad19314c2db1d7c3ea693ccf, 0x0e98d446d6059a1a1b9a5dec7bcdc05b00d940a4bc1a9f4391676cc9754d12fe);
        if (index == 3) return G1Point(0x00dd1da48526b047920a27b89873bda4a9632009e5e96876633502f9d87d57df, 0x217e2a1cad908d78be28fa0219ec5e1bcd0642329c8381e899c7c2f5c4249f75);
        if (index == 4) return G1Point(0x255544cc1cc1be33c91c2426200a4fe26be74a6529b2accc00aff0c4c8dd93b5, 0x03e5823e8dcd47218eaf4a9e441a2d6326454789eedf42464454bc2c12cc108e);
        if (index == 5) return G1Point(0x1f9d153b199af4684f462f8c990dc4c79a3fb67158e44fcebfcc880f4d2d15e4, 0x0e303ed6a55c3bb1f2b9e8ca1b2f2796c4866faa81e1daff73b3f506bd5c3a62);
        if (index == 6) return G1Point(0x2341a2595b407df564fcc1b703f60e9dae33582b3cf73885c5343a49af49d52c, 0x277414ce4f6b75d52189a74ab2714ec6a6c565c5386150974ed0bdf1a3e4be10);
        if (index == 7) return G1Point(0x181b82c458d9b86d21e35e7f6a383653ebf84a4b0001b8db11cb44522b990323, 0x2ce72844e4f6611e1470096a535e1b00ae7867fbba17d0119f58bc3a1e88366f);
        if (index == 8) return G1Point(0x1c7e07d4f8bd120e4bef09248d08a76ff0f5e4828168f2479ff8ae0ae19efd41, 0x0995fd9c376345dce68529bfbb790202da24bc6786478e8d37a026402721fd5c);
        if (index == 9) return G1Point(0x134eab6e1e225fbcb2952376d4c57c1a9401227ce43c4bc55324c8c710e8d56c, 0x12ee3e05d2e38bd2d554164fffee643f6f9d536eb9b42d362878c50a7f8eeb34);
        if (index == 10) return G1Point(0x1407011b8cce802c25eefa500036cf37ec66b7708b5c6c67a50740f098aff343, 0x0b909a01bc9e31349c6493c9f31f293b6229198830c3c7d6d01f9a89c6afd7b2);
        if (index == 11) return G1Point(0x0cfe52c144f7620fbd65826bb14e45cbd60789bb74479c42c8fa19a8f4e11810, 0x126d6b72ae61014321199013d0fe9138fc0f0959a9188ba1e99337e4b32880f3);
        if (index == 12) return G1Point(0x03899ae7a7a9ee69698ac42cb5d5a579c80757954fef6d69768536c0f1c1c85c, 0x1512609da44554a2613a43aa7958a4d7a126944c7f1a1760b1c3ce8038d00501);
        if (index == 13) return G1Point(0x22b93f5981c4f4284138119f101ff562d66651e76409cb33d6b5a636156ea8e4, 0x161ae7db07fa1cb617a45ae11fdb4679eec3b3a99ab0fc22d81be2d593cf829a);
        if (index == 14) return G1Point(0x03042f741d2cdfaa5fc1f55d94ba60d97ef850553146eebfa77e157be13629fa, 0x0a40fa621ad4a9950a8b48d60a12a5b5cd3c49cf94f0eb9d647b319830175408);
        if (index == 15) return G1Point(0x224260c9dec2e7348489f854379ac3feb4ac4fbe71c6675bfc228c4cefe2ccc2, 0x0adff5970acd81d70c055629fe4b25954bce0fc0667b1f143cef12e8431c4574);
        if (index == 16) return G1Point(0x17a53959078dc858ca1a524628270401b24fff3878ae6a29b9e52f569f5c83ca, 0x07be361f7f64774fcf903021d875350e965b3ac47d749d4c3df1d64a1d3c14e5);
        if (index == 17) return G1Point(0x1e4c299e68b77b73aad6e7151f714356d79e6417856279b53699f16ba6e31b8a, 0x2b52e0b347454fb00e8464a0d380b1af8be0b580d78db3fd8ae9395333269a61);
        revert Errors.InvalidProof();
    }

    function _insertion1Alpha() private pure returns (G1Point memory) {
        return G1Point(0x24754cc94670171e3a48bad5d70e6c1af79e69f1f1bd392920ae4fc67575779b, 0x0e4d4d8f2e66763368289a5da69f12882c468fae1fcaf3bdc2b091bf53963607);
    }

    function _insertion1Beta() private pure returns (G2Point memory) {
        return G2Point([0x2262e9e167399254a60a7c560c71c7d57c6ecd8c0c79d7b0a26b16fd8867e274, 0x01bdabc1949c5938c8547dd5be24e3bf66f2d96b7b97920fb05b8a4e67351162], [0x1492a696afac12befd0bea2e32e41aa229ac40a9bf45183d5bb217df0790d0a0, 0x275735a9bf6f4f094ef616a5d6ee734e2e9c5774ee0debc9df2177ece3105ae8]);
    }

    function _insertion1Gamma() private pure returns (G2Point memory) {
        return G2Point([0x092ceb63232178e383e258ef81a9ddc474ee844e7f3b32dca8d70773c8a6380d, 0x1cd166ec9bdd87f22de44eb67c149016d5a20c8a8a864c3146197eea8fe56823], [0x20d2880a0cc4d163506573ea5294c53e87dd8dd0f62ea36562feb6cf112c04a3, 0x1106d0d02b9a7e24e87f6757fd7a333612ad32f62608e0bdd13cf718ab4a04a2]);
    }

    function _insertion1Delta() private pure returns (G2Point memory) {
        return G2Point([0x01b0d75568ea950ddc32b59bfd0e819291d5fb1c9b71640a58b2d70bb36950ee, 0x1c4def100ad60170c3226b58ecf5fdb2dde54379fdfe8840ef3cd9deca4f85ed], [0x153961c687a005ded53cbe3258a94a305f7b75d925e8fbac61b9923bedfdf405, 0x0d39eb351f9567b37bdfbcfa318289dfd7e2c2ec7e13c531d89766fe4ad62fd9]);
    }

    function _insertion1Ic(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x00d3db5b0c05f4afd5084737c848a564c4a1416133fde23d33076ded457dbeb4, 0x14626dd5f9c7c6eab71847fb94a419e2ce3123430caf7fe12ffe226ed0d8d66a);
        if (index == 1) return G1Point(0x2f8d39ea4ed6ebaa1cce2e4ced805f2fb71230a5c2502ffb00042144b1e6b52b, 0x0775a5a3310e07fe5e580d30ad1b9dff7328a368eaceb2765a4e8568178c47a3);
        if (index == 2) return G1Point(0x14d2ca686078054436c8a38ce87b02d145e3d0ad39bb867e455ee131b5a430b6, 0x20013507a04a82514283ceafc0a3114c50a3275e8fd907d9a131346d1996a41c);
        if (index == 3) return G1Point(0x231b495b5e7a6df0d12198658e8910954a92d6afde830b8be82ed1c19a857b0b, 0x156ea6d822a7415b5e7e16a5a6269962f502f0b2677a1c04110b9a282aaab74f);
        if (index == 4) return G1Point(0x1535a17a267ccd23ce6dae47824a357b72bfa659f9cd813009f476c5b4a7ffda, 0x0b5c5c3a1df9e31314bb4c0adaf93ee064cd1646797f81bd327419b3e16afdc7);
        if (index == 5) return G1Point(0x059910f50c25b9f4063ef4eb520ba9b5dcf0dd55726267ea32d985ed88abeddd, 0x04def3b2c9555c530add6300192a04fab6bbcfde860769b935a9efcaef11cfde);
        revert Errors.InvalidProof();
    }

    function _insertion4Alpha() private pure returns (G1Point memory) {
        return G1Point(0x29654627b0b2c2231a14bd98dcf0aff34df15ff32088ad38ba96eea839b2ce20, 0x0c047a0086a7171c97c81401d82f682cf424ab4e0af03cdc58d94160600c5a3a);
    }

    function _insertion4Beta() private pure returns (G2Point memory) {
        return G2Point([0x1f7f2d2fed2d0517247b62c95296141a40f3ec08e2850e9046d2cd76180d83f8, 0x01b167d992fb1ddb9a2abd51aa765972d415227059015916acd8bcc894a5cd59], [0x1bb757d8d989752907809e37209973da20d59c468653c28d1bf533ad36139c38, 0x289592a998ab82fae65e9dfd0bac100e802f19db01c396104f3e6d705333e60f]);
    }

    function _insertion4Gamma() private pure returns (G2Point memory) {
        return G2Point([0x141a6691bd5a8f84760d98458ffdedfc5573fb95942eb60a40c68d3033a522bd, 0x114eddbdeed5827dc0a57b4de61d13758622557521e612603235631b668c8c16], [0x2b45a582c8ade78bcfd6964869e7717632ae384d97844a2799307315f11d0bcc, 0x24e24974598e7607c69650a3503e49d21caa150fd88c37945d6efce972560c39]);
    }

    function _insertion4Delta() private pure returns (G2Point memory) {
        return G2Point([0x1878c10463967484c5064bdeb32856221b24e28e5771606e2df5c355649ce5dd, 0x05469506174029ad637aa9769c59c413750f9fb00d88a1079879865d590d998c], [0x06dc848441349d1cbd9eca41d1d3a62137f78c91ca683f318b047cfbaf5f3267, 0x1b8d4c32b7a123ad09c6491d79a730aa3f3bcef2dc920eca3d88984c9b9076a5]);
    }

    function _insertion4Ic(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x23f0b72bd384ee238da6c9ecc7d0de7d13bd3fa8ff35ec7ac1c1bd5d148505ec, 0x1f0a136327d9af37a8ef0ac432848c5aac3f7ffd9cf1a4b162bbecf24175acd5);
        if (index == 1) return G1Point(0x235bd5b6fa9003630355dee3c310c5a947f9fdb03a50583253ed824719568757, 0x2ebdae6c3a98fd1d40286adda69da39b1a65a94d01e1c74fd53142aa7034f43c);
        if (index == 2) return G1Point(0x195f598117a19495d27b86a324dc7f827e05cd7465495ab75c874a32e04c85e3, 0x0a692c4d586172ba1ed7dcb50bbc09f4a8df2a73e2a9c2a1a6d1e4429f64eabe);
        if (index == 3) return G1Point(0x2d09d57585e7034f18f9cb01d383b55c382a19bb10463f0fb7fdda4314cc0d13, 0x1650f99b98520fffe50a5130058e0bd9d06948053bc735badbf5c3a9b80487c9);
        if (index == 4) return G1Point(0x0c2fc72197962f16e409924176a6023db45e89c13ac52a066512abf13c74fd0c, 0x13203cb4c53050c481ca2f9d23da42fd1464774aabb4d4c65687847691a86063);
        if (index == 5) return G1Point(0x0611805ebd723ea108ace386bee7f7c248ca6b652175d4d8a1374fa6f038ff2c, 0x139fbc9ac5c0f63e9c80b932c39e559dc615404e55a2cf5f73da5c9daab9919c);
        if (index == 6) return G1Point(0x034f62a0b37e6c398ee8562c50e27071bd07544e3338b762e6883e5ae470c960, 0x160d21cd080ec428108fa5ddc5a907b83ae18f0e462ed00b96cd71dc3644fe0c);
        if (index == 7) return G1Point(0x13f4f93ae1708e805573c92a2839061958715ffb5459234d20e6e8ff8da084ba, 0x2c7c652db1a9e50e9e93133402b1a898996392b2e5b21a2f5bb38832dfa3c16d);
        if (index == 8) return G1Point(0x048b136ac2c4e6e03f6ee7bb5193f510d440420418b8cd7f37a52d417a0e39d5, 0x052ff68b53b513e9fbabf553d83b65c5a193bad8d14593b487e3bb0d0df1dc96);
        if (index == 9) return G1Point(0x26ec722b4ac045a2c20fc178f3d6f03a8bcb8270ebe4f943e919403b7bed0d73, 0x0276d1d07b76a8078a2bddade81039d78a8dec03a5107118ab19cb61a69ab8bc);
        if (index == 10) return G1Point(0x1d38675f1f974fe2f30ab17d7e0b9ebfdb372245382ceeb9ec7a354a28a47020, 0x0d2dc6783729bab9dd6dbf228896105a5bd592a21d742d09c172f01e43af0cca);
        if (index == 11) return G1Point(0x2786e686b2652fa28e254446bb31f4d36dc6d23fa9f4f5f222b4c14627ac99c6, 0x1822be058654170722e3c3eff4bae1f3d129e364762f3ce2ba5457f6cfca3beb);
        revert Errors.InvalidProof();
    }

    function _insertion16Alpha() private pure returns (G1Point memory) {
        return G1Point(0x26abea33c20fcc091ecd8668e146f39259427fef47fb673348ca4a8b973b29a7, 0x1dfd0c6d38f8ff5c091c58e99f7a45225e8855b2a47bdfc74f1b1ee37248102d);
    }

    function _insertion16Beta() private pure returns (G2Point memory) {
        return G2Point([0x1069c7e4499db0326d11104646215d5a8135476c545683cb7300d5074f090722, 0x02b786dd2cda64fe2b0855ccc891335117c24b2c6cb0d2af2bf4c3d0efe5d280], [0x04c99e6cbb8eec5729c88f9ab51469c6583ef554d5f5e75a7fec000affd9ed4c, 0x1897c0af70e1af4251c52a77cf676195c57304a5387f04470c44e4e65159c7d4]);
    }

    function _insertion16Gamma() private pure returns (G2Point memory) {
        return G2Point([0x246cf7420cb79e91946c53f3f88098c90c94c9cab76873930fa4702c61ca9c7a, 0x2e0e23989c1ee270f6687822ecdf18d9aa070a31a72989decdb2241d6e6f615b], [0x24f0d650437f08da1495b570e32c33fd9487e9cc51902d45bab298df389ea6b4, 0x03048f1776dc8f35b591f9e0aa31a8e935b7f020d23b16671754e315a9eeaf8f]);
    }

    function _insertion16Delta() private pure returns (G2Point memory) {
        return G2Point([0x002d55bf122d3c8da9ef0779c24ba049be36079c727172c0434975ea20afaaa8, 0x1bd9277103aafb2d556b8855827664a48f6195cec9984eae132425669d2d9ab4], [0x14d84f02781bdf54420115f591beafa8f8da9aaaacd0da2157b202cd5df5b217, 0x0b2786b058912d125c669de344e8c4a14c426a750caa61ad898625e4015da210]);
    }

    function _insertion16Ic(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x22ef4fa08cdfeaf68af9690291dc9230d285384bf7b7ec83912f9938b643913c, 0x1291a76eb0756e0fee49a953a3d9b26fe32480598043a384730e6074bc4069cf);
        if (index == 1) return G1Point(0x2b618a7be8a7d191d1aadd7a3edca05c0518b8106f5483c8e291da12442736e7, 0x24cf73c98333cb4403db7c94a5d3855282238774d9281585fec6c127eaaf66a9);
        if (index == 2) return G1Point(0x200c4e0b3843eb131045114384d776b2ebf07e2e2e58d2b5a95d4cabda1aadb2, 0x1529209bcb96b8c9b1f875f79367aafecd96d3912365d5f43101a3d364376a25);
        if (index == 3) return G1Point(0x012b8c5e8ab605057ae70cc46b4471eff3d9a389902052525476c564c0732a39, 0x1c32b77f54fa6c58e83db4d80982d95e64328a7d0f30d0523e3582f17c260c45);
        if (index == 4) return G1Point(0x081bce4846e9c33d5bbfcd1edc09a96b9fc1540ba0a8792cb5b1ba16365c14c6, 0x0f4342dee6a05937d143ad93516aa2dfe18860e4a5dcadef7341682e50b82180);
        if (index == 5) return G1Point(0x18ab4a07a00858571f84c0a84713441c6c4b48ce16c0144a73e02aeb29977697, 0x1efd5fc9dfb9cd4b31ee086a799e8faab55a2850f4576ee6ccabc337d2c6e837);
        if (index == 6) return G1Point(0x0758524d47d1fc8a8bdf0f1f8d45343850d3478fd7fb3da9c953095a88f54401, 0x0a06305d65eaeb0b1cc924a3e9ef116ae1e1548a599ea964bd5563853d13ed88);
        if (index == 7) return G1Point(0x1649ef2cc19e1d67e83666218b562ee6952e0eb65ea319459eff57479e7f65c5, 0x2226e744dc4322ffb8d83e7262329b37ff58adaf43aa2a7ca1c7042039076120);
        if (index == 8) return G1Point(0x0d3ba4cf346fb5b5ffa8335503d2aad69fe7e86da513d0d9f5775d5a7ca5a276, 0x2f8b639b7cd949c70d61ea0b5122b18ed18764c46a4033d88897814a2ead5d4a);
        if (index == 9) return G1Point(0x0c68675c176577c081bd1f4678b26818bcf28f45da84aee0d8faa6b9a98f4cec, 0x22fa0fa84f73b3e28b18daea71efcd2641e163156470813dbd43319ad353f7e8);
        if (index == 10) return G1Point(0x2b393a4ec2eb0f824399328b4c5796496b356d9b38cd4e22cc662abd14e98e48, 0x114a8f77e8678416802ba8efb2b8aba9fc2ac6077eeefa5fcd112e6f27deb520);
        if (index == 11) return G1Point(0x1a5a398d82eb0c17d701a557a74e625b6ea227675830d31b571b645bf76cded1, 0x1cb5a13fd3520d4aede1005840e5d99c12a55c6597dec08bf288a3447b39e6ba);
        if (index == 12) return G1Point(0x0a26847b2bb8293510c19f55f3729931d6c708be2ca0ebdf9df11a6786fd4533, 0x20408f205a89b45ff6caff16eb090619a74aaaa5b8d4e68f983a4a8dcd7a76ea);
        if (index == 13) return G1Point(0x0b9b4b2eae5265a591cc1b617b71740bc712e8eebc15679c59a2ccf3301a9df5, 0x2620d2997feced21e49569349e9ba364dae3d0f3064e3d606bf5d0f91609dbae);
        if (index == 14) return G1Point(0x28b393b005f7e113be6c849a95d5225b5cd2add7e1c26f642498c988e40b7f86, 0x2c58c8ce4ec69bf99cf5ced96c71e981b233de0dda9804696b27f80b3bba88f7);
        if (index == 15) return G1Point(0x10256a53dba0e5a9e738199540be004b0157cb5db485e954571adbfdd2fe818c, 0x08aa1e39cc79a0096d6b5f1d8d12cfe4a9ebde6a05ba2a724cc26d4386fff9bb);
        if (index == 16) return G1Point(0x1e118cbc651d0d788d52da3a364303782b873862aacd9d84a7f0cfd613edeccc, 0x116f78fa51aa619d91b13c205165e305439e1d3c78be71bbfa5bd34039916428);
        if (index == 17) return G1Point(0x2f906dbc5a82ce502367fee8767b08ef995034c0451159b2dcba774d14c51088, 0x23f047e09762c3762ebb019035ceaabb652ef43db01fad5d2292d1f776335205);
        if (index == 18) return G1Point(0x22f48d55caea8721bdcf98ab9676aa4175e930f04e92832d3da681485c483786, 0x19a27923d5eab820d94dec7ca2d93951b32dbd505cdfe8ca4dfd99abfb37fbe6);
        if (index == 19) return G1Point(0x17941e2e5abdafffa05594aac1c89f78243befe6f8ab112b6e55da0f912f577a, 0x1873b9c7db101a045f3d9b5673bd9ad2b96b352c0f56770f8aa9a4c538ec1ad9);
        if (index == 20) return G1Point(0x01182cf2995748546cde85ae924a20ce5d5a22e12a058b6ce420769d050e5704, 0x2401580c3ba80716d424d650287af33eea513e75e7e14dd50039e952caf66251);
        if (index == 21) return G1Point(0x11a8904e6e74d2ea2190bb4b9afde089705f34ceca53d337b9b87eea404fd571, 0x236ae91e2a070f0b621557b3eda78e5300785b05541f2fc7bf8d1a01c08139c4);
        if (index == 22) return G1Point(0x21c8a299a6b300fe452644f55a1d0cdd96622901a3e846f5d552ec1289d9179a, 0x2f206af49ee049ff948fed6fa2cc60cda4eeae459e95376e4317c58f475eeccc);
        if (index == 23) return G1Point(0x1632388219d0b24cbbbaec89b6173f8dc0c912a622615d473f824e378c27f744, 0x15ff31b7c99fd971ac3a314a78bdbf7b2bb6f7fb9a0aaeae40325c40e44ef3aa);
        if (index == 24) return G1Point(0x23a2f39573191e519f08e46e857b903e787eb2c986fa8878b1068ca965e8a64f, 0x116f020f2b75a99447ecfeec3fdf378e8b1fca3039b62f1d4d39d595a37fb745);
        if (index == 25) return G1Point(0x17b4daf5f7daddc7d44a780d3b3af6cb906f92cdd1fc80977e2fb818e6a4df14, 0x03ffa7033e3cfce09a45c6372a7025237b70a8a8741c9edfcee834640a9aa0fb);
        if (index == 26) return G1Point(0x1daa288f85d176d3627c1c793944fc43b3a8ddd8bccf4104be4c2106d590691e, 0x0f408cddd270a3d6de126a7756a2ab12a243722b24c8ee74207a66edf51dcabb);
        if (index == 27) return G1Point(0x01cb29c2ecd3ba23b458954e6a4577aa105e7961476cf9743d9db7957c719348, 0x249204bf48250572e3188a4c3035adb780756bfa4299d511fd0f3ba4dc277ab5);
        if (index == 28) return G1Point(0x17f92a39c37f24fe0de63beff3560c2b3ff1f7f2e182e581473a3437548b1e11, 0x073b3e108fd20f9fa2d4dcf8a55246baa3a58f38807d17188a66d10da7bce944);
        if (index == 29) return G1Point(0x12e93dea9530c7748281c71934b1fcc15a14e48fd996143f32eb6e30ccab0201, 0x20dfa85d0cd2ff70c006ec7523be0d89a7838e619f2b3220b399da3a3eb3a16c);
        if (index == 30) return G1Point(0x1bed8ad89314caeb5473013e3525a284b8d1e378d87a86deb218f5e4b30a0070, 0x0dea23e2e82aaba39e66e6c9ee7e4cf7f64833830ec58990959dd0e33531ffcb);
        if (index == 31) return G1Point(0x0492273fe519ba6623e324584509e577ff104037d44202418287ea3fcac68896, 0x0b9f244eb56bc0143190da0c00d2791d481af63be14f529032328bcd15e04fa8);
        if (index == 32) return G1Point(0x12eb28d962e2783888a6a944ed28f7b274a10dce68e2e0cbe4a2d8675d18af27, 0x1d5ce56a443dac3770edc4010bed9d4c0826c753e43966ff4391664c93d3b9e4);
        if (index == 33) return G1Point(0x2df64e2e2f9da2f8832a250a8eb4d1384256941eb0112311ff54e8315b84dd08, 0x0e364a9d6954f36b34af32ac4a15efcd1a626ae6be7629eafebf7fb78def1acc);
        if (index == 34) return G1Point(0x2608090bea1be1026a993680e1c3b0836951844ca54e1c3908ea0937536d2c43, 0x060998ef1d61e79378402dd5b91717fce9657ccf7dd2f49f9ef00011ea40b064);
        if (index == 35) return G1Point(0x21ca53612782cb16dad2902d9295ad6fc39c8a0d7c09f0935734c0247dc5c1cd, 0x1b964c56b68687d000a8b8663f5e87d92f2d54e90705873543fb030d20321f10);
        revert Errors.InvalidProof();
    }
}
