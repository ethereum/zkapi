// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";

/// @title Groth16ProofAdapter
/// @notice zkAPI verifier for circuit zkapi-v2-concession-v2, setup dev, generated from its
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
/// @dev Every word is read from calldata as Solidity's ABI decoder reads it: the narrow fields
///      must be clean (an empty revert otherwise), the proof is 256 bytes and every input and
///      proof word must be canonical; any other failure reverts InvalidProof().
contract Groth16ProofAdapter is IZkApiProofAdapter {
    /// @notice keccak256("zkapi-v2-concession-v2"): the statement this adapter verifies.
    bytes32 public constant CIRCUIT_ID_HASH = 0xcbe7e9ff73a9d6e589b63f04856d01d48cc2306851a024a7621aab30a50488c1;
    /// @notice keccak256 of the request verifying key (arkworks compressed bytes of request.vk
    ///         without its header). Identifies the setup.
    bytes32 public constant REQUEST_VK_HASH = 0x38348b670fd21c8c622075f84f5c4a246f54081e09886b0a3c86c89edc01e1c8;
    /// @notice keccak256 of the withdrawal verifying key (withdrawal.vk without its header).
    bytes32 public constant WITHDRAWAL_VK_HASH = 0xc14844d3af2b29303852e7e47e642830552e0c73df3ebbed8f0d27c316be9ffa;

    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant BASE_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    /// @dev The protocol version every statement carries.
    uint256 private constant PROTOCOL_VERSION = 2;

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
    uint256 private constant REQUEST_ALPHA_X = 0x0248c5795b6781654ab9a8682cf8b967525749fda56a2739b8a43c56bbb2f989;
    uint256 private constant REQUEST_ALPHA_Y = 0x270a354015a928ee3ae05131cff080b96aa65ec55445a8aff14c8b98ecd93dd1;
    uint256 private constant REQUEST_BETA_X_C0 = 0x2f5b73907203a6823cdbbeefbfbc90656c45fe05476cca5e97e00ed2ab96d34b;
    uint256 private constant REQUEST_BETA_X_C1 = 0x1dcc16aedcab679c596ddfad77462f529820a21a7388dd5f87f1f41bc6b7f0c2;
    uint256 private constant REQUEST_BETA_Y_C0 = 0x152030b0e7bd54cad8d15914e13410b099840a09424252e59f140110cc5f2908;
    uint256 private constant REQUEST_BETA_Y_C1 = 0x1aa1462167ab5564608a299b8deb48b97589092768ffdf24b92adab2a22f49ef;
    uint256 private constant REQUEST_GAMMA_X_C0 = 0x002cb8a4b17110058c65fd992009f6c8afdad06ccc67c4705e64fcdc366968c4;
    uint256 private constant REQUEST_GAMMA_X_C1 = 0x27ab1ac38784d15943e39625e4b5777e6a756683df1d57fbe4ed2cb2a7ff20d4;
    uint256 private constant REQUEST_GAMMA_Y_C0 = 0x12764bef76f48b9a3e90c289ccbbe8452f202a7470a289fc66a2576e560cfe3c;
    uint256 private constant REQUEST_GAMMA_Y_C1 = 0x14a22d1da375d84fdf49f70791ad105d29a5f59a456dbd7f9a3d9998f0d6b1b8;
    uint256 private constant REQUEST_DELTA_X_C0 = 0x244b0bfe38f32d9d76bdf9e0e1b5ef4681cf099f01465d73c6d35d62fc3557e2;
    uint256 private constant REQUEST_DELTA_X_C1 = 0x2de26695e3e1638d33d4547303a0e0f618f6e91cd37aff92bc25568b534cb482;
    uint256 private constant REQUEST_DELTA_Y_C0 = 0x235ca3481e52716905d5cc0dc4f76675af8608b352f97478938f4acb4636bf85;
    uint256 private constant REQUEST_DELTA_Y_C1 = 0x15ef48bafe544725e5e0f90bdc9ef2ec78ecb7108dabd21f5281f84dffd1eb74;
    uint256 private constant REQUEST_IC0_X = 0x035c577ccb218a6ab93c7380cc902999fed5bf6ea648c32f53127c1c6e473217;
    uint256 private constant REQUEST_IC0_Y = 0x0d1fb434217f254e90ded50406f4c5ac9658856c7447b557e81d50139a9fc737;
    uint256 private constant REQUEST_IC1_X = 0x0c8a0023d3760669d00feb1510c13b9ab4064241695919e2e8e995c6162bf4a7;
    uint256 private constant REQUEST_IC1_Y = 0x0077635e68a6a3508264363ed6b848b30054c69e1856009d8b1b2b639186a064;
    uint256 private constant REQUEST_IC2_X = 0x187e481ca06c1404860c69ceb3a7c362f929daef91cd8aca0f3e5f242d4592ae;
    uint256 private constant REQUEST_IC2_Y = 0x292255747c897e3b9c71f551cb61a53413aee1d02eaf20c4c9f9431263ab7b35;
    uint256 private constant REQUEST_IC3_X = 0x09dec792f95619df55385825b1bd1017b6af5a359a726339502ac453ad802778;
    uint256 private constant REQUEST_IC3_Y = 0x060c766f97fb764f442b56a5e29ecd9989c2fe267048ea2d1731121b78ac8afe;
    uint256 private constant REQUEST_IC4_X = 0x2aa95a25cef7b15b7d721326cfd8960d7406360c9e92e3b8a92a112f5463055d;
    uint256 private constant REQUEST_IC4_Y = 0x29f0334b5b56ecce4493e7367574702dce8ce1c18fc15a78a7bb085b49cc9c7e;
    uint256 private constant REQUEST_IC5_X = 0x08c4ce0779f2ccd32932d2c41c695facce4c3661de5ef25e28da4b5a25e636e1;
    uint256 private constant REQUEST_IC5_Y = 0x0baa79a2c44b16bc7643e1eeb4788762470cce2d4a56c5e3a0c9e9e19701fc33;
    uint256 private constant REQUEST_IC6_X = 0x1dc70fdc48374214aaab4d67e3296ac9b0ddae673fd53999b65dc701651f3387;
    uint256 private constant REQUEST_IC6_Y = 0x2a3c64636e43801b66a0925ef269b00956c6e7ad1f04c88fd422538507d9854f;
    uint256 private constant REQUEST_IC7_X = 0x0c2cb21ee33a5e9650b4d667b3795c59ffc21dc81e4e3518ec2a6210390fa135;
    uint256 private constant REQUEST_IC7_Y = 0x1058d704c08ec634aaf7a76fa752f451a1440a2d5696aded4a3b9e967066654d;
    uint256 private constant REQUEST_IC8_X = 0x1db5deb140e12afb652bc09216ec9430eb3dd0280b6e5ab4f617841ed0d3053e;
    uint256 private constant REQUEST_IC8_Y = 0x1e1a82842bcfbb9cefd71103ca4cdd1fcd02a363cf769e7366fb69b773313c56;
    uint256 private constant REQUEST_IC9_X = 0x16f3a7b14c5c0b48becfd0c5745c3fb15643a2b970240bd6ce9bceac7e941e58;
    uint256 private constant REQUEST_IC9_Y = 0x098ce36640c1af0d96494595eb38cce010dd81152d948ce8993b5b95c4f1dbcb;
    uint256 private constant REQUEST_IC10_X = 0x3045d3b6f856897eb5f3fb4518d0c565bb6c6eb6f89511990e09765fcb301338;
    uint256 private constant REQUEST_IC10_Y = 0x1517a0b6ce57023abe563ee5e4232d26e791b595dc523326acd651db30459b8b;
    uint256 private constant REQUEST_IC11_X = 0x23c8025cbbce2b6f5aa94c8ecb6412a42cdd95fc28a7a4915cc4ced05a5bf514;
    uint256 private constant REQUEST_IC11_Y = 0x01153fba6c65d09ec4175be872664133ad5c212facf632914f9135f3aad908ff;
    uint256 private constant REQUEST_IC12_X = 0x29c37d8253e559e79ec40a11f9032e18c7a0f6a0222f2141cb03284ba902e1a6;
    uint256 private constant REQUEST_IC12_Y = 0x29c6a217a815a5532a669faf4773e292d3d7c254f59e9d58eb0ec8ab6fb5c50f;

    uint256 private constant WITHDRAWAL_ALPHA_X = 0x254d286733b4e16713578df6882b8247e43d5cf23a5b76ab4669875eeb707492;
    uint256 private constant WITHDRAWAL_ALPHA_Y = 0x2401e469e55ff1abcf857ae787fd9fd0024a618504cad6298685a2130fe0ab5f;
    uint256 private constant WITHDRAWAL_BETA_X_C0 = 0x0cd6860a4c24070908189ca8e83cef8b6893d14492239eddae48226debe50810;
    uint256 private constant WITHDRAWAL_BETA_X_C1 = 0x098f3b7bd57dd9b40deb4e9f34e779726d07d7ae32fe33af9f3aa1165dd76eb3;
    uint256 private constant WITHDRAWAL_BETA_Y_C0 = 0x0afedd16ff93618c031ac75e9b74f4d437147e9d76d5bf3ff5ff2b2ac2ef6e3e;
    uint256 private constant WITHDRAWAL_BETA_Y_C1 = 0x2a1d5b16b0b969f889138e82bf2b461c29fdb046903d5d07cac8971fba0da345;
    uint256 private constant WITHDRAWAL_GAMMA_X_C0 = 0x0debba46a4417c88a81bbe1a0ac7aff9d6125008bc79e20345d40a302c657a23;
    uint256 private constant WITHDRAWAL_GAMMA_X_C1 = 0x23d83512e686c985f195f0af06464e5cc0d30c6d9e0f04198516ccdf72537f2d;
    uint256 private constant WITHDRAWAL_GAMMA_Y_C0 = 0x2ed3229d148b70b213918667618560ebe78dd46828e03ba53cf57933ffdad7f8;
    uint256 private constant WITHDRAWAL_GAMMA_Y_C1 = 0x1405f58f2cf1dec780c554ae96870bb3db8c2a24bfc4a5499814c947f744648a;
    uint256 private constant WITHDRAWAL_DELTA_X_C0 = 0x2f55025dbf45004ad33894ee4c55176db34726f988da27d29547223c58f1dbf0;
    uint256 private constant WITHDRAWAL_DELTA_X_C1 = 0x1f71289e994ee44661279199f8f766bc6448b7746a503a2cae29d826a7c81389;
    uint256 private constant WITHDRAWAL_DELTA_Y_C0 = 0x24f3c054f18801744bca84949feebd7a71d77b553b5ec73d5270077dda12f204;
    uint256 private constant WITHDRAWAL_DELTA_Y_C1 = 0x1429b1513cfb580a142f164365c81be6808728eabb9fd1406db269f855c1a92c;
    uint256 private constant WITHDRAWAL_IC0_X = 0x06858ba755952777468d1f19203c5d23e55179d0a95d103278ffb9157a546410;
    uint256 private constant WITHDRAWAL_IC0_Y = 0x1324a9db6035575cf11ba482b5de04c6a0ec2c980f422240618a894c43f29988;
    uint256 private constant WITHDRAWAL_IC1_X = 0x1be2ae59ad7810a42f4571b15a04c26be73a6c825ff2f158307dd4054f49a2ce;
    uint256 private constant WITHDRAWAL_IC1_Y = 0x0893b9fd9e5eb3da29d7dc5650bc9775e1047bd5e5f16db95641cbfc6791b1a9;
    uint256 private constant WITHDRAWAL_IC2_X = 0x03cb358c003494b1859fe20c82cde5581b504969b885d3e170b081ec8b68d597;
    uint256 private constant WITHDRAWAL_IC2_Y = 0x2db42f5f7fd7690842cd287efe439d97eaf4d644ddee56cdb6eb66747ba986de;
    uint256 private constant WITHDRAWAL_IC3_X = 0x01937427a118d180a1bda5acd3c00ee888fcf9ab446193754cd662eab50a2f88;
    uint256 private constant WITHDRAWAL_IC3_Y = 0x0392c0cc3dba01cc1d5bf376993008c6d4fcf381426ea1e958e47942e53f9d9b;
    uint256 private constant WITHDRAWAL_IC4_X = 0x30267214bd6a7fa6cfc409197dbf9ee55ef6ef24523512edcd523fda6e494ed0;
    uint256 private constant WITHDRAWAL_IC4_Y = 0x0f86a0caf2442505f1b2583c29ef808ddbbd0858cf157bfc5a0be13869f4ee84;
    uint256 private constant WITHDRAWAL_IC5_X = 0x22b8b4b88973567a013fe4fcb46e58c8149561b07ad6b5697e4522078b33dbbd;
    uint256 private constant WITHDRAWAL_IC5_Y = 0x178a5a7b54b5faea71d809e040e4c2f5f5e109a207684c0586c80e0d277c425a;
    uint256 private constant WITHDRAWAL_IC6_X = 0x23247387870a18c6194f56d083893a05cf8836528ea77eac5bb1d05822e0a18c;
    uint256 private constant WITHDRAWAL_IC6_Y = 0x0194fb0da74b0e9841a99458d33d95a544b6a1868ee88b9e5ecd72e2fb4e4f40;
    uint256 private constant WITHDRAWAL_IC7_X = 0x2ed45afdc24dd978aa6912264588f3e4b400d4a99386ae27dddc9599fb7a29d8;
    uint256 private constant WITHDRAWAL_IC7_Y = 0x0f26c1be69534e05c56624c0673b0ce3736061aa43a7822f4794945d3166e88f;
    uint256 private constant WITHDRAWAL_IC8_X = 0x097b8c63e192acff27bd4b87111c81d65bcbb65cd32b4c2e2d4da84192ea102b;
    uint256 private constant WITHDRAWAL_IC8_Y = 0x2419d5f5535f557f96dcbe1ce8cd377c2baa7994f9510b8eb36217950a53a16d;
    uint256 private constant WITHDRAWAL_IC9_X = 0x17a960bc39b5cea3f547ec01a2853f93500563c5c4954dfe7ff824b2c15a2f16;
    uint256 private constant WITHDRAWAL_IC9_Y = 0x072b81cb1b42a27c28c66ae9d3064c445facee0f6ef10ca6baac642e4815efce;
    uint256 private constant WITHDRAWAL_IC10_X = 0x0f995c75e9d52b37a95dc7237ce6c39623a885db135416b8da3fbaad5d5e0a33;
    uint256 private constant WITHDRAWAL_IC10_Y = 0x039585e93c027e31756f4a95a6b764f303868bc6a64f3fff10fcb4bf0a89c6d4;
    uint256 private constant WITHDRAWAL_IC11_X = 0x1d1dd0edcf71d23c732362d193d0a820889016889dc803961c53c6e13583c551;
    uint256 private constant WITHDRAWAL_IC11_Y = 0x0c5979d6ef3f544364d146f946c8244648df863e035903909dd94891f74685f0;
    uint256 private constant WITHDRAWAL_IC12_X = 0x1d472777fadecbaff89ecdedf6f9615234dfa52d4427b1d0925fe2a2755f3fb6;
    uint256 private constant WITHDRAWAL_IC12_Y = 0x12581e4b2b6fd6995d8e996d64e0fcc4488e5e3a9a0175ec486fa132d438c0fd;
    uint256 private constant WITHDRAWAL_IC13_X = 0x27d40dd630a46bc1d4c9964b43ea64aa1cf999889cc043d0cc8b21d5b0d65d84;
    uint256 private constant WITHDRAWAL_IC13_Y = 0x2e56232481c606576cbd4abb5d51de37228deb1b0bc10f66a240ad1a76f63b41;
    uint256 private constant WITHDRAWAL_IC14_X = 0x241725863842aad777ee99ad9b23d4fcb23ad4b8272dbb41bec27d5224604c94;
    uint256 private constant WITHDRAWAL_IC14_Y = 0x1c380d4954ad8cf181ccc64ee76c775623ecee389b38b22c933837290d98feee;
    uint256 private constant WITHDRAWAL_IC15_X = 0x01e48999e520b8d3fba6dc91cd5a811c282d6316bcfdc8d70f67ed2000a2aa74;
    uint256 private constant WITHDRAWAL_IC15_Y = 0x0a692300133ca921e2a6bc706b5dc38f80f8a04f71020875749c7e906b37debe;
    uint256 private constant WITHDRAWAL_IC16_X = 0x207a88dbbb3cdcf4eecf45daac9e2ff3734926d531b8d34c018b437b4ba2f529;
    uint256 private constant WITHDRAWAL_IC16_Y = 0x13ec5d37bd995e958aac22012f221c3e9404862a81696b1117cc0130e91c15fc;

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

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IZkApiProofAdapter).interfaceId || interfaceId == 0x01ffc9a7;
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
            // protocolVersion (16), chainId (64), contractAddress (160), finalBalance (128),
            // destination (160), kind (8), conceded (128), validUntil (64).
            if or(
                or(
                    or(shr(16, calldataload(inputs)), shr(64, calldataload(add(inputs, 0x20)))),
                    or(shr(160, calldataload(add(inputs, 0x40))), shr(128, calldataload(add(inputs, 0x120))))
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
