// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Bn254Poseidon
/// @notice Poseidon over the BN254 scalar field, generated from zkAPI v2's arkworks parameters:
///         width 3, rate 2, x^5 S-box, 8 full rounds and 57 partial rounds. compress is the note
///         tree's node hash (one permutation, the domain in the capacity lane); hash5 is the sponge
///         (zkapi_core::v2::hash_fields) over five inputs, the note leaf.
/// @dev The permutation is in the optimized form of the Poseidon reference implementation: every
///      partial round adds one constant (the constants of the two words that skip the S-box are
///      moved through the linear layer into the next round) and multiplies by a sparse matrix (the
///      MDS matrix factored per round, the dense factor folded into the next round's matrix); the
///      hash function is unchanged. The rounds are Yul with the state in three locals and the round
///      constants read from memory, where each entry point copies them once.
library Bn254Poseidon {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev 372 words: the first 4 full rounds (3 constants each), 56 partial rounds (the
    ///      constant, the sparse matrix's first row and its first column below the diagonal), the
    ///      last partial round (3 constants and its dense matrix), the last 4 full rounds.
    bytes internal constant CONSTANTS =
        hex"0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e86408dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f52f27be690fdaee46c3ce28f7532b13c856c35342c84bda6e20966310fadc01d02b2ae1acf68b7b8d2416bebf3d4f6234b763fe04b8043ee48b8327bebca16cf20319d062072bef7ecca5eac06f97d4d55952c175ab6b03eae64b44c7dbf11cfa28813dcaebaeaa828a376df87af4a63bc8b7bf27ad49c6298ef7b387bf28526d2727673b2ccbc903f181bf38e1c1d40d2033865200c352bc150928adddf9cb78234ec45ca27727c2e74abd2b2a1494cd6efbd43e340587d6b8fb9e31e65cc63215b52534031ae18f7f862cb2cf7cf760ab10a8150a337b1ccd99ff6e8797d4280dc8fad6d9e4b35f5ed9a3d186b79ce38e0e8a8d1b58b132d701d4eecf68d1f61bcd95ffc211fbca600f705fad3fb567ea4eb378f62e1fec97805518a47e4d9c10520b0ab721cadfe9eff81b016fc34dc76da36c2578937817cb978d069de559109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e02b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d022643358103aa72b1e6dfcc210763146c5b07f8ceb052ab7d8264edddd22819126cf039cc824281e053e88557368c75d1dafa8f6545daaac0574ac0622e75f50a8526e9d9e0da22ce8d94e263a8ed5484d34614da2d768462cdf6dea7989b6b109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b07d4ea96a5398ba96ea0ec5d4d239311c18dfaec2b96e45ead603cef8554e3351d5309f362807f11b24f80db88f2fcd395e771a07dc7df2d217f402a86e97920168ae5a389e1b41ec9e15e5a03812eb5be603377895807317856d04222513a8e26769b55d5489959936ebd894652493bd4324664b145fca09d510d6e20fe3e091116fa006c17831ef3dc42d9dbeb7721d6372943d145e1d3572ce1e83d658fa7109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b221f71942808f5db7ace01497e60a54cfd26a40c1c4d51f78da8fa0bf421e62521a388fac1b608c87b4a1c507bab0f4754f282ecb99432a7708c58a607f9e7390d7233388ddde54f2048ce2e9728511e1e8de697013e063ded1a6b9dd1583ccb2797675577ef6605dbcec3ecfd14c116c773a96dd0183a07f9e1c37476bf8027238ce638b7f429c554db135a56b841dd1fafe5dbe5273eb1209a3d6fe16b702d109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b00e2016f890e3c413f542bf7f3211cd375173d0bad780beacc09c923b5c15c0e2d0b9395912b6374cf8c60fba30a51a16d25e6c170cc39611d7d8054e66e3bc20a088e6c8b892bd7c63fe9924fc427c9129425e59bb2032e8cca9ffefa908c3e289e04c50c960f11a082aa9fae8e444ed6ed8c344883433b4410ae6172bbb60f00185e9e6073fb916566e21fa72193d0f59a108b25eab222004ea72a8ffa97c1109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b09ed42d31d0b886974311f8773be68866bf70ca44ce31986a44b0f432c52f5f705baea916674edbaa4d692df9ac1331b35ba105227b1dbfc02037f4641510eb92616ae631d129d9582799a48529e1032d79929d8af6a2dbc6e1ffa318a2e11731cdd45b8ed0acbf53ffdf74c041c9dc684e8c633fa5def3e8150aa7e23684b6b116b402e300eb1750f4df186e918430eb2d7c0b94a317e1793a6a75278312c37109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b16bc96c9284b2ab4103a0a1afaba51bbc9867daf30d7918a93bd947193f2d9952495e894c4b2b39e982ef88d9522266b357087cd5dda6950acd1872feba5218b2ac0667885dfd6add370a6984de4ed00a6509ad390d778c76e37cfd8701354232e663bafd325bc93d91aa5d6dda2c9667b3a593fc58ab58ae75b5ba8ac568b6e06f7d4fce8d01aa6f063f5833010675fb4411547923229bd250e9f18734785b0109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b163ec1bbd5b64d7bacba50e4d1f94dcd51b67ae6a6c4c268dfbbee9f73ca2783120f20d111ab6905fe9815368905faaa1cc160adabd2e2538a51e0e8ae7181340d25498f328faa58b1c99b35138d8b7920c3ffa2b7f1d740447ca06002ebe35c0741630802b05758585d03d49e27de2ad9e1bc2c7ec1c43236067205148fe5940d7009d0dd50d1342d220cb69068ff9a575a903940d403f3973f00ad3a988e61109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0dcc9fc699ba0a3365882993c715ed04ecbd144e92a7a90f7cf14c4a0bcce19c246029460f564f8458b7b5ab6c700e8723992d80f6f41817411e0bec8ccf04ac1a3c267a9619df41a295f49cfe7b183435eb9c7948cc2a055a41fd065c59c43c2b255ee01c73f0e4b054d368d0eb89445b691b3f4509eb1876fe42a532ddab1307bf939ea61266e66e09daa5c95a2d475ea85006fd8202ac451fbdaf4d7713fd109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b1d351bdffa449821aabcceb0ab37076d72398b3a280e36ae803f2ab31e5e669000c39e40e2d62275a4c64b8ee73afa0cc2917017d1d61805b88ff5b2943b42d310400d7fe56a9b672b570517f54e93d92ddae37cf811ac17fe8bbed83b3bf15015c19783fba5e49bc329e30dac30166a012a8ebf795c2f5cdc6fb1cbb558f5cc2ccd4cd53395c5ef4099c8d032097d33c9bbf102afc350f29d73391e1b2815ae109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0657e557aa9a0857477e8c801aafb3ea314a6e7b53c09dc729133bdaf420a24c2a20eea32956af24893e370ad2a9dc2823f9cad71c08fe98de354b1ee22959ac1b92c8f28f2949b31edfefc5bf5d235d7feee5ef09f73635843bf959a8ce47730e9fc4ac97dab5a1c0ffeb553cce4255650a4e699cc5cb5df57c278572fb876706066582c016122a7f718be9336aab939b32cecba5cadf998c32852fbd3c67eb109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b238add2d541fe620d7bff2c109a554eb17bb48e6dca8164d546e18925034cc6d1ec45b3cd357e348638a906ed2bfc1c9f7b6bc43533a3b835376976bc278ec9d25e0b9424cb6fe0bb8bfc5d2b59002810c887cc5c2e86097bb224ebd540c88fa1cf8812fa36876df4d33e1b0680aa651e6ece33bca24cc1169b59f91b7acf4491da9873ad8b1439b0f089146fa84755247058ba96306472759a5d7570ee96a29109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2a2e763b9c2aa0c6eccc5725b3ceed606515207ea15cd4325a967b86c5f870e01dfe138c9618ee714652b5bf86b91c8c518d33a5cc0251a61aaa6c6d2b0c4f2527940f61980a0e8c113e07e9f6459ec3e4f048d80c8cc74fef784bf345a6fabb1654f7f420ef8ebbf76442b3770daa206bcd5093d71730c3a46a0db7d9509138184ee817dfb8eefc50d06c4c63dc247f1a750a5713998c53fdb03f954f63a10e109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b084404473bd5ce8373b2f02ee80b03d905dd88ff34981769a0cf01b4fb7c91442b3b1ff1b48662d0c4969652027c44cf98ae561ebcec7afcfda9a49ef3ba9d78148dd9cd53ddc3044370ae9b3c000adc89cfde6ebc28b1cc417aadb3fdfbb3f80e39b7d8036eb85bb140566133e4476faa0af1f7b16cbed70eebe7269b6bebe200abaf81fd3cbe5c354e900b5b305051890aa7d5477b6ee964250d18826cdcdd109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b23b2cf7d8b9d30dac0828c1095dd12614c4375b5d3c4c7e918d240d161e2526a2d0270d80affdf417daffe1612bbed6e6edae893682b8062f9f1e0f3ea17e421128080f49d5e4c96d3e7784e7cf62f72c9056ca38965a67a6131c1b675c14a5320efe628f684f11333249cbfd89d435a5e3647050cd2383648faf13cc0892d0218dd9e94f0a15f041ab8da038a7c3384799f18da930ccbde5ec154ee29231724109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2dc2ae6168e60a7eb211900d1dab1063fd20898c75cc25cfab0103caedf784ef0763e4951bf8abfeac306604c595cf7bce75208aa3ac9f83cfc892d3527795c41bf4421cfb8891b4eda74f7379e153f553304769a999eaec3570cf3e6b9c17251e2889909813a7cd95af6d0582154dca08ed1a9d6e158228a0687f4b0950d5b722a9db02cd988f336b6ef109f51485f3280bd3c708702c330d28b6f3f427ecb1109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2845ae49a5ed4aa1a97ab929262c43958636e441df36a9f0f9fb047388766ae226e8b4da4873d160e6955345214482f5f90adf4ebbb4f48b0a2e3163afb454cc1d4fceb73e8406cf97d14c69291dde115db1b96fe3b6a87e76c4014656e317ab108d6aa0aef22257b1fd393d8eb3bccc1650bc64eb271fe9c99aaefc58db57751213c545a1f6533025f8fc5f1e17f97cca1bd2b8c410fbf78079ad2b27b0288e109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b237ed1689fcf5a1fae5cd935b935da36057eff1c253a4224bd4e8199fa5ce86f07ad9e3409722f4044dd01c31fc40b5e9eda7f8bb84791633628d3247bc12f772daffb4cf09e18a6dfe7d272a2399a26c7c2fa39bb5086597175c7a5b2daafce21a562b80e0b202fa62644c79d785ac2f81e6a08419ee7114665e9f2304b4b5426e9635f4d46f26fba8dff00a1aaf37861f712963723b47054fc6e6c8780d977109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0238c637e33f00f2de992594400571dad82dca628bb85424db6387c677f771fa09fce2c3de0c4df73bbf19c0a9fc98817dd27535701fcd1b269c7c8363d6ce2a2019470819575bd1bd96d328df718c851c9428f1da1e1dfc0cc2427d3ebb0d6927b012ac70b508232d08ab49e1ffb6e3c17ba54e613c38d66bc3cd3843e4dc2f2dd744e809ecd0e7670257249369e2d8fa22efd5aafb0f2e79d2f8c2559728c4109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b220706a9aa08af064aa9a47af03d002608d64f638f945f5fc1800e9989a4c04c25cb4ed8e0b6421cdf89a2e0b6083dc776af176fc492b1a8430571f42fd4c2e9280c0190c129a063e6aff2277b20f450287f88f1f3188e04e539fa51dafd8eba217db2c5185d11e4831b28d1eaaaa5656a41571014c3098e214fd77c286e51500af00b5af30e88a3da0bbc526cceeff2c5230ee59dfe69236632ce3ea46b1561109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0341b7a0214f9c7ced5867d70966978f252e5c4ec4cff0b95fd9f9c7d8a7c2f31cf762eb7cd6c2d53cbe9f6ffa32b35d25e454f8d6e28684867334b11ad90d012ba8820816c78b4ddca951c30ac0daabce3dab93513183ef9ba5a54ad01f102a05850a8b6ec603a00347b5fd3f8d4b6c5f5e0f40315261767cd687a8f9580cb50393b7620d78da3651fd18b966d0fbac0f187233e4a9b32f47edc8db1b427e1c109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2f42bae72d393e49e1c9f6f3ff402f485af8269f127abb06fa83340ed3910e2203971debdf9f888c01d4f3a3c1855ae07844517b7e585f7d4df06d72e0db36c72aeb4212c4a48a1ca6c81f663778625efef05c016b6652763d2f31f7677368dd1cb8bd04c5065299d04cd5c7eebcada36d5e3c1698d90d13a25a0ad2c95aa747078941b8f2fa2025cd8f72fb3af64abde9e52f4dcc331c132e0872ba288cfd54109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0ac74ba3d3bb168bce49741dfc448052f218018a9be41bd5e11482e025f42bcb2ce3f10c9677fac23dd4f86ba1d38a00dc8f85eb2cc601d564c65fcf6d17a37f25fb81f51b6e6072af3c44eb69689e05d2a93e371016a2c1a45aa95202c1e17c045200a7e0339f33d7a16db8cbd139bc8af4441b99e9ddc28513c0424a7f070b0d0c396d574ccda3d9838a319307b9cb23c6da24708c9dc752b3ac7aa0c01754109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0e1a9c20d361e3173f71e3b8f10f8122762cc9894a1063802b9bd8bf209257fb112a4b841388ee693ec53063736dad3ebf2afa9e8ec5143224b001cec070cfa125ebbba0a117e404fae4926d265c7b6916eb01e969abc88c915a71a4b7902918176921ae16faf02be3bf7eb7656e74005ca545c0a50a18938be6f2d51262002c2d2d6c06688b5d61a28ac65fe5ceb6fbacaeda447e8c26378e4f1174fd0e7f0b109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b24d6fb10bd8b702cecb5f77585aca66c6716503e18d5091f6dd0c405afca9b791cf5f4dfff6503a1f67247e427f3507fa86c4c5f0de495a98dc9c1b00d1df427261b48735752ee147a665d2233aec49adfb362c04fe26af306d88d4ec617afee2c068378a0b34ea7305ee656ecf40713939525a3043f226709fba3934be964ee213cc690d85f0d7b12cede4e87721ccee84a0cf9140f100be64b937e89ee2b75109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0bda58dbc38937dd857f40fa655b6964914a42ec1cc029f9cb499d1f31f5840d170621c0e2c98295c56fe8ded9769868b962725f156d4af2464abda53b33e8f81d48f5b5ab3eba88870f240e001e2d31a4d54a5a2abbc1471751334d0ca2f97e09217887748ffac6a07262062e27b2951e9200b0364326b72608c4b053333427183c7f47bab034a6791607eb5507d2fb77c3bef7e1eb8f9e660ed49d6fa835a4109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0bc299112c701c77456e29cb1fa785b9e110dba68a42fac3d6bb8149879488462fa416815cd33b4f03f720ad4ffab7a0f3cdec40153ecb064ab865ea43aecb6d1bdc3936c546cf148aa4b8782e38ad7a917de2f8450aa3f9b17e3ae3bfac59810f91915f3fdd62c1bc7ddb8038bee9e5bd00a2a8411a91ced3494b72077fa48d12d38aca7d7f2999acdaa7afa470dbc0d014f994ff8a425dcf5d709b4c5f8891109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b08dcf5b24cfa6904931fd78bf00e79c1cbbf253201f358fe8d4db54877e775f80440e2f14f76c6059eaf89781cf2cf6cf89b93a1bccc0aa5cb59fc918a25553211908382a73caf826a7123f8fa2b37f1cea31bbca202031cb3e3cb793d0a58d803caab37bf2336b1e84f28f962ccf029766627ecf01b0cecebffa8e20b8c6c0505faa348214268d0b5c54ed0cde8c83a4d79fb15fa94b65a1b01ea1c50757625109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b226d20cd5f9db6b8c81d40b0d4f44262d8127f07e310c8c0c73127847c8c021f2a10a38c90a35d9b17eaf0b48d249fb89b4befac8b9ea6ce5030d9174f60e9b10504b04dbd74a6b4c879b86723ad23d3912c9df1a11e776ed1c8fcc094d9af082a1843da8d1bf5024999c19f0eb9e9c0cd0eeabb5bde8d143abdc1fc42ba82b60e8dd67f884a87588287f3ab55972a7496023a43f8da426ab59bf676425b6d4a109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b1c3a160edcb96a30bb3bc64c63d763a7ddfff07f9cfd0949c07a681909afa4452618b3fcd02fc717456261a06d2acf1938de5a1c2dc68b14ae0a0c472bd654b1112d29b65dfbae266114e995f465ab5bc68a9eb2846c47290e6e4ed46e6aa1de2f3ccbc5283146f36d0d4ed4c108d5ba74434de982d0b02b7d67ca49a41d303e0810d122c011c8830f48fdbe9b43231db5f2938aa501e15b0ace836776247e20109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b13f56967021b2d18e47493a0537f31fbeb62e45a3fecc7edcc1b96c7dad4e349232c2d13d00dbdaaf4ff4f2f28f5d41cd7bf1917e161344aa24ba461903ab23c29d4b4b5e047fcbfd77891cb7c9757182a665f67ac8c60a99c7222ad9d1e00c7013ef127471cc5112b5035fa7471730a42914d5b1452a2080682abaa2f2fc27a127e998cf30f76cc5f9b0e0359285a5df42549d1702a44ba117474f02632c618109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2cc1213e24292f3d1e7c2df75c20c56c7a15299d78d1c3fb7ba98f2be88337e101af41116268f585433bdcc81fad58bfb29c572b4070d4dc83e1c8066fce5bcb11a1008b38b590b8bfc094b8609acdd50fdae61e2dbbd7356efc0056b2264c23130f9117ee4644797953355005129d9b9573768da8e785140506035454781f0d03f148ee71169a9f22c37ad1338c285c9dd0113aa82c26dd2fb73e92f22b7a5d109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b1181ce50e3d01e76140f2aa71768e855f6e8ab43a2816828877747f0f6e9d2501a46c05da3438064cd257260afd003f0635c083a4115b888d51242665c7d4701160a9a049239cb1ead69f0e0b7b0babe1df8f59a394321ee8587a6ef96c40baf06a3041086d613f8dd4f81b65e6f02b8e8096d7eefb19d31c13c58b63aa996791fcc2a3ecd83418b7c04e83c213d6c53c03448efff4928365287f12883f12f0e109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b29df33fc315913dbe5782e99d0a3dac8d4d4a4dd3faf3b81c81d64a8ff9c4b0f043225cf9741664dfb238321558917dc00a57119afb9308d4c75888ac04578052069c42e2cac17bb9bb5a2d31fbc61ca9d00497ba3180aad453b0e4156925d2304ff26e82b96b794ac45f5fe661f3ad76f18526641a2e8624a68fd9b1a201ece1dac70a36e33ebca594a8830eaee643a5fe4edd016cc05119244e5eddb27be90109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2816f060cd22f19cda4111bf5e1e38da02caa67a32928b7abd726e71027256d60c3ff0e3196f7171ae771b819e68ce4e802358e1062821746d856ebecefc2d7a254ba2a13e736f582675f5fd74eff7f66f49f58d7cd1b3891742cac545062dd91bd6889bcaaf20e86fab76dd10228edacfa2b36262f163529dc1709b0b29caa9030ec7605dd5869a17ecb0b25596d75efe68ce5c8b4585a2833ec62d0608b202109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b25c520d41b0478b0a1144b199891c334354dd2afc7a84a65f7d4981b9340a36a18f8bf0732fec23ed6d898ab602c90bee5dda19689812dffc49011a0bed06fb2180ced8a391f10f33c7f3da5e55c5a6da2a520906ef62e1caa4e617eee13eece1f83ac7548d640427e441b80daf5623b55f9e97c0222b8ebd9a3305134aee8100ef0a55659c6c606355a3e0c1eb400b83cf39c44544b59f9d7391f1920dbde1b109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b28ee21956775eb657f2a2caeeb6286253f8f218c7b05d484a62866751712777a04162b3ece63229555144b3f548c5609d4b5f3206c74de68bcb2c9d48c61b592017cf428562632bf931d9723f428198adf1009851b88055f5329bc13ba70539e0cc0e513841cce2de8e3eab5b15f07763ba2c802c5428e015588e998b1c39ec52ea57e170f7d89c2034bd8fcc3e48ced68cca812b5ac7eeee6f30443f2be21df109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b24ed21086ebc03ca0fd7f5d763750b795132f76226ef99e79dee1fe35f8a7d6610d8cfeb82f9425242e7f5addf6922132a2a4f67192c4853c7ff4990a9a3d0602d364d006924161a72714319d22626548826cbb74df9b9586867ae5f77c853bb23453abe9f54b9df06940062feb84ee4e8b2b7aee1890e48ed9e6d7e4440bb810387db6cf8e365c34aa496466ac8127813e1fa2bc9c9084bf95214811b31ca45109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b1dd122b429688d67b2ace14662d8bb218b4b3f747d301ef3deaf7ec22777f13b1823e4bf19276ccbbbbe85b39819365905e17f55699aa937c9f1527f4c41ac981b7230f08490a451b7857afae775362e82d240acaa75de0fc74aca0795b1f33b02538cb3d699199bbb944b320d6c4f64ea5a244d933eb21d021947ca3dd23ffe1c17bcb60cad114daa86b7ab0faf2f9e53b4f1590d72ad49598a1c9f631762b3109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b097edd2e0148217bbfc64858b2e0834c1b805d5e5c3faa00a2a9b768676be3fc1fdcddbd3d0d12fc96cc98eec0ea896d5f02a76815a2e4272a6d952af9703335196d84a2b4cb6a932b6bcee64290f5450aefdea648b38ba6852b3bafe44e1bb82067fa23cede1254e049c786fdb28ad6bd28634f5dd36ea4c7cadfb2a75366251958056f36be3ded17384bb3a059357846f2b30b01f0337c1e1c2b704d3ea0e4109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b19ac41d171b063204d542b736c4b6b7314f0e20f0bc8d9b25935e4483e1d089b2fc168fee9a3d3d1aee6868a8973b016fc982ba68b9fb8d4e488b7726079f1a61314bc5eded375cdca6652c8c6261ad11d41581181ce1aa3c0397ded57b700600a7210825b226ccda79a9a27c6a98402636bb74000eacaf736fb167be5edf23f2de99b3e77de42ec6e5975d4477ae96d00b23bf9c6391e595529e0a4021221fb109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b02d0a7eabbd3f78e9216a926a4e34782ea713bc3683bb8e142c65490f4dc37a8200ad8ec758f04845d2d502b19f958c3f7775bf7be42239e52f72c9b3b8ac2d41eba762c634927970baab6906486ff1ec8b3d1d1fb51577f58f29fc3b48c772910b7ff3345d7ee090cb3aa4e49890178c1243bafad9563ad62e68e3604a82a532d2131086c3bc3418dde3237acaabb24b27e9e2cbfd7a9ebf52bd612688b3527109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b08358ae45e4c4fdd23857ed17bd7563764d13bab41f5c63408da545afdc183d32c3c248af3db01837ed23ddd26adcac20e5c9a83409195fa94ff40e689bc42d504c9a93b2ac9320778f408f98e5a826f4ec3fd7aa26d06173af965ce4990939a2bb2f7a3d776c62c3f316de9268660f1ee79737f7185537d0102114449d02de20ae349869aec39bf93f8b2cbd631d4baf910de6d1712142acfa2b82dd7ec01fa109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2a9ff8156fb6e2a8922f8761119da57a970dbe845d6c312e1d967a3b36bc08c22dbd2cd582a77cb9ac1a9803d8960bb77551eb7be1efd5467e3ce5efa79187cf14632a782f25927aa73472a59cd19458df39bd228db3b0411141f18edf74c3dd212c50ddac5802d5816b6099aac6d757502a622130ffdd330d9df54ad4e660aa209df7f7923cb342ca83896920e95f9f11c4729970172640b000430eca179989109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b10186e4ce856f27ea2115aac4ac2c040be219018044fa3657b09e677b8c612d52d6075ab20bdce5e7815eaa74ce5b1443e985202d8754eea0819caa16c4c19a20b5d343f020e9e417b5943f6281a359fe8b1a9026391d45e99b0a5516404eb7c2ce6aeebb2bc37147cda977acd9fd3372809a4cfae48fb6576aeb41b6ccc3dbf21e79c2d6c42734a9a608dc58c35c137517b1e64a5d5767fdddaa1a12efade88109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0db574efbe50d0faf49e8f60129fa106cb232337033bcbb32abc0d00511714e82b0ee28f2495bf064c7b3f53b20b1c39446a0cd8f42b75e030be5633688b859f20e614e359e8d31dc7b15f96bf82f4d5d1caac452b1137b5aa5c657e7f0ba76b039d44cfa29e9fc50faced0fafc054aba80aa474b4f9768d98f7918054624e2f049c4e33e7ccf5ad5ebd5d0794ade154e86af76537ee5ccfa237a262c4e467ba109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b26b9cccb5415d4cfd9ba63c4e23bafec3aaad614734e305d5d0bd15dcb5c05f31c9b3d050ac606917caa503392fb88cacc463adc21ddd2b562859598ca0be1942b962d0fe74cc59d84c0a367dd4dd8d860ecd8d6da9bd2865ef813170d79a64112b5d8dd56da5a49438ef6f32a67fb89ec54d1c6601ec05e40bcb31b009342cd1869d4e923fb31e8424a16c269e46ac49254c3d05ff35022a76b98b11f8b8b33109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0ae91bf29e5a445ce20b56ec2f548c28fd9bd0fb8f733cc4be5c79bf30a661870d97f7d83fea410bae249ab40c56bf1b2b6cfb1e19c5772a76f4c7e1dbf453c72b1d14d0a6f77683b2db96432f86ff91d73341ec41e72153518f0c3f1387729f1261c6314a93146756132819610312bc43cad6533fd68f9b34cd9c12b1edf40a23bf80f538756a283d8f04719a8b6e028ddedeb95e2fa971a1aa002d34539385109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b264f42fe25fb0675a5d1f67b2fd60632ad2624db29ce74969fd25c7e50b2f33f03ccefd988182226745c7efaa250b23d2d385ecf446378a1c7135742aae607051cd89a27fba4cddcc8b8f331b8b1e9e357b14a1110b2eaa1edd0013b8e660b300e9486847dc1fc9923e4602de8cb56c97a740af602827e3468b64657f7ecde0a26cde2d63e1b586581f632ce4c4fa2efc226bc5cf18d65c5525a8fcc5066fb94109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b14fd7cac4b60548b73b14a5374bbab0719c67f4fcf2490d9390724d0c03eb4690c31ea7a567339d2948ad56684f68acaed5e9fca40706859ca03b6e164a5af1d1614381ace75712faac31f924c3a59d59faab2e77cc49c5b4c3f72e6fa84923c2d84beedbda8cd603883f639ec6b940b16bd92d3f723d39d2c03804c5bdc90f214076b33136ec0e1ac549638a4b902ba5d6ebf052a8f14804256e47cf2c2f04b109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b1fa1bfcb3cdd14642c38c18f5e0587198828f98d9e4173f9f2ac6197f3108ae60c2393a41e97c27a584375adab8919b8ebf4f0c98625d531b6ab35a2a3b2f8142e5fb28f3607e2751b2e8986a7ea3df703ef05a3d12ab3b21b6e508d2cecb59c2b1ea6509ebede22c3b52bb0d27cfdeead0896f8a2a397e8cafadda18f3c24cf2cd8fb137caa0ed0b658a8fb3b7568185e987910e8aaa40e0db02a734e03c42e109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b2097773a66fb9e737c3b50426514e655c9a91edbccc3c53381a1ff377362579e0878ab6a9e0a7983e034c4e4b3b316b708dda7496fec08d51de6ef85bca5c9961d8c243fa89b6f080a0274bc36013fb01c6c653a312f981e2301230f8d1e26921be1be819c7a4d85cecec293eaae210785907dac1678675adea77f6cda2e784e024562fc799792e21a0c94cbb88e1a43b297948049cef86c17d04a0298d793b8109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b1962d8871652d69fec1e96f0d1b48b77cf389b0bb8bb78669f064d8f23d917c3189e38b277dd3fb9b07d80617f827fe3240ef6419238b696434563e62d913f200db30e2b22de73885cba254cc3bc16d14741954a902da59f5fe1d0d53ac041da2c954d1f44bb8535d04a41369c032462f27a10dd63a3ca412e2e086d0bf39814270aec6f1b7b1a1a241b2b0b78f713f2aa23a25cbcbe5220eae939775fc7295c109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b23fd36de6cf42a6600be937f2a5b779c9a854a3c806b8db69ab446ad6498ed5723642b53f6f5a5652a5fd7194cea1cf26a7300f82a548927379ea130e5e571d908d4eb39b66166decc4b794e59f4d4f9b4604f034ad19bb45a87742eaab68f9223ce982100e304db9d89a95832a86b63f21729130c506a6b70bb9eb3851e84c31a093a3014147bf0bac4e3c917c367b95f7955495b87549ecc6ce7f96d7087e6109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b190a59743a0a8cf26ddaa08fd47a4cde107db1100c16d63c008147158d9a1da017c7add33a9bc7a75105d58602ab1a8e5644fe8ac4f8d5e90ae8f4a24801247721aa0746190d9cd2671b01a7163fa872d5d7a52a8f52372379d1f96e01aca70c1bce98b8337fa5d774e66565fe184abcc819d5d6bf4a81af0cf8aeac79846b400dcebf0a0455c0d2b7cf2b4a674258af44a114be3a162795ed39938193b79f06109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b29e600fa879837add25c77f0dadda2be65e4ac3c381848922adc376012df94f11b85ff1bcf048d645d1c864b00e38e3a3e833f540db30be1194244f6846316712a5fa958053467576d8f7e4ebcd6733accae2bce455fdfca1bcf6be91d16b04528412038464afd68bb2f4e435f0293b3a7df65a832319fa090a251322a794e910910adbe751bb9038b98054eb027a8b71f83ad86ad8c06255d1c0c8d77a448f8109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b275c32b47a45b1b2e214442819a54e712ebf838e932d0ac8877a80cc2e4ebdeb08b9f1a3cef60a3156d6d022820ea5990d25f5f081a196bad1cb88f81a284ef01115f9b9203a59ea9e79b3b0f6b4e33ac65d1ea833698c9bf0afdab6f53c5c6e17c0cf3acbed718e026104ade5ffc92b106bb8962d99513efa45c49bcc971d83209a5c2333bdb226479c47dc0e045edb76cb46c3b886f5df3b9796842f174a8f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b0a2f995bffa2b74e1e0e347c325034b711362e0a86deb9c20c6b01c6c5f71bd20e8d5f60cab57053c81a28f0ac634b27192a489ea0b226dd48008f5edd26c9ae2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771075be6d3b7ae2cb49856e0b1aceaa84737fa30d5abcbc51787bea648df15b75c1a81a72b8e5439376d3e1f3ecd5bdbd8415b7680449d451219b117c9095fa111143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a72b3dee28c2ad61798b1c0e35472df28961bf999c84ff13b194acb673c9e87ede23aa557f8476747f032d0944d68b2ba21fed9aee9f67d3caff9275d3bf831c8918d1db85bf7812d2cc6e761ce8b778e46a8fb6dec2b640692e39748ee1857cba072c1bbe5b21fad79ea9520d9d76706713b173b7293f9c31eb5e88b77c646292069b898b636f3281d5e49d4e543e4134f3480e62c8a20d4c846db06afaea7a341cfb5662e8cf5ac9226a80ee17b36abecb73ab5f87e161927b4349e10e4bdf080f21177e302a771bbae6d8d1ecb373b62c99af346220ac0129c53f666eb241001671522374606992affb0dd7f71b12bec4236aede6290546bcef7e1f515c23200fa3ec5b9488259c2eb4cf24501bfad9be2ec9e42c5cc8ccd419d2a692cad870193c0e04e0bd298357cb266c1506080ed36edce85c648cc085e8c57b1ab54bba102adf8ef74735a27e9128306dcbc3c99f6f7291cd406578ce14ea2adaba68f80fe0af7858e49859e2a54d6f1ad945b1316aa24bfbdd23ae40a6d0cb70c3eab1216f6717bbc7dedb08536a2220843f4e2da5f1daa9ebdefde8a5ea7344798d221da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161";

    /// @notice One permutation of the state (capacity, left, right), its first rate lane: the
    ///         two-to-one compression of the note tree, zkapi_core::v2::compress_fields.
    function compress(uint256 capacity, uint256 left, uint256 right) public pure returns (uint256 result) {
        uint256 freeMemoryPointer;
        assembly ("memory-safe") {
            freeMemoryPointer := mload(0x40)
        }
        (, result,) = _permute(capacity, left, right, _constants());
        assembly ("memory-safe") {
            mstore(0x40, freeMemoryPointer)
        }
    }

    /// @notice The sponge over five inputs: zkapi_core::v2::hash_fields, the note leaf's hash.
    function hash5(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) public pure returns (uint256 result) {
        uint256 freeMemoryPointer;
        assembly ("memory-safe") {
            freeMemoryPointer := mload(0x40)
        }
        uint256 constants = _constants();
        (uint256 s0, uint256 s1, uint256 s2) = _permute(0, a, b, constants);
        (s0, s1, s2) = _permute(s0, addmod(s1, c, FIELD_MODULUS), addmod(s2, d, FIELD_MODULUS), constants);
        (, result,) = _permute(s0, addmod(s1, e, FIELD_MODULUS), s2, constants);
        assembly ("memory-safe") {
            mstore(0x40, freeMemoryPointer)
        }
    }

    /// @notice The roots of the depth-32 tree with oldLeaf and with newLeaf at index, from the
    ///         leaf's siblings (bottom up), and the new path's node at nodeLevel (the leaf at 0,
    ///         the root at 32): 64 compressions with capacity as the node domain.
    function compressPairPath32(
        uint256 capacity,
        uint32 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[32] calldata siblings,
        uint256 nodeLevel
    ) public pure returns (uint256 oldRoot, uint256 newRoot, uint256 newNode) {
        uint256 freeMemoryPointer;
        assembly ("memory-safe") {
            freeMemoryPointer := mload(0x40)
        }
        uint256 constants = _constants();
        oldRoot = oldLeaf;
        newRoot = newLeaf;
        newNode = newLeaf;
        for (uint256 level = 0; level < 32;) {
            if (level == nodeLevel) newNode = newRoot;
            uint256 sibling = siblings[level];
            if (((index >> level) & 1) == 0) {
                (, oldRoot,) = _permute(capacity, oldRoot, sibling, constants);
                (, newRoot,) = _permute(capacity, newRoot, sibling, constants);
            } else {
                (, oldRoot,) = _permute(capacity, sibling, oldRoot, constants);
                (, newRoot,) = _permute(capacity, sibling, newRoot, constants);
            }
            unchecked {
                ++level;
            }
        }
        if (nodeLevel >= 32) newNode = newRoot;
        assembly ("memory-safe") {
            mstore(0x40, freeMemoryPointer)
        }
    }

    /// @notice The root of the depth-32 tree with leaf at index, from the leaf's siblings (bottom
    ///         up), and the node the insertion completes: the path's node at the level of the
    ///         lowest zero bit of index (the leaf itself when index is even; the root when every
    ///         bit is set). An append-only tree stores that node as the left sibling of the
    ///         insertions that follow.
    function insertPath32(uint256 capacity, uint32 index, uint256 leaf, uint256[32] memory siblings)
        public
        pure
        returns (uint256 root, uint256 completed)
    {
        uint256 freeMemoryPointer;
        assembly ("memory-safe") {
            freeMemoryPointer := mload(0x40)
        }
        uint256 constants = _constants();
        root = leaf;
        completed = leaf;
        bool completing = true;
        for (uint256 level = 0; level < 32;) {
            uint256 sibling = siblings[level];
            if (((index >> level) & 1) == 0) {
                if (completing) {
                    completed = root;
                    completing = false;
                }
                (, root,) = _permute(capacity, root, sibling, constants);
            } else {
                (, root,) = _permute(capacity, sibling, root, constants);
            }
            unchecked {
                ++level;
            }
        }
        if (completing) completed = root;
        assembly ("memory-safe") {
            mstore(0x40, freeMemoryPointer)
        }
    }

    /// @dev The round constants copied to memory; returns the offset of their first word.
    function _constants() private pure returns (uint256 offset) {
        bytes memory constants = CONSTANTS;
        assembly ("memory-safe") {
            offset := add(constants, 0x20)
        }
    }

    /// @dev One Poseidon permutation: 4 full rounds, 57 partial rounds, 4 full rounds. The round
    ///      groups are separate functions so that the stack pressure of a full round (three S-box
    ///      outputs and a dense matrix) does not make the compiler keep the partial rounds' values
    ///      in memory.
    function _permute(uint256 s0, uint256 s1, uint256 s2, uint256 constants)
        private
        pure
        returns (uint256, uint256, uint256)
    {
        (s0, s1, s2) = _fullRounds(s0, s1, s2, constants);
        (s0, s1, s2) = _partialRounds(s0, s1, s2, constants + 384);
        (s0, s1, s2) = _lastPartialRound(s0, s1, s2, constants + 11136);
        (s0, s1, s2) = _fullRounds(s0, s1, s2, constants + 11520);
        return (s0, s1, s2);
    }

    /// @dev Four full rounds whose constants start at off.
    function _fullRounds(uint256 s0, uint256 s1, uint256 s2, uint256 off)
        private
        pure
        returns (uint256, uint256, uint256)
    {
        assembly ("memory-safe") {
            for { let end := add(off, 384) } lt(off, end) { off := add(off, 96) } {
                let x := addmod(s0, mload(off), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
                let y :=
                    addmod(s1, mload(add(off, 32)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
                let z :=
                    addmod(s2, mload(add(off, 64)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
                {
                    let q := mulmod(x, x, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
                    x := mulmod(
                        mulmod(q, q, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                        x,
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    )
                }
                {
                    let q := mulmod(y, y, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
                    y := mulmod(
                        mulmod(q, q, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                        y,
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    )
                }
                {
                    let q := mulmod(z, z, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
                    z := mulmod(
                        mulmod(q, q, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                        z,
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    )
                }
                s0 := addmod(
                    addmod(
                        mulmod(
                            x,
                            0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b,
                            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                        ),
                        mulmod(
                            y,
                            0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0,
                            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                        ),
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    ),
                    mulmod(
                        z,
                        0x2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d,
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    ),
                    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                )
                s1 := addmod(
                    addmod(
                        mulmod(
                            x,
                            0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771,
                            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                        ),
                        mulmod(
                            y,
                            0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23,
                            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                        ),
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    ),
                    mulmod(
                        z,
                        0x101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa,
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    ),
                    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                )
                s2 := addmod(
                    addmod(
                        mulmod(
                            x,
                            0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7,
                            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                        ),
                        mulmod(
                            y,
                            0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911,
                            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                        ),
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    ),
                    mulmod(
                        z,
                        0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0,
                        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    ),
                    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                )
            }
        }
        return (s0, s1, s2);
    }

    /// @dev The 56 partial rounds with a sparse matrix, constants at off (6 words each): the new
    ///      first word is a full row, the other two gain a multiple of the S-box output.
    function _partialRounds(uint256 s0, uint256 s1, uint256 s2, uint256 off)
        private
        pure
        returns (uint256, uint256, uint256)
    {
        assembly ("memory-safe") {
            let P := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            // Never taken (calldata is far smaller). The modulus must reach the rounds as one stack
            // value: left a single literal, the optimizer inlines it into every use and the code
            // transform then places each through codecopy and scratch memory, at a multiple of the
            // gas. A second, runtime-opaque definition prevents that.
            if gt(calldatasize(), 0xffffffffffff) { P := 1 }
            for { let end := add(off, 10752) } lt(off, end) { off := add(off, 192) } {
                let x := addmod(s0, mload(off), P)
                {
                    let q := mulmod(x, x, P)
                    x := mulmod(mulmod(q, q, P), x, P)
                }
                s0 := addmod(
                    addmod(mulmod(x, mload(add(off, 32)), P), mulmod(s1, mload(add(off, 64)), P), P),
                    mulmod(s2, mload(add(off, 96)), P),
                    P
                )
                s1 := addmod(s1, mulmod(x, mload(add(off, 128)), P), P)
                s2 := addmod(s2, mulmod(x, mload(add(off, 160)), P), P)
            }
        }
        return (s0, s1, s2);
    }

    /// @dev The last partial round, with its dense matrix: constants at off (3 words), the matrix
    ///      after them (9 words, row-major).
    function _lastPartialRound(uint256 s0, uint256 s1, uint256 s2, uint256 off)
        private
        pure
        returns (uint256, uint256, uint256)
    {
        assembly ("memory-safe") {
            let x := addmod(s0, mload(off), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
            let y := addmod(s1, mload(add(off, 32)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
            let z := addmod(s2, mload(add(off, 64)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
            {
                let q := mulmod(x, x, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
                x := mulmod(
                    mulmod(q, q, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                    x,
                    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                )
            }
            s0 := addmod(
                addmod(
                    mulmod(x, mload(add(off, 96)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                    mulmod(y, mload(add(off, 128)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                ),
                mulmod(z, mload(add(off, 160)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            )
            s1 := addmod(
                addmod(
                    mulmod(x, mload(add(off, 192)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                    mulmod(y, mload(add(off, 224)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                ),
                mulmod(z, mload(add(off, 256)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            )
            s2 := addmod(
                addmod(
                    mulmod(x, mload(add(off, 288)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                    mulmod(y, mload(add(off, 320)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                ),
                mulmod(z, mload(add(off, 352)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001),
                0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            )
        }
        return (s0, s1, s2);
    }
}
