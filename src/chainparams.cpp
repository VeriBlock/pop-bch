// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsconstants.h>
#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <vbk/genesis_common.hpp>

#include <cassert>

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
 * hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893,
 * vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                          int32_t nVersion, const Amount genesisReward) {
    const char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 210000;
        // 00000000000000ce80a7e057163a4db1d5ad7b20fb6f598c9597b9665c8fb0d4 -
        // April 1, 2012
        consensus.BIP16Height = 173805;
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = BlockHash::fromHex(
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP65Height = 388381;
        // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BIP66Height = 363725;
        // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.CSVHeight = 419328;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY] = {
            .bit = 28,
            // 95% of 2016
            .nActivationThreshold = 1916,
            // January 1, 2008
            .nStartTime = 1199145601,
            // December 31, 2008
            .nTimeout = 1230767999,
        };

        // The miner fund is enabled by default on mainnet.
        consensus.enableMinerFund = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::MAINNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::MAINNET_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 478558;

        // November 13, 2017 hard fork
        consensus.daaHeight = 504031;

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 556766;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 609135;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 635258;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2021 12:00:00 UTC protocol upgrade
        consensus.tachyonActivationTime = 1621080000;

        // Nov 15, 2021 12:00:00 UTC protocol upgrade
        consensus.selectronActivationTime = 1636977600;

        // VeriBlock
        // TODO: set an VeriBlock pop security fork height
        // consensus.VeriBlockPopSecurityHeight = -1;

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        diskMagic[0] = 0xf9;
        diskMagic[1] = 0xbe;
        diskMagic[2] = 0xb4;
        diskMagic[3] = 0xd9;
        netMagic[0] = 0xe3;
        netMagic[1] = 0xe1;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xe8;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size =
            ChainParamsConstants::MAINNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::MAINNET_ASSUMED_CHAINSTATE_SIZE;

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1,
                                     50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1"
                        "b60a8ce26f"));
        assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));

        // Note that of those which support the service bits prefix, most only
        // support a subset of possible options. This is fine at runtime as
        // we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all
        // service bits wanted by any release ASAP to avoid it where possible.
        // Bitcoin ABC seeder
        vSeeds.emplace_back("seed.bitcoinabc.org");
        // bitcoinforks seeders
        vSeeds.emplace_back("seed-bch.bitcoinforks.org");
        // BU backed seeder
        vSeeds.emplace_back("btccash-seeder.bitcoinunlimited.info");
        // Jason B. Cox
        vSeeds.emplace_back("seeder.jasonbcox.com");
        // Amaury SÉCHET
        vSeeds.emplace_back("seed.deadalnix.me");
        // BCHD
        vSeeds.emplace_back("seed.bchd.cash");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = "bitcoincash";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            .mapCheckpoints = {
                {11111, BlockHash::fromHex("0000000069e244f73d78e8fd29ba2fd2ed6"
                                           "18bd6fa2ee92559f542fdb26e7c1d")},
                {33333, BlockHash::fromHex("000000002dd5588a74784eaa7ab0507a18a"
                                           "d16a236e7b1ce69f00d7ddfb5d0a6")},
                {74000, BlockHash::fromHex("0000000000573993a3c9e41ce34471c079d"
                                           "cf5f52a0e824a81e7f953b8661a20")},
                {105000, BlockHash::fromHex("00000000000291ce28027faea320c8d2b0"
                                            "54b2e0fe44a773f3eefb151d6bdc97")},
                {134444, BlockHash::fromHex("00000000000005b12ffd4cd315cd34ffd4"
                                            "a594f430ac814c91184a0d42d2b0fe")},
                {168000, BlockHash::fromHex("000000000000099e61ea72015e79632f21"
                                            "6fe6cb33d7899acb35b75c8303b763")},
                {193000, BlockHash::fromHex("000000000000059f452a5f7340de6682a9"
                                            "77387c17010ff6e6c3bd83ca8b1317")},
                {210000, BlockHash::fromHex("000000000000048b95347e83192f69cf03"
                                            "66076336c639f9b7228e9ba171342e")},
                {216116, BlockHash::fromHex("00000000000001b4f4b433e81ee46494af"
                                            "945cf96014816a4e2370f11b23df4e")},
                {225430, BlockHash::fromHex("00000000000001c108384350f74090433e"
                                            "7fcf79a606b8e797f065b130575932")},
                {250000, BlockHash::fromHex("000000000000003887df1f29024b06fc22"
                                            "00b55f8af8f35453d7be294df2d214")},
                {279000, BlockHash::fromHex("0000000000000001ae8c72a0b0c301f67e"
                                            "3afca10e819efa9041e458e9bd7e40")},
                {295000, BlockHash::fromHex("00000000000000004d9b4ef50f0f9d686f"
                                            "d69db2e03af35a100370c64632a983")},
                // UAHF fork block.
                {478558, BlockHash::fromHex("0000000000000000011865af4122fe3b14"
                                            "4e2cbeea86142e8ff2fb4107352d43")},
                // Nov, 13 DAA activation block.
                {504031, BlockHash::fromHex("0000000000000000011ebf65b60d0a3de8"
                                            "0b8175be709d653b4c1a1beeb6ab9c")},
                // Monolith activation.
                {530359, BlockHash::fromHex("0000000000000000011ada8bd08f46074f"
                                            "44a8f155396f43e38acf9501c49103")},
                // Magnetic anomaly activation.
                {556767, BlockHash::fromHex("0000000000000000004626ff6e3b936941"
                                            "d341c5932ece4357eeccac44e6d56c")},
                // Great wall activation.
                {582680, BlockHash::fromHex("000000000000000001b4b8e36aec7d4f96"
                                            "71a47872cb9a74dc16ca398c7dcc18")},
                // Graviton activation.
                {609136, BlockHash::fromHex("000000000000000000b48bb207faac5ac6"
                                            "55c313e41ac909322eaa694f5bc5b1")},
                // Phonon activation.
                {635259, BlockHash::fromHex("00000000000000000033dfef1fc2d6a5d5"
                                            "520b078c55193a9bf498c5b27530f7")},
            }};

        // Data as of block
        // 000000000000000001d2ce557406b017a928be25ee98906397d339c3f68eec5d
        // (height 523992).
        chainTxData = ChainTxData{
            // UNIX timestamp of last known number of transactions.
            1522608016,
            // Total number of transactions between genesis and that timestamp
            // (the tx=... number in the ChainStateFlushed debug.log lines)
            248589038,
            // Estimated number of transactions per second after that timestamp.
            3.2,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 210000;
        // 00000000040b4e986385315e14bee30ad876d8b47f748025b26683116d21aa65
        consensus.BIP16Height = 514;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = BlockHash::fromHex(
            "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP65Height = 581885;
        // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BIP66Height = 330776;
        // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.CSVHeight = 770112;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY] = {
            .bit = 28,
            // 75% of 2016
            .nActivationThreshold = 1512,
            // January 1, 2008
            .nStartTime = 1199145601,
            // December 31, 2008
            .nTimeout = 1230767999,
        };

        // The miner fund is disabled by default on testnet.
        consensus.enableMinerFund = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::TESTNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::TESTNET_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 1155875;

        // November 13, 2017 hard fork
        consensus.daaHeight = 1188697;

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 1267996;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 1341711;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 1378460;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2021 12:00:00 UTC protocol upgrade
        consensus.tachyonActivationTime = 1621080000;

        // Nov 15, 2021 12:00:00 UTC protocol upgrade
        consensus.selectronActivationTime = 1636977600;

        // VeriBlock
        // TODO: set an VeriBlock pop security fork height
        // consensus.VeriBlockPopSecurityHeight = -1;

        diskMagic[0] = 0x0b;
        diskMagic[1] = 0x11;
        diskMagic[2] = 0x09;
        diskMagic[3] = 0x07;
        netMagic[0] = 0xf4;
        netMagic[1] = 0xe5;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xf4;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size =
            ChainParamsConstants::TESTNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::TESTNET_ASSUMED_CHAINSTATE_SIZE;

        genesis =
            CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526"
                        "f8d77f4943"));
        assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // Bitcoin ABC seeder
        vSeeds.emplace_back("testnet-seed.bitcoinabc.org");
        // bitcoinforks seeders
        vSeeds.emplace_back("testnet-seed-bch.bitcoinforks.org");
        // Amaury SÉCHET
        vSeeds.emplace_back("testnet-seed.deadalnix.me");
        // BCHD
        vSeeds.emplace_back("testnet-seed.bchd.cash");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";
        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            .mapCheckpoints = {
                {546, BlockHash::fromHex("000000002a936ca763904c3c35fce2f3556c5"
                                         "59c0214345d31b1bcebf76acb70")},
                // UAHF fork block.
                {1155875,
                 BlockHash::fromHex("00000000f17c850672894b9a75b63a1e72830bbd5f"
                                    "4c8889b5c1a80e7faef138")},
                // Nov, 13. DAA activation block.
                {1188697,
                 BlockHash::fromHex("0000000000170ed0918077bde7b4d36cc4c91be69f"
                                    "a09211f748240dabe047fb")},
                // Great wall activation.
                {1303885,
                 BlockHash::fromHex("00000000000000479138892ef0e4fa478ccc938fb9"
                                    "4df862ef5bde7e8dee23d3")},
                // Graviton activation.
                {1341712,
                 BlockHash::fromHex("00000000fffc44ea2e202bd905a9fbbb9491ef9e9d"
                                    "5a9eed4039079229afa35b")},
                // Phonon activation.
                {1378461, BlockHash::fromHex(
                              "0000000099f5509b5f36b1926bcf82b21d936ebeade"
                              "e811030dfbbb7fae915d7")},
            }};

        // Data as of block
        // 000000000005b07ecf85563034d13efd81c1a29e47e22b20f4fc6919d5b09cd6
        // (height 1223263)
        chainTxData = ChainTxData{1522608381, 15052068, 0.15};
    }
};

/**
 * Testnet (v3)
 */
class CPopTestNetParams : public CChainParams {
public:
    CPopTestNetParams() {
        strNetworkID = CBaseChainParams::POPTESTNET;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 514;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = BlockHash();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.powLimit = uint256S(
            "000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // 3 days
        //VeriBlock: reduced to 3 days to mitigate spiking difficulty due to excess hashrate
        consensus.nPowTargetTimespan = 3 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY] = {
            .bit = 28,
            // 75% of 2016
            .nActivationThreshold = 1512,
            // January 1, 2008
            .nStartTime = 1199145601,
            // December 31, 2008
            .nTimeout = 1230767999,
        };

        // The miner fund is disabled by default on testnet.
        consensus.enableMinerFund = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::TESTNET_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 0;

        // November 13, 2017 hard fork
        consensus.daaHeight = 500;
        // VeriBlock: DAA expects height to be this high
        assert(consensus.daaHeight > consensus.nPowTargetTimespan / consensus.nPowTargetSpacing);

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 0;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 0;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 0;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        // VeriBlock: disable Axion due to powLimit check
        consensus.axionActivationTime = 1889438400;

        // May 15, 2021 12:00:00 UTC protocol upgrade
        consensus.tachyonActivationTime = 0;

        // Nov 15, 2029 12:00:00 UTC protocol upgrade
        // Effectively disable it due to malfunction
        // Tests fail with mandatory-script-verify-flag-failed error and
        // Insufficient Funds error
        consensus.selectronActivationTime = 1889438400;

        // VeriBlock
        consensus.VeriBlockPopSecurityHeight = 1;

        diskMagic[0] = 0x0b;
        diskMagic[1] = 0x11;
        diskMagic[2] = 0x09;
        diskMagic[3] = 0x01;
        netMagic[0] = 0xf4;
        netMagic[1] = 0xe5;
        netMagic[2] = 0xf3;
        netMagic[3] = 0x01;

        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        std::string initialPubkey = "047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488";
        std::string pszTimestamp = "VeriBlock";

        genesis =
            VeriBlock::CreateGenesisBlock(1340, 97094286, 0x1d07ffff, 1, 50 * COIN, initialPubkey, pszTimestamp);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000015a1791b593053fe95626e6879cbf1be1f8fdb324ff28cf05d5da4bc3"));
        assert(genesis.hashMerkleRoot ==
               uint256S("314feb65abc8be73f5a93a0f6967a58c3d9526e7522adf1a09e43d700d34f1ff"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchpop";
        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_poptest, pnSeed6_poptest + ARRAYLEN(pnSeed6_poptest));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {{}};

        chainTxData = ChainTxData{0, 0, 0};
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        // always enforce P2SH BIP16 on regtest
        consensus.BIP16Height = 0;
        // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Height = 500;
        consensus.BIP34Hash = BlockHash();
        // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP65Height = 1351;
        // BIP66 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251;
        // CSV activated on regtest (Used in functional tests)
        consensus.CSVHeight = 576;
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // Faster than normal for regtest (144 instead of 2016)
        consensus.nMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY] = {
            .bit = 28,
            // 75% of 144
            .nActivationThreshold = 108,
        };

        // The miner fund is disabled by default on regnet.
        consensus.enableMinerFund = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = BlockHash();

        // UAHF is always enabled on regtest.
        consensus.uahfHeight = 0;

        // November 13, 2017 hard fork is always on on regtest.
        consensus.daaHeight = 0;

        // November 15, 2018 hard fork is always on on regtest.
        consensus.magneticAnomalyHeight = 0;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 0;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 0;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2021 12:00:00 UTC protocol upgrade
        consensus.tachyonActivationTime = 1621080000;

        // Nov 15, 2029 12:00:00 UTC protocol upgrade
        // Effectively disable it due to malfunction
        // Tests fail with mandatory-script-verify-flag-failed error and
        // Insufficient Funds error
        consensus.selectronActivationTime = 1889438400;

        // VeriBlock
        // TODO: set an VeriBlock pop security fork height
        consensus.VeriBlockPopSecurityHeight = 200;

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0] = 0xda;
        netMagic[1] = 0xb5;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xfa;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b"
                        "1a11466e2206"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab212"
                        "7b7afdeda33b"));

        //! Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //! Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            .mapCheckpoints = {
                {0, BlockHash::fromHex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb4"
                                       "36012afca590b1a11466e2206")},
            }};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchreg";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return std::make_unique<CMainParams>();
    }

    if (chain == CBaseChainParams::TESTNET) {
        return std::make_unique<CTestNetParams>();
    }

    if (chain == CBaseChainParams::POPTESTNET) {
        return std::make_unique<CPopTestNetParams>();
    }

    if (chain == CBaseChainParams::REGTEST) {
        return std::make_unique<CRegTestParams>();
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
