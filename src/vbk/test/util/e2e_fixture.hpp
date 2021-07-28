// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP
#define BITCOIN_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <consensus/merkle.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <validation.h>

#include <vbk/bootstraps.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/util.hpp>

#include <veriblock/pop.hpp>

using altintegration::ATV;
using altintegration::BtcBlock;
using altintegration::MockMiner;
using altintegration::PublicationData;
using altintegration::VbkBlock;
using altintegration::VTB;

struct TestLogger : public altintegration::Logger {
    ~TestLogger() override = default;

    void log(altintegration::LogLevel lvl, const std::string &msg) override {
        fmt::printf("[pop] [%s]\t%s\n", altintegration::LevelToString(lvl),
                    msg);
    }
};

struct E2eFixture : public TestChain100Setup {
    CScript cbKey = CScript()
                    << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    MockMiner popminer;
    altintegration::PopContext *pop;
    std::vector<uint8_t> defaultPayoutInfo = {1, 2, 3, 4, 5};

    E2eFixture() {
        altintegration::SetLogger<TestLogger>();
        altintegration::GetLogger().level = altintegration::LogLevel::warn;

        CScript scriptPubKey =
            CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

        while (!Params().isPopActive(ChainActive().Tip()->nHeight)) {
            CBlock b = CreateAndProcessBlock({}, scriptPubKey);
            m_coinbase_txns.push_back(b.vtx[0]);
        }

        pop = &VeriBlock::GetPop();
    }

    void InvalidateTestBlock(CBlockIndex *pblock) {
        BlockValidationState state;
        ChainstateActive().InvalidateBlock(GetConfig(), state, pblock);
        ActivateBestChain(GetConfig(), state);
        g_mempool.clear();
    }

    void ReconsiderTestBlock(CBlockIndex *pblock) {
        BlockValidationState state;

        {
            LOCK(cs_main);
            ResetBlockFailureFlags(pblock);
        }
        ActivateBestChain(GetConfig(), state);
    }

    BtcBlock::hash_t getLastKnownBTCblock() {
        auto blocks = VeriBlock::getLastKnownBTCBlocks(1);
        BOOST_CHECK(blocks.size() == 1);
        return blocks[0];
    }

    VbkBlock::hash_t getLastKnownVBKblock() {
        auto blocks = VeriBlock::getLastKnownVBKBlocks(1);
        BOOST_CHECK(blocks.size() == 1);
        return blocks[0];
    }

    ATV endorseAltBlock(BlockHash hash,
                        const std::vector<uint8_t> &payoutInfo) {
        CBlockIndex *endorsed = nullptr;
        {
            LOCK(cs_main);
            endorsed = LookupBlockIndex(hash);
            BOOST_CHECK(endorsed != nullptr);
        }

        auto publicationdata = createPublicationData(endorsed, payoutInfo);
        auto vbktx = popminer.createVbkTxEndorsingAltBlock(publicationdata);
        auto *vbkblock = popminer.mineVbkBlocks(1, {vbktx});
        auto atv = popminer.createATV(vbkblock->getHeader(), vbktx);
        return atv;
    }

    ATV endorseAltBlock(BlockHash hash) {
        return endorseAltBlock(hash, defaultPayoutInfo);
    }

    CBlock endorseAltBlockAndMine(const std::vector<BlockHash> &hashes,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(
            hashes, ChainActive().Tip()->GetBlockHash(), generateVtbs);
    }

    CBlock endorseAltBlockAndMine(const std::vector<BlockHash> &hashes,
                                  BlockHash prevBlock,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(hashes, prevBlock, defaultPayoutInfo,
                                      generateVtbs);
    }

    CBlock endorseAltBlockAndMine(const std::vector<BlockHash> &hashes,
                                  BlockHash prevBlock,
                                  const std::vector<uint8_t> &payoutInfo,
                                  size_t generateVtbs = 0,
                                  bool expectAccepted = false) {
        std::vector<VTB> vtbs;
        vtbs.reserve(generateVtbs);
        std::generate_n(std::back_inserter(vtbs), generateVtbs,
                        [&]() { return endorseVbkTip(); });

        std::vector<ATV> atvs;
        atvs.reserve(hashes.size());
        std::transform(hashes.begin(), hashes.end(), std::back_inserter(atvs),
                       [&](const BlockHash &hash) -> ATV {
                           return endorseAltBlock(hash, payoutInfo);
                       });

        auto &pop_mempool = VeriBlock::GetPop().getMemPool();
        altintegration::ValidationState state;
        for (const auto &atv : atvs) {
            pop_mempool.submit(atv, state);
            // do not check the submit result - expect statefully invalid data
            // for testing purposes
        }

        for (const auto &vtb : vtbs) {
            pop_mempool.submit(vtb, state);
            // do not check the submit result - expect statefully invalid data
            // for testing purposes
        }

        bool isValid = false;
        const auto &block = CreateAndProcessBlock({}, cbKey, &isValid);
        BOOST_CHECK(isValid);
        return block;
    }

    CBlock endorseAltBlockAndMine(BlockHash hash, BlockHash prevBlock,
                                  const std::vector<uint8_t> &payoutInfo,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(std::vector<BlockHash>{hash}, prevBlock,
                                      payoutInfo, generateVtbs);
    }

    CBlock endorseAltBlockAndMine(BlockHash hash, size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(hash, ChainActive().Tip()->GetBlockHash(),
                                      generateVtbs);
    }

    CBlock endorseAltBlockAndMine(BlockHash hash, BlockHash prevBlock,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(hash, prevBlock, defaultPayoutInfo,
                                      generateVtbs);
    }

    VTB endorseVbkTip() {
        auto best = popminer.vbk().getBestChain();
        auto tip = best.tip();
        BOOST_CHECK(tip != nullptr);
        return endorseVbkBlock(tip->getHeight());
    }

    VTB endorseVbkBlock(int height) {
        auto vbkbest = popminer.vbk().getBestChain();
        auto endorsed = vbkbest[height];
        if (!endorsed) {
            throw std::logic_error("can not find VBK block at height " +
                                   std::to_string(height));
        }

        {
            LOCK(cs_main);
            return popminer.endorseVbkBlock(endorsed->getHeader(),
                                        getLastKnownBTCblock());
        }
    }

    PublicationData createPublicationData(CBlockIndex* endorsed, const std::vector<uint8_t>& payoutInfo)
    {
        assert(endorsed);

        auto hash = endorsed->GetBlockHash();
        CBlock block;
        bool read = ReadBlockFromDisk(block, endorsed, Params().GetConsensus());
        assert(read && "expected to read endorsed block from disk");

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << endorsed->GetBlockHeader();
        std::vector<uint8_t> header{stream.begin(), stream.end()};

        auto txRoot = BlockMerkleRoot(block, nullptr).asVector();
        auto* libendorsed = VeriBlock::GetPop().getAltBlockTree().getBlockIndex(hash.asVector());
        assert(libendorsed && "expected to have endorsed header in library");
        return altintegration::GeneratePublicationData(
            header,
            *libendorsed,
            txRoot,
            block.popData,
            payoutInfo,
            VeriBlock::GetPop().getConfig().getAltParams());
    }

    PublicationData createPublicationData(CBlockIndex *endorsed) {
        return createPublicationData(endorsed, defaultPayoutInfo);
    }

    CBlockIndex* MineToKeystone()
    {
        while (true) {
            CBlockIndex* tip = ChainActive().Tip();
            if (tip == nullptr) return tip;
            if (VeriBlock::isKeystone(*tip)) return tip;
            CreateAndProcessBlock({}, cbKey);
        }
    }
};

#endif // BITCOIN_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP