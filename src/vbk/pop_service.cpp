// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <memory>
#include <vector>

#include <chainparams.h>
#include <dbwrapper.h>
#include <shutdown.h>
#include <txdb.h>

#include <vbk/adaptors/block_batch_adaptor.hpp>
#include <vbk/adaptors/payloads_provider.hpp>
#include <vbk/p2p_sync.hpp>
#include <vbk/pop_common.hpp>
#include <vbk/pop_service.hpp>

#include <veriblock/storage/util.hpp>

#ifdef WIN32
#include <boost/thread/interruption.hpp>
#endif // WIN32

namespace VeriBlock {

static std::shared_ptr<PayloadsProvider> payloads = nullptr;
static std::vector<altintegration::PopData> disconnected_popdata;

bool acceptBlock(const CBlockIndex &indexNew, BlockValidationState &state) {
    AssertLockHeld(cs_main);
    auto containing = VeriBlock::blockToAltBlock(indexNew);
    altintegration::ValidationState instate;
    if (!GetPop().altTree->acceptBlockHeader(containing, instate)) {
        LogPrintf("ERROR: alt tree cannot accept block %s\n",
                  instate.toString());
        return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID,
                             REJECT_INVALID, "", "instate.GetDebugMessage()");
    }

    return true;
}

bool checkPopDataSize(const altintegration::PopData &popData,
                      altintegration::ValidationState &state) {
    uint32_t nPopDataSize = ::GetSerializeSize(popData, CLIENT_VERSION);
    if (nPopDataSize >= GetPop().config->alt->getMaxPopDataSize()) {
        return state.Invalid("popdata-overisize",
                             "popData raw size more than allowed");
    }

    return true;
}

bool popdataStatelessValidation(const altintegration::PopData &popData,
                                altintegration::ValidationState &state) {
    auto &config = *GetPop().config;

    for (const auto &b : popData.context) {
        if (!altintegration::checkBlock(b, state, *config.vbk.params)) {
            return state.Invalid("pop-vbkblock-statelessly-invalid");
        }
    }

    for (const auto &vtb : popData.vtbs) {
        if (!altintegration::checkVTB(vtb, state, *config.btc.params)) {
            return state.Invalid("pop-vtb-statelessly-invalid");
        }
    }

    for (const auto &atv : popData.atvs) {
        if (!altintegration::checkATV(atv, state, *config.alt)) {
            return state.Invalid("pop-atv-statelessly-invalid");
        }
    }

    return true;
}

bool addAllBlockPayloads(const CBlock &block, BlockValidationState &state) {
    AssertLockHeld(cs_main);
    auto bootstrapBlockHeight =
        GetPop().config->alt->getBootstrapBlock().height;
    auto hash = block.GetHash();
    auto *index = LookupBlockIndex(hash);

    if (index->nHeight == bootstrapBlockHeight) {
        // skip bootstrap block block
        return true;
    }

    altintegration::ValidationState instate;

    if (!checkPopDataSize(block.popData, instate) ||
        !popdataStatelessValidation(block.popData, instate)) {
        return error(
            "[%s] block %s is not accepted because popData is invalid: %s",
            __func__, hash.ToString(), instate.toString());
    }

    auto &provider = GetPayloadsProvider();
    provider.write(block.popData);

    GetPop().altTree->acceptBlock(
        std::vector<uint8_t>{hash.begin(), hash.end()}, block.popData);

    return true;
}

bool setState(const BlockHash &hash, altintegration::ValidationState &state) {
    AssertLockHeld(cs_main);
    return GetPop().altTree->setState(
        std::vector<uint8_t>{hash.begin(), hash.end()}, state);
}

altintegration::PopData getPopData() {
    AssertLockHeld(cs_main);
    return GetPop().mempool->getPop();
}

void removePayloadsFromMempool(const altintegration::PopData &popData) {
    AssertLockHeld(cs_main);
    GetPop().mempool->removeAll(popData);
}

void updatePopMempoolForReorg() {
    AssertLockHeld(cs_main);
    auto &pop = GetPop();
    for (const auto &popData : disconnected_popdata) {
        pop.mempool->submitAll(popData);
    }
    disconnected_popdata.clear();
}

void addDisconnectedPopdata(const altintegration::PopData &popData) {
    AssertLockHeld(cs_main);
    disconnected_popdata.push_back(popData);
}

void SetPop(CDBWrapper &db) {
    payloads = std::make_shared<PayloadsProvider>(db);
    std::shared_ptr<altintegration::PayloadsProvider> dbrepo = payloads;
    SetPop(dbrepo);

    auto &app = GetPop();
    app.mempool->onAccepted<altintegration::ATV>(
        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::ATV>);
    app.mempool->onAccepted<altintegration::VTB>(
        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VTB>);
    app.mempool->onAccepted<altintegration::VbkBlock>(
        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VbkBlock>);
}

PayloadsProvider &GetPayloadsProvider() {
    return *payloads;
}

bool hasPopData(CBlockTreeDB &db) {
    return db.Exists(BlockBatchAdaptor::btctip()) &&
           db.Exists(BlockBatchAdaptor::vbktip()) &&
           db.Exists(BlockBatchAdaptor::alttip());
}

void saveTrees(altintegration::BlockBatchAdaptor &batch) {
    AssertLockHeld(cs_main);
    altintegration::SaveAllTrees(*GetPop().altTree, batch);
}

template <typename BlockTree>
bool LoadTree(CDBIterator &iter, char blocktype,
              std::pair<char, std::string> tiptype, BlockTree &out,
              altintegration::ValidationState &state) {
    using index_t = typename BlockTree::index_t;
    using block_t = typename index_t::block_t;
    using hash_t = typename BlockTree::hash_t;

    // Load tip
    hash_t tiphash;
    std::pair<char, std::string> ckey;

    iter.Seek(tiptype);
    if (!iter.Valid()) {
        // no valid tip is stored = no need to load anything
        return error("%s: failed to load %s tip", block_t::name());
    }
    if (!iter.GetKey(ckey)) {
        return error("%s: failed to find key %c:%s in %s", __func__,
                     tiptype.first, tiptype.second, block_t::name());
    }
    if (ckey != tiptype) {
        return error("%s: bad key for tip %c:%s in %s", __func__, tiptype.first,
                     tiptype.second, block_t::name());
    }
    if (!iter.GetValue(tiphash)) {
        return error("%s: failed to read tip value in %s", __func__,
                     block_t::name());
    }

    std::vector<index_t> blocks;

    // Load blocks
    iter.Seek(std::make_pair(blocktype, hash_t()));
    while (iter.Valid()) {
#if defined BOOST_THREAD_PROVIDES_INTERRUPTIONS
        boost::this_thread::interruption_point();
#endif
        if (ShutdownRequested()) return false;
        std::pair<char, hash_t> key;
        if (iter.GetKey(key) && key.first == blocktype) {
            index_t diskindex;
            if (iter.GetValue(diskindex)) {
                blocks.push_back(diskindex);
                iter.Next();
            } else {
                return error("%s: failed to read %s block", __func__,
                             block_t::name());
            }
        } else {
            break;
        }
    }

    // sort blocks by height
    std::sort(blocks.begin(), blocks.end(),
              [](const index_t &a, const index_t &b) {
                  return a.getHeight() < b.getHeight();
              });
    if (!altintegration::LoadTree(out, blocks, tiphash, state)) {
        return error("%s: failed to load tree %s", __func__, block_t::name());
    }

    auto *tip = out.getBestChain().tip();
    assert(tip);
    LogPrintf("Loaded %d blocks in %s tree with tip %s\n",
              out.getBlocks().size(), block_t::name(),
              tip->toShortPrettyString());

    return true;
}

bool loadTrees(CDBIterator &iter) {
    auto &pop = GetPop();
    altintegration::ValidationState state;
    if (!LoadTree(iter, DB_BTC_BLOCK, BlockBatchAdaptor::btctip(),
                  pop.altTree->btc(), state)) {
        return error("%s: failed to load BTC tree %s", __func__,
                     state.toString());
    }
    if (!LoadTree(iter, DB_VBK_BLOCK, BlockBatchAdaptor::vbktip(),
                  pop.altTree->vbk(), state)) {
        return error("%s: failed to load VBK tree %s", __func__,
                     state.toString());
    }
    if (!LoadTree(iter, DB_ALT_BLOCK, BlockBatchAdaptor::alttip(), *pop.altTree,
                  state)) {
        return error("%s: failed to load ALT tree %s", __func__,
                     state.toString());
    }

    return true;
}

PoPRewards getPopRewards(const CBlockIndex &pindexPrev) {
    AssertLockHeld(cs_main);
    auto &param = Params();

    if (!param.isPopEnabled(pindexPrev.nHeight)) {
        return {};
    }

    const auto &pop = GetPop();
    auto &cfg = *pop.config;

    if (pindexPrev.nHeight < (int)cfg.alt->getEndorsementSettlementInterval()) {
        return {};
    }

    if (pindexPrev.nHeight < (int)cfg.alt->getPopPayoutDelay()) {
        return {};
    }

    altintegration::ValidationState state;
    auto hash = pindexPrev.GetBlockHash();
    std::vector<uint8_t> v_hash{hash.begin(), hash.end()};

    bool ret = pop.altTree->setState(v_hash, state);
    (void)ret;
    assert(ret);

    auto rewards = pop.altTree->getPopPayout(v_hash);
    int halving =
        (pindexPrev.nHeight + 1) / param.GetConsensus().nSubsidyHalvingInterval;
    PoPRewards btcRewards{};
    // erase rewards, that pay 0 satoshis and halve rewards
    for (const auto &r : rewards) {
        auto rewardValue = r.second;
        rewardValue >>= halving;

        if ((rewardValue != 0) && (halving < 64)) {
            CScript key = CScript(r.first.begin(), r.first.end());
            btcRewards[key] = param.PopRewardCoefficient() * rewardValue;
        }
    }

    return btcRewards;
}

void addPopPayoutsIntoCoinbaseTx(CMutableTransaction &coinbaseTx,
                                 const CBlockIndex &pindexPrev) {
    AssertLockHeld(cs_main);
    PoPRewards rewards = getPopRewards(pindexPrev);

    assert(coinbaseTx.vout.size() == 1 &&
           "at this place we should have only PoW payout here");

    for (const auto &itr : rewards) {
        CTxOut out;
        out.scriptPubKey = itr.first;

        out.nValue = itr.second * Amount::satoshi();
        coinbaseTx.vout.push_back(out);
    }
}

bool checkCoinbaseTxWithPopRewards(const CTransaction &tx, const Amount &nFees,
                                   const CBlockIndex &pindexPrev,
                                   const Consensus::Params &consensusParams,
                                   Amount &blockReward,
                                   BlockValidationState &state) {
    AssertLockHeld(cs_main);
    PoPRewards rewards = getPopRewards(pindexPrev);
    Amount nTotalPopReward = Amount::zero();

    if (tx.vout.size() < rewards.size()) {
        return state.Invalid(
            BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
            "bad-pop-vouts-size",
            strprintf(
                "checkCoinbaseTxWithPopRewards(): coinbase has incorrect size "
                "of pop vouts (actual vouts size=%d vs expected vouts=%d)",
                tx.vout.size(), rewards.size()));
    }

    std::map<CScript, Amount> cbpayouts;
    // skip first reward, as it is always PoW payout
    for (auto out = tx.vout.begin() + 1, end = tx.vout.end(); out != end;
         ++out) {
        // pop payouts can not be null
        if (out->IsNull()) {
            continue;
        }
        cbpayouts[out->scriptPubKey] += out->nValue;
    }

    // skip first (regular pow) payout, and last 2 0-value payouts
    for (const auto &payout : rewards) {
        auto &script = payout.first;
        Amount expectedAmount = payout.second * Amount::satoshi();

        auto p = cbpayouts.find(script);
        // coinbase pays correct reward?
        if (p == cbpayouts.end()) {
            // we expected payout for that address
            return state.Invalid(
                BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
                "bad-pop-missing-payout",
                strprintf("[tx: %s] missing payout for scriptPubKey: '%s' with "
                          "amount: '%d'",
                          tx.GetHash().ToString(), HexStr(script),
                          expectedAmount));
        }

        // payout found
        Amount actualAmount{p->second};
        // does it have correct amount?
        if (actualAmount != expectedAmount) {
            return state.Invalid(
                BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
                "bad-pop-wrong-payout",
                strprintf("[tx: %s] wrong payout for scriptPubKey: '%s'. "
                          "Expected %d, got %d.",
                          tx.GetHash().ToString(), HexStr(script),
                          expectedAmount, actualAmount));
        }

        nTotalPopReward += expectedAmount;
    }

    Amount PoWBlockReward =
        GetBlockSubsidy(pindexPrev.nHeight, consensusParams);

    blockReward = nTotalPopReward + PoWBlockReward + nFees;

    if (tx.GetValueOut() > blockReward) {
        return state.Invalid(
            BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
            "bad-cb-pop-amount",
            strprintf("ConnectBlock(): coinbase pays too much (actual=%s vs "
                      "limit=%s)",
                      tx.GetValueOut().ToString(), blockReward.ToString()));
    }
    return true;
}

Amount getCoinbaseSubsidy(Amount subsidy, int32_t height) {
    if (Params().isPopEnabled(height)) {
        // int64_t powRewardPercentage = 100 - Params().PopRewardPercentage();
        // subsidy = powRewardPercentage * subsidy;
        // subsidy = subsidy / 100;
    }
    return subsidy;
}

CBlockIndex *compareTipToBlock(CBlockIndex *candidate) {
    AssertLockHeld(cs_main);
    assert(candidate != nullptr &&
           "block has no according header in block tree");

    auto blockHash = candidate->GetBlockHash();
    auto *tip = ChainActive().Tip();
    if (!tip) {
        // if tip is not set, candidate wins
        return tip;
    }

    auto tipHash = tip->GetBlockHash();
    if (tipHash == blockHash) {
        // we compare tip with itself
        return tip;
    }

    int result = 0;
    if (Params().isPopEnabled(tip->nHeight)) {
        result = compareForks(*tip, *candidate);
    } else {
        result = CBlockIndexWorkComparator()(tip, candidate) == true ? -1 : 1;
    }

    if (result < 0) {
        // candidate has higher POP score
        return candidate;
    }

    if (result == 0 && tip->nChainWork < candidate->nChainWork) {
        // candidate is POP equal to current tip;
        // candidate has higher chainwork
        return candidate;
    }

    // otherwise, current chain wins
    return tip;
}

int compareForks(const CBlockIndex &leftForkTip,
                 const CBlockIndex &rightForkTip) {
    AssertLockHeld(cs_main);

    auto &pop = GetPop();

    if (&leftForkTip == &rightForkTip) {
        return 0;
    }

    auto left = blockToAltBlock(leftForkTip);
    auto right = blockToAltBlock(rightForkTip);
    auto state = altintegration::ValidationState();

    if (!pop.altTree->setState(left.hash, state)) {
        if (!pop.altTree->setState(right.hash, state)) {
            throw std::logic_error("both chains are invalid");
        }
        return -1;
    }

    return pop.altTree->comparePopScore(left.hash, right.hash);
}

std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks) {
    AssertLockHeld(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().altTree->vbk(), blocks);
}
std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks) {
    AssertLockHeld(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().altTree->btc(), blocks);
}

} // namespace VeriBlock