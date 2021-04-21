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
#include <vbk/adaptors/payloads_provider.hpp>

#ifdef WIN32
#include <boost/thread/interruption.hpp>
#endif // WIN32

#include "pop_service.hpp"
#include <utility>
#include <vbk/adaptors/block_provider.hpp>
#include <vbk/p2p_sync.hpp>
#include <vbk/pop_common.hpp>
#include <vbk/util.hpp>
#include <veriblock/pop.hpp>

namespace VeriBlock {

static std::vector<altintegration::PopData> disconnected_popdata;

bool acceptBlock(const CBlockIndex &indexNew, BlockValidationState &state) {
    AssertLockHeld(cs_main);
    auto containing = VeriBlock::blockToAltBlock(indexNew);
    altintegration::ValidationState instate;
    if (!GetPop().getAltBlockTree().acceptBlockHeader(containing, instate)) {
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
    if (nPopDataSize >=
        GetPop().getConfig().getAltParams().getMaxPopDataSize()) {
        return state.Invalid("popdata-overisize",
                             "popData raw size more than allowed");
    }

    return true;
}

bool addAllBlockPayloads(const CBlock &block, BlockValidationState &state) {
    AssertLockHeld(cs_main);
    auto bootstrapBlockHeight =
        GetPop().getConfig().getAltParams().getBootstrapBlock().height;
    auto hash = block.GetHash();
    auto *index = LookupBlockIndex(hash);

    if (index->nHeight == bootstrapBlockHeight) {
        // skip bootstrap block block
        return true;
    }

    altintegration::ValidationState instate;

    if (!GetPop().check(block.popData, instate)) {
        return error(
            "[%s] block %s is not accepted because popData is invalid: %s",
            __func__, block.GetHash().ToString(), instate.toString());
    }

    GetPop().getAltBlockTree().acceptBlock(
        std::vector<uint8_t>{hash.begin(), hash.end()}, block.popData);

    return true;
}

bool setState(const BlockHash &hash, altintegration::ValidationState &state) {
    AssertLockHeld(cs_main);
    return GetPop().getAltBlockTree().setState(
        std::vector<uint8_t>{hash.begin(), hash.end()}, state);
}

void removePayloadsFromMempool(const altintegration::PopData &popData) {
    AssertLockHeld(cs_main);
    GetPop().getMemPool().removeAll(popData);
}

void updatePopMempoolForReorg() {
    AssertLockHeld(cs_main);
    altintegration::ValidationState state;
    auto &popmp = VeriBlock::GetPop().getMemPool();
    for (const auto &popData : disconnected_popdata) {
        for (const auto &i : popData.context) {
            popmp.submit(i, state);
        }
        for (const auto &i : popData.vtbs) {
            popmp.submit(i, state);
        }
        for (const auto &i : popData.atvs) {
            popmp.submit(i, state);
        }
    }
    disconnected_popdata.clear();
}

void addDisconnectedPopdata(const altintegration::PopData &popData) {
    AssertLockHeld(cs_main);
    disconnected_popdata.push_back(popData);
}

void SetPop(CDBWrapper &db) {
    auto payloads_provider = std::make_shared<PayloadsProvider>(db);
    SetPop(payloads_provider);

    auto &app = GetPop();
    app.getMemPool().onAccepted<altintegration::ATV>(
        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::ATV>);
    app.getMemPool().onAccepted<altintegration::VTB>(
        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VTB>);
    app.getMemPool().onAccepted<altintegration::VbkBlock>(
        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VbkBlock>);
}

altintegration::PopData getPopData(const CBlockIndex &pindexPrev)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    auto prevHash = pindexPrev.GetBlockHash().asVector();
    auto res = GetPop().generatePopData(prevHash);
    return res;
}

bool hasPopData(CBlockTreeDB &db) {
    return db.Exists(tip_key<altintegration::BtcBlock>()) &&
           db.Exists(tip_key<altintegration::VbkBlock>()) &&
           db.Exists(tip_key<altintegration::AltBlock>());
}

void saveTrees(CDBBatch *batch) {
    AssertLockHeld(cs_main);
    VeriBlock::BlockBatch b(*batch);
    GetPop().saveAllTrees(b);
}
bool loadTrees(CDBWrapper &db) {
    altintegration::ValidationState state;

    BlockReader reader(db);
    if (!GetPop().loadAllTrees(reader, state)) {
        return error("%s: failed to load trees %s", __func__, state.toString());
    }

    return true;
}

PoPRewards getPopRewards(const CBlockIndex &pindexPrev) {
    AssertLockHeld(cs_main);
    auto &param = Params();

    if (!param.isPopActive(pindexPrev.nHeight)) {
        return {};
    }

    auto &pop = GetPop();
    auto &cfg = pop.getConfig();

    if (pindexPrev.nHeight <
        (int)cfg.getAltParams().getEndorsementSettlementInterval()) {
        return {};
    }

    if (pindexPrev.nHeight <
        (int)cfg.getAltParams().getPayoutParams().getPopPayoutDelay()) {
        return {};
    }

    altintegration::ValidationState state;
    auto hash = pindexPrev.GetBlockHash();
    std::vector<uint8_t> v_hash{hash.begin(), hash.end()};

    bool ret = pop.getAltBlockTree().setState(v_hash, state);
    (void)ret;
    assert(ret);

    auto rewards = pop.getPopPayout(v_hash);
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
    if (Params().isPopActive(height)) {
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
    if (Params().isPopActive(tip->nHeight)) {
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

    if (!pop.getAltBlockTree().setState(left.hash, state)) {
        if (!pop.getAltBlockTree().setState(right.hash, state)) {
            throw std::logic_error("both chains are invalid");
        }
        return -1;
    }

    return pop.getAltBlockTree().comparePopScore(left.hash, right.hash);
}

std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks) {
    AssertLockHeld(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().getAltBlockTree().vbk(),
                                              blocks);
}
std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks) {
    AssertLockHeld(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().getAltBlockTree().btc(),
                                              blocks);
}

bool isPopEnabled()
{
    auto* tip = ChainActive().Tip();
    if (tip != nullptr) {
        return isPopEnabled(tip->nHeight);
    }
    return false;
}

bool isPopEnabled(int32_t height)
{
    auto block = VeriBlock::GetPop().getConfig().getAltParams().getBootstrapBlock();
    return height >= block.getHeight();
}

} // namespace VeriBlock