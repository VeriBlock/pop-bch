// Copyright (c) 2019-2021 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <limits>
#include <shutdown.h>
#include <txdb.h>
#include <validation.h>
#include <vbk/adaptors/payloads_provider.hpp>
#include <veriblock/pop.hpp>


#ifdef WIN32
#include <boost/thread/interruption.hpp>
#endif //WIN32

#include "pop_service.hpp"
#include <utility>
#include <vbk/adaptors/block_provider.hpp>
#include <vbk/p2p_sync.hpp>
#include <vbk/pop_common.hpp>
#include <veriblock/pop.hpp>


namespace VeriBlock {

static uint64_t popScoreComparisons = 0ULL;
template <typename T>
void onAcceptedToMempool(const T& t) {
    assert(g_rpc_node);
    assert(g_rpc_node->connman);
    p2p::RelayPopPayload(g_rpc_node->connman.get(), t);
}

void InitPopContext(CDBWrapper& db)
{
    auto payloads_provider = std::make_shared<PayloadsProvider>(db);
    auto block_provider = std::make_shared<BlockReader>(db);
    SetPop(payloads_provider, block_provider);

    auto& app = GetPop();
    app.getMemPool().onAccepted<altintegration::ATV>(onAcceptedToMempool<altintegration::ATV>);
    app.getMemPool().onAccepted<altintegration::VTB>(onAcceptedToMempool<altintegration::VTB>);
    app.getMemPool().onAccepted<altintegration::VbkBlock>(onAcceptedToMempool<altintegration::VbkBlock>);
}

CBlockIndex* compareTipToBlock(CBlockIndex* candidate)
{
    AssertLockHeld(cs_main);
    assert(candidate != nullptr && "block has no according header in block tree");

    auto blockHash = candidate->GetBlockHash();
    auto* tip = ChainActive().Tip();
    if (!tip) {
        // if tip is not set, candidate wins
        return nullptr;
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
        result = CBlockIndexWorkComparator()(tip, candidate) ? -1 : 1;
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

bool acceptBlock(const CBlockIndex& indexNew, BlockValidationState& state)
{
    AssertLockHeld(cs_main);
    auto containing = VeriBlock::blockToAltBlock(indexNew);
    altintegration::ValidationState instate;
    if (!GetPop().getAltBlockTree().acceptBlockHeader(containing, instate)) {
        LogPrintf("ERROR: alt tree cannot accept block %s\n", instate.toString());
        return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID, REJECT_INVALID, instate.GetPath());
    }

    return true;
}

bool addAllBlockPayloads(const CBlock& block, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    auto bootstrapBlockHeight = GetPop().getConfig().getAltParams().getBootstrapBlock().height;
    auto hash = block.GetHash();
    auto* index = LookupBlockIndex(hash);

    if (index->nHeight == bootstrapBlockHeight) {
        // skip bootstrap block block
        return true;
    }

    altintegration::ValidationState instate;

    if (!GetPop().check(block.popData, instate)) {
        return error("[%s] block %s is not accepted because popData is invalid: %s", __func__, block.GetHash().ToString(),
            instate.toString());
    }

    GetPop().getAltBlockTree().acceptBlock(block.GetHash().asVector(), block.popData);

    return true;
}

bool setState(const uint256& block, altintegration::ValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    return GetPop().getAltBlockTree().setState(block.asVector(), state);
}

altintegration::PopData generatePopData() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    return GetPop().generatePopData();
}

// PoP rewards are calculated for the current tip but are paid in the next block
PoPRewards getPopRewards(const CBlockIndex& tip, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    auto& pop = GetPop();

    if (!params.isPopActive(tip.nHeight)) {
        return {};
    }

    auto& cfg = pop.getConfig();
    if (tip.nHeight < (int)cfg.alt->getEndorsementSettlementInterval()) {
        return {};
    }
    if (tip.nHeight < (int)cfg.alt->getPayoutParams().getPopPayoutDelay()) {
        return {};
    }

    altintegration::ValidationState state;
    auto prevHash = tip.GetBlockHash().asVector();
    bool ret = pop.getAltBlockTree().setState(prevHash, state);
    VBK_ASSERT_MSG(ret, "error: %s", state.toString());

    altintegration::PopPayouts rewards;
    ret = pop.getPopPayout(prevHash, rewards, state);
    VBK_ASSERT_MSG(ret, "error: %s", state.toString());

    // erase rewards, that pay 0 satoshis, then halve rewards
    PoPRewards result{};
    for (const auto& r : rewards) {
        // we use airth_uint256 to prevent any overflows
        arith_uint256 coeff(r.second);
        // 50% of multiplier towards POP.
        arith_uint256 payout = coeff * arith_uint256((VeriBlock::GetSubsidyMultiplier(tip.nHeight + 1, params) / 2) / COIN);
        if(payout > 0) {
            CScript key = CScript(r.first.begin(), r.first.end());
            assert(payout <= std::numeric_limits<int64_t>::max() && "overflow!");
            result[key] = payout.GetLow64();
        }
    }

    return result;
}

void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main){
    AssertLockHeld(cs_main);
    PoPRewards rewards = getPopRewards(pindexPrev, params);
    assert(coinbaseTx.vout.size() == 1 && "at this place we should have only PoW payout here");
    for (const auto& itr : rewards) {
        CTxOut out;
        out.scriptPubKey = itr.first;
        out.nValue = itr.second * Amount::satoshi();
        coinbaseTx.vout.push_back(out);
    }
}

bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const Amount& nFees, const CBlockIndex& pindex, const CChainParams& params, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    PoPRewards expectedRewards = getPopRewards(*pindex.pprev, params);
    Amount nTotalPopReward = Amount::zero();

    if (tx.vout.size() < expectedRewards.size()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID, "bad-pop-vouts-size",
            strprintf("checkCoinbaseTxWithPopRewards(): coinbase has incorrect size of pop vouts (actual vouts size=%d vs expected vouts=%d)", tx.vout.size(), expectedRewards.size()));
    }

    std::map<CScript, Amount> cbpayouts;
    // skip first reward, as it is always PoW payout
    for (auto out = tx.vout.begin() + 1, end = tx.vout.end(); out != end; ++out) {
        // pop payouts can not be null
        if (out->IsNull()) {
            continue;
        }
        cbpayouts[out->scriptPubKey] += out->nValue;
    }

    // skip first (regular pow) payout, and last 2 0-value payouts
    for (const auto& payout : expectedRewards) {
        auto& script = payout.first;
        auto expectedAmount = payout.second * Amount::satoshi();

        auto p = cbpayouts.find(script);
        // coinbase pays correct reward?
        if (p == cbpayouts.end()) {
            // we expected payout for that address
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID, "bad-pop-missing-payout",
                strprintf("[tx: %s] missing payout for scriptPubKey: '%s' with amount: '%d'",
                    tx.GetHash().ToString(),
                    HexStr(script),
                    expectedAmount));
        }

        // payout found
        auto& actualAmount = p->second;
        // does it have correct amount?
        if (actualAmount != expectedAmount) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID, "bad-pop-wrong-payout",
                strprintf("[tx: %s] wrong payout for scriptPubKey: '%s'. Expected %d, got %d.",
                    tx.GetHash().ToString(),
                    HexStr(script),
                    expectedAmount, actualAmount));
        }

        nTotalPopReward += expectedAmount;
    }

    Amount PoWBlockReward = GetBlockSubsidy(pindex.nHeight, params);

    if (tx.GetValueOut() > nTotalPopReward + PoWBlockReward + nFees) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
            "bad-cb-pop-amount",
            strprintf("ConnectBlock(): coinbase pays too much (actual=%d vs POW=%d + POP=%d)", tx.GetValueOut(), PoWBlockReward, nTotalPopReward));
    }

    return true;
}

std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks)
{
    LOCK(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().getVbkBlockTree(), blocks);
}

std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks)
{
    LOCK(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().getBtcBlockTree(), blocks);
}

bool hasPopData(CBlockTreeDB& db)
{
    return db.Exists(tip_key<altintegration::BtcBlock>()) &&
           db.Exists(tip_key<altintegration::VbkBlock>()) &&
           db.Exists(tip_key<altintegration::AltBlock>());
}

void saveTrees(CDBBatch* batch)
{
    AssertLockHeld(cs_main);
    VeriBlock::BlockBatch b(*batch);
    GetPop().saveAllTrees(b);
}
bool loadTrees()
{
    altintegration::ValidationState state;

    if (!GetPop().loadAllTrees(state)) {
        return error("%s: failed to load trees %s", __func__, state.toString());
    }

    return true;
}

void removePayloadsFromMempool(const altintegration::PopData& popData) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    GetPop().getMemPool().removeAll(popData);
}

int compareForks(const CBlockIndex& leftForkTip, const CBlockIndex& rightForkTip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto& pop = GetPop();
    AssertLockHeld(cs_main);
    if (&leftForkTip == &rightForkTip) {
        return 0;
    }

    if (leftForkTip.GetAncestor(rightForkTip.nHeight) == &rightForkTip) {
        // do not run POP FR on blocks which are already in active chain
        return 1;
    }

    auto left = blockToAltBlock(leftForkTip);
    auto right = blockToAltBlock(rightForkTip);
    auto state = altintegration::ValidationState();

    if (!pop.getAltBlockTree().setState(left.hash, state)) {
        assert(false && "current tip is invalid");
    }

    popScoreComparisons++;
    return pop.getAltBlockTree().comparePopScore(left.hash, right.hash);
}

void addDisconnectedPopdata(const altintegration::PopData& popData) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    altintegration::ValidationState state;
    auto& popmp = VeriBlock::GetPop().getMemPool();
    for (const auto& i : popData.context) {
        popmp.submit(i, state);
    }
    for (const auto& i : popData.vtbs) {
        popmp.submit(i, state);
    }
    for (const auto& i : popData.atvs) {
        popmp.submit(i, state);
    }
}

bool isCrossedBootstrapBlock()
{
    auto* tip = ChainActive().Tip();
    if (tip != nullptr) {
        return isCrossedBootstrapBlock(tip->nHeight);
    }
    return false;
}

bool isCrossedBootstrapBlock(int32_t height)
{
    auto block = VeriBlock::GetPop().getConfig().getAltParams().getBootstrapBlock();
    return height >= block.getHeight();
}

bool isPopActive()
{
    auto* tip = ChainActive().Tip();
    if (tip != nullptr) {
        return isPopActive(tip->nHeight);
    }
    return false;
}
bool isPopActive(int32_t height)
{
    if (!isCrossedBootstrapBlock(height)) {
        // if we didn't cross bootstrap block, then POP can't be active
        return false;
    }
    return Params().isPopActive(height);
}

// get stats on POP score comparisons
uint64_t getPopScoreComparisons() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    return popScoreComparisons;
}

Amount GetSubsidyMultiplier(int nHeight, const CChainParams& params) {
    // Subsidy calculation has been moved here from GetBlockSubsidy()

    int halvings = nHeight / params.GetConsensus().nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64) {
        return Amount::zero();
    }

    Amount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur
    // approximately every 4 years.
    return ((nSubsidy / SATOSHI) >> halvings) * SATOSHI;
}


} // namespace VeriBlock
