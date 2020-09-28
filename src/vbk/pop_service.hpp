// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SRC_VBK_POP_SERVICE_HPP
#define BITCOIN_SRC_VBK_POP_SERVICE_HPP

#include <consensus/validation.h>
#include <validation.h>

#include <vbk/adaptors/block_batch_adaptor.hpp>
#include <vbk/adaptors/payloads_provider.hpp>
#include <vbk/pop_common.hpp>
#include <vbk/util.hpp>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

class CBlockIndex;
class CBlock;
class CScript;
class CBlockTreeDB;
class CDBIterator;
class CDBWrapper;
class BlockValidationState;

namespace VeriBlock {

using BlockBytes = std::vector<uint8_t>;
using PoPRewards = std::map<CScript, CAmount>;

void SetPop(CDBWrapper &db);

PayloadsProvider &GetPayloadsProvider();

//! returns true if all tips are stored in database, false otherwise
bool hasPopData(CBlockTreeDB &db);
altintegration::PopData getPopData();
void saveTrees(altintegration::BlockBatchAdaptor &batch);
bool loadTrees(CDBIterator &iter);

//! pop rewards
PoPRewards getPopRewards(const CBlockIndex &pindexPrev)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void addPopPayoutsIntoCoinbaseTx(CMutableTransaction &coinbaseTx,
                                 const CBlockIndex &pindexPrev)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool checkCoinbaseTxWithPopRewards(const CTransaction &tx, const Amount &nFees,
                                   const CBlockIndex &pindexPrev,
                                   const Consensus::Params &consensusParams,
                                   Amount &blockReward,
                                   BlockValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

Amount getCoinbaseSubsidy(Amount subsidy, int32_t height,
                          const Consensus::Params &consensusParams);

//! alttree methods
bool acceptBlock(const CBlockIndex &indexNew, BlockValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool addAllBlockPayloads(const CBlock &block, BlockValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool setState(const BlockHash &hash, altintegration::ValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

//! mempool methods
altintegration::PopData getPopData() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void removePayloadsFromMempool(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void updatePopMempoolForReorg() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void addDisconnectedPopdata(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks);
std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);

} // namespace VeriBlock

#endif