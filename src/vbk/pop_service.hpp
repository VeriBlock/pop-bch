// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SRC_VBK_POP_SERVICE_HPP
#define BITCOIN_SRC_VBK_POP_SERVICE_HPP

#include <consensus/validation.h>
#include <validation.h>

#include "pop_common.hpp"
#include <vbk/adaptors/payloads_provider.hpp>

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

//! returns true if all tips are stored in database, false otherwise
bool hasPopData(CBlockTreeDB& db);
altintegration::PopData getPopData(const CBlockIndex& prev);
void saveTrees(CDBBatch* batch);
bool loadTrees(CDBWrapper& db);

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

Amount getCoinbaseSubsidy(Amount subsidy, int32_t height);

//! pop forkresolution
CBlockIndex *compareTipToBlock(CBlockIndex *candidate)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
int compareForks(const CBlockIndex &left, const CBlockIndex &right)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

//! alttree methods
bool acceptBlock(const CBlockIndex &indexNew, BlockValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool addAllBlockPayloads(const CBlock &block, BlockValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool setState(const BlockHash &hash, altintegration::ValidationState &state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

//! mempool methods
void removePayloadsFromMempool(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void updatePopMempoolForReorg() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void addDisconnectedPopdata(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks);
std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);

bool isPopEnabled();

bool isPopEnabled(int32_t height);

} // namespace VeriBlock

#endif