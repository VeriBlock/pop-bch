// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SRC_VBK_POP_SERVICE_HPP
#define BITCOIN_SRC_VBK_POP_SERVICE_HPP

#include <validation.h>

#include <vbk/adaptors/block_batch_adaptor.hpp>
#include <vbk/adaptors/payloads_provider.hpp>
#include <vbk/pop_common.hpp>

class CBlockTreeDB;
class CDBIterator;
class CDBWrapper;

namespace VeriBlock {

void SetPop(CDBWrapper &db);

PayloadsProvider &GetPayloadsProvider();

//! returns true if all tips are stored in database, false otherwise
bool hasPopData(CBlockTreeDB &db);
altintegration::PopData getPopData();
void saveTrees(altintegration::BlockBatchAdaptor &batch);
bool loadTrees(CDBIterator &iter);

//! mempool methods
altintegration::PopData getPopData() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void removePayloadsFromMempool(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void updatePopMempoolForReorg() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void addDisconnectedPopdata(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

} // namespace VeriBlock

#endif