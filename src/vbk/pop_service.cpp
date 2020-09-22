// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <memory>
#include <vector>

#include <dbwrapper.h>
#include <shutdown.h>
#include <txdb.h>
#include <validation.h>

#include <vbk/adaptors/block_batch_adaptor.hpp>
#include <vbk/adaptors/payloads_provider.hpp>
#include <vbk/pop_common.hpp>
#include <vbk/pop_service.hpp>

#include <veriblock/storage/util.hpp>

#ifdef WIN32
#include <boost/thread/interruption.hpp>
#endif // WIN32

namespace VeriBlock {

static std::shared_ptr<PayloadsProvider> payloads = nullptr;
static std::vector<altintegration::PopData> disconnected_popdata;

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

} // namespace VeriBlock