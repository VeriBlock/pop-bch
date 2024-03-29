// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <interfaces/chain.h>
#include <node/context.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcdump.h>
#include <wallet/wallet.h>

#include <test/util/setup_common.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <cstdint>
#include <memory>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static void AddKey(CWallet &wallet, const CKey &key) {
    auto spk_man = wallet.GetLegacyScriptPubKeyMan();
    LOCK(wallet.cs_wallet);
    AssertLockHeld(spk_man->cs_wallet);
    spk_man->AddKeyPubKey(key, key.GetPubKey());
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions, TestChain100Setup) {
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex *oldTip = ::ChainActive().Tip();
    GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex *newTip = ::ChainActive().Tip();

    NodeContext node;
    auto chain = interfaces::MakeChain(node, Params());
    auto locked_chain = chain->lock();
    LockAssertion lock(::cs_main);

    // Verify ScanForWalletTransactions accommodates a null start block.
    {
        CWallet wallet(Params(), chain.get(), WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            BlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, Amount::zero());
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(Params(), chain.get(), WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            oldTip->GetBlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, 100 * COIN);
    }

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet(Params(), chain.get(), WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            oldTip->GetBlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, oldTip->GetBlockHash());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, 50 * COIN);
    }

    // Prune the remaining block file.
    PruneOneBlockFile(newTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({newTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions scans no blocks.
    {
        CWallet wallet(Params(), chain.get(), WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            oldTip->GetBlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, newTip->GetBlockHash());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, Amount::zero());
    }
}

BOOST_FIXTURE_TEST_CASE(importmulti_rescan, TestChain100Setup) {
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex *oldTip = ::ChainActive().Tip();
    GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex *newTip = ::ChainActive().Tip();

    NodeContext node;
    auto chain = interfaces::MakeChain(node, Params());
    auto locked_chain = chain->lock();
    LockAssertion lock(::cs_main);

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        std::shared_ptr<CWallet> wallet =
            std::make_shared<CWallet>(Params(), chain.get(), WalletLocation(),
                                      WalletDatabase::CreateDummy());
        AddWallet(wallet);
        UniValue keys;
        keys.setArray();
        UniValue key;
        key.setObject();
        key.pushKV("scriptPubKey",
                   HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.pushKV("timestamp", 0);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        key.clear();
        key.setObject();
        CKey futureKey;
        futureKey.MakeNewKey(true);
        key.pushKV("scriptPubKey",
                   HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.pushKV("timestamp",
                   newTip->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(keys);

        UniValue response = importmulti(GetConfig(), request);
        BOOST_CHECK_EQUAL(
            response.write(),
            strprintf("[{\"success\":false,\"error\":{\"code\":-1,\"message\":"
                      "\"Rescan failed for key with creation timestamp %d. "
                      "There was an error reading a block from time %d, which "
                      "is after or within %d seconds of key creation, and "
                      "could contain transactions pertaining to the key. As a "
                      "result, transactions and coins using this key may not "
                      "appear in the wallet. This error could be caused by "
                      "pruning or data corruption (see bitcoind log for "
                      "details) and could be dealt with by downloading and "
                      "rescanning the relevant blocks (see -reindex and "
                      "-rescan options).\"}},{\"success\":true}]",
                      0, oldTip->GetBlockTimeMax(), TIMESTAMP_WINDOW));
        RemoveWallet(wallet);
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain100Setup) {
    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = ::ChainActive().Tip()->GetBlockTimeMax() + 5;
    SetMockTime(BLOCK_TIME);
    m_coinbase_txns.emplace_back(
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()))
            .vtx[0]);
    m_coinbase_txns.emplace_back(
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()))
            .vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + TIMESTAMP_WINDOW;
    SetMockTime(KEY_TIME);
    m_coinbase_txns.emplace_back(
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()))
            .vtx[0]);

    NodeContext node;
    auto chain = interfaces::MakeChain(node, Params());
    auto locked_chain = chain->lock();
    LockAssertion lock(::cs_main);

    std::string backup_file = (GetDataDir() / "wallet.backup").string();

    // Import key into wallet and call dumpwallet to create backup file.
    {
        std::shared_ptr<CWallet> wallet =
            std::make_shared<CWallet>(Params(), chain.get(), WalletLocation(),
                                      WalletDatabase::CreateDummy());
        auto spk_man = wallet->GetLegacyScriptPubKeyMan();
        LOCK(wallet->cs_wallet);
        AssertLockHeld(spk_man->cs_wallet);
        spk_man->mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime =
            KEY_TIME;
        spk_man->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(backup_file);
        AddWallet(wallet);
        ::dumpwallet(GetConfig(), request);
        RemoveWallet(wallet);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        std::shared_ptr<CWallet> wallet =
            std::make_shared<CWallet>(Params(), chain.get(), WalletLocation(),
                                      WalletDatabase::CreateDummy());

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(backup_file);
        AddWallet(wallet);
        ::importwallet(GetConfig(), request);
        RemoveWallet(wallet);

        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 103U);
        BOOST_CHECK_EQUAL(m_coinbase_txns.size(), 103U);
        for (size_t i = 0; i < m_coinbase_txns.size(); ++i) {
            bool found = wallet->GetWalletTx(m_coinbase_txns[i]->GetId());
            bool expected = i >= 0;
            BOOST_CHECK_EQUAL(found, expected);
        }
    }
}

// Check that GetImmatureCredit() returns a newly calculated value instead of
// the cached value after a MarkDirty() call.
//
// This is a regression test written to verify a bugfix for the immature credit
// function. Similar tests probably should be written for the other credit and
// debit functions.
BOOST_FIXTURE_TEST_CASE(coin_mark_dirty_immature_credit, TestChain100Setup) {
    NodeContext node;
    auto chain = interfaces::MakeChain(node, Params());
    CWallet wallet(Params(), chain.get(), WalletLocation(),
                   WalletDatabase::CreateDummy());
    auto spk_man = wallet.GetLegacyScriptPubKeyMan();
    CWalletTx wtx(&wallet, m_coinbase_txns.back());

    auto locked_chain = chain->lock();
    LockAssertion lock(::cs_main);
    LOCK(wallet.cs_wallet);
    AssertLockHeld(spk_man->cs_wallet);

    wtx.SetConf(CWalletTx::Status::CONFIRMED,
                ::ChainActive().Tip()->GetBlockHash(), 0);

    // Call GetImmatureCredit() once before adding the key to the wallet to
    // cache the current immature credit amount, which is 0.
    BOOST_CHECK_EQUAL(wtx.GetImmatureCredit(*locked_chain), Amount::zero());

    // Invalidate the cached value, add the key, and make sure a new immature
    // credit amount is calculated.
    wtx.MarkDirty();
    BOOST_CHECK(spk_man->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey()));
    BOOST_CHECK_EQUAL(wtx.GetImmatureCredit(*locked_chain), 50 * COIN);
}

static int64_t AddTx(CWallet &wallet, uint32_t lockTime, int64_t mockTime,
                     int64_t blockTime) {
    CMutableTransaction tx;
    tx.nLockTime = lockTime;
    SetMockTime(mockTime);
    CBlockIndex *block = nullptr;
    if (blockTime > 0) {
        auto locked_chain = wallet.chain().lock();
        LockAssertion lock(::cs_main);
        auto inserted =
            mapBlockIndex.emplace(BlockHash(GetRandHash()), new CBlockIndex);
        assert(inserted.second);
        const BlockHash &hash = inserted.first->first;
        block = inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
    }

    CWalletTx wtx(&wallet, MakeTransactionRef(tx));
    LOCK(cs_main);
    LOCK(wallet.cs_wallet);
    // If transaction is already in map, to avoid inconsistencies,
    // unconfirmation is needed before confirm again with different block.
    std::map<TxId, CWalletTx>::iterator it = wallet.mapWallet.find(wtx.GetId());
    if (it != wallet.mapWallet.end()) {
        wtx.setUnconfirmed();
        wallet.AddToWallet(wtx);
    }
    if (block) {
        wtx.SetConf(CWalletTx::Status::CONFIRMED, block->GetBlockHash(), 0);
    }
    wallet.AddToWallet(wtx);
    return wallet.mapWallet.at(wtx.GetId()).nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart) {
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 1, 100, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 1, 200, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 2, 300, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 3, 420, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 4, 500, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 5, 50, 600), 300);

    // Reset mock time for other tests.
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(LoadReceiveRequests) {
    CTxDestination dest = PKHash();
    LOCK(m_wallet.cs_wallet);
    m_wallet.AddDestData(dest, "misc", "val_misc");
    m_wallet.AddDestData(dest, "rr0", "val_rr0");
    m_wallet.AddDestData(dest, "rr1", "val_rr1");

    auto values = m_wallet.GetDestValues("rr");
    BOOST_CHECK_EQUAL(values.size(), 2U);
    BOOST_CHECK_EQUAL(values[0], "val_rr0");
    BOOST_CHECK_EQUAL(values[1], "val_rr1");
}

// Test some watch-only LegacyScriptPubKeyMan methods by the procedure of
// loading (LoadWatchOnly), checking (HaveWatchOnly), getting (GetWatchPubKey)
// and removing (RemoveWatchOnly) a given PubKey, resp. its corresponding P2PK
// Script. Results of the the impact on the address -> PubKey map is dependent
// on whether the PubKey is a point on the curve
static void TestWatchOnlyPubKey(LegacyScriptPubKeyMan *spk_man,
                                const CPubKey &add_pubkey) {
    CScript p2pk = GetScriptForRawPubKey(add_pubkey);
    CKeyID add_address = add_pubkey.GetID();
    CPubKey found_pubkey;
    LOCK(spk_man->cs_wallet);

    // all Scripts (i.e. also all PubKeys) are added to the general watch-only
    // set
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));
    spk_man->LoadWatchOnly(p2pk);
    BOOST_CHECK(spk_man->HaveWatchOnly(p2pk));

    // only PubKeys on the curve shall be added to the watch-only address ->
    // PubKey map
    bool is_pubkey_fully_valid = add_pubkey.IsFullyValid();
    if (is_pubkey_fully_valid) {
        BOOST_CHECK(spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == add_pubkey);
    } else {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        // passed key is unchanged
        BOOST_CHECK(found_pubkey == CPubKey());
    }

    AssertLockHeld(spk_man->cs_wallet);
    spk_man->RemoveWatchOnly(p2pk);
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));

    if (is_pubkey_fully_valid) {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        // passed key is unchanged
        BOOST_CHECK(found_pubkey == add_pubkey);
    }
}

// Cryptographically invalidate a PubKey whilst keeping length and first byte
static void PollutePubKey(CPubKey &pubkey) {
    std::vector<uint8_t> pubkey_raw(pubkey.begin(), pubkey.end());
    std::fill(pubkey_raw.begin() + 1, pubkey_raw.end(), 0);
    pubkey = CPubKey(pubkey_raw);
    assert(!pubkey.IsFullyValid());
    assert(pubkey.IsValid());
}

// Test watch-only logic for PubKeys
BOOST_AUTO_TEST_CASE(WatchOnlyPubKeys) {
    CKey key;
    CPubKey pubkey;
    LegacyScriptPubKeyMan *spk_man = m_wallet.GetLegacyScriptPubKeyMan();

    BOOST_CHECK(!spk_man->HaveWatchOnly());

    // uncompressed valid PubKey
    key.MakeNewKey(false);
    pubkey = key.GetPubKey();
    assert(!pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // uncompressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed valid PubKey
    key.MakeNewKey(true);
    pubkey = key.GetPubKey();
    assert(pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // invalid empty PubKey
    pubkey = CPubKey();
    TestWatchOnlyPubKey(spk_man, pubkey);
}

class ListCoinsTestingSetup : public TestChain100Setup {
public:
    ListCoinsTestingSetup() {
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet =
            std::make_unique<CWallet>(Params(), m_chain.get(), WalletLocation(),
                                      WalletDatabase::CreateMock());
        bool firstRun;
        wallet->LoadWallet(firstRun);
        AddKey(*wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet.get());
        reserver.reserve();
        CWallet::ScanResult result = wallet->ScanForWalletTransactions(
            ::ChainActive().Genesis()->GetBlockHash(), BlockHash(), reserver,
            false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK_EQUAL(result.last_scanned_block,
                          ::ChainActive().Tip()->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height,
                          ::ChainActive().Height());
        BOOST_CHECK(result.last_failed_block.IsNull());
    }

    ~ListCoinsTestingSetup() { wallet.reset(); }

    CWalletTx &AddTx(CRecipient recipient) {
        CTransactionRef tx;
        Amount fee;
        int changePos = -1;
        std::string error;
        CCoinControl dummy;
        {
            auto locked_chain = m_chain->lock();
            BOOST_CHECK(wallet->CreateTransaction(
                *locked_chain, {recipient}, tx, fee, changePos, error, dummy));
        }
        wallet->CommitTransaction(tx, {}, {});
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx =
                CMutableTransaction(*wallet->mapWallet.at(tx->GetId()).tx);
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

        LOCK(cs_main);
        LOCK(wallet->cs_wallet);
        auto it = wallet->mapWallet.find(tx->GetId());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.SetConf(CWalletTx::Status::CONFIRMED,
                           ::ChainActive().Tip()->GetBlockHash(), 1);
        return it->second;
    }

    std::unique_ptr<interfaces::Chain> m_chain =
        interfaces::MakeChain(m_node, Params());
    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(ListCoins, ListCoinsTestingSetup) {
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<COutput>> list;
    {
        auto locked_chain = m_chain->lock();
        LOCK(wallet->cs_wallet);
        list = wallet->ListCoins(*locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(boost::get<PKHash>(list.begin()->first).ToString(),
                      coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 1U);

    // Check initial balance from one mature coinbase transaction.
    BOOST_CHECK_EQUAL(50 * COIN, wallet->GetAvailableBalance());

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{GetScriptForRawPubKey({}), 1 * COIN,
                     false /* subtract fee */});
    {
        auto locked_chain = m_chain->lock();
        LOCK(wallet->cs_wallet);
        list = wallet->ListCoins(*locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(boost::get<PKHash>(list.begin()->first).ToString(),
                      coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        auto locked_chain = m_chain->lock();
        LOCK(wallet->cs_wallet);
        std::vector<COutput> available;
        wallet->AvailableCoins(*locked_chain, available);
        BOOST_CHECK_EQUAL(available.size(), 2U);
    }
    for (const auto &group : list) {
        for (const auto &coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(COutPoint(coin.tx->GetId(), coin.i));
        }
    }
    {
        auto locked_chain = m_chain->lock();
        LOCK(wallet->cs_wallet);
        std::vector<COutput> available;
        wallet->AvailableCoins(*locked_chain, available);
        BOOST_CHECK_EQUAL(available.size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        auto locked_chain = m_chain->lock();
        LOCK(wallet->cs_wallet);
        list = wallet->ListCoins(*locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(boost::get<PKHash>(list.begin()->first).ToString(),
                      coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup) {
    NodeContext node;
    auto chain = interfaces::MakeChain(node, Params());
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(
        Params(), chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    wallet->SetMinVersion(FEATURE_LATEST);
    wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    BOOST_CHECK(!wallet->TopUpKeyPool(1000));
    CTxDestination dest;
    std::string error;
    BOOST_CHECK(
        !wallet->GetNewDestination(OutputType::LEGACY, "", dest, error));
}

BOOST_AUTO_TEST_SUITE_END()
