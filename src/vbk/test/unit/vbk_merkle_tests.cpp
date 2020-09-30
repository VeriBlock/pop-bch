// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <boost/test/unit_test.hpp>

#include <algorithm>

#include <chain.h>
#include <config.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/wallet.h>

#include <vbk/merkle.hpp>
#include <vbk/test/util/e2e_fixture.hpp>

namespace VeriBlock {

int GetPopMerkleRootCommitmentIndex(const CBlock &block);

}

BOOST_AUTO_TEST_SUITE(vbk_merkle_tests)

struct MerkleFixture {
    // this inits veriblock services
    E2eFixture blockchain;
};

BOOST_FIXTURE_TEST_CASE(TestChain100Setup_has_valid_merkle_roots,
                        MerkleFixture) {
    BlockValidationState state;
    CBlock block;

    for (int i = 0; i <= 100; i++) {
        CBlockIndex *index = ChainActive()[i];
        BOOST_REQUIRE_MESSAGE(index != nullptr,
                              "can not find block at given height");
        BOOST_REQUIRE_MESSAGE(
            ReadBlockFromDisk(block, index, Params().GetConsensus()),
            "can not read block");
        BOOST_CHECK_MESSAGE(
            VeriBlock::VerifyTopLevelMerkleRoot(block, index->pprev, state),
            strprintf("merkle root of block %d is invalid, reject reason: %s, "
                      "debug message: %s",
                      i, state.GetRejectReason(), state.GetDebugMessage()));
    }
}

BOOST_FIXTURE_TEST_CASE(addPopTransactionRootIntoCoinbaseCommitment_test,
                        MerkleFixture) {
    CScript scriptPubKey = CScript()
                           << ToByteVector(blockchain.coinbaseKey.GetPubKey())
                           << OP_CHECKSIG;

    CBlock block = blockchain.CreateAndProcessBlock({}, scriptPubKey);
    CBlockIndex *index = ChainActive().Tip();

    BlockValidationState state;
    BOOST_CHECK(
        VeriBlock::VerifyTopLevelMerkleRoot(block, index->pprev, state));

    // change pop merkle root
    int commitpos = VeriBlock::GetPopMerkleRootCommitmentIndex(block);
    BOOST_CHECK(commitpos != -1);
    CMutableTransaction tx(*block.vtx[0]);
    tx.vout[0].scriptPubKey[4] = 0xff;
    tx.vout[0].scriptPubKey[5] = 0xff;
    tx.vout[0].scriptPubKey[6] = 0xff;
    tx.vout[0].scriptPubKey[7] = 0xff;
    tx.vout[0].scriptPubKey[8] = 0xff;
    tx.vout[0].scriptPubKey[9] = 0xff;
    tx.vout[0].scriptPubKey[10] = 0xff;
    block.vtx[0] = MakeTransactionRef(tx);

    BOOST_CHECK(
        !VeriBlock::VerifyTopLevelMerkleRoot(block, index->pprev, state));

    // erase commitment
    tx.vout.erase(tx.vout.begin() + commitpos);
    block.vtx[0] = MakeTransactionRef(tx);

    BOOST_CHECK(
        !VeriBlock::VerifyTopLevelMerkleRoot(block, index->pprev, state));
}

BOOST_AUTO_TEST_SUITE_END()
