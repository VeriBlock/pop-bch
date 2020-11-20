// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <hash.h>

#include <vbk/entity/context_info_container.hpp>
#include <vbk/merkle.hpp>
#include <vbk/pop_common.hpp>

namespace VeriBlock {

template <typename pop_t>
void popDataToHash(const std::vector<pop_t> &data,
                   std::vector<uint256> &leaves) {
    for (const auto &el : data) {
        auto id = el.getId();
        uint256 leaf;
        std::copy(id.begin(), id.end(), leaf.begin());
        leaves.push_back(leaf);
    }
}

bool isKeystone(const CBlockIndex &block) {
    auto keystoneInterval =
        VeriBlock::GetPop().config->alt->getKeystoneInterval();
    return (block.nHeight % keystoneInterval) == 0;
}

const CBlockIndex *getPreviousKeystone(const CBlockIndex &block) {
    const CBlockIndex *pblockWalk = &block;

    do {
        pblockWalk = pblockWalk->pprev;
    } while (pblockWalk != nullptr && !isKeystone(*pblockWalk));

    return pblockWalk;
}

KeystoneArray getKeystoneHashesForTheNextBlock(const CBlockIndex *pindexPrev) {
    const CBlockIndex *pwalk = pindexPrev;

    KeystoneArray keystones;
    auto it = keystones.begin();
    auto end = keystones.end();
    while (it != end) {
        if (pwalk == nullptr) {
            break;
        }

        if (isKeystone(*pwalk)) {
            *it = pwalk->GetBlockHash();
            ++it;
        }

        pwalk = getPreviousKeystone(*pwalk);
    }

    return keystones;
}

int GetPopMerkleRootCommitmentIndex(const CBlock &block) {
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            auto &s = block.vtx[0]->vout[o].scriptPubKey;
            if (s.size() >= 37 && s[0] == OP_RETURN && s[1] == 0x23 &&
                s[2] == 0x3a && s[3] == 0xe6 && s[4] == 0xca) {
                commitpos = o;
            }
        }
    }

    return commitpos;
}

uint256 BlockPopDataMerkleRoot(const CBlock &block) {
    std::vector<uint256> leaves;

    popDataToHash(block.popData.context, leaves);
    popDataToHash(block.popData.vtbs, leaves);
    popDataToHash(block.popData.atvs, leaves);

    return ComputeMerkleRoot(std::move(leaves), nullptr);
}

uint256 makeTopLevelRoot(int height, const KeystoneArray &keystones,
                         const uint256 &txRoot) {
    ContextInfoContainer context(height, keystones, txRoot);
    return context.getTopLevelMerkleRoot();
}

uint256 TopLevelMerkleRoot(const CBlockIndex *prevIndex, const CBlock &block,
                           bool *mutated) {
    if (prevIndex == nullptr ||
        !Params().isPopEnabled(prevIndex->nHeight + 1)) {
        return BlockMerkleRoot(block);
    }

    uint256 txRoot = BlockMerkleRoot(block, mutated);
    uint256 popRoot = BlockPopDataMerkleRoot(block);

    if (prevIndex == nullptr) {
        // special case: this is genesis block
        KeystoneArray keystones;
        return makeTopLevelRoot(
            0, keystones,
            Hash(txRoot.begin(), txRoot.end(), popRoot.begin(), popRoot.end()));
    }

    auto keystones = getKeystoneHashesForTheNextBlock(prevIndex);
    return makeTopLevelRoot(
        prevIndex->nHeight + 1, keystones,
        Hash(txRoot.begin(), txRoot.end(), popRoot.begin(), popRoot.end()));
}

bool VerifyTopLevelMerkleRoot(const CBlock &block, const CBlockIndex *prevIndex,
                              BlockValidationState &state) {
    bool mutated = false;
    uint256 hashMerkleRoot2 =
        VeriBlock::TopLevelMerkleRoot(prevIndex, block, &mutated);

    if (block.hashMerkleRoot != hashMerkleRoot2) {
        return state.Invalid(
            BlockValidationResult::BLOCK_MUTATED, REJECT_INVALID,
            strprintf("hashMerkleRoot mismatch. expected %s, got %s",
                      hashMerkleRoot2.GetHex(), block.hashMerkleRoot.GetHex()));
    }

    // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
    // of transactions in a block without affecting the merkle root of a block,
    // while still invalidating it.
    if (mutated) {
        return state.Invalid(BlockValidationResult::BLOCK_MUTATED,
                             REJECT_INVALID, "bad-txns-duplicate",
                             "duplicate transaction");
    }

    if (prevIndex == nullptr ||
        !Params().isPopEnabled(prevIndex->nHeight + 1)) {
        return true;
    }

    // Add PopMerkleRoot commitment validation
    int commitpos = GetPopMerkleRootCommitmentIndex(block);
    if (commitpos != -1) {
        uint256 popMerkleRoot = BlockPopDataMerkleRoot(block);
        if (!memcpy(popMerkleRoot.begin(),
                    &block.vtx[0]->vout[commitpos].scriptPubKey[4], 32)) {
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED,
                                 REJECT_INVALID, "bad-pop-tx-root-commitment",
                                 "pop merkle root mismatch");
        }
    } else {
        // If block is not genesis
        if (prevIndex != nullptr) {
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED,
                                 REJECT_INVALID, "bad-pop-tx-root-commitment",
                                 "commitment is missing");
        }
    }

    return true;
}

CTxOut AddPopDataRootIntoCoinbaseCommitment(const CBlock &block) {
    CTxOut out;
    out.nValue = Amount::zero();
    out.scriptPubKey.resize(37);
    out.scriptPubKey[0] = OP_RETURN;
    out.scriptPubKey[1] = 0x23;
    out.scriptPubKey[2] = 0x3a;
    out.scriptPubKey[3] = 0xe6;
    out.scriptPubKey[4] = 0xca;

    uint256 popMerkleRoot = BlockPopDataMerkleRoot(block);
    memcpy(&out.scriptPubKey[5], popMerkleRoot.begin(), 32);

    return out;
}

} // namespace VeriBlock