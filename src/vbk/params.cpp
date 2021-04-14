// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "params.hpp"
#include "util.hpp"
#include <boost/algorithm/string.hpp>
#include <chainparams.h>
#include <pow/pow.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <vbk/bootstraps.hpp>
#include <vbk/pop_common.hpp>
#include <veriblock/pop.hpp>


namespace VeriBlock {

bool AltChainParamsBCH::checkBlockHeader(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& root, altintegration::ValidationState& state) const noexcept
{
    const CChainParams& params = Params();

    try {
        // this throws
        auto header = VeriBlock::headerFromBytes(bytes);

        /* top level merkle `root` calculated by library is same as in endorsed header */
        auto actual = header.hashMerkleRoot.asVector();
        if(actual != root) {
            return state.Invalid("bad-merkle-root", strprintf("Expected %s, got %s", HexStr(root), HexStr(actual)));
        }

        /* and POW of endorsed header is valid */
        if(!CheckProofOfWork(header.GetHash(), header.nBits, params.GetConsensus())) {
            return state.Invalid("bad-pow", "Bad proof of work");
        }

        return true;
    } catch (...) {
        return state.Invalid("bad-header", "Can not parse block header");
    }
}


std::vector<uint8_t> AltChainParamsBCH::getHash(const std::vector<uint8_t>& bytes) const noexcept
{
    try {
        return VeriBlock::headerFromBytes(bytes).GetHash().asVector();
    } catch (...) {
        // return empty hash, since we can't deserialize header
        return {};
    }
}

void printConfig(const altintegration::Config& config)
{
    std::string btclast = config.btc.blocks.empty() ? "<empty>" : config.btc.blocks.rbegin()->getHash().toHex();
    std::string btcfirst = config.btc.blocks.empty() ? "<empty>" : config.btc.blocks.begin()->getHash().toHex();
    std::string vbklast = config.vbk.blocks.empty() ? "<empty>" : config.vbk.blocks.rbegin()->getHash().toHex();
    std::string vbkfirst = config.vbk.blocks.empty() ? "<empty>" : config.vbk.blocks.begin()->getHash().toHex();


    assert(config.alt);

    LogPrintf(R"(Applied POP config:
 BTC:
  network     : %s
  startHeight : %d
  total blocks: %d
  first       : %s
  last        : %s

 VBK:
  network     : %s
  startHeight : %d
  total blocks: %d
  first       : %s
  last        : %s

 ALT:
  network     : %s
  block height: %d
  block hash  : %s
  chain id    : %lld
)",
        config.btc.params->networkName(), config.btc.startHeight, config.btc.blocks.size(), btcfirst, btclast,
        config.vbk.params->networkName(), config.vbk.startHeight, config.vbk.blocks.size(), vbkfirst, vbklast,

        Params().NetworkIDString(), config.alt->getBootstrapBlock().height,
        HexStr(config.alt->getBootstrapBlock().hash),
        config.alt->getIdentifier());
}

void selectPopConfig(const std::string& network)
{
    altintegration::Config popconfig;

    if (network == "test") {
        //! SET BTC
        auto btcparam = std::make_shared<altintegration::BtcChainParamsTest>();
        popconfig.setBTC(testnetBTCstartHeight, testnetBTCblocks, btcparam);
        //! SET VBK
        auto vbkparam = std::make_shared<altintegration::VbkChainParamsTest>();
        popconfig.setVBK(testnetVBKstartHeight, testnetVBKblocks, vbkparam);
    } else if (network == "regtest") {
        //! SET BTC
        auto btcparam = std::make_shared<altintegration::BtcChainParamsRegTest>();
        popconfig.setBTC(0, {}, btcparam);
        //! SET VBK
        auto vbkparam = std::make_shared<altintegration::VbkChainParamsRegTest>();
        popconfig.setVBK(0, {}, vbkparam);
    } else {
        throw std::invalid_argument("currently only supports test/regtest");
    }

    auto altparams = std::make_shared<VeriBlock::AltChainParamsBCH>(Params().GenesisBlock());
    popconfig.alt = altparams;
    VeriBlock::SetPopConfig(popconfig);
    printConfig(popconfig);
}

} // namespace VeriBlock
