// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/algorithm/string.hpp>
#include <chainparams.h>
#include <util/strencodings.h>

#include "bootstraps.hpp"
#include "util.hpp"
#include "vbk/pop_common.hpp"

namespace VeriBlock {

std::vector<uint8_t> AltChainParamsVBITCASH::getHash(
    const std::vector<uint8_t> &bytes) const noexcept {
    auto hash = VeriBlock::headerFromBytes(bytes).GetHash();
    return std::vector<uint8_t>{hash.begin(), hash.end()};
}

static std::vector<std::string> parseBlocks(const std::string &s) {
    std::vector<std::string> strs;
    boost::split(strs, s, boost::is_any_of(","));
    return strs;
}

void printConfig(const altintegration::Config &config) {
    std::string btclast = config.btc.blocks.empty()
                              ? "<empty>"
                              : config.btc.blocks.rbegin()->getHash().toHex();
    std::string btcfirst = config.btc.blocks.empty()
                               ? "<empty>"
                               : config.btc.blocks.begin()->getHash().toHex();
    std::string vbklast = config.vbk.blocks.empty()
                              ? "<empty>"
                              : config.vbk.blocks.rbegin()->getHash().toHex();
    std::string vbkfirst = config.vbk.blocks.empty()
                               ? "<empty>"
                               : config.vbk.blocks.begin()->getHash().toHex();

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
              config.btc.params->networkName(), config.btc.startHeight,
              config.btc.blocks.size(), btcfirst, btclast,

              config.vbk.params->networkName(), config.vbk.startHeight,
              config.vbk.blocks.size(), vbkfirst, vbklast,

              Params().NetworkIDString(),
              config.alt->getBootstrapBlock().height,
              HexStr(config.alt->getBootstrapBlock().hash),
              config.alt->getIdentifier());
}

void selectPopConfig(const std::string &btcnet, const std::string &vbknet,
                     bool popautoconfig, int btcstart,
                     const std::string &btcblocks, int vbkstart,
                     const std::string &vbkblocks) {
    altintegration::Config popconfig;

    //! SET BTC
    if (btcnet == "test") {
        auto param = std::make_shared<altintegration::BtcChainParamsTest>();
        if (popautoconfig) {
            popconfig.setBTC(testnetBTCstartHeight, testnetBTCblocks, param);
        } else {
            popconfig.setBTC(btcstart, parseBlocks(btcblocks), param);
        }
    } else if (btcnet == "regtest") {
        auto param = std::make_shared<altintegration::BtcChainParamsRegTest>();
        if (popautoconfig) {
            popconfig.setBTC(0, {}, param);
        } else {
            popconfig.setBTC(btcstart, parseBlocks(btcblocks), param);
        }
    } else {
        throw std::invalid_argument(
            "btcnet currently only supports test/regtest");
    }

    //! SET VBK
    if (vbknet == "test") {
        auto param = std::make_shared<altintegration::VbkChainParamsTest>();
        if (popautoconfig) {
            popconfig.setVBK(testnetVBKstartHeight, testnetVBKblocks, param);
        } else {
            popconfig.setVBK(vbkstart, parseBlocks(vbkblocks), param);
        }
    } else if (btcnet == "regtest") {
        auto param = std::make_shared<altintegration::VbkChainParamsRegTest>();
        if (popautoconfig) {
            popconfig.setVBK(0, {}, param);
        } else {
            popconfig.setVBK(vbkstart, parseBlocks(vbkblocks), param);
        }
    } else {
        throw std::invalid_argument(
            "vbknet currently only supports test/regtest");
    }

    auto altparams =
        std::make_shared<AltChainParamsVBITCASH>(Params().GenesisBlock());
    popconfig.alt = altparams;
    VeriBlock::SetPopConfig(popconfig);
    printConfig(popconfig);
}

void selectPopConfig(const ArgsManager &args) {
    std::string btcnet = args.GetArg("-popbtcnetwork", "regtest");
    std::string vbknet = args.GetArg("-popvbknetwork", "regtest");
    bool popautoconfig = args.GetBoolArg("-popautoconfig", true);
    int btcstart = args.GetArg("-popbtcstartheight", 0);
    std::string btcblocks = args.GetArg("-popbtcblocks", "");
    int vbkstart = args.GetArg("-popvbkstartheight", 0);
    std::string vbkblocks = args.GetArg("-popvbkblocks", "");

    selectPopConfig(btcnet, vbknet, popautoconfig, btcstart, btcblocks,
                    vbkstart, vbkblocks);
}

const int testnetVBKstartHeight = 860529;
const int testnetBTCstartHeight = 1832624;

const std::vector<std::string> testnetBTCblocks = {};

const std::vector<std::string> testnetVBKblocks = {};

} // namespace VeriBlock