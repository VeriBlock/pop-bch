// Copyright (c) 2019-2021 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __BOOTSTRAPS_BTC_VBK
#define __BOOTSTRAPS_BTC_VBK

#include <string>
#include <vector>

#include <primitives/block.h>
#include <util/system.h> // for gArgs
#include <veriblock/pop.hpp>

namespace VeriBlock {

extern const int testnetVBKstartHeight;
extern const std::vector<std::string> testnetVBKblocks;

extern const int testnetBTCstartHeight;
extern const std::vector<std::string> testnetBTCblocks;

} // namespace VeriBlock

#endif