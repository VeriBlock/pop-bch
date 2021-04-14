// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef INTEGRATION_REFERENCE_BCH_PARAMS_HPP
#define INTEGRATION_REFERENCE_BCH_PARAMS_HPP

#include <primitives/block.h>
#include <veriblock/pop.hpp>

class ArgsManager;

namespace VeriBlock {

struct AltChainParamsBCH : public altintegration::AltChainParams {
    ~AltChainParamsBCH() override = default;

    AltChainParamsBCH(const CBlock& genesis)
    {
        bootstrap.hash = genesis.GetHash().asVector();
        // intentionally leave prevHash empty
        bootstrap.height = 0;
        bootstrap.timestamp = genesis.GetBlockTime();
    }

    altintegration::AltBlock getBootstrapBlock() const noexcept override
    {
        return bootstrap;
    }

    int64_t getIdentifier() const noexcept override
    {
        return 0x3e4fac;
    }

    std::vector<uint8_t> getHash(const std::vector<uint8_t>& bytes) const noexcept override;

    // we should verify:
    // - check that 'bytes' can be deserialized to a CBlockHeader
    // - check that this CBlockHeader is valid (time, pow, version...)
    // - check that 'root' is equal to Merkle Root in CBlockHeader
    bool checkBlockHeader(
        const std::vector<uint8_t>& bytes,
        const std::vector<uint8_t>& root, altintegration::ValidationState& state) const noexcept override;

    altintegration::AltBlock bootstrap;
};

void printConfig(const altintegration::Config& config);
void selectPopConfig(const std::string& network = "test");

} // namespace VeriBlock

#endif //INTEGRATION_REFERENCE_BCH_PARAMS_HPP
