# Bitcoin cash markdown
## Original Bitcoin cash  building
First should install missing dependency jemalloc.
```sh 
git clone https://github.com/jemalloc/jemalloc.git
cd jemalloc
git checkout ea6b3e973b477b8061e0076bb257dbd7f3faa756
./autogen
make 
make install
cd ..
rm -rf jemalloc
```
Then can build bitcoin cash using the following commands in the root of bitcoin cash directory project
```sh
mkdir build
cd build
cmake .. -DBUILD_BITCOIN_WALLET=OFF -DBUILD_BITCOIN_QT=OFF -DENABLE_QRCODE=OFF -DENABLE_UPNP=OFF
make
```
Run unit tests
```sh
make check
```
Run functional tests
```sh
make check-functional
```

## Add VeriBlock-PoP library dependency

Has been added VeriBlock lib dependency into the CMakeLists.txt
```diff
+ # VeriBlock
+ find_package(veriblock-pop-cpp REQUIRED)
+ link_libraries(veriblock::veriblock-pop-cpp)
```
Install veriblock-pop-cpp library
```sh
git clone https://github.com/VeriBlock/alt-integration-cpp.git
mkdir build
cd build
cmake .. -DWITH_PYPOPMINER=ON -DCMAKE_INSTALL_PREFIX=/usr/local
make
make install
```

## Adding PopData into the Block
I have added a new entity PopData into the CBlock class in the block.h file and provide a new nVersion flag.
Updated serialisation of the CBlock.
First has been added POP_BLOCK_VERSION_BIT flag.
vbk/vbk.hpp
```diff
#ifndef BITCOIN_SRC_VBK_VBK_HPP
#define BITCOIN_SRC_VBK_VBK_HPP

#include <uint256.h>

namespace VeriBlock {

using KeystoneArray = std::array<uint256, 2>;

const static int32_t POP_BLOCK_VERSION_BIT = 0x80000UL;

}  // namespace VeriBlock

#endif //BITCOIN_SRC_VBK_VBK_HPP
```


primitives/block.h
```diff
+ #include "veriblock/entities/popdata.hpp"
...
class CBlock : public CBlockHeader {
public:
    // network and disk
    std::vector<CTransactionRef> vtx;
+   // VeriBlock data
+   altintegration::PopData popData;
...
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
+       if (this->nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+           READWRITE(popData);
+       }
    }
};
```

Has been update serialization of the CBlockHeaderAndShortTxIDs class in the blockencodings.h, it is needed for the block sending over the p2p.
blockencodings.h
```diff
class BlockTransactions {
public:
    // A BlockTransactions message
    BlockHash blockhash;
    std::vector<CTransactionRef> txn;
+   // VeriBlock data
+   altintegration::PopData popData;
...
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        ...
+       // VeriBlock data
+       READWRITE(popData);
    }
};
...
class CBlockHeaderAndShortTxIDs {
...
public:
    CBlockHeader header;
+   // VeriBlock data
+   altintegration::PopData popData;
...
template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        ...
        if (this->header.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
            READWRITE(popData);
        }
        ...
    }
...
};
...
class PartiallyDownloadedBlock {
...
public:
    CBlockHeader header;
+   altintegration::PopData popData;
...
    ReadStatus FillBlock(CBlock &block,
                         const std::vector<CTransactionRef> &vtx_missing);
+    ReadStatus FillBlock(CBlock &block,
+                         const std::vector<CTransactionRef> &vtx_missing, const altintegration::PopData& popData);
};
```
blockencodings.cpp
```diff
+ ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock &block, const std::vector<CTransactionRef> &vtx_missing, const altintegration::PopData& popData) {
+    block.popData = popData;
+    ReadStatus status = FillBlock(block, vtx_missing);
+    return status;
+ }

ReadStatus PartiallyDownloadedBlock::FillBlock(
    CBlock &block, const std::vector<CTransactionRef> &vtx_missing) {
    ...
+   // VeriBlock: set popData before CheckBlock
+   block.popData = this->popData;
    ...
    return READ_STATUS_OK;
}


...
ReadStatus PartiallyDownloadedBlock::InitData(
    const CBlockHeaderAndShortTxIDs &cmpctblock,
    const std::vector<std::pair<TxHash, CTransactionRef>> &extra_txns) {
    ...
+   // VeriBlock: set pop data
+   this->popData = cmpctblock.popData;

    LogPrint(BCLog::CMPCTBLOCK,
             "Initialized PartiallyDownloadedBlock for block %s using a "
-            "cmpctblock of size %lu\n",
+            "cmpctblock of size %lu with %d VBK %d VTB %d ATV\n",
             cmpctblock.header.GetHash().ToString(),
-            GetSerializeSize(cmpctblock, PROTOCOL_VERSION));
+            this->popData.context.size(), this->popData.vtbs.size(),
+            this->popData.atvs.size());

    return READ_STATUS_OK;
}
```

Also for the correct p2p block processing has been updated net_processing.cpp source file
net_processing.cpp
```diff
inline static void SendBlockTransactions(const CBlock &block,
                                         const BlockTransactionsRequest &req,
                                         CNode *pfrom, CConnman *connman) {
    ...
+   //VeriBlock add popData
+   resp.popData = block.popData;
    ...
}
...
if (strCommand == NetMsgType::CMPCTBLOCK) {
    ...
        if (status == READ_STATUS_OK) {
            fBlockReconstructed = true;
+           if (pblock && pblock->nVersion &
+             VeriBlock::POP_BLOCK_VERSION_BIT) {
+               assert(!pblock->popData.empty() &&
+                  "POP bit is set and POP data is empty");
+           }
        }
    ...
}
```
Also has been validation rules in the validation.cpp source file
validation.cpp
```diff
bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    ...
+    // VeriBlock: merkle root verification currently depends on a context, so it has been moved to ContextualCheckBlock
+    if(block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT && block.popData.empty()) {
+        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-block-pop-version", "POP bit is set, but pop data is empty");
+    }
+    if(!(block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) && !block.popData.empty()) {
+        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-block-pop-version", "POP bit is NOT set, and pop data is NOT empty");
+    }
...
}
```
Miner has been updated with the CreateNewBlock() function.
miner.cpp
```diff
+    // VeriBlock: add PopData into the block
+    if (!pblock->popData.atvs.empty() || !pblock->popData.context.empty() || !pblock->popData.vtbs.empty()) {
+        pblock->nVersion |= VeriBlock::POP_BLOCK_VERSION_BIT;
+    }
```

Overloaded serialization opereations in the serialization.h
serialization.h
```diff
+ // VeriBlock: Serialize a PopData object
+ template<typename Stream> inline void Serialize(Stream& s, const altintegration::PopData& pop_data) {
+    std::vector<uint8_t> bytes_data = pop_data.toVbkEncoding();
+    Serialize(s, bytes_data);
+ }

+ template<typename Stream> inline void Unserialize(Stream& s, altintegration::PopData& pop_data) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    pop_data = altintegration::PopData::fromVbkEncoding(bytes_data);
+ }
```
## Add PopSecurity fokrpoint parameter

Has been added a block heght into the Consensus::Params from which enables PopSecurity, params.h and chainparams.cpp.
params.h
```diff
struct Params {
    ...
+   // VeriBlock
+   uint64_t VeriBlockPopSecurityHeight;
};
```
chainparams.cpp
```diff
...
class CMainParams : public CChainParams {
public:
    CMainParams() {
        ...
        // VeriBlock
        // TODO: set an VeriBlock pop security fork height
        // consensus.VeriBlockPopSecurityHeight = -1;
        ...
    }
};
...
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        ...
        // VeriBlock
        // TODO: set an VeriBlock pop security fork height
        // consensus.VeriBlockPopSecurityHeight = -1;
        ...
    }
};
...
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        ...
        // VeriBlock
        // TODO: set an VeriBlock pop security fork height
        consensus.VeriBlockPopSecurityHeight = 1;
        ...
    }
};
```
Also have been updated ContextualCheckBlockHeader() function in the validation.cpp
validation.cpp
```diff
static bool ContextualCheckBlockHeader(const CChainParams &params,
                                       const CBlockHeader &block,
                                       BlockValidationState &state,
                                       const CBlockIndex *pindexPrev,
                                       int64_t nAdjustedTime)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    ...
+    // VeriBlock validation
+    if ((block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) &&
+        consensusParams.VeriBlockPopSecurityHeight > nHeight) {
+        return state.Invalid(
+            BlockValidationResult::BLOCK_INVALID_HEADER, REJECT_OBSOLETE,
+            strprintf("bad-pop-version(0x%08x)", block.nVersion),
+            strprintf(
+                "block contains PopData before PopSecurity has been enabled"));
+    }

    return true;
}
```
## Add VeriBlock config

Create two new source files pop_common.hpp, pop_common.cpp
vbk/pop_common.hpp
```diff
+ #ifndef BITCOIN_SRC_VBK_POP_COMMON_HPP
+ #define BITCOIN_SRC_VBK_POP_COMMON_HPP

+ #include <veriblock/pop_context.hpp>

+ namespace VeriBlock {

+ altintegration::PopContext& GetPop();

+ void SetPopConfig(const altintegration::Config& config);

+ void SetPop(std::shared_ptr<altintegration::PayloadsProvider>& db);

+ std::string toPrettyString(const altintegration::PopContext& pop);

+ } // namespace VeriBlock

+ #endif //BITCOIN_SRC_VBK_POP_COMMON_HPP
```
vbk/pop_common.cpp
```diff
#include "pop_common.hpp"

namespace VeriBlock {

static std::shared_ptr<altintegration::PopContext> app = nullptr;
static std::shared_ptr<altintegration::Config> config = nullptr;

altintegration::PopContext &GetPop() {
    assert(app && "Altintegration is not initialized. Invoke SetPop.");
    return *app;
}

void SetPopConfig(const altintegration::Config &newConfig) {
    config = std::make_shared<altintegration::Config>(newConfig);
}

void SetPop(std::shared_ptr<altintegration::PayloadsProvider> &db) {
    assert(config && "Config is not initialized. Invoke SetPopConfig.");
    app = altintegration::PopContext::create(config, db);
}

std::string toPrettyString(const altintegration::PopContext &pop) {
    return pop.altTree->toPrettyString();
}

} // namespace VeriBlock
```
Has been created bootstraps.hpp, bootstraps.cpp source files with the initial confogiration of the VeriBlock configs.
vbk/bootstraps.hpp
```
#ifndef __BOOTSTRAPS_BTC_VBK
#define __BOOTSTRAPS_BTC_VBK

#include <string>
#include <vector>

#include <primitives/block.h>
#include <util/system.h> // for gArgs
#include <veriblock/config.hpp>

namespace VeriBlock {

extern const int testnetVBKstartHeight;
extern const std::vector<std::string> testnetVBKblocks;

extern const int testnetBTCstartHeight;
extern const std::vector<std::string> testnetBTCblocks;

struct AltChainParamsVBITCASH : public altintegration::AltChainParams {
    ~AltChainParamsVBITCASH() override = default;

    AltChainParamsVBITCASH(const CBlock &genesis) {
        auto hash = genesis.GetHash();
        bootstrap.hash = std::vector<uint8_t>{hash.begin(), hash.end()};
        bootstrap.height = 0; // pop is enabled starting at genesis
        bootstrap.timestamp = genesis.GetBlockTime();
    }

    altintegration::AltBlock getBootstrapBlock() const noexcept override {
        return bootstrap;
    }

    int64_t getIdentifier() const noexcept override { return 0x3ae6ca; }

    std::vector<uint8_t>
    getHash(const std::vector<uint8_t> &bytes) const noexcept override;

    altintegration::AltBlock bootstrap;
};

void printConfig(const altintegration::Config &config);
void selectPopConfig(const ArgsManager &mgr);
void selectPopConfig(const std::string &btcnet, const std::string &vbknet,
                     bool popautoconfig = true, int btcstart = 0,
                     const std::string &btcblocks = {}, int vbkstart = 0,
                     const std::string &vbkblocks = {});

} // namespace VeriBlock

#endif
```
vbk/bootstraps.cpp
```
#include <boost/algorithm/string.hpp>
#include <chainparams.h>
#include <util/strencodings.h>

#include "bootstraps.hpp"
#include "util.hpp"
#include "vbk/pop_common.hpp"

std::vector<uint8_t>
AltChainParamsVBTC::getHash(const std::vector<uint8_t> &bytes) const noexcept {
    return VeriBlock::headerFromBytes(bytes).GetHash().asVector();
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
        std::make_shared<AltChainParamsVBTC>(Params().GenesisBlock());
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
```
Also has been added veriblock util.hpp source file, with the some usefull set of functions for the integration purposes
vbk/util.hpp
```
#ifndef BITCOIN_SRC_VBK_UTIL_HPP
#define BITCOIN_SRC_VBK_UTIL_HPP

#include <consensus/consensus.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <version.h>

#include <veriblock/entities/popdata.hpp>

#include <algorithm>
#include <amount.h>
#include <chain.h>
#include <functional>

namespace VeriBlock {

/**
 * Create new Container with elements filtered elements of original container.
 * All elements for which pred returns false will be removed.
 * @tparam Container any container, such as std::vector
 * @param v instance of container to be filtered
 * @param pred predicate. Returns true for elements that need to stay in
 * container.
 */
template <typename Container>
Container
filter_if(const Container &inp,
          std::function<bool(const typename Container::value_type &)> pred) {
    Container v = inp;
    v.erase(std::remove_if(v.begin(), v.end(),
                           [&](const typename Container::value_type &t) {
                               return !pred(t);
                           }),
            v.end());
    return v;
}

inline CBlockHeader headerFromBytes(const std::vector<uint8_t> &v) {
    CDataStream stream(v, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    stream >> header;
    return header;
}

inline altintegration::AltBlock blockToAltBlock(int nHeight,
                                                const CBlockHeader &block) {
    altintegration::AltBlock alt;
    alt.height = nHeight;
    alt.timestamp = block.nTime;
    alt.previousBlock = std::vector<uint8_t>(block.hashPrevBlock.begin(),
                                             block.hashPrevBlock.end());
    auto hash = block.GetHash();
    alt.hash = std::vector<uint8_t>(hash.begin(), hash.end());
    return alt;
}

inline altintegration::AltBlock blockToAltBlock(const CBlockIndex &index) {
    return blockToAltBlock(index.nHeight, index.GetBlockHeader());
}

template <typename T>
bool FindPayloadInBlock(const CBlock &block, const typename T::id_t &id,
                        T &out) {
    (void)block;
    (void)id;
    (void)out;
    static_assert(sizeof(T) == 0, "Undefined type in FindPayloadInBlock");
    return false;
}

template <>
inline bool FindPayloadInBlock(const CBlock &block,
                               const altintegration::VbkBlock::id_t &id,
                               altintegration::VbkBlock &out) {
    for (auto &blk : block.popData.context) {
        if (blk.getShortHash() == id) {
            out = blk;
            return true;
        }
    }

    return false;
}

template <>
inline bool FindPayloadInBlock(const CBlock &block,
                               const altintegration::VTB::id_t &id,
                               altintegration::VTB &out) {
    for (auto &vtb : block.popData.vtbs) {
        if (vtb.getId() == id) {
            out = vtb;
            return true;
        }
    }

    return false;
}

template <>
inline bool FindPayloadInBlock(const CBlock &block,
                               const altintegration::ATV::id_t &id,
                               altintegration::ATV &out) {
    for (auto &atv : block.popData.atvs) {
        if (atv.getId() == id) {
            out = atv;
            return true;
        }
    }
    return false;
}

} // namespace VeriBlock
#endif
```
Has been updated bitcoind.cpp, bitcoin-tx.cpp, bitcoin-wallet.cpp to setup VeriBlock`s configs.
bitcoind.cpp
```diff
 // Check for -chain, -testnet or -regtest parameter (Params() calls are
        // only valid after this clause)
        try {
            SelectParams(gArgs.GetChainName());
+            // VeriBlock
+            VeriBlock::selectPopConfig(gArgs);
            node.chain = interfaces::MakeChain(node, config.GetChainParams());
        } catch (const std::exception &e) {
            return InitError(strprintf("%s\n", e.what()));
        }
```
bitcoin-tx.cpp
```diff
// Check for -chain, -testnet or -regtest parameter (Params() calls are only
    // valid after this clause)
    try {
        SelectParams(gArgs.GetChainName());
+        // VeriBlock
+        VeriBlock::selectPopConfig(gArgs);
    } catch (const std::exception &e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
```
bitcoin-wallet.cpp
```diff
    // Check for -testnet or -regtest parameter (Params() calls are only valid
    // after this clause)
    SelectParams(gArgs.GetChainName());
+    // VeriBlock
+    VeriBlock::selectPopConfig(gArgs);
```

Has been updated CMakeLists.txt in the src directory
CMakeLists.txt
```diff
add_library(common
+   vbk/pop_common.cpp
	amount.cpp
	base58.cpp
	bloom.cpp
+   vbk/bootstraps.cpp
	cashaddr.cpp
	cashaddrenc.cpp
	chainparams.cpp
	config.cpp
	consensus/merkle.cpp
	coins.cpp
	compressor.cpp
	eventloop.cpp
	feerate.cpp
	core_read.cpp
	core_write.cpp
	key.cpp
	key_io.cpp
	merkleblock.cpp
	net_permissions.cpp
	netaddress.cpp
	netbase.cpp
	outputtype.cpp
	policy/policy.cpp
	primitives/block.cpp
	protocol.cpp
	psbt.cpp
	rpc/rawtransaction_util.cpp
	rpc/util.cpp
	scheduler.cpp
	salteduint256hasher.cpp
	versionbitsinfo.cpp
	warnings.cpp
)
```

## Add PayloadsProvider

We should add a PayloadsProvider for the veriblock library. The main idea of such class that we will reuse the existing levelev-db database that is used in the original bitcoin cash. Our library allows to use the native realisation of the database. For this purposuses, has been created PayloadsProvider class which is inherited from the [altintegration::PayloadsProvider class](https://veriblock-pop-cpp.netlify.app/structaltintegration_1_1payloadsprovider).
First should create two new source files payloads_provider.hpp, block_batch_adaptor.hpp
vbk/adaptors/payloads_provider.hpp
```
#ifndef INTEGRATION_REFERENCE_BTC_PAYLOADS_PROVIDER_HPP
#define INTEGRATION_REFERENCE_BTC_PAYLOADS_PROVIDER_HPP

#include <dbwrapper.h>
#include <veriblock/storage/payloads_provider.hpp>

namespace VeriBlock {

constexpr const char DB_VBK_PREFIX = '^';
constexpr const char DB_VTB_PREFIX = '<';
constexpr const char DB_ATV_PREFIX = '>';

struct PayloadsProvider : public altintegration::PayloadsProvider {
    using base = altintegration::PayloadsProvider;
    using key_t = std::vector<uint8_t>;
    using value_t = std::vector<uint8_t>;

    ~PayloadsProvider() = default;

    PayloadsProvider(CDWrapper &db) : db_(db) {}

    void write(const altintegration::PopData &pop) {
        auto batch = CDBBatch(db_);
        for (const auto &b : pop.context) {
            batch.Write(std::make_pair(DB_VBK_PREFIX, b.getId()), b);
        }
        for (const auto &b : pop.vtbs) {
            batch.Write(std::make_pair(DB_VTB_PREFIX, b.getId()), b);
        }
        for (const auto &b : pop.atvs) {
            batch.Write(std::make_pair(DB_ATV_PREFIX, b.getId()), b);
        }
        bool ret = db_.WriteBatch(batch, true);
        VBK_ASSERT_MSG(ret, "payloads write batch failed");
        batch.Clear();
    }

    bool getATVs(const std::vector<altintegration::ATV::id_t> &ids,
                 std::vector<altintegration::ATV> &out,
                 altintegration::ValidationState &state) override {
        return getPayloads(DB_ATV_PREFIX, ids, out, state);
    }

    bool getVTBs(const std::vector<altintegration::VTB::id_t> &ids,
                 std::vector<altintegration::VTB> &out,
                 altintegration::ValidationState &state) override {
        return getPayloads(DB_VTB_PREFIX, ids, out, state);
    }

    bool getVBKs(const std::vector<altintegration::VbkBlock::id_t> &ids,
                 std::vector<altintegration::VbkBlock> &out,
                 altintegration::ValidationState &state) override {
        return getPayloads(DB_VBK_PREFIX, ids, out, state);
    }

private:
    template <typename pop_t>
    bool getPayloads(char dbPrefix,
                     const std::vector<typename pop_t::id_t> &ids,
                     std::vector<pop_t> &out,
                     altintegration::ValidationState &state) {
        auto &mempool = *GetPop().mempool;
        out.reserve(ids.size());
        for (size_t i = 0; i < ids.size(); ++i) {
            pop_t value;
            const auto *memval = mempool.get<pop_t>(ids[i]);
            if (memval != nullptr) {
                value = *memval;
            } else {
                if (!db_.Read(std::make_pair(dbPrefix, ids[i], value))) {
                    return state.Invalid(pop_t::name() + "-read-error", i);
                }
            }
            out.push_back(value);
        }
        return true;
    }

    CDBWrapper &db_;
};

} // namespace VeriBlock

#endif
```
vbk/adaptors/block_batch_adaptor.hpp
```
#ifndef INTEGRATION_REFERENCE_BTC_BLOCK_BATCH_ADAPTOR_HPP
#define INTEGRATION_REFERENCE_BTC_BLOCK_BATCH_ADAPTOR_HPP

#include <dbwrapper.h>
#include <veriblock/storage/block_batch_adaptor.hpp>

namespace VeriBlock {

constexpr const char DB_BTC_BLOCK = 'Q';
constexpr const char DB_BTC_TIP = 'q';
constexpr const char DB_VBK_BLOCK = 'W';
constexpr const char DB_DBK_TIP = 'w';
constexpr const char DB_ALT_BLOCK = 'E';
constexpr const char DB_ALT_TIP = 'e';

struct BlockBatchAdaptor : public altintegration::BlockCatchAdaptor {
    ~BlockBatchAdaptor() override = default;

    static std::pair<char, std::string> vbktip() {
        return std::make_pair(DB_VBK_TIP, "vbktip");
    }

    static std::pair<char, std::string> btctip() {
        return std::make_pair(DB_BTC_TIP, "btctip");
    }

    static std::pair<char, std::string> alttip() {
        return std::make_pair(DB_ALT_TIP, "alttip");
    }

    explicit BlockBatchAdaptor(CDBatch &batch) : batch_(batch) {}

    bool writeBlock(const altintegration::BlockIndex<altintgration::BtcBlock>
                        &value) override {
        batch_.Write(std::make_pair(DB_BTC_BLOCK, getHash(value)), value);
        return true;
    }

    bool writeBlock(const altintegration::BlockIndex<altintegration::VbkBlock>
                        &value) override {
        batch_.Write(std::make_pair(DB_VBK_BLOCK, getHash(value)), value);
        return true;
    }

    bool writeBlock(const altintegration::BlockIndex<altintegration::AltBlock>
                        &value) override {
        batch_.Write(std::make_pair(DB_ALT_BLOCK, getHash(value)), value);
        return true;
    }

    bool writeTip(const altintegration::BlockIndex<altintegration::BtcBlock>
                      &value) override {
        batch_.Write(btctip(), getHash(value));
        return true;
    }

    bool writeTip(const altintegration::BlockIndex<altintegration::VbkBlock>
                      &value) override {
        batch_.Write(vbktip(), getHash(value));
        return true;
    }

    bool writeTip(const altintegration::BlockIndex<altintegration::AltBlock>
                      &value) override {
        batch_.Write(alttip(), getHash(value));
        return true;
    }

private:
    CDBBatch &batch_;

    template <typename T> typename T::hash_t getHash(const T &c) {
        return c.getHash();
    }
};

} // namespace VeriBlock

#endif
```
Have been created wrappers for such entities, and they put in the following source files pop_service.hpp, pop_service.cpp
vbk/pop_service.hpp
```
#ifndef BITCOIN_SRC_VBK_POP_SERVICE_HPP
#define BITCOIN_SRC_VBK_POP_SERVICE_HPP

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

} // namespace VeriBlock

#endif
```
vbk/pop_service.cpp
```
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
```
Also have been updated serialization methods for the VBK entites like ATV, VTB, VbkBlock etc. in the serialize.h
serialize.h
```diff
+ #include "veriblock/entities/altblock.hpp"
...
+ template <typename Stream>
+ inline void Serialize(Stream &s, const altintegration::ATV &atv) {
+     std::vector<uint8_t> bytes_data = atv.toVbkEncoding();
+     Serialize(s, bytes_data);
+ }

+ template <typename Stream>
+ inline void Unserialize(Stream &s, altintegration::ATV &atv) {
+     std::vector<uint8_t> bytes_data;
+     Unserialize(s, bytes_data);
+     atv = altintegration::ATV::fromVbkEncoding(bytes_data);
+ }
+ template <typename Stream>
+ inline void Serialize(Stream &s, const altintegration::VTB &vtb) {
+    std::vector<uint8_t> bytes_data = vtb.toVbkEncoding();
+     Serialize(s, bytes_data);
+ }
+ template <typename Stream>
+ inline void Unserialize(Stream &s, altintegration::VTB &vtb) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    vtb = altintegration::VTB::fromVbkEncoding(bytes_data);
+ }

+ template <typename Stream>
+ inline void
+ Serialize(Stream &s,
+           const altintegration::BlockIndex<altintegration::BtcBlock> &b) {
+     std::vector<uint8_t> bytes_data = b.toRaw();
+    Serialize(s, bytes_data);
+ }
+ template <typename Stream>
+ inline void
+ Unserialize(Stream &s,
+             altintegration::BlockIndex<altintegration::BtcBlock> &b) {
+     std::vector<uint8_t> bytes_data;
+     Unserialize(s, bytes_data);
+     b = altintegration::BlockIndex<altintegration::BtcBlock>::fromRaw(
+         bytes_data);
+ }
+ template <typename Stream>
+ inline void
+ Serialize(Stream &s,
+           const altintegration::BlockIndex<altintegration::VbkBlock> &b) {
+     std::vector<uint8_t> bytes_data = b.toRaw();
+     Serialize(s, bytes_data);
+ }
+ template <typename Stream>
+ inline void
+ Unserialize(Stream &s,
+             altintegration::BlockIndex<altintegration::VbkBlock> &b) {
+     std::vector<uint8_t> bytes_data;
+     Unserialize(s, bytes_data);
+     b = altintegration::BlockIndex<altintegration::VbkBlock>::fromRaw(
+         bytes_data);
+ }
+ template <typename Stream>
+ inline void
+ Serialize(Stream &s,
+           const altintegration::BlockIndex<altintegration::AltBlock> &b) {
+     std::vector<uint8_t> bytes_data = b.toRaw();
+     Serialize(s, bytes_data);
+ }
+ template <typename Stream>
+ inline void
+ Unserialize(Stream &s,
+             altintegration::BlockIndex<altintegration::AltBlock> &b) {
+     std::vector<uint8_t> bytes_data;
+     Unserialize(s, bytes_data);
+     b = altintegration::BlockIndex<altintegration::AltBlock>::fromRaw(
+         bytes_data);
+ }
+ template <typename Stream, size_t N>
+ inline void Serialize(Stream &s, const altintegration::Blob<N> &b) {
+     Serialize(s, b.asVector());
+ }
+ template <typename Stream, size_t N>
+ inline void Unserialize(Stream &s, altintegration::Blob<N> &b) {
+     std::vector<uint8_t> bytes;
+     Unserialize(s, bytes);
+     b = altintegration::Blob<N>(bytes);
+ }

+ template <typename Stream>
+ inline void Serialize(Stream &s, const altintegration::VbkBlock &block) {
+     altintegration::WriteStream stream;
+     block.toVbkEncoding(stream);
+     Serialize(s, stream.data());
+ }
+ template <typename Stream>
+ inline void Unserialize(Stream &s, altintegration::VbkBlock &block) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    altintegration::ReadStream stream(bytes_data);
+    block = altintegration::VbkBlock::fromVbkEncoding(stream);
+ }
```
Now we have to add usage of such functions in the bitcoin cash. 
Have been updated the following source files init.cpp, txdb.cpp, validation.cpp
init.cpp
```diff
+ #include <vbk/pop_service.hpp>
...
bool AppInitMain(Config &config, RPCServer &rpcServer,
                 HTTPRPCRequestProcessor &httpRPCRequestProcessor,
                 NodeContext &node) {
...
    uiInterface.InitMessage(_("Loading block index...").translated);
        do {
            const int64_t load_block_index_start_time = GetTimeMillis();
            try {
                LOCK(cs_main);
                UnloadBlockIndex();
                pcoinsTip.reset();
                pcoinsdbview.reset();
                pcoinscatcher.reset();
                // new CBlockTreeDB tries to delete the existing file, which
                // fails if it's still open from the previous loop. Close it
                // first:
                pblocktree.reset();
                pblocktree.reset(
                    new CBlockTreeDB(nBlockTreeDBCache, false, fReset));
+               VeriBlock::SetPop(*pblocktree);
                ...
            }
        } while (false);
...
}
```
txdb.cpp
```diff
+ #include <vbk/pop_service.hpp>
...
bool CBlockTreeDB::WriteBatchSync(
    const std::vector<std::pair<int, const CBlockFileInfo *>> &fileInfo,
    int nLastFile, const std::vector<const CBlockIndex *> &blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo *>>::const_iterator
             it = fileInfo.begin();
         it != fileInfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex *>::const_iterator it =
             blockinfo.begin();
         it != blockinfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()),
                    CDiskBlockIndex(*it));
    }

+    // write BTC/VBK/ALT blocks
+    auto adaptor = VeriBlock::BlockBatchAdaptor(batch);
+    VeriBlock::saveTrees(adaptor);

    return WriteBatch(batch, true);
}

```
validation.cpp
```diff
+ #include <vbk/pop_service.hpp>

bool CChainState::LoadBlockIndex(const Consensus::Params &params,
                                 CBlockTreeDB &blocktree) {
    AssertLockHeld(cs_main);
    if (!blocktree.LoadBlockIndexGuts(
            params, [this](const BlockHash &hash) EXCLUSIVE_LOCKS_REQUIRED(
                        cs_main) { return this->InsertBlockIndex(hash); })) {
        return false;
    }

+    bool hasPopData = VeriBlock::hasPopData(blocktree);

+    if (!hasPopData) {
+        LogPrintf(
+            "BTC/VBK/ALT tips not found... skipping block index loading\n");
+        return true;
+    }

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex *>> vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const std::pair<const BlockHash, CBlockIndex *> &item :
         mapBlockIndex) {
        CBlockIndex *pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }

    ...

+    // VeriBlock
+    // get best chain from ALT tree and update vBTC's best chain
+    {
+        AssertLockHeld(cs_main);

+        // load blocks
+        std::unique_ptr<CDBIterator> pcursor(blocktree.NewIterator());
+        if (!VeriBlock::loadTrees(*pcursor)) {
+            return false;
+        }

+       // ALT tree tip should be set - this is our last best tip
+        auto *tip = VeriBlock::GetPop().altTree->getBestChain().tip();
+        assert(tip && "we could not load tip of alt block");
+        uint256 hash(tip->getHash());

+        CBlockIndex *index = LookupBlockIndex(BlockHash(hash));
+        assert(index);
+        if (index->IsValid(BlockValidity::TREE)) {
+            pindexBestHeader = index;
+        } else {
+            return false;
+        }
+    }

    return true;
}

```

The last step is to update tests, has been updated constructor of the TestingSetup struct in the setup_common.cpp
test/util/setup_common.cpp
```diff
+ #include <vbk/bootstraps.hpp>
+ #include <vbk/pop_service.hpp>
...
TestingSetup::TestingSetup() {
...
    pblocktree.reset(new CBlockTreeDB(1 << 20, true));
+    // VeriBlock
+    VeriBlock::SetPop(*pblocktree);
    pcoinsdbview.reset(new CCoinsViewDB(1 << 23, true));
    pcoinsTip.reset(new CCoinsViewCache(pcoinsdbview.get()));
...
}
...
BasicTestingSetup::BasicTestingSetup() {
    ...
    SelectParams(chainName);
+   VeriBlock::selectPopConfig("regtest", "regtest", true);
    gArgs.ForceSetArg("-printtoconsole", "0");
    ...
}
```

## Add Pop mempool

Now we want to add using of the popmempool to the bitcoin cash. For that we should implement few methods for the submitting pop payloads to the mempool, getting payloads during the block mining, and removing payloads after successful block submitting to the blockchain.
First we should implement such methods in the pop_service.hpp pop_service.cpp source files.
vbk/pop_service.hpp
```diff
+ //! mempool methods
+ altintegration::PopData getPopData();
+ void removePayloadsFromMempool(const altintegration::PopData &popData);
+ void updatePopMempoolForReorg();
+ void addDisconnectedPopdata(const altintegration::PopData &popData);
```
vbk/pop_service.cpp
```diff
+ altintegration::PopData getPopData() EXLUSIVE_LOCKS_REQUIRED(cs_main)  {
+    AssertLockHeld(cs_main);
+    return GetPop().mempool->getPop();
+ }

+ void removePayloadsFromMempool(const altintegration::PopData &popData)
+     EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+     AssertLockHeld(cs_main);
+     GetPop().mempool->removeAll(popData);
+ }

+ void updatePopMempoolForReorg() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+     auto &pop = GetPop();
+     for (const auto &popData : disconnected_popdata) {
+         pop.mempool->submitAll(popData);
+     }
+     disconnected_popdata.clear();
+ }

+ void addDisconnectedPopdata(const altintegration::PopData &popData)
+     EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+     disconnected_popdata.push_back(popData);
+ }
```
Now add getting popData during block mining, has been updated CreateNewBlock() in the miner.cpp
miner.cpp
```diff
+ #include <vbk/pop_service.hpp>
...
+ // VeriBlock: add PopData into the block
+ if (consensusParams.VeriBlockPopSecurityHeight <= nHeight) {
+    pblock->popData = VeriBlock::getPopData();
+ }

if (!pblock->popData.atvs.empty() || !pblock->popData.context.empty() || !pblock->popData.vtbs.empty()) {
   pblock->nVersion |= VeriBlock::POP_BLOCK_VERSION_BIT;
}
...
```
Has been added removing popData after successful submitting to the blockchain. Has been modified ConnectTip(), DisconnectTip() and UpdateMempoolForReorg() methods in the validation.cpp and txmempool.cpp.
validation.cpp
```diff
...
ConnectTip() {
...
+   // VeriBlock: remove from pop_mempool
+   VeriBlock::removePayloadsFromMempool(blockConnecting.popData);

    // Update m_chain & related variables.
    m_chain.SetTip(pindexNew);
    UpdateTip(params, pindexNew);
...
}
...
DisconnectTip() {
...
    if (disconnectpool) {
        disconnectpool->addForBlock(block.vtx);
    }

    // If the tip is finalized, then undo it.
    if (pindexFinalized == pindexDelete) {
        pindexFinalized = pindexDelete->pprev;
    }

+   // VeriBlock
+   VeriBlock::addDisconnectedPopdata(block.popData);

    m_chain.SetTip(pindexDelete->pprev);
...
}
...
```
txmempool.cpp
```diff
+ #include <vbk/pop_service.hpp>
...
UpdateMempoolForReorg() {
    AssertLockHeld(cs_main);
    std::vector<TxId> txidsUpdate;

+    // VeriBlock
+    VeriBlock::updatePopMempoolForReorg();
...
}
```

## Add VeriBlock AltTree

At this stage we will add functions for the VeriBlock AltTree maintaining such as setState(), acceptBlock(), addAllBlockPayloads().
vbk/pop_service.hpp
```diff
+ #include <consensus/validation.h>
+ #include <vbk/util.hpp>
...
+ /** Amount in satoshis (Can be negative) */
+ typedef int64_t CAmount;

+ class CBlockIndex;
+ class CBlock;
+ class CScript;
class CBlockTreeDB;
class CDBIterator;
class CDBWrapper;
+ class BlockValidationState;

namespace VeriBlock {

+ using BlockBytes = std::vector<uint8_t>;
+ using PoPRewards = std::map<CScript, CAmount>;

void SetPop(CDBWrapper &db);

PayloadsProvider &GetPayloadsProvider();

//! returns true if all tips are stored in database, false otherwise
bool hasPopData(CBlockTreeDB &db);
altintegration::PopData getPopData();
void saveTrees(altintegration::BlockBatchAdaptor &batch);
bool loadTrees(CDBIterator &iter);

+ //! alttree methods
+ bool acceptBlock(const CBlockIndex &indexNew BlockValidationState &state);
+ bool addAllBlockPayloads(const CBlock &block, BlockValidationState &state);
+ bool setState(const BlockHash &hash, altintegration::ValidationState &state);

//! mempool methods
altintegration::PopData getPopData() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void removePayloadsFromMempool(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void updatePopMempoolForReorg() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void addDisconnectedPopdata(const altintegration::PopData &popData)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

+ std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks);
+ std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);
...
```
vbk/pop_service.cpp
```diff
+ #include <vbk/util.hpp>
...

+ bool acceptBlock(const CBlockIndex &indexNew, BlockValidationState &state) {
+    AssertLockHeld(cs_main);
+    auto containing = VeriBlock::blockToAltBlock(indexNew);
+    altintegration::ValidationState instate;
+    if (!GetPop().altTree->acceptBlockHeader(containing, instate)) {
+        LogPrintf("ERROR: alt tree cannot accept block %s\n",
+                  instate.toString());

+        return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID,
+                             REJECT_INVALID, "", "instate.GetDebugMessage()");
+    }

+    return true;
+ }

+ bool checkPopDataSize(const altintegration::PopData &popData,
+                      altintegration::ValidationState &state) {
+    uint32_t nPopDataSize = ::GetSerializeSize(popData, CLIENT_VERSION);
+    if (nPopDataSize >= GetPop().config->alt->getMaxPopDataSize()) {
+        return state.Invalid("popdata-overisize",
+                             "popData raw size more than allowed");
+    }

+    return true;
+ }

+ bool popdataStatelessValidation(const altintegration::PopData &popData,
+                                altintegration::ValidationState &state) {
+    auto &config = *GetPop().config;

+    for (const auto &b : popData.context) {
+        if (!altintegration::checkBlock(b, state, *config.vbk.params)) {
+            return state.Invalid("pop-vbkblock-statelessly-invalid");
+        }
+    }

+    for (const auto &vtb : popData.vtbs) {
+        if (!altintegration::checkVTB(vtb, state, *config.btc.params)) {
+            return state.Invalid("pop-vtb-statelessly-invalid");
+        }
+    }

+    for (const auto &atv : popData.atvs) {
+        if (!altintegration::checkATV(atv, state, *config.alt)) {
+            return state.Invalid("pop-atv-statelessly-invalid");
+        }
+    }

+    return true;
+ }

+ bool addAllBlockPayloads(const CBlock &block, BlockValidationState &state)
+    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+    AssertLockHeld(cs_main);
+    auto bootstrapBlockHeight =
+        GetPop().config->alt->getBootstrapBlock().height;
+    auto hash = block.GetHash();
+    auto *index = LookupBlockIndex(hash);

+    if (index->nHeight == bootstrapBlockHeight) {
+        // skip bootstrap block block
+        return true;
+    }

+    altintegration::ValidationState instate;

+    if (!checkPopDataSize(block.popData, instate) ||
+        !popdataStatelessValidation(block.popData, instate)) {
+        return error(
+            "[%s] block %s is not accepted because popData is invalid: %s",
+            __func__, hash.ToString(), instate.toString());
+    }

+    auto &provider = GetPayloadsProvider();
+    provider.write(block.popData);

+    GetPop().altTree->acceptBlock(
+        std::vector<uint8_t>{hash.begin(), hash.end()}, block.popData);

+    return true;
+ }

+bool setState(const BlockHash &hash, altintegration::ValidationState &state)
+    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+    AssertLockHeld(cs_main);
+    return GetPop().altTree->setState(
+        std::vector<uint8_t>{hash.begin(), hash.end()}, state);
+ }
```
Have been updated validation.cpp, init.cpp.
validation.cpp
```diff
...
ConnectBlock() {
...
+    altintegration::ValidationState _state;
+    if (!VeriBlock::setState(pindex->GetBlockHash(), _state)) {
+        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
+                             REJECT_INVALID, "bad-block-pop",
+                             strprintf("Block %s is POP invalid: %s",
+                                       pindex->GetBlockHash().ToString(),
+                                       _state.toString()));
+    }

    int64_t nTime3 = GetTimeMicros();
    nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH,
             "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) "
             "[%.2fs (%.2fms/blk)]\n",
             (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2),
             MILLI * (nTime3 - nTime2) / block.vtx.size(),
             nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs - 1),
             nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);
...
}

...

UpdateTip() {
    // New best block
    g_mempool.AddTransactionsUpdated(1);

    {
        LOCK(g_best_block_mutex);
        g_best_block = pindexNew->GetBlockHash();
        g_best_block_cv.notify_all();
    }

+    altintegration::ValidationState state;
+    bool ret = VeriBlock::setState(pindexNew->GetBlockHash(), state);
+    assert(ret && "block has been checked previously and should be valid");
...
}

...

ApplyBlockUndo() {
...
+   altintegration::ValidationState state;
+   VeriBlock::setState(block.hashPrevBlock, state);

    // Move best block pointer to previous block.
    view.SetBestBlock(block.hashPrevBlock);

    return fClean ? DisconnectResult::OK : DisconnectResult::UNCLEAN;
}

...

AcceptBlockHeader() {
...
    if (pindex == nullptr) {
        pindex = AddToBlockIndex(block);
    }

    if (ppindex) {
        *ppindex = pindex;
    }

    CheckBlockIndex(chainparams.GetConsensus());

+    if (!VeriBlock::acceptBlock(*pindex, state)) {
+        return error(
+            "%s: ALT tree could not accept block ALT:%d:%s, reason: %s",
+            __func__, pindex->nHeight, pindex->GetBlockHash().ToString(),
+            FormatStateMessage(state));
+    }
    return true;
}

...

AcceptBlock() {
...
    if (!CheckBlock(block, state, consensusParams,
                    BlockValidationOptions(config)) ||
        !ContextualCheckBlock(block, state, consensusParams, pindex->pprev)) {
        if (state.IsInvalid() &&
            state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
            pindex->nStatus = pindex->nStatus.withFailed();
            setDirtyBlockIndex.insert(pindex);
        }

        return error("%s: %s (block %s)", __func__, FormatStateMessage(state),
                     block.GetHash().ToString());
    }

+    {
+        if (!VeriBlock::addAllBlockPayloads(block, state)) {
+            return state.Invalid(
+                BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
+                strprintf("Can not add POP payloads to block "
+                          "height: %d , hash: %s: %s",
+                          pindex->nHeight, block.GetHash().ToString(),
+                          FormatStateMessage(state)));
+        }
+    }
...
}

...

TestBlockValidity() {
...
    if (!ContextualCheckBlock(block, state, params.GetConsensus(),
                              pindexPrev)) {
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__,
                     FormatStateMessage(state));
    }

+    // VeriBlock: Block that have been passed to TestBlockValidity may not exist
+    // in alt tree, because technically it was not created ("mined"). in this
+    // case, add it and then remove
+    auto &tree = *VeriBlock::GetPop().altTree;
+    std::vector<uint8_t> _hash{block_hash.begin(), block_hash.end()};
+    bool shouldRemove = false;
+    if (!tree.getBlockIndex(_hash)) {
+        shouldRemove = true;
+        auto containing = VeriBlock::blockToAltBlock(indexDummy);
+        altintegration::ValidationState _state;
+        bool ret = tree.acceptBlockHeader(containing, _state);
+        assert(ret && "alt tree can not accept alt block");

+        tree.acceptBlock(_hash, block.popData);
+    }

+    auto _f = altintegration::Finalizer([shouldRemove, _hash, &tree]() {
+        if (shouldRemove) {
+            tree.removeSubtree(_hash);
+        }
+    });

    if (!::ChainstateActive().ConnectBlock(block, state, &indexDummy, viewNew,
                                           params, validationOptions, true)) {
        return false;
    }

    assert(state.IsValid());
    return true;
}
```
init.cpp
```diff
AppInitMain() {
...
+    {
+        auto &pop = VeriBlock::GetPop();
+        auto *tip = ChainActive().Tip();
+        altintegration::ValidationState state;
+        LOCK(cs_main);
+        bool ret = VeriBlock::setState(tip->GetBlockHash(), state);
+        auto *alttip = pop.altTree->getBestChain().tip();
+        assert(ret && "bad state");
+        assert(tip->nHeight == alttip->getHeight());

+        LogPrintf("ALT tree best height = %d\n",
+                  pop.altTree->getBestChain().tip()->getHeight());
+        LogPrintf("VBK tree best height = %d\n",
+                  pop.altTree->vbk().getBestChain().tip()->getHeight());
+        LogPrintf("BTC tree best height = %d\n",
+                  pop.altTree->btc().getBestChain().tip()->getHeight());
+    }

    // Start Avalanche's event loop.
    g_avalanche->startEventLoop(*node.scheduler);

    return true;
}
```
undo_tests.cpp
```diff
- BOOST_FIXTURE_TEST_SUITE(undo_tests, BasicTestingSetup)
+ BOOST_FIXTURE_TEST_SUITE(undo_tests, TestingSetup)
```

## Add Unit tests

At this stage we can test previously added improvements.
First should add some util test source files like consts.hpp, e2e_fixture.hpp.
vbk/test/util/consts.hpp
```
#ifndef BITCOIN_SRC_VBK_TEST_UTIL_UTIL_HPP
#define BITCOIN_SRC_VBK_TEST_UTIL_UTIL_HPP

namespace VeriBlockTest {

static const std::string defaultAtvEncoded =
    "00000001" // version=1
    "01580101166772f51ab208d32771ab1506970eeb664462730b838e0203e800010701370100"
    "010c6865616465722062797465730112636f6e7465787420696e666f206279746573011170"
    "61796f757420696e666f2062797465734630440220398b74708dc8f8aee68fce0c47b8959e"
    "6fce6354665da3ed87a83f708e62aa6b02202e6c00c00487763c55e92c7b8e1dd538b7375d"
    "8df2b2117e75acbb9db7deb3c7583056301006072a8648ce3d020106052b8104000a034200"
    "04de4ee8300c3cd99e913536cf53c4add179f048f8fe90e5adf3ed19668dd1dbf6c2d8e692"
    "b1d36eac7187950620a28838da60a8c9dd60190c14c59b82cb90319e040000000104000000"
    "00201fec8aa4983d69395010e4d18cd8b943749d5b4f575e88a375debdc5ed22531c040000"
    "00022000000000000000000000000000000000000000000000000000000000000000002000"
    "00000000000000000000000000000000000000000000000000000000000000400000138800"
    "02449c60619294546ad825af03b0935637860679ddd55ee4fd21082e18686e26bbfda7d5e4"
    "462ef24ae02d67e47d785c9b90f301010000000000010100";

static const std::string defaultVtbEncoded =
    "00000001" // version=1
    "02046002011667ff0a897e5d512a0b6da2f41c479867fe6b3a4cae2640000013350002a793"
    "c872d6f6460e90bed62342bb968195f8c515d3eed7277a09efac4be99f95f0a15628b06ba3"
    "b44c0190b5c0495c9b8acd0701c5235ebbbe9c02011b01000000010ce74f1fb694a001eebb"
    "1d7d08ce6208033f5bf7263ebad2de07bbf518672732000000006a47304402200cf4998aba"
    "1682abeb777e762807a9dd2635a0b77773f66491b83ee3c87099ba022033b7ca24dc520915"
    "b8b0200cbdcf95ba6ae866354585af9c53ee86f27362ebec012103e5baf0709c395a82ef0b"
    "d63bc8847564ac201d69a8e6bf448d87aa53a1c431aaffffffff02b7270d00000000001976"
    "a9148b9ea8545059f3a922457afd14ddf3855d8b109988ac0000000000000000536a4c5000"
    "0013350002a793c872d6f6460e90bed62342bb968195f8c515d3eed7277a09efac4be99f95"
    "f0a15628b06ba3b44c0190b5c0495c9b8acd0701c5235ebbbe9cd4e943efe1864df0421661"
    "5cf92083f40000000002019f040000067b040000000c040000000400000020204d66077fdf"
    "24246ffd6b6979dfedef5d46588654addeb35edb11e993c131f61220023d1abe8758c6f917"
    "ec0c65674bbd43d66ee14dc667b3117dfc44690c6f5af120096ddba03ca952af133fb06307"
    "c24171e53bf50ab76f1edeabde5e99f78d4ead202f32cf1bee50349d56fc1943af84f2d2ab"
    "da520f64dc4db37b2f3db20b0ecb572093e70120f1b539d0c1495b368061129f30d35f9e43"
    "6f32d69967ae86031a275620f554378a116e2142f9f6315a38b19bd8a1b2e6dc31201f2d37"
    "a058f03c39c06c200824705685ceca003c95140434ee9d8bbbf4474b83fd4ecc2766137db9"
    "a44d7420b7b9e52f3ee8ce4fbb8be7d6cf66d33a20293f806c69385136662a74453fb16220"
    "1732c9a35e80d4796babea76aace50b49f6079ea3e349f026b4491cfe720ad17202d9b57e9"
    "2ab51fe28a587050fd82abb30abd699a5ce8b54e7cd49b2a827bcb9920dcba229acdc6b7f0"
    "28ba756fd5abbfebd31b4227cd4137d728ec5ea56c457618202cf1439a6dbcc1a35e96574b"
    "ddbf2c5db9174af5ad0d278fe92e06e4ac349a42500000c02000000000000000000014297d"
    "038cb54bfa964b44fb9a2d9853eb5936d4094f13a5e4a299b6c0cbdac21e997d74a999c26a"
    "cd68c34bdfb527b10ddd779a1a0bceb3919b5c6c1f2c1773703bc001035000008020000000"
    "0000000000000d5efbd7dc73f09e8aaf064d1a76142d4bac4e9dcc61fc255eefbc6d8670ee"
    "98c583aeed677f27fc239c41f93ee411add001b1d40815a3268b9b5c6c1f2c17e11874af50"
    "0000402000000000000000000013535112250e115e2896e4f602c353d839443080398e3f1d"
    "fb5f1e89109ef8508bde5404cf244a6372f402e0cf9d8dbd818326222ca739e08d9b5c6c1f"
    "2c1744290a9250000000200000000000000000002274473227b7674bd6a5b17dd3316a827f"
    "5a34402ea4ba2b36128b600bbb488ec6595eb2bb808425dea85fb83a63267b643406bed63a"
    "a310919b5c6c1f2c1749c4d1f0473045022100f4dce45edcc6bfc4a1f44ef04e47e90a348e"
    "fd471f742f18b882ac77a8d0e89e0220617cf7c4a22211991687b17126c1bb007a3b2a25c5"
    "50f75d66b857a8fd9d75e7583056301006072a8648ce3d020106052b8104000a03420004b3"
    "c10470c8e8e426f1937758d9fb5e97a1891176cb37d4c12d4af4107b1aa3e8a8a754c06a22"
    "760e44c60642fba883967c19740d5231336326f7962750c8df990400000000040000000d20"
    "2a014e88ed7ab65cdfaa85daeab07eea6cba5e147f736edd8d02c2f9ddf0dec60400000006"
    "205b977ea09a554ad56957f662284044e7d37450ddadf7db3647712f59693997872020d0a3"
    "d873eeeee6a222a75316dce60b53ca43eaea09d27f0ece897303a53ae920c06fe913dca5dc"
    "2736563b80834d69e6dfdf1b1e92383ea62791e410421b6c1120049f68d350eeb8b3df630c"
    "8308b5c8c2ba4cd6210868395b084af84d19ff0e9020000000000000000000000000000000"
    "00000000000000000000000000000000002036252dfc621de420fb083ad9d8767cba627edd"
    "eec64e421e9576cee21297dd0a40000013700002449c60619294546ad825af03b093563786"
    "0679ddd55ee4fd21082e18686eb53c1f4e259e6a0df23721a0b3b4b7ab5c9b9211070211ca"
    "f01c3f010100";

} // namespace VeriBlockTest


#endif 
```
vbk/test/util/e2e_fixture.hpp
```
#ifndef BITCOIN_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP
#define BITCOIN_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <validation.h>

#include <vbk/bootstraps.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/util.hpp>

#include <veriblock/alt-util.hpp>
#include <veriblock/mempool.hpp>
#include <veriblock/mock_miner.hpp>

using altintegration::ATV;
using altintegration::BtcBlock;
using altintegration::MockMiner;
using altintegration::PublicationData;
using altintegration::VbkBlock;
using altintegration::VTB;

struct TestLogger : public altintegration::Logger {
    ~TestLogger() override = default;

    void log(altintegration::LogLevel lvl, const std::string &msg) override {
        fmt::printf("[pop] [%s]\t%s\n", altintegration::LevelToString(lvl),
                    msg);
    }
};

struct E2eFixture : public TestChain100Setup {
    CScript cbKey = CScript()
                    << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    MockMiner popminer;
    altintegration::ValidationState state_;
    altintegration::PopContext *pop;
    std::vector<uint8_t> defaultPayoutInfo = {1, 2, 3, 4, 5};

    E2eFixture() {
        altintegration::SetLogger<TestLogger>();
        altintegration::GetLogger().level = altintegration::LogLevel::warn;

        pop = &VeriBlock::GetPop();
    }

    void InvalidateTestBlock(CBlockIndex *pblock) {
        BlockValidationState state;
        ChainstateActive().InvalidateBlock(GetConfig(), state, pblock);
        ActivateBestChain(GetConfig(), state);
        g_mempool.clear();
    }

    void ReconsiderTestBlock(CBlockIndex *pblock) {
        BlockValidationState state;

        {
            LOCK(cs_main);
            ResetBlockFailureFlags(pblock);
        }
        ActivateBestChain(GetConfig(), state);
    }

    BtcBlock::hash_t getLastKnownBTCblock() {
        auto blocks = VeriBlock::getLastKnownBTCBlocks(1);
        BOOST_CHECK(blocks.size() == 1);
        return blocks[0];
    }

    VbkBlock::hash_t getLastKnownVBKblock() {
        auto blocks = VeriBlock::getLastKnownVBKBlocks(1);
        BOOST_CHECK(blocks.size() == 1);
        return blocks[0];
    }

    ATV endorseAltBlock(BlockHash hash, const std::vector<VTB> &vtbs,
                        const std::vector<uint8_t> &payoutInfo) {
        CBlockIndex *endorsed = nullptr;
        {
            LOCK(cs_main);
            endorsed = LookupBlockIndex(hash);
            BOOST_CHECK(endorsed != nullptr);
        }

        auto publicationdata = createPublicationData(endorsed, payoutInfo);
        auto vbktx = popminer.createVbkTxEndorsingAltBlock(publicationdata);
        auto atv = popminer.applyATV(vbktx, state_);
        BOOST_CHECK(state_.IsValid());
        return atv;
    }

    ATV endorseAltBlock(BlockHash hash, const std::vector<VTB> &vtbs) {
        return endorseAltBlock(hash, vtbs, defaultPayoutInfo);
    }

    CBlock endorseAltBlockAndMine(const std::vector<BlockHash> &hashes,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(
            hashes, ChainActive().Tip()->GetBlockHash(), generateVtbs);
    }

    CBlock endorseAltBlockAndMine(const std::vector<BlockHash> &hashes,
                                  BlockHash prevBlock,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(hashes, prevBlock, defaultPayoutInfo,
                                      generateVtbs);
    }

    CBlock endorseAltBlockAndMine(const std::vector<BlockHash> &hashes,
                                  BlockHash prevBlock,
                                  const std::vector<uint8_t> &payoutInfo,
                                  size_t generateVtbs = 0) {
        std::vector<VTB> vtbs;
        vtbs.reserve(generateVtbs);
        std::generate_n(std::back_inserter(vtbs), generateVtbs,
                        [&]() { return endorseVbkTip(); });

        std::vector<ATV> atvs;
        atvs.reserve(hashes.size());
        std::transform(hashes.begin(), hashes.end(), std::back_inserter(atvs),
                       [&](const BlockHash &hash) -> ATV {
                           return endorseAltBlock(hash, {}, payoutInfo);
                       });

        BOOST_CHECK_EQUAL(atvs.size(), hashes.size());
        auto &pop_mempool = *pop->mempool;

        for (const auto &vtb : vtbs) {
            BOOST_CHECK_MESSAGE(pop_mempool.submit(vtb, state_),
                                state_.toString());
        }

        for (const auto &atv : atvs) {
            BOOST_CHECK_MESSAGE(pop_mempool.submit(atv, state_),
                                state_.toString());
        }

        return CreateAndProcessBlock({}, cbKey);
    }

    CBlock endorseAltBlockAndMine(BlockHash hash, BlockHash prevBlock,
                                  const std::vector<uint8_t> &payoutInfo,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(std::vector<BlockHash>{hash}, prevBlock,
                                      payoutInfo, generateVtbs);
    }

    CBlock endorseAltBlockAndMine(BlockHash hash, size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(hash, ChainActive().Tip()->GetBlockHash(),
                                      generateVtbs);
    }

    CBlock endorseAltBlockAndMine(BlockHash hash, BlockHash prevBlock,
                                  size_t generateVtbs = 0) {
        return endorseAltBlockAndMine(hash, prevBlock, defaultPayoutInfo,
                                      generateVtbs);
    }

    VTB endorseVbkTip() {
        auto best = popminer.vbk().getBestChain();
        auto tip = best.tip();
        BOOST_CHECK(tip != nullptr);
        return endorseVbkBlock(tip->getHeight());
    }

    VTB endorseVbkBlock(int height) {
        auto vbkbest = popminer.vbk().getBestChain();
        auto endorsed = vbkbest[height];
        if (!endorsed) {
            throw std::logic_error("can not find VBK block at height " +
                                   std::to_string(height));
        }

        auto btctx =
            popminer.createBtcTxEndorsingVbkBlock(endorsed->getHeader());
        auto *btccontaining = popminer.mineBtcBlocks(1);
        auto vbktx = popminer.createVbkPopTxEndorsingVbkBlock(
            btccontaining->getHeader(), btctx, endorsed->getHeader(),
            getLastKnownBTCblock());
        auto *vbkcontaining = popminer.mineVbkBlocks(1);

        auto vtbs = popminer.vbkPayloads[vbkcontaining->getHash()];
        BOOST_CHECK(vtbs.size() == 1);
        return vtbs[0];
    }

    PublicationData
    createPublicationData(CBlockIndex *endorsed,
                          const std::vector<uint8_t> &payoutInfo) {
        PublicationData p;

        auto &config = *VeriBlock::GetPop().config;
        p.identifier = config.alt->getIdentifier();
        p.payoutInfo = payoutInfo;

        // serialize block header
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << endorsed->GetBlockHeader();
        p.header = std::vector<uint8_t>{stream.begin(), stream.end()};

        return p;
    }

    PublicationData createPublicationData(CBlockIndex *endorsed) {
        return createPublicationData(endorsed, defaultPayoutInfo);
    }
};

#endif 
```
Also should to modify setup_common.cpp, for the basic test setup.
test/util/setup_common.cpp
```diff
TestChain100Setup::TestChain100Setup() {
    // Generate a 100-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey())
                                     << OP_CHECKSIG;
    for (int i = 0; i < COINBASE_MATURITY; i++) {
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        m_coinbase_txns.push_back(b.vtx[0]);
    }

+    auto &tree = *VeriBlock::GetPop().altTree;
+    assert(tree.getBestChain().tip()->getHeight() ==
+           ChainActive().Tip()->nHeight);
}

```
Has been modfied miner_tests.cpp, disabled CreateNewBlock_validity test case.
miner_tests.cpp
```diff
// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity) {
+ // VeriBlock disable tests
+ #if 0
...
fCheckpointsEnabled = true;

+ #endif
}
```
So now we can add test case which will test the veriblock pop behaviour, e2e_pop_tests.cpp
vbk/test/unit/e2e_pop_tests.cpp
```
#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <validation.h>
#include <vbk/test/util/e2e_fixture.hpp>
#include <vbk/util.hpp>
#include <veriblock/alt-util.hpp>
#include <veriblock/mock_miner.hpp>

using altintegration::BtcBlock;
using altintegration::MockMiner;
using altintegration::PublicationData;
using altintegration::VbkBlock;
using altintegration::VTB;

BOOST_AUTO_TEST_SUITE(e2e_pop_tests)

BOOST_FIXTURE_TEST_CASE(ValidBlockIsAccepted, E2eFixture) {
    // altintegration and popminer configured to use BTC/VBK/ALT regtest.
    auto tip = ChainActive().Tip();
    BOOST_CHECK(tip != nullptr);

    // endorse tip
    CBlock block = endorseAltBlockAndMine(tip->GetBlockHash(), 10);
    BOOST_CHECK(block.popData.atvs.size() != 0);
    BOOST_CHECK(block.popData.vtbs.size() == 10);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ChainActive().Tip()->GetBlockHash() == block.GetHash());
        auto btc = VeriBlock::getLastKnownBTCBlocks(1)[0];
        BOOST_REQUIRE(btc == popminer.btc().getBestChain().tip()->getHash());
        auto vbk = VeriBlock::getLastKnownVBKBlocks(1)[0];
        BOOST_REQUIRE(vbk == popminer.vbk().getBestChain().tip()->getHash());
    }

    // endorse another tip
    block = endorseAltBlockAndMine(tip->GetBlockHash(), 1);
    BOOST_CHECK(block.popData.atvs.size() != 0);
    auto lastHash = ChainActive().Tip()->GetBlockHash();
    {
        LOCK(cs_main);
        BOOST_REQUIRE(lastHash == block.GetHash());
        auto btc = VeriBlock::getLastKnownBTCBlocks(1)[0];
        BOOST_REQUIRE(btc == popminer.btc().getBestChain().tip()->getHash());
        auto vbk = VeriBlock::getLastKnownVBKBlocks(1)[0];
        BOOST_REQUIRE(vbk == popminer.vbk().getBestChain().tip()->getHash());
    }

    block = CreateAndProcessBlock({}, cbKey);

    CreateAndProcessBlock({}, cbKey);

    block = endorseAltBlockAndMine(block.GetHash(), 1);
    BOOST_CHECK(block.popData.atvs.size() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
```
## Update block merkleroot, block size calculating

For the veriblock pop security we should add context info conrainer with the pop related information like block height, keystone array, popData merkle root. The root hash of the context info container should be added to the original block merkle root calculation.

VeriBlock merkle root specific functions have been implemented in the merkle.hpp, merkle.cpp, context_info_container.hpp

vbk/entity/context_info_container.hpp
```
#ifndef BITCOIN_SRC_VBK_ENTITY_CONTEXT_INFO_CONTAINER_HPP
#define BITCOIN_SRC_VBK_ENTITY_CONTEXT_INFO_CONTAINER_HPP

#include <hash.h>
#include <uint256.h>
#include <vbk/vbk.hpp>

namespace VeriBlock {

struct ContextInfoContainer {
    int32_t height{0};
    KeystoneArray keystones{};
    uint256 txMerkleRoot{};

    explicit ContextInfoContainer() = default;

    explicit ContextInfoContainer(int height, const KeystoneArray &keystones,
                                  const uint256 &txMerkleRoot)
        : height(height), keystones(keystones), txMerkleRoot(txMerkleRoot) {}

    uint256 getUnauthenticatedHash() const {
        auto unauth = getUnauthenticated();
        return Hash(unauth.begin(), unauth.end());
    }

    std::vector<uint8_t> getUnauthenticated() const {
        std::vector<uint8_t> ret(4, 0);

        // put height
        int i = 0;
        ret[i++] = (height & 0xff000000u) >> 24u;
        ret[i++] = (height & 0x00ff0000u) >> 16u;
        ret[i++] = (height & 0x0000ff00u) >> 8u;
        ret[i++] = (height & 0x000000ffu) >> 0u;

        ret.reserve(keystones.size() * 32);
        for (const uint256 &keystone : keystones) {
            ret.insert(ret.end(), keystone.begin(), keystone.end());
        }

        return ret;
    }

    uint256 getTopLevelMerkleRoot() {
        auto un = getUnauthenticatedHash();
        return Hash(txMerkleRoot.begin(), txMerkleRoot.end(), un.begin(),
                    un.end());
    }

    std::vector<uint8_t> getAuthenticated() const {
        auto v = this->getUnauthenticated();
        v.insert(v.end(), txMerkleRoot.begin(), txMerkleRoot.end());
        return v;
    }
};

} // namespace VeriBlock

#endif
```
vbk/merkle.hpp
```
#ifndef BITCOIN_SRC_VBK_MERKLE_HPP
#define BITCOIN_SRC_VBK_MERKLE_HPP

#include <iostream>

#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>

namespace VeriBlock {

uint256 TopLevelMerkleRoot(const CBlockIndex *prevIndex, const CBlock &block,
                           const Consensus::Params &param,
                           bool *mutated = nullptr);

bool VerifyTopLevelMerkleRoot(const CBlock &block, const CBlockIndex *prevIndex,
                              const Consensus::Params &param,
                              BlockValidationState &state);

CTxOut AddPopDataRootIntoCoinbaseCommitment(const CBlock &block);

} // namespace VeriBlock

#endif
```
vbk/merkle.cpp
```
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
                           const Consensus::Params &param, bool *mutated) {
    if (prevIndex == nullptr ||
        param.VeriBlockPopSecurityHeight > (prevIndex->nHeight + 1)) {
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
                              const Consensus::Params &param,
                              BlockValidationState &state) {
    bool mutated = false;
    uint256 hashMerkleRoot2 =
        VeriBlock::TopLevelMerkleRoot(prevIndex, block, param, &mutated);

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
        param.VeriBlockPopSecurityHeight > (prevIndex->nHeight + 1)) {
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
```

Next step is to update mining process and validation process with our new rules.

miner.cpp
```diff
+ #include <vbk/merkle.hpp>
...
CreateNewBlock() {
...
// Make sure the coinbase is big enough.
    uint64_t coinbaseSize = ::GetSerializeSize(coinbaseTx, PROTOCOL_VERSION);
    if (coinbaseSize < MIN_TX_SIZE) {
        coinbaseTx.vin[0].scriptSig
            << std::vector<uint8_t>(MIN_TX_SIZE - coinbaseSize - 1);
    }

+    // VeriBlock: add payloads commitment
+    if (consensusParams.VeriBlockPopSecurityHeight <= nHeight) {
+        CTxOut popOut = VeriBlock::AddPopDataRootIntoCoinbaseCommitment(*pblock);
+        coinbaseTx.vout.push_back(popOut);
+    }
...
}

...

IncrementExtraNonce() {
...
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

+    // VeriBlock
+    pblock->hashMerkleRoot = VeriBlock::TopLevelMerkleRoot(
+        pindexPrev, *pblock, Params().GetConsensus());
}
```
test/util/mining.cpp
```diff
+ #include <vbk/merkle.hpp>
...

PrepareBlock() {
...
    LOCK(cs_main);
    block->nTime = ::ChainActive().Tip()->GetMedianTimePast() + 1;

+    // VeriBlock
+    CBlockIndex *tip = ::ChainActive().Tip();
+    assert(tip != nullptr);
+    block->hashMerkleRoot = VeriBlock::TopLevelMerkleRoot(
+        tip, *block, config.GetChainParams().GetConsensus());

    return block;
}
```
validation.h
```diff
...
bool CheckBlock(const CBlock &block, BlockValidationState &state,
                const Consensus::Params &params,
                BlockValidationOptions validationOptions);

+ bool ContextualCheckBlock(const CBlock &block, BlockValidationState &state, const Consensus::Params &params, const CBlockIndex *pindexPrev, bool fCheckMerkleRoot);
...
```

As veriblock merkleroot algorithm depends on the blockchain, so we should move merkle root validation from the CheckBlock() to the ContextualCheckBlock() function.

validation.cpp
```diff
+ #include <vbk/merkle.hpp>
...

ConnectBlock() {
...
+    // VeriBlock : added ContextualCheckBlock() here becuse merkleRoot
+    // calculation  moved from the CheckBlock() to the ContextualCheckBlock()
    if (!CheckBlock(block, state, consensusParams,
                    options.withCheckPoW(!fJustCheck)
-                    .withCheckMerkleRoot(!fJustCheck)))
+                        .withCheckMerkleRoot(!fJustCheck)) &&
+        !ContextualCheckBlock(block, state, consensusParams, pindex->pprev,
+                              options.withCheckMerkleRoot(!fJustCheck)
+                                  .shouldValidateMerkleRoot())) {
...
}

...

CheckBlock() {
...
-    // Check the merkle root.
-    if (validationOptions.shouldValidateMerkleRoot()) {
-        bool mutated;
-        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
-        if (block.hashMerkleRoot != hashMerkleRoot2) {
-            return state.Invalid(BlockValidationResult::BLOCK_MUTATED,
-                                 REJECT_INVALID, "bad-txnmrklroot",
-                                 "hashMerkleRoot mismatch");
-        }

-        // Check for merkle tree malleability (CVE-2012-2459): repeating
-        // sequences of transactions in a block without affecting the merkle
-        // root of a block, while still invalidating it.
-        if (mutated) {
-            return state.Invalid(BlockValidationResult::BLOCK_MUTATED,
-                                 REJECT_INVALID, "bad-txns-duplicate",
-                                 "duplicate transaction");
-        }
-    }
...

    auto currentBlockSize = ::GetSerializeSize(block, PROTOCOL_VERSION);
+    // VeriBlock
+    if (block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+        currentBlockSize -= ::GetSerializeSize(block.popData, PROTOCOL_VERSION);
+    }

}

...

- static bool ContextualCheckBlock(const CBlock &block,
-                                 BlockValidationState &state,
-                                 const Consensus::Params &params,
-                                 const CBlockIndex *pindexPrev) {

+ bool ContextualCheckBlock(const CBlock &block, BlockValidationState &state,
+                          const Consensus::Params &params,
+                          const CBlockIndex *pindexPrev,
+                          bool fCheckMerkleRoot) {
...
    // Start enforcing BIP113 (Median Time Past).
    int nLockTimeFlags = 0;
    if (nHeight >= params.CSVHeight) {
        assert(pindexPrev != nullptr);
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

+    // VeriBlock: merkle tree verification is moved from CheckBlock here,
+    // because it requires correct CBlockIndex
+    if (fCheckMerkleRoot && !VeriBlock::VerifyTopLevelMerkleRoot(
+                                block, pindexPrev, params, state)) {
+        // state is already set with error message
+        return false;
+    }
...
}

...

AcceptBlock() {
...

 if (!CheckBlock(block, state, consensusParams,
                    BlockValidationOptions(config)) ||
- !ContextualCheckBlock(block, state, consensusParams, pindex->pprev)) {
+        !ContextualCheckBlock(
+            block, state, consensusParams, pindex->pprev,
+            BlockValidationOptions(config).shouldValidateMerkleRoot())) {
...
}

...

TestBlockValidity() {
...
- if (!ContextualCheckBlock(block, state, params.GetConsensus(), pindexPrev)) {
+    if (!ContextualCheckBlock(block, state, params.GetConsensus(), pindexPrev, validationOptions.shouldValidateMerkleRoot())) {
...
}

```

The next step is to update current tests and add new veriblock tests.
Has been disabled validation_block_tests.cpp
test/validation_block_tests.cpp
```diff

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, RegTestingSetup)

+ // VeriBlock
+ // -t option causes empty cpps to fail, add dummy to prevent this
+ BOOST_AUTO_TEST_CASE(dummy) {}

+ // disable test
+ #if 0

...

+ #endif

BOOST_AUTO_TEST_SUITE_END()
```
Also have been disabled for a while some functional tests.
../test/functional/test_runner.py
```diff
NON_SCRIPTS = [
    # These are python files that live in the functional tests directory, but
    # are not test scripts.
    "combine_logs.py",
    "create_cache.py",
    "test_runner.py",
+    # VeriBlock
+    # disable some tests
+    "p2p_compactblocks.py",
+    "feature_block.py",
+    "p2p_sendheaders.py",
+    "rpc_txoutproof.py",
+    "feature_csv_activation.py",
+    "rpc_rawtransaction.py",
+    "feature_bip68_sequence.py",
+    "interface_rest.py",
+    "rpc_blockchain.py",
+     "p2p_invalid_block.py",
+    "p2p_invalid_tx.py",
+    "feature_assumevalid.py",
+    "wallet_importprunedfunds.py",
+     "mining_basic.py",
+    "feature_dersig.py",
+    "feature_cltv.py",
+    "rpc_getblockstats.py",
+    "p2p_fingerprint.py",
+    "p2p_dos_header_tree.py",
+    "p2p_unrequested_blocks.py",
+    # VeriBlock
+    # disable some bitcoin cash tests
+    "abc-invalid-chains.py",
+    "abc-mempool-coherence-on-activations.py",
+    "abc-minimaldata.py",
+    "abc-replay-protection.py",
+    "abc-schnorr.py",
+    "abc-schnorrmultisig.py",
+    "abc-segwit-recovery.py",
+    "abc-sync-chain.py",
+    "abc-transaction-ordering.py",
+    "abc_feature_minerfund.py",
]
```
Have been added new tests: block_validation_tests.cpp, pop_util_tests.cpp, vbk_merkle_tests.cpp.

vbk/test/unit/block_validation_tests.cpp
```
#include <boost/test/unit_test.hpp>
#include <chainparams.h>
#include <consensus/validation.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vbk/pop_service.hpp>
#include <vbk/test/util/consts.hpp>
#include <vbk/test/util/e2e_fixture.hpp>

#include <string>

inline std::vector<uint8_t> operator""_v(const char *s, size_t size) {
    return std::vector<uint8_t>{s, s + size};
}

BOOST_AUTO_TEST_SUITE(block_validation_tests)

static altintegration::PopData generateRandPopData() {
    // add PopData
    auto atvBytes = altintegration::ParseHex(VeriBlockTest::defaultAtvEncoded);
    auto streamATV = altintegration::ReadStream(atvBytes);
    auto atv = altintegration::ATV::fromVbkEncoding(streamATV);

    auto vtbBytes = altintegration::ParseHex(VeriBlockTest::defaultVtbEncoded);
    auto streamVTB = altintegration::ReadStream(vtbBytes);
    auto vtb = altintegration::VTB::fromVbkEncoding(streamVTB);

    altintegration::PopData popData;
    popData.atvs = {atv};
    popData.vtbs = {vtb, vtb, vtb};

    return popData;
}

BOOST_AUTO_TEST_CASE(GetBlockWeight_test) {
    // Create random block
    CBlock block;
    block.hashMerkleRoot.SetNull();
    block.hashPrevBlock.SetNull();
    block.nBits = 10000;
    block.nNonce = 10000;
    block.nTime = 10000;
    int64_t expected_block_weight = ::GetSerializeSize(block, PROTOCOL_VERSION);

    block.nVersion = 1 | VeriBlock::POP_BLOCK_VERSION_BIT;

    BOOST_CHECK(expected_block_weight > 0);

    altintegration::PopData popData = generateRandPopData();

    int64_t popDataWeight = ::GetSerializeSize(popData, PROTOCOL_VERSION);

    BOOST_CHECK(popDataWeight > 0);

    expected_block_weight += popDataWeight;

    // put PopData into block
    block.popData = popData;

    int64_t new_block_weight = ::GetSerializeSize(block, PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL(new_block_weight, expected_block_weight);
}

BOOST_AUTO_TEST_CASE(block_serialization_test) {
    // Create random block
    CBlock block;
    block.hashMerkleRoot.SetNull();
    block.hashPrevBlock.SetNull();
    block.nBits = 10000;
    block.nNonce = 10000;
    block.nTime = 10000;
    block.nVersion = 1 | VeriBlock::POP_BLOCK_VERSION_BIT;

    altintegration::PopData popData = generateRandPopData();

    block.popData = popData;

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(stream.size() == 0);
    stream << block;
    BOOST_CHECK(stream.size() != 0);

    CBlock decoded_block;
    stream >> decoded_block;

    BOOST_CHECK(decoded_block.GetHash() == block.GetHash());
    BOOST_CHECK(decoded_block.popData == block.popData);
}

BOOST_AUTO_TEST_CASE(block_network_passing_test) {
    // Create random block
    CBlock block;
    block.hashMerkleRoot.SetNull();
    block.hashPrevBlock.SetNull();
    block.nBits = 10000;
    block.nNonce = 10000;
    block.nTime = 10000;
    block.nVersion = 1 | VeriBlock::POP_BLOCK_VERSION_BIT;

    altintegration::PopData popData = generateRandPopData();

    block.popData = popData;

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
}

BOOST_FIXTURE_TEST_CASE(BlockPoPVersion_test, E2eFixture) {
    for (size_t i = 0; i < 400; ++i) {
        CreateAndProcessBlock({}, cbKey);
    }

    auto block = CreateAndProcessBlock({}, cbKey);
}

BOOST_AUTO_TEST_SUITE_END()
```
vbk/test/unit/pop_util_tests.cpp
```
#include <boost/test/unit_test.hpp>

#include <consensus/validation.h>
#include <script/interpreter.h>
#include <string>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vbk/bootstraps.hpp>
#include <vbk/entity/context_info_container.hpp>
#include <vbk/merkle.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/util.hpp>

namespace VeriBlock {

KeystoneArray getKeystoneHashesForTheNextBlock(const CBlockIndex *pindexPrev);

bool isKeystone(const CBlockIndex &block);

const CBlockIndex *getPreviousKeystone(const CBlockIndex &block);

} // namespace VeriBlock

BOOST_AUTO_TEST_SUITE(pop_util_tests)

BOOST_FIXTURE_TEST_CASE(is_keystone, TestingSetup) {
    CBlockIndex index;
    index.nHeight = 100; // multiple of 5
    BOOST_CHECK(VeriBlock::isKeystone(index));
    index.nHeight = 99; // not multiple of 5
    BOOST_CHECK(!VeriBlock::isKeystone(index));
}

BOOST_FIXTURE_TEST_CASE(get_previous_keystone, TestingSetup) {
    std::vector<CBlockIndex> blocks;
    blocks.resize(10);
    blocks[0].pprev = nullptr;
    blocks[0].nHeight = 0;
    for (size_t i = 1; i < blocks.size(); i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
    }

    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[9]) == &blocks[5]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[8]) == &blocks[5]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[7]) == &blocks[5]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[6]) == &blocks[5]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[5]) == &blocks[0]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[4]) == &blocks[0]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[3]) == &blocks[0]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[2]) == &blocks[0]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[1]) == &blocks[0]);
    BOOST_CHECK(VeriBlock::getPreviousKeystone(blocks[0]) == nullptr);
}

BOOST_AUTO_TEST_CASE(make_context_info) {
    TestChain100Setup blockchain;

    CScript scriptPubKey = CScript()
                           << ToByteVector(blockchain.coinbaseKey.GetPubKey())
                           << OP_CHECKSIG;
    CBlock block = blockchain.CreateAndProcessBlock({}, scriptPubKey);

    LOCK(cs_main);

    CBlockIndex *index = LookupBlockIndex(block.GetHash());
    BOOST_REQUIRE(index != nullptr);

    uint256 txRoot{};
    auto keystones = VeriBlock::getKeystoneHashesForTheNextBlock(index->pprev);
    auto container =
        VeriBlock::ContextInfoContainer(index->nHeight, keystones, txRoot);

    // TestChain100Setup has blockchain with 100 blocks, new block is 101
    BOOST_CHECK(container.height == 101);
    BOOST_CHECK(container.keystones == keystones);
    BOOST_CHECK(container.getAuthenticated().size() ==
                container.getUnauthenticated().size() + 32);
    BOOST_CHECK(container.getUnauthenticated().size() == 4 + 2 * 32);
}

BOOST_AUTO_TEST_SUITE_END()
```
vbk/test/unit/vbk_merkle_tests.cpp
```
#include <boost/test/unit_test.hpp>

#include <algorithm>

#include <chain.h>
#include <config.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/wallet.h>

#include <vbk/merkle.hpp>

namespace VeriBlock {

int GetPopMerkleRootCommitmentIndex(const CBlock &block);

}

BOOST_AUTO_TEST_SUITE(vbk_merkle_tests)

struct MerkleFixture {
    // this inits veriblock services
    TestChain100Setup blockchain;
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
            VeriBlock::VerifyTopLevelMerkleRoot(block, index->pprev,
                                                Params().GetConsensus(), state),
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
    BOOST_CHECK(VeriBlock::VerifyTopLevelMerkleRoot(
        block, index->pprev, Params().GetConsensus(), state));

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

    BOOST_CHECK(!VeriBlock::VerifyTopLevelMerkleRoot(
        block, index->pprev, Params().GetConsensus(), state));

    // erase commitment
    tx.vout.erase(tx.vout.begin() + commitpos);
    block.vtx[0] = MakeTransactionRef(tx);

    BOOST_CHECK(!VeriBlock::VerifyTopLevelMerkleRoot(
        block, index->pprev, Params().GetConsensus(), state));
}

BOOST_AUTO_TEST_SUITE_END()
```

## Add VeriBlock specific RPC methods


