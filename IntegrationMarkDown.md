# Bitcoin cash markdown
#### Original Bitcoin cash  building
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

#### Add VeriBlock-PoP library dependency

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

#### Adding PopData into the Block
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
#### Add PopSecurity fokrpoint parameter

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
#### Add VeriBlock config

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

#### Add PayloadsProvider

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




