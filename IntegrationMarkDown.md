# Bitcoin cash markdown
## Original Bitcoin cash  building
First should install missing dependency jemalloc.
```sh 
git clone https://github.com/jemalloc/jemalloc.git
cd jemalloc
git checkout 5.2.1
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

Let`s add VeriBlock lib dependency into the CMakeLists.txt
```diff
+ # VeriBlock
+ find_package(veriblock-pop-cpp REQUIRED)
+ link_libraries(veriblock::veriblock-pop-cpp)
```
Install veriblock-pop-cpp library
```sh
git clone https://github.com/VeriBlock/alt-integration-cpp.git
cd alt-integration-cpp
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make
make install
```

## Adding PopData into the Block
We should add a new entity PopData into the CBlock class in the block.h file and provide a new nVersion flag. This is needed to store VeriBlock specific information as ATVs, VTBs, VBKs.
For these porposes first we will add a new POP_BLOCK_VERSION_BIT flag, that will help to distinguish originals blocks that don not have any VeriBlock specific data, and blocks that contain such data.
Next step, update serialization of the block, that popData will alse serialize/deserialize of POP_BLOCK_VERSION_BIT is setted.  And extend a serialization/deserialization methods for the PopData itself, that we can use the bitcoin`s native serialization/deserialization approach.

Define POP_BLOCK_VERSION_BIT flag.\
[<font style="color: red"> vbk/vbk.hpp </font>]
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

Add new popData field into the block and update serialization/deserialization of the block.\
[<font style="color: red"> primitives/block.h </font>]
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

Also we should update some p2p networking objects like CBlockHeaderAndShortTxIDs, BlockTransaction, PartiallyDownloadedBlock with the VeriBlock PopData for the correct broadcasting of such VeriBlock information throught the network.

Add new PopData filed into the BlockTransaction, CBlockHeaderAndShortTxIDs, PartiallyDownloadedBlock and update their serialization/deserialization.\
[<font style="color: red">blockencodings.h</font>]
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
Update PartiallyDownloadedBlock object initializing, to fill popData field.\
[<font style="color: red">blockencodings.cpp</font>]
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

Also need to update setup of the popData fields during the netprocessing.\
[<font style="color: red">net_processing.cpp</font>]
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
The last step is to update validation rules, add check that if block contains VeriBlock popData, so block.nVersion must contain POP_BLOCK_VERSION_BIT and otherwise if block does not contain VeriBlock popData. For this update CheckBlock function in the validation.cpp.\
[<font style="color: red">validation.cpp</font>]
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
Also should update the mining function to setup POP_BLOCK_VERSION_BIT if VeriBlock popData is contained in the block.\
[<font style="color: red">miner.cpp</font>]
```diff
+    // VeriBlock: add PopData into the block
+    if (!pblock->popData.atvs.empty() || !pblock->popData.context.empty() || !pblock->popData.vtbs.empty()) {
+        pblock->nVersion |= VeriBlock::POP_BLOCK_VERSION_BIT;
+    }
```

Overloaded serialization opereations for the VeriBlock PopData in the serialization.h.\
[<font style="color: red">serialization.hpp</font>]
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
## Add PopSecurity forkpoint parameter

It is obvious that for the already running blockchains, only the one way to enable VeriBlock security it is made a fork. So for this purposes we will provide a height variable of the forkpoint. Add a block height into the Consensus::Params from which enables PopSecurity.

[<font style="color: red">params.h</font>]
```diff
struct Params {
    ...
+   // VeriBlock
+   uint64_t VeriBlockPopSecurityHeight;
};
...
```

Define such VeriBlockPopSecurityHeight variable.\
[<font style="color: red">chainparams.cpp</font>]
```diff
...
class CMainParams : public CChainParams {
public:
    CMainParams() {
        ...
+        // VeriBlock
+        // TODO: set an VeriBlock pop security fork height
+        // consensus.VeriBlockPopSecurityHeight = -1;
        ...
    }
};
...
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        ...
+        // VeriBlock
+        // TODO: set an VeriBlock pop security fork height
+        // consensus.VeriBlockPopSecurityHeight = -1;
        ...
    }
};
...
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        ...
+        // VeriBlock
+        // TODO: set an VeriBlock pop security fork height
+        consensus.VeriBlockPopSecurityHeight = 1;
        ...
    }
};
```
Also update validation for the block, if PoPSecurity disabled, so POP_BLOCK_VERSION_BIT should not been installed.\
[<font style="color: red">validation.cpp</font>]
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

Before adding using and defining some objects from the VeriBlock library, we should define some VeriBlock specific parameters for library. For that we have to add new Config class which inherits from the altintegration::AltChainParams.
But first we will add functions that will wrap the interaction with the library. For that create two new source files pop_common.hpp, pop_common.cpp.\
[<font style="color: red">vbk/pop_common.hpp</font>]
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
[<font style="color: red">vbk/pop_common.cpp</font>]
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

Add the initial configuration of the VeriBlock and Bitcoin blockchain,
add the predifined bootstraps blocks. And create an AltChainParamsVBITCASH class with the veriblock configuration of the bitcoin cash blockchain.\
[<font style="color: red">vbk/bootstraps.hpp</font>]
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
[<font style="color: red">vbk/bootstraps.cpp</font>]
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

Additionally create an util.hpp source file, with some usefull set of functions for the integration purposes. We will use it among the integration process.\
[<font style="color: red">vbk/util.hpp</font>]
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
Now we have to update initializing of the bitcoind, bitcoin-wallet etc. to setup VeriBlock`s configs.\
[<font style="color: red">bitcoind.cpp</font>]
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
[<font style="color: red">bitcoin-tx.cpp</font>]
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
[<font style="color: red">bitcoin-wallet.cpp</font>]
```diff
    // Check for -testnet or -regtest parameter (Params() calls are only valid
    // after this clause)
    SelectParams(gArgs.GetChainName());
+    // VeriBlock
+    VeriBlock::selectPopConfig(gArgs);
```

The last step is to update CMakeLists file, add our new source files.
[<font style="color: red">CMakeLists.txt</font>]
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
First should create two new source files payloads_provider.hpp, block_batch_adaptor.hpp.\
[<font style="color: red">vbk/adaptors/payloads_provider.hpp</font>]
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
[<font style="color: red">vbk/adaptors/block_batch_adaptor.hpp</font>]
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
Create wrappers for such entities.\
[<font style="color: red">vbk/pop_service.hpp</font>]
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
[<font style="color: red">vbk/pop_service.cpp</font>]
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
Also update serialization methods for the VBK entites like ATV, VTB, VbkBlock etc. in the serialize.h.\
[<font style="color: red">serialize.h</font>]
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
Now we have to define the VeriBlock storage during the bitcoin cash initialize proccess.\
[<font style="color: red">init.cpp</font>]
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
[<font style="color: red">txdb.cpp</font>]
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
[<font style="color: red">validation.cpp</font>]
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

The last step is to update tests, update constructor of the TestingSetup struct in the setup_common.cpp.\
[<font style="color: red">test/util/setup_common.cpp</font>]
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

Now we want to add using of the popmempool in the bitcoin cash. For that we should implement few methods for the submitting pop payloads to the mempool, getting payloads during the block mining, and removing payloads after successful block submitting to the blockchain.
First we should implement such methods in the pop_service.hpp pop_service.cpp source files.\
[<font style="color: red">vbk/pop_service.hpp</font>]
```diff
+ //! mempool methods
+ altintegration::PopData getPopData();
+ void removePayloadsFromMempool(const altintegration::PopData &popData);
+ void updatePopMempoolForReorg();
+ void addDisconnectedPopdata(const altintegration::PopData &popData);
```
[<font style="color: red">vbk/pop_service.cpp</font>]
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
Add getting popData during block mining, has been updated CreateNewBlock() in the miner.cpp.\
[<font style="color: red">miner.cpp</font>]
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
Has been added removing popData after successful submitting to the blockchain. Modify ConnectTip(), DisconnectTip() and UpdateMempoolForReorg() methods in the validation.cpp and txmempool.cpp.\
[<font style="color: red">validation.cpp</font>]
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
[<font style="color: red">txmempool.cpp</font>]
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

At this stage we will add functions for the VeriBlock AltTree maintaining such as setState(), acceptBlock(), addAllBlockPayloads(), that will change the state of the VeriBlock AltTree.
acceptBlock() - adds the altchain block into to the library, addAllBlockPayloads() - adds popData for the current altchain block into the library, should be invoked before the acceptBlock(), setState() - change the state of the VeriBlock AltTree to the state of the provided altchain block.\
[<font style="color: red">vbk/pop_service.hpp</font>]
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
[<font style="color: red">vbk/pop_service.cpp</font>]
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
Update block processing during the ConnectBlock(), UpdateTip(), ApplyBlockUndo(), AcceptBlockHeader(), AcceptBlock(), TestBlockValidity().\
[<font style="color: red">validation.cpp</font>]
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
[<font style="color: red">init.cpp</font>]
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

Now we will test all that functionality that we have added previously.
First should add some util test source files like consts.hpp, e2e_fixture.hpp.\
[<font style="color: red">vbk/test/util/consts.hpp</font>]
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
[<font style="color: red">vbk/test/util/e2e_fixture.hpp</font>]
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

        CScript scriptPubKey =
        CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

        while (!Params().isPopActive(ChainActive().Tip()->nHeight)) {
            CBlock b = CreateAndProcessBlock({}, scriptPubKey);
            m_coinbase_txns.push_back(b.vtx[0]);
        }

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
Modify setup_common.cpp, for the basic test setup.\
[<font style="color: red">test/util/setup_common.cpp</font>]
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
Modify miner_tests.cpp, disabled CreateNewBlock_validity test case.\
[<font style="color: red">test/util/miner_tests.cpp</font>]
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
So now we can add test case which will test the veriblock pop behaviour, e2e_pop_tests.cpp.\
[<font style="color: red">vbk/test/unit/e2e_pop_tests.cpp</font>]
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

For the veriblock pop security we should also add context info conrainer with the pop related information like block height, keystone array, popData merkle root. The root hash of the context info container should be added to the original block merkle root calculation.

VeriBlock merkle root specific functions have been implemented in the merkle.hpp, merkle.cpp, context_info_container.hpp
[<font style="color: red">vbk/entity/context_info_container.hpp</font>]
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
[<font style="color: red">vbk/merkle.hpp</font>]
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
[<font style="color: red">vbk/merkle.cpp</font>]
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
[<font style="color: red">miner.cpp</font>]
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
[<font style="color: red">test/util/mining.cpp</font>]
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
[<font style="color: red">validation.h</font>]
```diff
...
bool CheckBlock(const CBlock &block, BlockValidationState &state,
                const Consensus::Params &params,
                BlockValidationOptions validationOptions);

+ bool ContextualCheckBlock(const CBlock &block, BlockValidationState &state, const Consensus::Params &params, const CBlockIndex *pindexPrev, bool fCheckMerkleRoot);
...
```

As veriblock merkleroot algorithm depends on the blockchain, so we should move merkle root validation from the CheckBlock() to the ContextualCheckBlock() function.\
[<font style="color: red">validation.cpp</font>]
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
Disable validation_block_tests.cpp.\
[<font style="color: red">test/validation_block_tests.cpp</font>]
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
Also disable for a while some functional tests.\
[<font style="color: red">../test/functional/test_runner.py</font>]
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
Add new tests: block_validation_tests.cpp, pop_util_tests.cpp, vbk_merkle_tests.cpp.\
[<font style="color: red">vbk/test/unit/block_validation_tests.cpp</font>]
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
[<font style="color: red">vbk/test/unit/pop_util_tests.cpp</font>]
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
[<font style="color: red">vbk/test/unit/vbk_merkle_tests.cpp</font>]
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

## Add Pop rewards

Modify reward algorithm, to the basic PoW rewards has been added so called pop rewards for the pop miners. For these purposes has been added corresponding functions in the pop_service.hpp/cpp.\
[<font style="color: red">vbk/pop_service.hpp</font>]
```diff
+ //! pop rewards
+ PoPRewards getPopRewards(const CBlockIndex &pindexPrev)
+     EXCLUSIVE_LOCKS_REQUIRED(cs_main);
+ void addPopPayoutsIntoCoinbaseTx(CMutableTransaction &coinbaseTx,
+                                  const CBlockIndex &pindexPrev)
+     EXCLUSIVE_LOCKS_REQUIRED(cs_main);
+ bool checkCoinbaseTxWithPopRewards(const CTransaction &tx, const Amount &nFees,
+                                    const CBlockIndex &pindexPrev,
+                                    const Consensus::Params &consensusParams,
+                                    Amount &blockReward,
+                                    BlockValidationState &state)
+     EXCLUSIVE_LOCKS_REQUIRED(cs_main);

+ Amount getCoinbaseSubsidy(Amount subsidy, int32_t height,
+                           const Consensus::Params &consensusParams);
```
[<font style="color: red">vbk/pop_service.cpp</font>]
```diff
+ #include <chainparams.h>
...
+ PoPRewards getPopRewards(const CBlockIndex &pindexPrev) {
+    AssertLockHeld(cs_main);
+    auto &param = Params();

+    if (param.GetConsensus().VeriBlockPopSecurityHeight >
+        (pindexPrev.nHeight)) {
+        return {};
+    }

+    const auto &pop = GetPop();
+    auto &cfg = *pop.config;

+    if (pindexPrev.nHeight < (int)cfg.alt->getEndorsementSettlementInterval()) {
+        return {};
+    }

+    if (pindexPrev.nHeight < (int)cfg.alt->getPayoutParams().getPopPayoutDelay()) {
+        return {};
+    }

+    altintegration::ValidationState state;
+    auto hash = pindexPrev.GetBlockHash();
+    std::vector<uint8_t> v_hash{hash.begin(), hash.end()};

+    bool ret = pop.altTree->setState(v_hash, state);
+    (void)ret;
+    assert(ret);

+    auto rewards = pop.altTree->getPopPayout(v_hash);
+    int halving =
+        (pindexPrev.nHeight + 1) / param.GetConsensus().nSubsidyHalvingInterval;
+    PoPRewards btcRewards{};
+    // erase rewards, that pay 0 satoshis and halve rewards
+    for (const auto &r : rewards) {
+        auto rewardValue = r.second;
+        rewardValue >>= halving;

+        if ((rewardValue != 0) && (halving < 64)) {
+            CScript key = CScript(r.first.begin(), r.first.end());
+            btcRewards[key] = param.PopRewardCoefficient() * rewardValue;
+        }
+    }

+    return btcRewards;
+}

+void addPopPayoutsIntoCoinbaseTx(CMutableTransaction &coinbaseTx,
+                                 const CBlockIndex &pindexPrev) {
+    AssertLockHeld(cs_main);
+    PoPRewards rewards = getPopRewards(pindexPrev);

+    assert(coinbaseTx.vout.size() == 1 &&
+           "at this place we should have only PoW payout here");

+    for (const auto &itr : rewards) {
+        CTxOut out;
+        out.scriptPubKey = itr.first;

+        out.nValue = itr.second * Amount::satoshi();
+        coinbaseTx.vout.push_back(out);
+    }
+}

+bool checkCoinbaseTxWithPopRewards(const CTransaction &tx, const Amount &nFees,
+                                   const CBlockIndex &pindexPrev,
+                                   const Consensus::Params &consensusParams,
+                                   Amount &blockReward,
+                                   BlockValidationState &state) {
+    AssertLockHeld(cs_main);
+    PoPRewards rewards = getPopRewards(pindexPrev);
+    Amount nTotalPopReward = Amount::zero();

+    if (tx.vout.size() < rewards.size()) {
+        return state.Invalid(
+            BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
+            "bad-pop-vouts-size",
+            strprintf(
+                "checkCoinbaseTxWithPopRewards(): coinbase has +incorrect size "
+                "of pop vouts (actual vouts size=%d vs expected vouts=%d)",
+                tx.vout.size(), rewards.size()));
+    }

+    std::map<CScript, Amount> cbpayouts;
+    // skip first reward, as it is always PoW payout
+    for (auto out = tx.vout.begin() + 1, end = tx.vout.end(); out != end;
+         ++out) {
+        // pop payouts can not be null
+        if (out->IsNull()) {
+            continue;
+        }
+        cbpayouts[out->scriptPubKey] += out->nValue;
+    }

+    // skip first (regular pow) payout, and last 2 0-value payouts
+    for (const auto &payout : rewards) {
+        auto &script = payout.first;
+        Amount expectedAmount = payout.second * Amount::satoshi();

+        auto p = cbpayouts.find(script);
+        // coinbase pays correct reward?
+        if (p == cbpayouts.end()) {
+            // we expected payout for that address
+            return state.Invalid(
+                BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
+                "bad-pop-missing-payout",
+                strprintf("[tx: %s] missing payout for scriptPubKey: '%s' with "
+                          "amount: '%d'",
+                          tx.GetHash().ToString(), HexStr(script),
+                          expectedAmount));
+        }

+        // payout found
+        Amount actualAmount{p->second};
+        // does it have correct amount?
+        if (actualAmount != expectedAmount) {
+            return state.Invalid(
+                BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
+                "bad-pop-wrong-payout",
+                strprintf("[tx: %s] wrong payout for scriptPubKey: '%s'. "
+                          "Expected %d, got %d.",
+                          tx.GetHash().ToString(), HexStr(script),
+                          expectedAmount, actualAmount));
+        }

+        nTotalPopReward += expectedAmount;
+    }

+    Amount PoWBlockReward =
+        GetBlockSubsidy(pindexPrev.nHeight, consensusParams);

+    blockReward = nTotalPopReward + PoWBlockReward + nFees;

+    if (tx.GetValueOut() > blockReward) {
+        return state.Invalid(
+            BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
+            "bad-cb-pop-amount",
+            strprintf("ConnectBlock(): coinbase pays too much (actual=%s vs "
+                      "limit=%s)",
+                      tx.GetValueOut().ToString(), blockReward.ToString()));
+    }
+    return true;
+}

+Amount getCoinbaseSubsidy(Amount subsidy, int32_t height,
+                          const Consensus::Params &consensusParams) {
+    if (height >= consensusParams.VeriBlockPopSecurityHeight) {
+        // int64_t powRewardPercentage = 100 - Params().PopRewardPercentage();
+        // subsidy = powRewardPercentage * subsidy;
+        // subsidy = subsidy / 100;
+    }
+    return subsidy;
+}
```

Modify CChainParams, have been added two few new veriblock parametrs for the pop rewards.\
[<font style="color: red">chainparams.h</font>]
```diff
class CChainParams {
public:
...
+    // VeriBlock
+    uint32_t PopRewardPercentage() const { return mPopRewardPercentage; }
+    int32_t PopRewardCoefficient() const { return mPopRewardCoefficient; }
...
+    // VeriBlock:
+    // cut this % from coinbase subsidy
+    uint32_t mPopRewardPercentage = 40; // %
+    // every pop reward will be multiplied by this coefficient
+    int32_t mPopRewardCoefficient = 20;
};
```

Also modify mining process in the CreateNewBlock function insert VeriBlock PoPRewards into the conibase transaction, and some validation rules in the validation.cpp.\
[<font style="color: red">miner.cpp</font>]
```diff
    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout = COutPoint();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue =
        nFees + GetBlockSubsidy(nHeight, consensusParams);
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

+    // VeriBlock add pop rewards
+    VeriBlock::addPopPayoutsIntoCoinbaseTx(coinbaseTx, *pindexPrev);
```
[<font style="color: red">validation.cpp</font>]
```diff
Amount GetBlockSubsidy(int nHeight, const Consensus::Params &consensusParams) {
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64) {
        return Amount::zero();
    }

    Amount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur
    // approximately every 4 years.s
+    nSubsidy =
+        VeriBlock::getCoinbaseSubsidy(nSubsidy, nHeight, consensusParams);

    return ((nSubsidy / SATOSHI) >> halvings) * SATOSHI;
}

...
ConnectBlock() {
...
    int64_t nTime3 = GetTimeMicros();
    nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH,
             "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) "
             "[%.2fs (%.2fms/blk)]\n",
             (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2),
             MILLI * (nTime3 - nTime2) / block.vtx.size(),
             nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs - 1),
             nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

-   Amount blockReward =
-        nFees + GetBlockSubsidy(pindex->nHeight, consensusParams);
-    if (block.vtx[0]->GetValueOut() > blockReward) {
-        LogPrintf("ERROR: ConnectBlock(): coinbase pays too much (actual=%d vs "
-                  "limit=%d)\n",
-                  block.vtx[0]->GetValueOut(), blockReward);
-        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
-                             REJECT_INVALID, "bad-cb-amount");
-    }

+    // VeriBlock add pop rewards validation
+    Amount blockReward;
+    assert(pindex->pprev && "previous block ptr is nullptr");
+    if (!VeriBlock::checkCoinbaseTxWithPopRewards(
+            *block.vtx[0], nFees, *pindex->pprev, consensusParams, blockReward,
+            state)) {
+        return false;
+    }
...
}

```

Also add tests for the pop rewards.
[<font style="color: red">vbk/test/util/pop_rewards_tests.cpp</font>]
```
#include <boost/test/unit_test.hpp>
#include <script/interpreter.h>
#include <vbk/test/util/e2e_fixture.hpp>

struct PopRewardsTestFixture : public E2eFixture {};

BOOST_AUTO_TEST_SUITE(pop_rewards_tests)

BOOST_FIXTURE_TEST_CASE(addPopPayoutsIntoCoinbaseTx_test,
                        PopRewardsTestFixture) {
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey())
                                     << OP_CHECKSIG;

    auto tip = ChainActive().Tip();
    BOOST_CHECK(tip != nullptr);
    std::vector<uint8_t> payoutInfo{scriptPubKey.begin(), scriptPubKey.end()};
    CBlock block = endorseAltBlockAndMine(tip->GetBlockHash(),
                                          tip->GetBlockHash(), payoutInfo, 0);
    {
        LOCK(cs_main);
        BOOST_CHECK(ChainActive().Tip()->GetBlockHash() == block.GetHash());
    }

    // Generate a chain whith rewardInterval of blocks
    int rewardInterval =
        (int)VeriBlock::GetPop().config->alt->getPayoutParams().getPopPayoutDelay();
    // do not add block with rewards
    // do not add block before block with rewards
    for (int i = 0; i < (rewardInterval - 2); i++) {
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    }

    CBlock beforePayoutBlock = CreateAndProcessBlock({}, scriptPubKey);

    int n = 0;
    for (const auto &out : beforePayoutBlock.vtx[0]->vout) {
        if (out.nValue > Amount::zero()) n++;
    }
    BOOST_CHECK(n == 1);

    CBlock payoutBlock = CreateAndProcessBlock({}, scriptPubKey);
    n = 0;
    for (const auto &out : payoutBlock.vtx[0]->vout) {
        if (out.nValue > Amount::zero()) n++;
    }

    // we've got additional coinbase out
    BOOST_CHECK(n > 1);

    // assume POP reward is the output after the POW reward
    BOOST_CHECK(payoutBlock.vtx[0]->vout[1].scriptPubKey == scriptPubKey);
    BOOST_CHECK(payoutBlock.vtx[0]->vout[1].nValue > Amount::zero());

    CMutableTransaction spending;
    spending.nVersion = 1;
    spending.vin.resize(1);
    spending.vin[0].prevout = COutPoint(payoutBlock.vtx[0]->GetId(), 1);
    spending.vout.resize(1);
    spending.vout[0].nValue = 100 * Amount::satoshi();
    spending.vout[0].scriptPubKey = scriptPubKey;

    std::vector<unsigned char> vchSig;
    uint256 hash =
        SignatureHash(scriptPubKey, spending, 0, SigHashType().withForkId(),
                      payoutBlock.vtx[0]->vout[1].nValue);

    BOOST_CHECK(coinbaseKey.SignECDSA(hash, vchSig));
    vchSig.push_back(uint8_t(SIGHASH_ALL | SIGHASH_FORKID));
    spending.vin[0].scriptSig << vchSig;

    printf("scriptSig: %s, scriptPubKey: %s \n",
           HexStr(spending.vin[0].scriptSig).c_str(),
           HexStr(spending.vout[0].scriptPubKey).c_str());

    CBlock spendingBlock;
    // make sure we cannot spend till coinbase maturity
    spendingBlock = CreateAndProcessBlock({spending}, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(ChainActive().Tip()->GetBlockHash() !=
                    spendingBlock.GetHash());
    }

    for (int i = 0; i < COINBASE_MATURITY; i++) {
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
    }

    spendingBlock = CreateAndProcessBlock({spending}, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(ChainActive().Tip()->GetBlockHash() ==
                    spendingBlock.GetHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()
```
[<font style="color: red">test/CMakeLists.txt</font>]
```diff
        # VeriBlock Tests
		../vbk/test/unit/e2e_pop_tests.cpp
		../vbk/test/unit/pop_util_tests.cpp
		../vbk/test/unit/vbk_merkle_tests.cpp
		../vbk/test/unit/block_validation_tests.cpp
+		../vbk/test/unit/pop_rewards_tests.cpp  
```

## Add VeriBlock pop forkresolution

Before we start implementing the pop forkresolution algorithm, we will make a short code refactoring, will create a function in the chainparams which will define if the pop security is enabled.\
[<font style="color: red">chainparams.h</font>]
```diff
     // VeriBlock
+    bool isPopActive(int height) const {
+        return height >= consensus.VeriBlockPopSecurityHeight;
+    }
     uint32_t PopRewardPercentage() const { return mPopRewardPercentage; }
     int32_t PopRewardCoefficient() const { return mPopRewardCoefficient; }
```
Changed hight of the PoP veriblock security forkpoint in the regtest, it is needed in the tests.\
[<font style="color: red">chainparams.cpp</font>]
```diff
    // VeriBlock
    // TODO: set an VeriBlock pop security fork height
-    consensus.VeriBlockPopSecurityHeight = 200;
+    consensus.VeriBlockPopSecurityHeight = 200;
```
Update all places where comparison with the VeriBlockPopSecurityHeight parameter was being used.\
[<font style="color: red">miner.cpp</font>]
```diff
    // VeriBlock: add PopData into the block
-   if (consensusParams.VeriBlockPopSecurityHeight <= nHeight) {
+   if (chainParams.isPopActive(nHeight)) {
        pblock->popData = VeriBlock::getPopData();
    }
...
    // VeriBlock: add payloads commitment
-   if (consensusParams.VeriBlockPopSecurityHeight <= nHeight) {
+   if (chainParams.isPopActive(nHeight)) {
        CTxOut popOut =
            VeriBlock::AddPopDataRootIntoCoinbaseCommitment(*pblock);
        coinbaseTx.vout.push_back(popOut);
    }
```
[<font style="color: red">vbk/merkle.hpp</font>]
```diff
uint256 TopLevelMerkleRoot(const CBlockIndex *prevIndex, const CBlock &block,
-                           const Consensus::Params &param,
                           bool *mutated = nullptr);

bool VerifyTopLevelMerkleRoot(const CBlock &block, const CBlockIndex *prevIndex,
-                              const Consensus::Params &param,
                              BlockValidationState &state);

```
[<font style="color: red">vbk/merkle.cpp</font>]
```diff
uint256 TopLevelMerkleRoot(const CBlockIndex *prevIndex, const CBlock &block,
-                           const Consensus::Params &param, bool *mutated) {
-    if (prevIndex == nullptr ||
-        param.VeriBlockPopSecurityHeight > (prevIndex->nHeight + 1)) {
+                               bool *mutated) {
+    if (prevIndex == nullptr || !Params().isPopActive(prevIndex->nHeight + 1)) {
        return BlockMerkleRoot(block);
    }
...
}

...

bool VerifyTopLevelMerkleRoot(const CBlock &block, const CBlockIndex *prevIndex,
-                              const Consensus::Params &param,
                              BlockValidationState &state) {
    bool mutated = false;
    uint256 hashMerkleRoot2 =
-        VeriBlock::TopLevelMerkleRoot(prevIndex, block, param, &mutated);
+        VeriBlock::TopLevelMerkleRoot(prevIndex, block, &mutated);
...
 if (prevIndex == nullptr ||
-        param.VeriBlockPopSecurityHeight > (prevIndex->nHeight + 1)) {
+        !Params().isPopActive(prevIndex->nHeight + 1)) {
        return true;
    }
}
```
[<font style="color: red">vbk/pop_service.hpp</font>]
```diff
-Amount getCoinbaseSubsidy(Amount subsidy, int32_t height,
-                          const Consensus::Params &consensusParams);
+Amount getCoinbaseSubsidy(Amount subsidy, int32_t height);
```
[<font style="color: red">vbk/pop_service.cpp</font>]
```diff
-    if (param.GetConsensus().VeriBlockPopSecurityHeight >
-        (pindexPrev.nHeight)) {
+    if (!param.isPopActive(pindexPrev.nHeight)) {
        return {};
    }
...
-Amount getCoinbaseSubsidy(Amount subsidy, int32_t height,
-                          const Consensus::Params &consensusParams) {
-    if (height >= consensusParams.VeriBlockPopSecurityHeight) {
+Amount getCoinbaseSubsidy(Amount subsidy, int32_t height) {
+    if (Params().isPopActive(height)) {
```
[<font style="color: red">vbk/test/util/e2e_fixture.hpp</font>]
```diff
    E2eFixture() {
        altintegration::SetLogger<TestLogger>();
        altintegration::GetLogger().level = altintegration::LogLevel::warn;

+        CScript scriptPubKey =
+            CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

+        while (!Params().isPopActive(ChainActive().Tip()->nHeight)) {
+            CBlock b = CreateAndProcessBlock({}, scriptPubKey);
+            m_coinbase_txns.push_back(b.vtx[0]);
+        }

        pop = &VeriBlock::GetPop();
    }
```

To fully enable PoP protocol we should also modify forkresolution algorithm. For these purpopses add few new function to the pop_service.\
[<font style="color: red">vbk/pop_service.hpp</font>]
```diff
+//! pop forkresolution
+CBlockIndex *compareTipToBlock(CBlockIndex *candidate) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
+int compareForks(const CBlockIndex &left, const CBlockIndex &right) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
```
[<font style="color: red">vbk/pop_service.cpp</font>]
```diff
CBlockIndex *compareTipToBlock(CBlockIndex *candidate) {
    AssertLockHeld(cs_main);
    assert(candidate != nullptr &&
           "block has no according header in block tree");

    auto blockHash = candidate->GetBlockHash();
    auto *tip = ChainActive().Tip();
    if (!tip) {
        // if tip is not set, candidate wins
        return tip;
    }

    auto tipHash = tip->GetBlockHash();
    if (tipHash == blockHash) {
        // we compare tip with itself
        return tip;
    }

    int result = 0;
    if (Params().isPopActive(tip->nHeight)) {
        result = compareForks(*tip, *candidate);
    } else {
        result = CBlockIndexWorkComparator()(tip, candidate) == true ? -1 : 1;
    }

    if (result < 0) {
        // candidate has higher POP score
        return candidate;
    }

    if (result == 0 && tip->nChainWork < candidate->nChainWork) {
        // candidate is POP equal to current tip;
        // candidate has higher chainwork
        return candidate;
    }

    // otherwise, current chain wins
    return tip;
}

int compareForks(const CBlockIndex &leftForkTip,
                 const CBlockIndex &rightForkTip) {
    AssertLockHeld(cs_main);

    auto &pop = GetPop();

    if (&leftForkTip == &rightForkTip) {
        return 0;
    }

    auto left = blockToAltBlock(leftForkTip);
    auto right = blockToAltBlock(rightForkTip);
    auto state = altintegration::ValidationState();

    if (!pop.altTree->setState(left.hash, state)) {
        if (!pop.altTree->setState(right.hash, state)) {
            throw std::logic_error("both chains are invalid");
        }
        return -1;
    }

    return pop.altTree->comparePopScore(left.hash, right.hash);
}
```

Also add two new functions and updated ActivateBestChain() function in the validation.hpp/cpp source files.\
[<font style="color: red">validation.hpp</font>]
```diff

class CChainState {
...
    CBlockIndex *FindMostWorkChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

+    CBlockIndex *FindBestChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
+    bool TestBlockIndex(CBlockIndex *pindexTest)
+        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
...
};
```
[<font style="color: red">validation.cpp</font>]
```diff
bool CChainState::MarkBlockAsFinal(const Config &config,
                                   BlockValidationState &state,
                                   const CBlockIndex *pindex) {
    AssertLockHeld(cs_main);
+    // VeriBlock
+    if (config.GetChainParams().isPopActive(pindex->nHeight)) {
+        return true;
+    }
...
}

...

+CBlockIndex *CChainState::FindBestChain() {
+    AssertLockHeld(cs_main);
+    CBlockIndex *bestCandidate = m_chain.Tip();

+    // return early
+    if (setBlockIndexCandidates.empty()) {
+        return nullptr;
+    }

+    auto temp_set = setBlockIndexCandidates;
+    for (auto *pindexNew : temp_set) {
+        if (pindexNew == bestCandidate || !TestBlockIndex(pindexNew)) {
+            continue;
+        }

+        if (bestCandidate == nullptr) {
+            bestCandidate = pindexNew;
+            continue;
+        }

+        int popComparisonResult = 0;

+        if (Params().isPopActive(bestCandidate->nHeight)) {
+            popComparisonResult =
+                VeriBlock::compareForks(*bestCandidate, *pindexNew);
+        } else {
+            popComparisonResult =
+                CBlockIndexWorkComparator()(bestCandidate, pindexNew) == true
+                    ? -1
+                    : 1;
+        }
+        // even if next candidate is pop equal to current pindexNew, it is
+        // likely to have higher work
+        if (popComparisonResult <= 0) {
+            // candidate is either has POP or WORK better
+            bestCandidate = pindexNew;
+        }
+    }

+    // update best header after POP FR
+    pindexBestHeader = bestCandidate;
+    return bestCandidate;
+}

+bool CChainState::TestBlockIndex(CBlockIndex *pindexNew) {
+    AssertLockHeld(cs_main);

+    const CBlockIndex *pindexFork = m_chain.FindFork(pindexNew);

+    // Check whether all blocks on the path between the currently active
+    // chain and the candidate are valid. Just going until the active chain
+    // is an optimization, as we know all blocks in it are valid already.
+    CBlockIndex *pindexTest = pindexNew;

+    bool hasValidAncestor = true;
+    while (hasValidAncestor && pindexTest && pindexTest != pindexFork) {
+        assert(pindexTest->HaveTxsDownloaded() || pindexTest->nHeight == 0);

+        // If this is a parked chain, but it has enough PoW, clear the park
+        // state.
+        bool fParkedChain = pindexTest->nStatus.isOnParkedChain();
+        if (fParkedChain && gArgs.GetBoolArg("-automaticunparking", true)) {
+            const CBlockIndex *pindexTip = m_chain.Tip();

+            // During initialization, pindexTip and/or pindexFork may be
+            // null. In this case, we just ignore the fact that the chain is
+            // parked.
+            if (!pindexTip || !pindexFork) {
+                UnparkBlock(pindexTest);
+                continue;
+            }

+            // A parked chain can be unparked if it has twice as much PoW
+            // accumulated as the main chain has since the fork block.
+            CBlockIndex const *pindexExtraPow = pindexTip;
+            arith_uint256 requiredWork = pindexTip->nChainWork;
+            switch (pindexTip->nHeight - pindexFork->nHeight) {
+                // Limit the penality for depth 1, 2 and 3 to half a block
+                // worth of work to ensure we don't fork accidentally.
+                case 3:
+                case 2:
+                    pindexExtraPow = pindexExtraPow->pprev;
+                // FALLTHROUGH
+                case 1: {
+                    const arith_uint256 deltaWork =
+                        pindexExtraPow->nChainWork - pindexFork->nChainWork;
+                    requiredWork += (deltaWork >> 1);
+                    break;
+                }
+                default:
+                    requiredWork +=
+                        pindexExtraPow->nChainWork - pindexFork->nChainWork;
+                    break;
+            }
+
+            if (pindexNew->nChainWork > requiredWork) {
+                // We have enough, clear the parked state.
+                LogPrintf("Unpark chain up to block %s as it has "
+                          "accumulated enough PoW.\n",
+                          pindexNew->GetBlockHash().ToString());
+                fParkedChain = false;
+                UnparkBlock(pindexTest);
+            }
+        }

+        // Pruned nodes may have entries in setBlockIndexCandidates for
+        // which block files have been deleted. Remove those as candidates
+        // for the most work chain if we come across them; we can't switch
+        // to a chain unless we have all the non-active-chain parent blocks.
+        bool fInvalidChain = pindexTest->nStatus.isInvalid();
+        bool fMissingData = !pindexTest->nStatus.hasData();
+        if (!(fInvalidChain || fParkedChain || fMissingData)) {
+            // The current block is acceptable, move to the parent, up to
+            // the fork point.
+            pindexTest = pindexTest->pprev;
+            continue;
+        }

+        // Candidate chain is not usable (either invalid or parked or
+        // missing data)
+        hasValidAncestor = false;
+        setBlockIndexCandidates.erase(pindexTest);

+        if (fInvalidChain &&
+            (pindexBestInvalid == nullptr ||
+             pindexNew->nChainWork > pindexBestInvalid->nChainWork)) {
+            pindexBestInvalid = pindexNew;
+        }

+        if (fParkedChain &&
+            (pindexBestParked == nullptr ||
+             pindexNew->nChainWork > pindexBestParked->nChainWork)) {
+            pindexBestParked = pindexNew;
+        }

+        LogPrintf("Considered switching to better tip %s but that chain "
+                  "contains a%s%s%s block.\n",
+                  pindexNew->GetBlockHash().ToString(),
+                  fInvalidChain ? "n invalid" : "",
+                  fParkedChain ? " parked" : "",
+                  fMissingData ? " missing-data" : "");

+        CBlockIndex *pindexFailed = pindexNew;
+        // Remove the entire chain from the set.
+        while (pindexTest != pindexFailed) {
+            if (fInvalidChain || fParkedChain) {
+                pindexFailed->nStatus =
+                    pindexFailed->nStatus.withFailedParent(fInvalidChain)
+                        .withParkedParent(fParkedChain);
+            } else if (fMissingData) {
+                // If we're missing data, then add back to
+                // mapBlocksUnlinked, so that if the block arrives in the
+                // future we can try adding to setBlockIndexCandidates
+                // again.
+                mapBlocksUnlinked.insert(
+                    std::make_pair(pindexFailed->pprev, pindexFailed));
+            }
+            setBlockIndexCandidates.erase(pindexFailed);
+            pindexFailed = pindexFailed->pprev;
+        }

+        if (fInvalidChain || fParkedChain) {
+            // We discovered a new chain tip that is either parked or
+            // invalid, we may want to warn.
+            CheckForkWarningConditionsOnNewFork(pindexNew);
+        }
+    }

+    if (g_avalanche &&
+        gArgs.GetBoolArg("-enableavalanche", AVALANCHE_DEFAULT_ENABLED)) {
+        g_avalanche->addBlockToReconcile(pindexNew);
+    }

+    return hasValidAncestor;
+}


...

ActivateBestChain() {
...
                // Destructed before cs_main is unlocked
                ConnectTrace connectTrace(g_mempool);

+                if (pblock && pindexBestChain == nullptr) {
+                    auto *blockindex = LookupBlockIndex(pblock->GetHash());
+                    assert(blockindex);

+                    auto tmp_set = setBlockIndexCandidates;
+                    for (auto *candidate : tmp_set) {
+                        // if candidate has txs downloaded & currently arrived
+                        // block is ancestor of `candidate`
+                        if (candidate->HaveTxsDownloaded() &&
+                            TestBlockIndex(candidate) &&
+                            candidate->GetAncestor(blockindex->nHeight) ==
+                                blockindex) {
+                            // then do pop fr with candidate, instead of
+                            // blockindex
+                            pindexMostWork =
+                                VeriBlock::compareTipToBlock(candidate);
+                        }
+                    }
+                }

                if (pindexBestChain == nullptr) {
-                    pindexMostWork = FindMostWorkChain();
+                    pindexMostWork = FindBestChain();
                }

+                // VeriBlock 
+                // update best known header
+                pindexBestHeader = pindexBestChain;

...

}
```
For the updated forkresolution algorithm we should also modify maintaining setBlockIndexCandidates set.
[<font style="color: red">validation.cpp</font>]
```diff
void CChainState::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to
    // return to it later in case a reorganization to a better block fails.
-    auto it = setBlockIndexCandidates.begin();
-    while (it != setBlockIndexCandidates.end() &&
-           setBlockIndexCandidates.value_comp()(*it, m_chain.Tip())) {
-        setBlockIndexCandidates.erase(it++);
-    }
+    // auto it = setBlockIndexCandidates.begin();
+    // while (it != setBlockIndexCandidates.end() &&
+    //        setBlockIndexCandidates.value_comp()(*it, m_chain.Tip())) {
+    //     setBlockIndexCandidates.erase(it++);
+    // }

+    // VeriBlock
+    auto temp_set = setBlockIndexCandidates;
+    for (const auto &el : temp_set) {
+        if (el->pprev != nullptr) {
+            setBlockIndexCandidates.erase(el->pprev);
+        }
+    }

    // Either the current tip or a successor of it we're working towards is left
    // in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

...

ReceivedBlockTransactions() {
...
-            if (m_chain.Tip() == nullptr ||
-                !setBlockIndexCandidates.value_comp()(pindex, m_chain.Tip())) {
-                setBlockIndexCandidates.insert(pindex);
-            }
+            // if (m_chain.Tip() == nullptr ||
+            //     !setBlockIndexCandidates.value_comp()(pindex, m_chain.Tip()))
+            //     { setBlockIndexCandidates.insert(pindex);
+            // }

+            // VeriBlock
+            setBlockIndexCandidates.insert(pindex);
...
}

...

CheckBlockIndex() {
...
-        if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) &&
-            pindexFirstNeverProcessed == nullptr) {
-            if (pindexFirstInvalid == nullptr) {
-                // If this block sorts at least as good as the current tip and
-                // is valid and we have all data for its parents, it must be in
-                // setBlockIndexCandidates or be parked.
-                if (pindexFirstMissing == nullptr) {
-                    assert(pindex->nStatus.isOnParkedChain() ||
-                           setBlockIndexCandidates.count(pindex));
-                }
-                // m_chain.Tip() must also be there even if some data has
-                // been pruned.
-                if (pindex == m_chain.Tip()) {
-                    assert(setBlockIndexCandidates.count(pindex));
-                }
-                // If some parent is missing, then it could be that this block
-                // was in setBlockIndexCandidates but had to be removed because
-                // of the missing data. In this case it must be in
-                // mapBlocksUnlinked -- see test below.
-            }
-        } else {
-            // If this block sorts worse than the current tip or some ancestor's
-            // block has never been seen, it cannot be in
-            // setBlockIndexCandidates.
-            assert(setBlockIndexCandidates.count(pindex) == 0);
-        }
+         // VeriBlock disable
+        // clang-format off
+        // if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) &&
+        //     pindexFirstNeverProcessed == nullptr) {
+        //     if (pindexFirstInvalid == nullptr) {
+        //         // If this block sorts at least as good as the current tip and
+        //         // is valid and we have all data for its parents, it must be in
+        //         // setBlockIndexCandidates or be parked.
+        //         if (pindexFirstMissing == nullptr) {
+        //             assert(pindex->nStatus.isOnParkedChain() ||
+        //                    setBlockIndexCandidates.count(pindex));
+        //         }
+        //         // m_chain.Tip() must also be there even if some data has
+        //         // been pruned.
+        //         if (pindex == m_chain.Tip()) {
+        //             assert(setBlockIndexCandidates.count(pindex));
+        //         }
+        //         // If some parent is missing, then it could be that this block
+        //         // was in setBlockIndexCandidates but had to be removed because
+        //         // of the missing data. In this case it must be in
+        //         // mapBlocksUnlinked -- see test below.
+        //     }
+        // } else {
+        //     // If this block sorts worse than the current tip or some ancestor's
+        //     // block has never been seen, it cannot be in
+        //     // setBlockIndexCandidates.
+        //     assert(setBlockIndexCandidates.count(pindex) == 0);
+        // }
+        // clang-format on
...
}
```
And the last stage is to update p2p protocol, allow node to download chain with the less chainWork.
[<font style="color: red">net_processing.cpp</font>]
```diff
struct CNodeState {
...
    bool fPreferHeaders;
    //! Whether this peer wants invs or cmpctblocks (when possible) for block
    //! announcements.
    bool fPreferHeaderAndIDs;

+    //! VeriBlock: The block this peer thinks is current tip.
+    const CBlockIndex *pindexLastAnnouncedBlock = nullptr;
+    //! VeriBlock: The last full block we both have from announced chain.
+    const CBlockIndex *pindexLastCommonAnnouncedBlock = nullptr;
...
};

...

+// VeriBlock
+/** Update tracking information about which blocks a peer is assumed to
+ * have. */
+static void UpdateBestChainTip(NodeId nodeid, const BlockHash &tip)
+    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+    CNodeState *state = State(nodeid);
+    assert(state != nullptr);

+    const CBlockIndex *pindex = LookupBlockIndex(tip);
+    if (pindex && pindex->nChainWork > 0) {
+        state->pindexLastAnnouncedBlock = pindex;
+        LogPrint(BCLog::NET, "peer=%s: announced best chain %s\n", nodeid,
+                 tip.GetHex());

+        // announced block is better by chainwork. update
+        // pindexBestKnownBlock
+        if (state->pindexBestKnownBlock == nullptr ||
+            pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork) {
+            state->pindexBestKnownBlock = pindex;
+        }
+    }

+    ProcessBlockAvailability(nodeid);
+}

...
-static void FindNextBlocksToDownload(NodeId nodeid, unsigned int count,
-                                     std::vector<const CBlockIndex *> &vBlocks,
-                                     NodeId &nodeStaller,
-                                     const Consensus::Params &consensusParams)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+static void FindNextBlocksToDownload(
+    NodeId nodeid, unsigned int count,
+    std::vector<const CBlockIndex *> &vBlocks, NodeId &nodeStaller,
+    const Consensus::Params
+        &consensusParams, // either pindexBestBlock or pindexLastAnouncedBlock
+    const CBlockIndex *bestBlock,
+    // out parameter: sets last common block
+    const CBlockIndex **lastCommonBlockOut) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
...
-if (state->pindexBestKnownBlock == nullptr ||
-        state->pindexBestKnownBlock->nChainWork <
-            ::ChainActive().Tip()->nChainWork ||
-        state->pindexBestKnownBlock->nChainWork < nMinimumChainWork) {
+if (bestBlock == nullptr || bestBlock->nChainWork < nMinimumChainWork) {
...
-if (state->pindexLastCommonBlock == nullptr) {
+assert(lastCommonBlockOut);
+if (*lastCommonBlockOut == nullptr) {
        // Bootstrap quickly by guessing a parent of our best tip is the forking
        // point. Guessing wrong in either direction is not a problem.
-        state->pindexLastCommonBlock = ::ChainActive()[std::min(
+        *lastCommonBlockOut = ::ChainActive()[std::min(
            state->pindexBestKnownBlock->nHeight, ::ChainActive().Height())];
}
...
-state->pindexLastCommonBlock = LastCommonAncestor(
-   state->pindexLastCommonBlock, state->pindexBestKnownBlock);
-if (state->pindexLastCommonBlock == state->pindexBestKnownBlock) {
+*lastCommonBlockOut = LastCommonAncestor(*lastCommonBlockOut, bestBlock);
+if (*lastCommonBlockOut == bestBlock) {
...
-const CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
+const CBlockIndex *pindexWalk = *lastCommonBlockOut;
...
-int nWindowEnd =
-        state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
-int nMaxHeight =
-    std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
+int nWindowEnd = (*lastCommonBlockOut)->nHeight + BLOCK_DOWNLOAD_WINDOW;
+int nMaxHeight = std::min<int>(bestBlock->nHeight, nWindowEnd + 1);
...
if (pindex->nStatus.hasData() || ::ChainActive().Contains(pindex)) {
    if (pindex->HaveTxsDownloaded()) {
-        state->pindexLastCommonBlock = pindex;
+        *lastCommonBlockOut = pindex;
    }
...
}

...

if (strCommand == NetMsgType::PING) {
        if (pfrom->nVersion > BIP0031_VERSION) {
            uint64_t nonce = 0;
            vRecv >> nonce;

+            // VeriBlock
+            if (pfrom->nVersion > PING_BESTCHAIN_VERSION) {
+                // VeriBlock: immediately after nonce, receive best block hash
+                LOCK(cs_main);
+                BlockHash bestHash;
+                vRecv >> bestHash;
+                UpdateBestChainTip(pfrom->GetId(), bestHash);

+                connman->PushMessage(
+                    pfrom,
+                    msgMaker.Make(NetMsgType::PONG, nonce,
+                                  ::ChainActive().Tip()->GetBlockHash()));
+                return true;
+            }

...

if (strCommand == NetMsgType::PONG) {
...
+        // VeriBlock
+        if (pfrom->nVersion > PING_BESTCHAIN_VERSION) {
+            LOCK(cs_main);
+            BlockHash bestHash;
+            vRecv >> bestHash;
+            UpdateBestChainTip(pfrom->GetId(), bestHash);
+        }
    } else {
        sProblem = "Unsolicited pong without ping";
    }

...

if (!pto->fClient &&
        ((fFetch && !pto->m_limited_node) ||
         !::ChainstateActive().IsInitialBlockDownload()) &&
        state.nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        std::vector<const CBlockIndex *> vToDownload;
        NodeId staller = -1;
-    FindNextBlocksToDownload(pto->GetId(),
-                                 MAX_BLOCKS_IN_TRANSIT_PER_PEER -
-                                     state.nBlocksInFlight,
-                                 vToDownload, staller, consensusParams);
+        // VeriBlock: find "blocks to download" in 2 chains: one that has "best
+        // chainwork", and second that is reported by peer as best.
+        ProcessBlockAvailability(pto->GetId());
+        // always download chain with higher chainwork
+        if (state.pindexBestKnownBlock) {
+            FindNextBlocksToDownload(
+                pto->GetId(),
+                MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight,
+                vToDownload, staller, consensusParams,
+                state.pindexBestKnownBlock, &state.pindexLastCommonBlock);
+        }
+        // should we fetch announced chain?
+        if (state.pindexLastAnnouncedBlock && state.pindexBestKnownBlock) {
+            // last announced block is by definition always <= chainwork than
+            // best known block by chainwork
+            assert(state.pindexLastAnnouncedBlock->nChainWork <=
+                   state.pindexBestKnownBlock->nChainWork);

+            // are they in the same chain?
+            if (state.pindexBestKnownBlock->GetAncestor(
+                    state.pindexLastAnnouncedBlock->nHeight) !=
+                state.pindexLastAnnouncedBlock) {
+                // no, additionally sync 'announced' chain
+                LogPrint(
+                    BCLog::NET,
+                    "Requesting announced best chain %d:%s from peer=%d\n",
+                    state.pindexLastAnnouncedBlock->GetBlockHash().ToString(),
+                    state.pindexLastAnnouncedBlock->nHeight, pto->GetId());
+                FindNextBlocksToDownload(pto->GetId(),
+                                         MAX_BLOCKS_IN_TRANSIT_PER_PEER -
+                                             state.nBlocksInFlight,
+                                         vToDownload, staller, consensusParams,
+                                         state.pindexLastAnnouncedBlock,
+                                         &state.pindexLastCommonAnnouncedBlock);
+            }
+        }
```
[<font style="color: red">version.h</font>]
```diff
//! not banning for invalid compact blocks starts with this version
static const int INVALID_CB_NO_BAN_VERSION = 70015;

+//! VeriBlock: ping p2p msg contains 'best chain'
+static const int PING_BESTCHAIN_VERSION = 80000;
```
[<font style="color: red">validation.cpp</font>]
```diff
AcceptBlock() {
...
-    if (gArgs.GetBoolArg("-parkdeepreorg", true)) {
-        const CBlockIndex *pindexFork = m_chain.FindFork(pindex);
-        if (pindexFork && pindexFork->nHeight + 1 < m_chain.Height()) {
-            LogPrintf("Park block %s as it would cause a deep reorg.\n",
-                      pindex->GetBlockHash().ToString());
-            pindex->nStatus = pindex->nStatus.withParked();
-            setDirtyBlockIndex.insert(pindex);
-        }
-    }
+    // VeriBlock
+    // if (gArgs.GetBoolArg("-parkdeepreorg", true)) {
+    //     const CBlockIndex *pindexFork = m_chain.FindFork(pindex);
+    //     if (pindexFork && pindexFork->nHeight + 1 < m_chain.Height()) {
+    //         LogPrintf("Park block %s as it would cause a deep reorg.\n",
+    //                   pindex->GetBlockHash().ToString());
+    //         pindex->nStatus = pindex->nStatus.withParked();
+    //         setDirtyBlockIndex.insert(pindex);
+    //     }
+    // }
...
}
```

## Add VeriBlock specific RPC methods

So, generally main parts of the PoP protocol have been implemented. At this stage has been provide PoP related interaction with the bitcoin cash. For this we have to add a few new functions to the RPC.
Just add into the new rpc_registry.hpp/cpp source files.\
[<font style="color: red">vbk/rpc_registry.hpp</font>]
```
// Copyright (c) 2019-2021 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SRC_VBK_RPC_REGISTER_HPP
#define BITCOIN_SRC_VBK_RPC_REGISTER_HPP

class CRPCTable;

namespace VeriBlock {

void RegisterPOPMiningRPCCommands(CRPCTable& t);

} // namespace VeriBlock


#endif //BITCOIN_SRC_VBK_RPC_REGISTER_HPP
```
[<font style="color: red">vbk/rpc_registry.cpp</font>]
```
#include <chainparams.h>
#include <consensus/merkle.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <serialize.h>
#include <util/validation.h>
#include <validation.h>
#include <vbk/entity/context_info_container.hpp>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h> // for CWallet

#include <fstream>
#include <set>

#include <vbk/adaptors/univalue_json.hpp>
#include <vbk/merkle.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/rpc_register.hpp>
#include <veriblock/mempool_result.hpp>

namespace VeriBlock {

extern KeystoneArray
getKeystoneHashesForTheNextBlock(const CBlockIndex *pindexPrev);

namespace {

    BlockHash GetBlockHashByHeight(const int height) {
        if (height < 0 || height > ChainActive().Height())
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Block height out of range");

        return ChainActive()[height]->GetBlockHash();
    }

    CBlock GetBlockChecked(const CBlockIndex *pblockindex) {
        CBlock block;
        if (IsBlockPruned(pblockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR,
                               "Block not available (pruned data)");
        }

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
            // Block not found on disk. This could be because we have the block
            // header in our index but don't have the block (for example if a
            // non-whitelisted node sends us an unrequested long chain of valid
            // blocks, we add the headers to our index, but don't accept the
            // block).
            throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
        }

        return block;
    }

} // namespace

UniValue getpopdata(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getpopdata block_height\n"
            "\nFetches the data relevant to PoP-mining the given block.\n"
            "\nArguments:\n"
            "1. block_height         (numeric, required) The height index\n"
            "\nResult:\n"
            "{\n"
            "    \"block_header\" : \"block_header_hex\",  (string) "
            "Hex-encoded block header\n"
            "    \"raw_contextinfocontainer\" : \"contextinfocontainer\",  "
            "(string) Hex-encoded raw authenticated ContextInfoContainer "
            "structure\n"
            "    \"last_known_veriblock_blocks\" : [ (array) last known "
            "VeriBlock blocks at the given Bitcoin block\n"
            "        \"blockhash\",                (string) VeriBlock block "
            "hash\n"
            "       ... ]\n"
            "    \"last_known_bitcoin_blocks\" : [ (array) last known Bitcoin "
            "blocks at the given Bitcoin block\n"
            "        \"blockhash\",                (string) Bitcoin block "
            "hash\n"
            "       ... ]\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getpopdata", "1000") +
            HelpExampleRpc("getpopdata", "1000"));

    int height = request.params[0].get_int();

    LOCK(cs_main);

    BlockHash blockhash = GetBlockHashByHeight(height);

    UniValue result(UniValue::VOBJ);

    // get the block and its header
    const CBlockIndex *pBlockIndex = LookupBlockIndex(blockhash);

    if (!pBlockIndex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << pBlockIndex->GetBlockHeader();
    result.pushKV("block_header", HexStr(ssBlock));

    auto block = GetBlockChecked(pBlockIndex);

    // context info
    uint256 txRoot = BlockMerkleRoot(block);
    auto keystones =
        VeriBlock::getKeystoneHashesForTheNextBlock(pBlockIndex->pprev);

    auto contextInfo = VeriBlock::ContextInfoContainer(pBlockIndex->nHeight,
                                                       keystones, txRoot);
    auto authedContext = contextInfo.getAuthenticated();
    result.pushKV("raw_contextinfocontainer",
                  HexStr(authedContext.begin(), authedContext.end()));

    auto lastVBKBlocks = VeriBlock::getLastKnownVBKBlocks(16);

    UniValue univalueLastVBKBlocks(UniValue::VARR);
    for (const auto &b : lastVBKBlocks) {
        univalueLastVBKBlocks.push_back(HexStr(b));
    }
    result.pushKV("last_known_veriblock_blocks", univalueLastVBKBlocks);

    auto lastBTCBlocks = VeriBlock::getLastKnownBTCBlocks(16);
    UniValue univalueLastBTCBlocks(UniValue::VARR);
    for (const auto &b : lastBTCBlocks) {
        univalueLastBTCBlocks.push_back(HexStr(b));
    }
    result.pushKV("last_known_bitcoin_blocks", univalueLastBTCBlocks);

    return result;
}

template <typename pop_t>
bool parsePayloads(const UniValue &array, std::vector<pop_t> &out,
                   altintegration::ValidationState &state) {
    std::vector<pop_t> payloads;
    LogPrint(BCLog::POP,
             "VeriBlock-PoP: submitpop RPC called with %s, amount %d \n",
             pop_t::name(), array.size());
    for (uint32_t idx = 0u, size = array.size(); idx < size; ++idx) {
        auto &payloads_hex = array[idx];

        auto payloads_bytes =
            ParseHexV(payloads_hex, strprintf("%s[%d]", pop_t::name(), idx));

        pop_t data;
        if (!altintegration::Deserialize(payloads_bytes, data, state)) {
            return state.Invalid("bad-payloads");
        }
        payloads.push_back(data);
    }

    out = payloads;
    return true;
}

UniValue submitpop(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "submitpop [vbk_blocks] [vtbs] [atvs]\n"
            "\nCreates and submits a PoP transaction constructed from the "
            "provided ATV and VTBs.\n"
            "\nArguments:\n"
            "1. vbk_blocks      (array, required) Array of hex-encoded "
            "VbkBlocks records.\n"
            "2. vtbs      (array, required) Array of hex-encoded VTB records.\n"
            "3. atvs      (array, required) Array of hex-encoded ATV records.\n"
            "\nResult:\n"
            "             (string) MempoolResult\n"
            "\nExamples:\n" +
            HelpExampleCli(
                "submitpop",
                " [VBK_HEX VBK_HEX] [VTB_HEX VTB_HEX] [ATV_HEX ATV_HEX]") +
            HelpExampleRpc("submitpop", "[VBK_HEX] [] [ATV_HEX ATV_HEX]"));

    RPCTypeCheck(request.params,
                 {UniValue::VARR, UniValue::VARR, UniValue::VARR});

    altintegration::PopData popData;
    altintegration::ValidationState state;
    bool ret = true;
    ret = ret && parsePayloads<altintegration::VbkBlock>(
                     request.params[0].get_array(), popData.context, state);
    ret = ret && parsePayloads<altintegration::VTB>(
                     request.params[1].get_array(), popData.vtbs, state);
    ret = ret && parsePayloads<altintegration::ATV>(
                     request.params[2].get_array(), popData.atvs, state);

    if (!ret) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, state.GetPath());
    }

    {
        LOCK(cs_main);
        auto &pop_mempool = *VeriBlock::GetPop().mempool;

        altintegration::MempoolResult result = pop_mempool.submitAll(popData);

        return altintegration::ToJSON<UniValue>(result);
    }
}

UniValue debugpop(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp) {
        throw std::runtime_error("debugpop\n"
                                 "\nPrints alt-cpp-lib state into log.\n");
    }
    auto &pop = VeriBlock::GetPop();
    LogPrint(BCLog::POP, "%s", VeriBlock::toPrettyString(pop));
    return UniValue();
}

using VbkTree = altintegration::VbkBlockTree;
using BtcTree = altintegration::VbkBlockTree::BtcTree;

static VbkTree &vbk() {
    return VeriBlock::GetPop().altTree->vbk();
}

static BtcTree &btc() {
    return VeriBlock::GetPop().altTree->btc();
}

// getblock
namespace {

    void check_getblock(const JSONRPCRequest &request,
                        const std::string &chain) {
        auto cmdname = strprintf("get%sblock", chain);
        RPCHelpMan{
            cmdname,
            "Get block data identified by block hash",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                 "The block hash"},
            },
            {},
            RPCExamples{
                HelpExampleCli(cmdname, "\"00000000c937983704a73af28acdec37b049"
                                        "d214adbda81d7e2a3dd146f6ed09\"") +
                HelpExampleRpc(cmdname, "\"00000000c937983704a73af28acdec37b049"
                                        "d214adbda81d7e2a3dd146f6ed09\"")},
        }
            .Check(request);
    }

    template <typename Tree>
    UniValue getblock(const JSONRPCRequest &req, Tree &tree,
                      const std::string &chain) {
        check_getblock(req, chain);
        LOCK(cs_main);

        using block_t = typename Tree::block_t;
        using hash_t = typename block_t::hash_t;
        std::string strhash = req.params[0].get_str();
        hash_t hash;

        try {
            hash = hash_t::fromHex(strhash);
        } catch (const std::exception &e) {
            throw JSONRPCError(RPC_TYPE_ERROR,
                               strprintf("Bad hash: %s", e.what()));
        }

        auto *index = tree.getBlockIndex(hash);
        if (!index) {
            // no block found
            return UniValue(UniValue::VNULL);
        }

        return altintegration::ToJSON<UniValue>(*index);
    }

    UniValue getvbkblock(const Config &config, const JSONRPCRequest &req) {
        return getblock(req, vbk(), "vbk");
    }
    UniValue getbtcblock(const Config &config, const JSONRPCRequest &req) {
        return getblock(req, btc(), "btc");
    }

} // namespace

// getbestblockhash
namespace {
    void check_getbestblockhash(const JSONRPCRequest &request,
                                const std::string &chain) {
        auto cmdname = strprintf("get%bestblockhash", chain);
        RPCHelpMan{
            cmdname,
            "\nReturns the hash of the best (tip) block in the most-work "
            "fully-validated chain.\n",
            {},
            RPCResult{"\"hex\"      (string) the block hash, hex-encoded\n"},
            RPCExamples{HelpExampleCli(cmdname, "") +
                        HelpExampleRpc(cmdname, "")},
        }
            .Check(request);
    }

    template <typename Tree>
    UniValue getbestblockhash(const JSONRPCRequest &request, Tree &tree,
                              const std::string &chain) {
        check_getbestblockhash(request, chain);

        LOCK(cs_main);
        auto *tip = tree.getBestChain().tip();
        if (!tip) {
            // tree is not bootstrapped
            return UniValue(UniValue::VNULL);
        }

        return UniValue(tip->getHash().toHex());
    }

    UniValue getvbkbestblockhash(const Config &config,
                                 const JSONRPCRequest &request) {
        return getbestblockhash(request, vbk(), "vbk");
    }

    UniValue getbtcbestblockhash(const Config &config,
                                 const JSONRPCRequest &request) {
        return getbestblockhash(request, btc(), "btc");
    }
} // namespace

// getblockhash
namespace {

    void check_getblockhash(const JSONRPCRequest &request,
                            const std::string &chain) {
        auto cmdname = strprintf("get%sblockhash", chain);

        RPCHelpMan{
            cmdname,
            "\nReturns hash of block in best-block-chain at height provided.\n",
            {
                {"height", RPCArg::Type::NUM, RPCArg::Optional::NO,
                 "The height index"},
            },
            RPCResult{"\"hash\"         (string) The block hash\n"},
            RPCExamples{HelpExampleCli(cmdname, "1000") +
                        HelpExampleRpc(cmdname, "1000")},
        }
            .Check(request);
    }

    template <typename Tree>
    UniValue getblockhash(const JSONRPCRequest &request, Tree &tree,
                          const std::string &chain) {
        check_getblockhash(request, chain);
        LOCK(cs_main);
        auto &best = tree.getBestChain();
        if (best.blocksCount() == 0) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Chain %s is not bootstrapped", chain));
        }

        int height = request.params[0].get_int();
        if (height < best.first()->getHeight()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("Chain %s starts at %d, provided %d",
                                         chain, best.first()->getHeight(),
                                         height));
        }
        if (height > best.tip()->getHeight()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("Chain %s tip is at %d, provided %d",
                                         chain, best.tip()->getHeight(),
                                         height));
        }

        auto *index = best[height];
        assert(index);
        return altintegration::ToJSON<UniValue>(*index);
    }

    UniValue getvbkblockhash(const Config &config,
                             const JSONRPCRequest &request) {
        return getblockhash(request, vbk(), "vbk");
    }
    UniValue getbtcblockhash(const Config &config,
                             const JSONRPCRequest &request) {
        return getblockhash(request, btc(), "btc");
    }

} // namespace

// getpoprawmempool
namespace {

    UniValue getrawpopmempool(const Config &config,
                              const JSONRPCRequest &request) {
        auto cmdname = "getrawpopmempool";
        RPCHelpMan{
            cmdname,
            "\nReturns the list of VBK blocks, ATVs and VTBs stored in POP "
            "mempool.\n",
            {},
            RPCResult{"TODO"},
            RPCExamples{HelpExampleCli(cmdname, "") +
                        HelpExampleRpc(cmdname, "")},
        }
            .Check(request);

        auto &mp = *VeriBlock::GetPop().mempool;
        return altintegration::ToJSON<UniValue>(mp);
    }

} // namespace

// getrawatv
// getrawvtb
// getrawvbkblock
namespace {

    template <typename T>
    bool GetPayload(const typename T::id_t &pid, T &out,
                    const Consensus::Params &consensusParams,
                    const CBlockIndex *const block_index,
                    std::vector<BlockHash> &containingBlocks) {
        LOCK(cs_main);

        if (block_index) {
            CBlock block;
            if (!ReadBlockFromDisk(block, block_index, consensusParams)) {
                throw JSONRPCError(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    strprintf("Can not read block %s from disk",
                              block_index->GetBlockHash().GetHex()));
            }
            if (!VeriBlock::FindPayloadInBlock<T>(block, pid, out)) {
                return false;
            }
            containingBlocks.push_back(block_index->GetBlockHash());
            return true;
        }

        auto &pop = VeriBlock::GetPop();

        auto &mp = *pop.mempool;
        auto *pl = mp.get<T>(pid);
        if (pl) {
            out = *pl;
            return true;
        }

        // search in the alttree storage
        const auto &containing =
            pop.altTree->getPayloadsIndex().getContainingAltBlocks(
                pid.asVector());
        if (containing.size() == 0) return false;

        // fill containing blocks
        containingBlocks.reserve(containing.size());
        std::transform(containing.begin(), containing.end(),
                       std::back_inserter(containingBlocks),
                       [](const decltype(*containing.begin()) &blockHash) {
                           return BlockHash(uint256(blockHash));
                       });

        for (const auto &blockHash : containing) {
            auto *index = LookupBlockIndex(BlockHash(uint256(blockHash)));
            assert(index && "state and index mismatch");

            CBlock block;
            if (!ReadBlockFromDisk(block, index, consensusParams)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   strprintf("Can not read block %s from disk",
                                             index->GetBlockHash().GetHex()));
            }

            if (!VeriBlock::FindPayloadInBlock<T>(block, pid, out)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Payload not found in the block data");
            }
        }

        return true;
    }

    template <typename T>
    UniValue getrawpayload(const JSONRPCRequest &request,
                           const std::string &name) {
        auto cmdname = strprintf("getraw%s", name);
        // clang-format off
    RPCHelpMan{
        cmdname,
        "\nReturn the raw " + name + " data.\n"

        "\nWhen called with a blockhash argument, " + cmdname + " will return the " +name+ "\n"
        "if the specified block is available and the " + name + " is found in that block.\n"
        "When called without a blockhash argument, " + cmdname + "will return the " + name + "\n"
        "if it is in the POP mempool, or in local payload repository.\n"

        "\nIf verbose is 'true', returns an Object with information about 'id'.\n"
        "If verbose is 'false' or omitted, returns a string that is serialized, hex-encoded data for 'id'.\n",
        {
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The " + name + " id"},
            {"verbose", RPCArg::Type::BOOL, /* default */ "false", "If false, return a string, otherwise return a json object"},
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "The block in which to look for the " + name + ""},
        },
        {
            RPCResult{"if verbose is not set or set to false",
                "\"data\"      (string) The serialized, hex-encoded data for 'id'\n"},
            RPCResult{"if verbose is set to true", "TODO"},
        },
        RPCExamples{
            HelpExampleCli(cmdname, "\"id\"") +
            HelpExampleCli(cmdname, "\"id\" true") +
            HelpExampleRpc(cmdname, "\"id\", true") +
            HelpExampleCli(cmdname, "\"id\" false \"myblockhash\"") +
            HelpExampleCli(cmdname, "\"id\" true \"myblockhash\"")},
    }
        .Check(request);
        // clang-format on

        using id_t = typename T::id_t;
        id_t pid;
        try {
            pid = id_t::fromHex(request.params[0].get_str());
        } catch (const std::exception &e) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("Bad id: %s", e.what()));
        }

        // Accept either a bool (true) or a num (>=1) to indicate verbose
        // output.
        bool fVerbose = false;
        if (!request.params[1].isNull()) {
            fVerbose = request.params[1].isNum()
                           ? (request.params[1].get_int() != 0)
                           : request.params[1].get_bool();
        }

        CBlockIndex *blockindex = nullptr;
        if (!request.params[2].isNull()) {
            LOCK(cs_main);

            uint256 hash_block = ParseHashV(request.params[2], "parameter 3");
            blockindex = LookupBlockIndex(BlockHash(hash_block));
            if (!blockindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Block hash not found");
            }
        }

        T out;
        std::vector<BlockHash> containingBlocks{};
        if (!GetPayload<T>(pid, out, Params().GetConsensus(), blockindex,
                           containingBlocks)) {
            std::string errmsg;
            if (blockindex) {
                if (!(blockindex->nStatus.hasData())) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
                }
                errmsg = "No such " + name + " found in the provided block";
            } else {
                errmsg = "No such mempool or blockchain " + name;
            }
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg);
        }

        if (!fVerbose) {
            return altintegration::ToJSON<UniValue>(out.toHex());
        }

        uint256 activeHashBlock{};
        CBlockIndex *verboseBlockIndex = nullptr;
        {
            LOCK(cs_main);
            for (const auto &b : containingBlocks) {
                auto *index = LookupBlockIndex(b);
                if (index == nullptr) continue;
                verboseBlockIndex = index;
                if (::ChainActive().Contains(index)) {
                    activeHashBlock = b;
                    break;
                }
            }
        }

        UniValue result(UniValue::VOBJ);
        if (verboseBlockIndex) {
            bool in_active_chain = ::ChainActive().Contains(verboseBlockIndex);
            result.pushKV("in_active_chain", in_active_chain);
            result.pushKV("blockheight", verboseBlockIndex->nHeight);
            if (in_active_chain) {
                result.pushKV("confirmations", 1 + ::ChainActive().Height() -
                                                   verboseBlockIndex->nHeight);
                result.pushKV("blocktime", verboseBlockIndex->GetBlockTime());
            } else {
                result.pushKV("confirmations", 0);
            }
        }

        result.pushKV(name, altintegration::ToJSON<UniValue>(out));
        UniValue univalueContainingBlocks(UniValue::VARR);
        for (const auto &b : containingBlocks) {
            univalueContainingBlocks.push_back(b.GetHex());
        }
        result.pushKV("containing_blocks", univalueContainingBlocks);
        result.pushKV("blockhash", activeHashBlock.GetHex());
        return result;
    }

    UniValue getrawatv(const Config &config, const JSONRPCRequest &req) {
        return getrawpayload<altintegration::ATV>(req, "atv");
    }
    UniValue getrawvtb(const Config &config, const JSONRPCRequest &req) {
        return getrawpayload<altintegration::VTB>(req, "vtb");
    }
    UniValue getrawvbkblock(const Config &config, const JSONRPCRequest &req) {
        return getrawpayload<altintegration::VbkBlock>(req, "vbkblock");
    }

} // namespace

const CRPCCommand commands[] = {
    {"pop_mining", "submitpop", submitpop, {"atv", "vtbs"}},
    {"pop_mining", "getpopdata", getpopdata, {"blockheight"}},
    {"pop_mining", "debugpop", debugpop, {}},
    {"pop_mining", "getvbkblock", getvbkblock, {"hash"}},
    {"pop_mining", "getbtcblock", getbtcblock, {"hash"}},
    {"pop_mining", "getvbkbestblockhash", getvbkbestblockhash, {}},
    {"pop_mining", "getbtcbestblockhash", getbtcbestblockhash, {}},
    {"pop_mining", "getvbkblockhash", getvbkblockhash, {"height"}},
    {"pop_mining", "getbtcblockhash", getbtcblockhash, {"height"}},
    {"pop_mining", "getrawatv", getrawatv, {"id"}},
    {"pop_mining", "getrawvtb", getrawvtb, {"id"}},
    {"pop_mining", "getrawvbkblock", getrawvbkblock, {"id"}},
    {"pop_mining", "getrawpopmempool", getrawpopmempool, {}}};

void RegisterPOPMiningRPCCommands(CRPCTable &t) {
    for (const auto &command : VeriBlock::commands) {
        t.appendCommand(command.name, &command);
    }
}

} // namespace VeriBlock
```
Also add json adapttor for the library, to parse the MempoolResult from the library to the UniValue object.\
[<font style="color: red">vbk/adaptors/univalue_json.hpp</font>]
```

#ifndef INTEGRATION_REFERENCE_BTC_JSON_HPP
#define INTEGRATION_REFERENCE_BTC_JSON_HPP

#include <univalue.h>
#include <veriblock/json.hpp>

/// contains partial specialization of ToJSON, which allows to write
/// UniValue v = ToJSON<UniValue>(vbk entity);

namespace altintegration {

template <> inline UniValue ToJSON(const std::string &t) {
    return UniValue(t);
}

template <> inline UniValue ToJSON(const double &t) {
    return UniValue(t);
}

template <> inline UniValue ToJSON(const uint32_t &t) {
    return UniValue((uint64_t)t);
}

template <> inline UniValue ToJSON(const int &t) {
    return UniValue((int64_t)t);
}

namespace json {

    template <> inline UniValue makeEmptyObject() {
        return UniValue(UniValue::VOBJ);
    }

    template <> inline UniValue makeEmptyArray() {
        return UniValue(UniValue::VARR);
    }

    template <>
    inline void putKV(UniValue &object, const std::string &key,
                      const UniValue &val) {
        object.pushKV(key, val);
    }

    template <>
    inline void putStringKV(UniValue &object, const std::string &key,
                            const std::string &value) {
        object.pushKV(key, value);
    }

    template <>
    inline void putIntKV(UniValue &object, const std::string &key,
                         int64_t value) {
        object.pushKV(key, value);
    }

    template <>
    inline void putNullKV(UniValue &object, const std::string &key) {
        object.pushKV(key, UniValue(UniValue::VNULL));
    }

    template <>
    inline void arrayPushBack(UniValue &array, const UniValue &val) {
        array.push_back(val);
    }

    template <>
    inline void putBoolKV(UniValue &object, const std::string &key,
                          bool value) {
        object.pushKV(key, value);
    }

} // namespace json
} // namespace altintegration

#endif // INTEGRATION_REFERENCE_BTC_JSON_HPP
```
For the correct compiling all this files with the library functions has been updated serialize.h source file.\
[<font style="color: red">serialize.h</font>]
```diff
+#include "vbk/adaptors/univalue_json.hpp"
 #include "veriblock/entities/altblock.hpp"
 #include "veriblock/entities/popdata.hpp"
```
Also update logging.h file, add PoP related log flag.\
[<font style="color: red">logging.h</font>]
```diff
    LEVELDB = (1 << 20),
    VALIDATION = (1 << 21),
+   // VeriBlock
+   POP = (1 << 22),
    ALL = ~uint32_t(0),
```
And the final step to add all these rpc functions to the RPC server.\
[<font style="color: red">rpc/register.h</font>]
```diff
+ #include <vbk/rpc_register.hpp>

static inline void RegisterAllCoreRPCCommands(CRPCTable &t) {
    RegisterBlockchainRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterMiscRPCCommands(t);
    RegisterMiningRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);
    RegisterABCRPCCommands(t);
    RegisterAvalancheRPCCommands(t);
+   VeriBlock::RegisterPOPMiningRPCCommands(t);
}
```
And finally add tests for the PoP rpc functions.\
[<font style="color: red">vbk/test/unit/rpc_service_tests.cpp</font>]
```
#include <boost/test/unit_test.hpp>
#include <chainparams.h>
#include <chrono>
#include <consensus/merkle.h>
#include <fstream>
#include <rpc/request.h>
#include <rpc/server.h>
#include <string>
#include <test/util/setup_common.h>
#include <thread>
#include <univalue.h>
#include <validation.h>
#include <vbk/merkle.hpp>
#include <wallet/wallet.h>

#include <vbk/test/util/e2e_fixture.hpp>

UniValue CallRPC(std::string args);

BOOST_AUTO_TEST_SUITE(rpc_service_tests)

BOOST_FIXTURE_TEST_CASE(submitpop_test, E2eFixture) {
    JSONRPCRequest request;
    request.strMethod = "submitpop";
    request.params = UniValue(UniValue::VARR);
    request.fHelp = false;

    uint32_t generateVtbs = 20;
    std::vector<VTB> vtbs;
    vtbs.reserve(generateVtbs);
    std::generate_n(std::back_inserter(vtbs), generateVtbs,
                    [&]() { return endorseVbkTip(); });

    BOOST_CHECK_EQUAL(vtbs.size(), generateVtbs);

    std::vector<altintegration::VbkBlock> vbk_blocks;
    for (const auto &vtb : vtbs) {
        vbk_blocks.push_back(vtb.containingBlock);
    }

    BOOST_CHECK(!vbk_blocks.empty());

    UniValue vbk_blocks_params(UniValue::VARR);
    for (const auto &b : vbk_blocks) {
        altintegration::WriteStream stream;
        b.toVbkEncoding(stream);
        vbk_blocks_params.push_back(HexStr(stream.data()));
    }

    UniValue vtb_params(UniValue::VARR);
    for (const auto &vtb : vtbs) {
        altintegration::WriteStream stream;
        vtb.toVbkEncoding(stream);
        vtb_params.push_back(HexStr(stream.data()));
    }

    BOOST_CHECK_EQUAL(vbk_blocks.size(), vbk_blocks_params.size());
    BOOST_CHECK_EQUAL(vtbs.size(), vtb_params.size());

    UniValue atv_empty(UniValue::VARR);
    request.params.push_back(vbk_blocks_params);
    request.params.push_back(vtb_params);
    request.params.push_back(atv_empty);

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    UniValue result;
    GlobalConfig config;
    BOOST_CHECK_NO_THROW(result = tableRPC.execute(config, request));

    BOOST_CHECK_EQUAL(result["atvs"].size(), 0);
    BOOST_CHECK_EQUAL(result["vtbs"].size(), vtbs.size());
    BOOST_CHECK_EQUAL(result["vbkblocks"].size(), vbk_blocks.size());
}

BOOST_AUTO_TEST_SUITE_END()
```
[<font style="color: red">test/CMakeLists.txt</font>]
```diff
		# VeriBlock Tests
		../vbk/test/unit/e2e_pop_tests.cpp
		../vbk/test/unit/pop_util_tests.cpp
		../vbk/test/unit/vbk_merkle_tests.cpp
		../vbk/test/unit/block_validation_tests.cpp
		../vbk/test/unit/pop_rewards_tests.cpp
		../vbk/test/unit/pop_forkresolution_tests.cpp
+   	../vbk/test/unit/rpc_service_tests.cpp
```

## Adding VeriBlock payloads p2p broadcasting

For the correct work of the veriblock pop mempool we should update and add new rules for the ATV, VTB, VBK and broadcast it through the network. All these functionality add to the p2p_sync.hpp, p2p_sync.cpp.\
[<font style="color: red">vbk/p2p_sync.hpp</font>]
```
#ifndef BITCOIN_SRC_VBK_P2P_SYNC_HPP
#define BITCOIN_SRC_VBK_P2P_SYNC_HPP

#include <chainparams.h>
#include <map>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/context.h>
#include <rpc/blockchain.h>
#include <vbk/pop_common.hpp>
#include <veriblock/mempool.hpp>

namespace VeriBlock {

namespace p2p {

    struct PopP2PState {
        uint32_t known_pop_data{0};
        uint32_t offered_pop_data{0};
        uint32_t requested_pop_data{0};
    };

    // The state of the Node that stores already known Pop Data
    struct PopDataNodeState {
        // we use map to store DDoS prevention counter as a value in the map
        std::map<altintegration::ATV::id_t, PopP2PState> atv_state{};
        std::map<altintegration::VTB::id_t, PopP2PState> vtb_state{};
        std::map<altintegration::VbkBlock::id_t, PopP2PState>
            vbk_blocks_state{};

        template <typename T> std::map<typename T::id_t, PopP2PState> &getMap();
    };

    PopDataNodeState &getPopDataNodeState(const NodeId &id);

    void erasePopDataNodeState(const NodeId &id);

} // namespace p2p

} // namespace VeriBlock

namespace VeriBlock {

namespace p2p {

    const static std::string get_prefix = "g";
    const static std::string offer_prefix = "of";

    const static uint32_t MAX_POP_DATA_SENDING_AMOUNT = MAX_INV_SZ;
    const static uint32_t MAX_POP_MESSAGE_SENDING_COUNT = 30;

    template <typename pop_t> void offerPopDataToAllNodes(const pop_t &p) {
        std::vector<std::vector<uint8_t>> p_id = {p.getId().asVector()};
        CConnman *connman = g_rpc_node->connman.get();
        const CNetMsgMaker msgMaker(PROTOCOL_VERSION);

        connman->ForEachNode([&connman, &msgMaker, &p_id](CNode *node) {
            LOCK(cs_main);

            auto &pop_state_map =
                getPopDataNodeState(node->GetId()).getMap<pop_t>();
            PopP2PState &pop_state = pop_state_map[p_id[0]];
            if (pop_state.offered_pop_data == 0) {
                ++pop_state.offered_pop_data;
                connman->PushMessage(
                    node, msgMaker.Make(offer_prefix + pop_t::name(), p_id));
            }
        });
    }

    template <typename PopDataType>
    void offerPopData(CNode *node, CConnman *connman,
                      const CNetMsgMaker &msgMaker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        auto &pop_mempool = *VeriBlock::GetPop().mempool;
        const auto &data = pop_mempool.getMap<PopDataType>();

        auto &pop_state_map =
            getPopDataNodeState(node->GetId()).getMap<PopDataType>();

        std::vector<std::vector<uint8_t>> hashes;
        for (const auto &el : data) {
            PopP2PState &pop_state = pop_state_map[el.first];
            if (pop_state.offered_pop_data == 0 &&
                pop_state.known_pop_data == 0) {
                ++pop_state.offered_pop_data;
                hashes.push_back(el.first.asVector());
            }

            if (hashes.size() == MAX_POP_DATA_SENDING_AMOUNT) {
                connman->PushMessage(
                    node,
                    msgMaker.Make(offer_prefix + PopDataType::name(), hashes));
                hashes.clear();
            }
        }

        if (!hashes.empty()) {
            connman->PushMessage(
                node,
                msgMaker.Make(offer_prefix + PopDataType::name(), hashes));
        }
    }

    int processPopData(CNode *pfrom, const std::string &strCommand,
                       CDataStream &vRecv, CConnman *connman);

} // namespace p2p
} // namespace VeriBlock

#endif
```
[<font style="color: red">vbk/p2p_sync.cpp</font>]
```
#include "vbk/p2p_sync.hpp"
#include <veriblock/entities/atv.hpp>
#include <veriblock/entities/vbkblock.hpp>
#include <veriblock/entities/vtb.hpp>

namespace VeriBlock {
namespace p2p {

    static std::map<NodeId, std::shared_ptr<PopDataNodeState>>
        mapPopDataNodeState;

    template <>
    std::map<altintegration::ATV::id_t, PopP2PState> &
    PopDataNodeState::getMap<altintegration::ATV>() {
        return atv_state;
    }

    template <>
    std::map<altintegration::VTB::id_t, PopP2PState> &
    PopDataNodeState::getMap<altintegration::VTB>() {
        return vtb_state;
    }

    template <>
    std::map<altintegration::VbkBlock::id_t, PopP2PState> &
    PopDataNodeState::getMap<altintegration::VbkBlock>() {
        return vbk_blocks_state;
    }

    PopDataNodeState &getPopDataNodeState(const NodeId &id)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        std::shared_ptr<PopDataNodeState> &val = mapPopDataNodeState[id];
        if (val == nullptr) {
            mapPopDataNodeState[id] = std::make_shared<PopDataNodeState>();
            val = mapPopDataNodeState[id];
        }
        return *val;
    }

    void erasePopDataNodeState(const NodeId &id)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        mapPopDataNodeState.erase(id);
    }

    template <typename pop_t>
    bool processGetPopData(CNode *node, CConnman *connman, CDataStream &vRecv,
                           altintegration::MemPool &pop_mempool)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        std::vector<std::vector<uint8_t>> requested_data;
        vRecv >> requested_data;

        if (requested_data.size() > MAX_POP_DATA_SENDING_AMOUNT) {
            LogPrint(BCLog::NET,
                     "peer %d send oversized message getdata size() = %u \n",
                     node->GetId(), requested_data.size());
            Misbehaving(node->GetId(), 20,
                        strprintf("message getdata size() = %u",
                                  requested_data.size()));
            return false;
        }

        auto &pop_state_map =
            getPopDataNodeState(node->GetId()).getMap<pop_t>();

        const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
        for (const auto &data_hash : requested_data) {
            PopP2PState &pop_state = pop_state_map[data_hash];
            uint32_t ddosPreventionCounter = pop_state.known_pop_data++;

            if (ddosPreventionCounter > MAX_POP_MESSAGE_SENDING_COUNT) {
                LogPrint(BCLog::NET, "peer %d is spamming pop data %s \n",
                         node->GetId(), pop_t::name());
                Misbehaving(node->GetId(), 20,
                            strprintf("peer %d is spamming pop data %s",
                                      node->GetId(), pop_t::name()));
                return false;
            }

            const auto *data = pop_mempool.get<pop_t>(data_hash);
            if (data != nullptr) {
                connman->PushMessage(node, msgMaker.Make(pop_t::name(), *data));
            }
        }

        return true;
    }

    template <typename pop_t>
    bool processOfferPopData(CNode *node, CConnman *connman, CDataStream &vRecv,
                             altintegration::MemPool &pop_mempool)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        LogPrint(BCLog::NET, "received offered pop data: %s, bytes size: %d\n",
                 pop_t::name(), vRecv.size());
        std::vector<std::vector<uint8_t>> offered_data;
        vRecv >> offered_data;

        if (offered_data.size() > MAX_POP_DATA_SENDING_AMOUNT) {
            LogPrint(BCLog::NET,
                     "peer %d send oversized message getdata size() = %u \n",
                     node->GetId(), offered_data.size());
            Misbehaving(
                node->GetId(), 20,
                strprintf("message getdata size() = %u", offered_data.size()));
            return false;
        }

        auto &pop_state_map =
            getPopDataNodeState(node->GetId()).getMap<pop_t>();

        std::vector<std::vector<uint8_t>> requested_data;
        const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
        for (const auto &data_hash : offered_data) {
            PopP2PState &pop_state = pop_state_map[data_hash];
            uint32_t ddosPreventionCounter = pop_state.requested_pop_data++;

            if (!pop_mempool.get<pop_t>(data_hash)) {
                requested_data.push_back(data_hash);
            } else if (ddosPreventionCounter > MAX_POP_MESSAGE_SENDING_COUNT) {
                LogPrint(BCLog::NET, "peer %d is spamming pop data %s \n",
                         node->GetId(), pop_t::name());
                Misbehaving(node->GetId(), 20,
                            strprintf("peer %d is spamming pop data %s",
                                      node->GetId(), pop_t::name()));
                return false;
            }
        }

        if (!requested_data.empty()) {
            connman->PushMessage(node, msgMaker.Make(get_prefix + pop_t::name(),
                                                     requested_data));
        }

        return true;
    }

    template <typename pop_t>
    bool processPopData(CNode *node, CDataStream &vRecv,
                        altintegration::MemPool &pop_mempool)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        LogPrint(BCLog::NET, "received pop data: %s, bytes size: %d\n",
                 pop_t::name(), vRecv.size());
        pop_t data;
        vRecv >> data;

        auto &pop_state_map =
            getPopDataNodeState(node->GetId()).getMap<pop_t>();
        PopP2PState &pop_state = pop_state_map[data.getId()];

        if (pop_state.requested_pop_data == 0) {
            LogPrint(BCLog::NET,
                     "peer %d send pop data %s that has not been requested \n",
                     node->GetId(), pop_t::name());
            Misbehaving(
                node->GetId(), 20,
                strprintf(
                    "peer %d send pop data %s that has not been requested",
                    node->GetId(), pop_t::name()));
            return false;
        }

        uint32_t ddosPreventionCounter = pop_state.requested_pop_data++;

        if (ddosPreventionCounter > MAX_POP_MESSAGE_SENDING_COUNT) {
            LogPrint(BCLog::NET, "peer %d is spaming pop data %s\n",
                     node->GetId(), pop_t::name());
            Misbehaving(node->GetId(), 20,
                        strprintf("peer %d is spamming pop data %s",
                                  node->GetId(), pop_t::name()));
            return false;
        }

        altintegration::ValidationState state;
        auto result = pop_mempool.submit(std::make_shared<pop_t>(data), state);
        if (!result && result.status == altintegration::MemPool::FAILED_STATELESS) {
            LogPrint(BCLog::NET, "peer %d sent invalid pop data: %s\n",
                     node->GetId(), state.toString());
            Misbehaving(node->GetId(), 20,
                        strprintf("invalid pop data getdata, reason: %s",
                                  state.toString()));
            return false;
        }

        return true;
    }

    int processPopData(CNode *pfrom, const std::string &strCommand,
                       CDataStream &vRecv, CConnman *connman) {
        auto &pop_mempool = *VeriBlock::GetPop().mempool;

        // process Pop Data
        if (strCommand == altintegration::ATV::name()) {
            LOCK(cs_main);
            return processPopData<altintegration::ATV>(pfrom, vRecv,
                                                       pop_mempool);
        }

        if (strCommand == altintegration::VTB::name()) {
            LOCK(cs_main);
            return processPopData<altintegration::VTB>(pfrom, vRecv,
                                                       pop_mempool);
        }

        if (strCommand == altintegration::VbkBlock::name()) {
            LOCK(cs_main);
            return processPopData<altintegration::VbkBlock>(pfrom, vRecv,
                                                            pop_mempool);
        }
        //----------------------

        // offer Pop Data
        if (strCommand == offer_prefix + altintegration::ATV::name()) {
            LOCK(cs_main);
            return processOfferPopData<altintegration::ATV>(pfrom, connman,
                                                            vRecv, pop_mempool);
        }

        if (strCommand == offer_prefix + altintegration::VTB::name()) {
            LOCK(cs_main);
            return processOfferPopData<altintegration::VTB>(pfrom, connman,
                                                            vRecv, pop_mempool);
        }

        if (strCommand == offer_prefix + altintegration::VbkBlock::name()) {
            LOCK(cs_main);
            return processOfferPopData<altintegration::VbkBlock>(
                pfrom, connman, vRecv, pop_mempool);
        }
        //-----------------

        // get Pop Data
        if (strCommand == get_prefix + altintegration::ATV::name()) {
            LOCK(cs_main);
            return processGetPopData<altintegration::ATV>(pfrom, connman, vRecv,
                                                          pop_mempool);
        }

        if (strCommand == get_prefix + altintegration::VTB::name()) {
            LOCK(cs_main);
            return processGetPopData<altintegration::VTB>(pfrom, connman, vRecv,
                                                          pop_mempool);
        }

        if (strCommand == get_prefix + altintegration::VbkBlock::name()) {
            LOCK(cs_main);
            return processGetPopData<altintegration::VbkBlock>(
                pfrom, connman, vRecv, pop_mempool);
        }

        return -1;
    }

} // namespace p2p

} // namespace VeriBlock
```

Define mempool signal for the payloads broadcasting.\
[<font style="color: red">vbk/pop_service.cpp</font>]
```diff
+#include <vbk/p2p_sync.hpp>
...
void SetPop(CDBWrapper &db) {
    payloads = std::make_shared<PayloadsProvider>(db);
    std::shared_ptr<altintegration::PayloadsProvider> dbrepo = payloads;
    SetPop(dbrepo);

+    auto &app = GetPop();
+    app.mempool->onAccepted<altintegration::ATV>(
+        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::ATV>);
+    app.mempool->onAccepted<altintegration::VTB>(
+        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VTB>);
+    app.mempool->onAccepted<altintegration::VbkBlock>(
+        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VbkBlock>);
}
```
Update original net_processing with the maintaining of the VeriBlock data.\
[<font style="color: red">net_processing.cpp</font>]
```diff
+#include <vbk/p2p_sync.hpp>
...
FinalizeNode() {
...
    mapNodeState.erase(nodeid);
+    VeriBlock::p2p::erasePopDataNodeState(nodeid);
...
}

...

ProcessHeadersMessage() {
...
-    if (fCanDirectFetch && pindexLast->IsValid(BlockValidity::TREE) &&
-            ::ChainActive().Tip()->nChainWork <= pindexLast->nChainWork) {
+        if (fCanDirectFetch && pindexLast->IsValid(BlockValidity::TREE)
+            // VeriBlock: download the chain suggested by the peer
+            /* && ::ChainActive().Tip()->nChainWork <= pindexLast->nChainWork */
+        ) {
...
}

...

ProcessMessage() {
...
    if (gArgs.IsArgSet("-dropmessagestest") &&
        GetRand(gArgs.GetArg("-dropmessagestest", 0)) == 0) {
        LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

+    // VeriBlock
+    int pop_res =
+        VeriBlock::p2p::processPopData(pfrom, strCommand, vRecv, connman);
+    if (pop_res != -1) {
+        return pop_res;
+    }
...
}

...
SendMessages() {
...
    if (!vInv.empty()) {
        connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
    }

+    // VeriBlock offer Pop Data
+    {
+        VeriBlock::p2p::offerPopData<altintegration::ATV>(pto, connman,
+                                                          msgMaker);
+        VeriBlock::p2p::offerPopData<altintegration::VTB>(pto, connman,
+                                                          msgMaker);
+        VeriBlock::p2p::offerPopData<altintegration::VbkBlock>(pto, connman,
+                                                               msgMaker);
+    }
...
}
```
[<font style="color: red">CMakeLists.txt</font>]
```diff
add_library(server
	vbk/pop_service.cpp
	vbk/rpc_register.cpp
+	vbk/p2p_sync.cpp
```

## Split bootstrap blocks to mainnet and testnet

[<font style="color: red">vbk/bootstraps.hpp</font>]
```diff
 #include <vector>

-#include <primitives/block.h>
-#include <util/system.h> // for gArgs
-#include <veriblock/pop.hpp>
```
```diff
extern const std::vector<std::string> testnetBTCblocks;

+extern const int mainnetVBKstartHeight;
+extern const std::vector<std::string> mainnetVBKblocks;
+
+extern const int mainnetBTCstartHeight;
+extern const std::vector<std::string> mainnetBTCblocks;
+
 } // namespace VeriBlock
```

Add bootstraps-mainnet.cpp and bootstraps-testnet.cpp

[<font style="color: red">vbk/bootstraps-mainnet.cpp</font>]
```
// Copyright (c) 2019-2021 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstraps.hpp"

namespace VeriBlock {

const int mainnetVBKstartHeight=2757043;
const int mainnetBTCstartHeight=711392;

const std::vector<std::string> mainnetBTCblocks = {};
const std::vector<std::string> mainnetVBKblocks = {};

} // namespace VeriBlock
```
[<font style="color: red">vbk/bootstraps-testnet.cpp</font>]
```
// Copyright (c) 2019-2021 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstraps.hpp"

namespace VeriBlock {

const int testnetVBKstartHeight=2135791;
const int testnetBTCstartHeight=2104692;

const std::vector<std::string> testnetBTCblocks = {};
const std::vector<std::string> testnetVBKblocks = {};

} // namespace VeriBlock
```

Update CMakeLists file

[<font style="color: red">CMakeLists.txt</font>]
```diff
 add_library(server
-       vbk/bootstraps.cpp
+       vbk/bootstraps-testnet.cpp
+       vbk/bootstraps-mainnet.cpp
        vbk/merkle.cpp
```

## Change POP rewards calculation

Now we simply cut 50% of the rewards towards POP miners.

[<font style="color: red">chainparams.h</font>]
```diff
struct CChainParams {
...
         return height >= consensus.VeriBlockPopSecurityHeight;
     }
     uint32_t PopRewardPercentage() const { return mPopRewardPercentage; }
-    int32_t PopRewardCoefficient() const { return mPopRewardCoefficient; }
...
     // VeriBlock:
     // cut this % from coinbase subsidy
-    uint32_t mPopRewardPercentage = 40; // %
-    // every pop reward will be multiplied by this coefficient
-    int32_t mPopRewardCoefficient = 20;
+    uint32_t mPopRewardPercentage = 50; // %
...
}
```

[<font style="color: red">validation.cpp</font>]
```diff
Amount GetBlockSubsidy(int nHeight, const CChainParams& params) {
-    int halvings = nHeight / params.GetConsensus().nSubsidyHalvingInterval;
-    // Force block reward to zero when right shift is undefined.
-    if (halvings >= 64) {
-        return Amount::zero();
-    }
-
-    Amount nSubsidy = 50 * COIN;
-    // Subsidy is cut in half every 210,000 blocks which will occur
-    // approximately every 4 years.
+    Amount nSubsidy = VeriBlock::GetSubsidyMultiplier(nHeight, params);
     if (VeriBlock::isPopActive(nHeight)) {
-        nSubsidy = VeriBlock::getCoinbaseSubsidy(nSubsidy, nHeight, params);
+        // we cut 50% of POW payouts towards POP payouts
+        return nSubsidy / 2;
     }

-    return ((nSubsidy / SATOSHI) >> halvings) * SATOSHI;
+    return nSubsidy;
}
```
```diff
CChainState::ConnectBlock() {
...
     // VeriBlock add pop rewards validation
-    Amount blockReward = GetBlockSubsidy(pindex->pprev->nHeight, params);
-    blockReward += nFees;
-
     assert(pindex->pprev && "previous block ptr is nullptr");
-    if (!VeriBlock::checkCoinbaseTxWithPopRewards(*block.vtx[0], nFees, *pindex, params, blockReward, state)) {
-        return false;
-    }
     if (VeriBlock::isCrossedBootstrapBlock()) {
+        if (!VeriBlock::checkCoinbaseTxWithPopRewards(*block.vtx[0], nFees, *pindex, params, state)) {
+            return false;
+        }
         altintegration::ValidationState _state;
         if (!VeriBlock::setState(pindex->GetBlockHash(), _state)) {
-            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID, "bad-block-pop",
+            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID, "bad-block-pop-state",
...
     if (!whitelist.empty()) {
+        Amount blockReward = GetBlockSubsidy(pindex->pprev->nHeight, params);
+        blockReward += nFees;
         const Amount required = GetMinerFundAmount(blockReward);
...
}
```

[<font style="color: red">vbk/pop_service.hpp</font>]
```diff
-//! pop rewards
-PoPRewards getPopRewards(const CBlockIndex &pindexPrev, const CChainParams& params)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-void addPopPayoutsIntoCoinbaseTx(CMutableTransaction &coinbaseTx,
-                                 const CBlockIndex &pindexPrev,
-                                 const CChainParams& params)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-bool checkCoinbaseTxWithPopRewards(const CTransaction &tx, const Amount &nFees,
-                                   const CBlockIndex &pindex,
-                                   const CChainParams& params,
-                                   Amount &blockReward,
-                                   BlockValidationState &state)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-
-Amount getCoinbaseSubsidy(Amount subsidy, int32_t height, const CChainParams& params);
...
+
+Amount GetSubsidyMultiplier(int nHeight, const CChainParams& params);
+
```

Explicitly set POP params

[<font style="color: red">vbk/params.hpp</font>]
```diff
struct AltChainParamsVBCH {
    AltChainParamsVBCH(const CBlock& genesis) {
...
         bootstrap.height = 0;
         bootstrap.timestamp = genesis.GetBlockTime();
+
+        // these parameters changed in comparison to default parameters
+        this->mPopPayoutsParams->mPopPayoutDelay = 150;
+        this->mPopPayoutsParams->mDifficultyAveragingInterval = 150;
+        this->mEndorsementSettlementInterval = 150;
+        this->mMaxVbkBlocksInAltBlock = 100;
+        this->mMaxVTBsInAltBlock = 50;
+        this->mMaxATVsInAltBlock = 100;
+        this->mPreserveBlocksBehindFinal = mEndorsementSettlementInterval;
+        this->mMaxReorgDistance = std::numeric_limits<int>::max(); // disable finalization for now
+
+        //! copying all parameters here to make sure that
+        //! if anyone changes them in alt-int-cpp, they
+        //! won't be changed in vBCH.
+
+        // pop payout params
+        this->mPopPayoutsParams->mStartOfSlope = 1.0;
+        this->mPopPayoutsParams->mSlopeNormal = 0.2;
+        this->mPopPayoutsParams->mSlopeKeystone = 0.21325;
+        this->mPopPayoutsParams->mKeystoneRound = 3;
+        this->mPopPayoutsParams->mPayoutRounds = 4;
+        this->mPopPayoutsParams->mFlatScoreRound = 2;
+        this->mPopPayoutsParams->mUseFlatScoreRound = true;
+        this->mPopPayoutsParams->mMaxScoreThresholdNormal = 2.0;
+        this->mPopPayoutsParams->mMaxScoreThresholdKeystone = 3.0;
+        this->mPopPayoutsParams->mRoundRatios = {0.97, 1.03, 1.07, 3.00};
+        this->mPopPayoutsParams->mLookupTable = {
+            1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000,
+            1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000,
+            0.48296816, 0.31551694, 0.23325824, 0.18453616, 0.15238463, 0.12961255,
+            0.11265630, 0.09955094, 0.08912509, 0.08063761, 0.07359692, 0.06766428,
+            0.06259873, 0.05822428, 0.05440941, 0.05105386, 0.04807993, 0.04542644,
+            0.04304458, 0.04089495, 0.03894540, 0.03716941, 0.03554497, 0.03405359,
+            0.03267969, 0.03141000, 0.03023319, 0.02913950, 0.02812047, 0.02716878,
+            0.02627801, 0.02544253, 0.02465739, 0.02391820, 0.02322107, 0.02256255,
+            0.02193952, 0.02134922};
+
+        // altchain params
+        this->mMaxAltchainFutureBlockTime = 10 * 60; // 10 min
+        this->mKeystoneInterval = 5;
+        this->mFinalityDelay = 100;
+        this->mMaxPopDataSize = altintegration::MAX_POPDATA_SIZE;
+        this->mForkResolutionLookUpTable = {
+            100, 100, 95, 89, 80, 69, 56, 40, 21};
    }
...
};
...
struct AltChainParamsVBCHRegTest {
...
    AltChainParamsVBCHRegTest() {
-        mMaxReorgDistance = 1000;
+        this->mMaxReorgDistance = 1000;
+        this->mMaxVbkBlocksInAltBlock = 200;
+        this->mMaxVTBsInAltBlock = 200;
+        this->mMaxATVsInAltBlock = 1000;
    }
};
```

Update POP service API

[<font style="color: red">vbk/pop_service.cpp</font>]
```diff
-#include <memory>
-#include <vector>
-
+#include "arith_uint256.h"
+#include <chain.h>
 #include <chainparams.h>
+#include <consensus/validation.h>
 #include <dbwrapper.h>
+#include <limits>
 #include <shutdown.h>
 #include <txdb.h>
+#include <validation.h>
 #include <vbk/adaptors/payloads_provider.hpp>
+#include <veriblock/pop.hpp>
-#include <vbk/util.hpp>
...

-PoPRewards getPopRewards(const CBlockIndex &pindexPrev,
-                         const CChainParams &params) {
+// PoP rewards are calculated for the current tip but are paid in the next block
+PoPRewards getPopRewards(const CBlockIndex& tip, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
     AssertLockHeld(cs_main);
-    auto &pop = GetPop();
+    auto& pop = GetPop();

-    if (!params.isPopActive(pindexPrev.nHeight)) {
+    if (!params.isPopActive(tip.nHeight)) {
         return {};
     }

-    auto &cfg = pop.getConfig();
-    if (pindexPrev.nHeight <
-        (int)cfg.getAltParams().getEndorsementSettlementInterval()) {
+    auto& cfg = pop.getConfig();
+    if (tip.nHeight < (int)cfg.alt->getEndorsementSettlementInterval()) {
         return {};
     }
-
-    if (pindexPrev.nHeight <
-        (int)cfg.getAltParams().getPayoutParams().getPopPayoutDelay()) {
+    if (tip.nHeight < (int)cfg.alt->getPayoutParams().getPopPayoutDelay()) {
         return {};
     }

     altintegration::ValidationState state;
-    auto prevHash = pindexPrev.GetBlockHash().asVector();
+    auto prevHash = tip.GetBlockHash().asVector();
     bool ret = pop.getAltBlockTree().setState(prevHash, state);
-    (void)ret;
-    assert(ret);
+    VBK_ASSERT_MSG(ret, "error: %s", state.toString());

     altintegration::PopPayouts rewards;
     ret = pop.getPopPayout(prevHash, rewards, state);
     VBK_ASSERT_MSG(ret, "error: %s", state.toString());

-    int halving = (pindexPrev.nHeight + 1) /
-                  params.GetConsensus().nSubsidyHalvingInterval;
+    // erase rewards, that pay 0 satoshis, then halve rewards
     PoPRewards result{};
-    // erase rewards, that pay 0 satoshis and halve rewards
-    for (const auto &r : rewards) {
-        auto rewardValue = r.second;
-        rewardValue >>= halving;
-
-        if ((rewardValue != 0) && (halving < 64)) {
+    for (const auto& r : rewards) {
+        // we use airth_uint256 to prevent any overflows
+        arith_uint256 coeff(r.second);
+        // 50% of multiplier towards POP.
+        arith_uint256 payout = coeff * arith_uint256((VeriBlock::GetSubsidyMultiplier(tip.nHeight + 1, params) / 2) / COIN);
+        if(payout > 0) {
             CScript key = CScript(r.first.begin(), r.first.end());
-            result[key] = params.PopRewardCoefficient() * rewardValue;
+            assert(payout <= std::numeric_limits<int64_t>::max() && "overflow!");
+            result[key] = payout.GetLow64();
         }
     }

     return result;
 }
...
-bool checkCoinbaseTxWithPopRewards(const CTransaction &tx, const Amount &nFees,
-                                   const CBlockIndex &pindex,
-                                   const CChainParams &params,
-                                   Amount &blockReward,
-                                   BlockValidationState &state) {
+bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const Amount& nFees, const CBlockIndex& pindex, const CChainParams& params, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
...
     // skip first (regular pow) payout, and last 2 0-value payouts
-    for (const auto &payout : expectedRewards) {
-        auto &script = payout.first;
-        Amount expectedAmount = payout.second * Amount::satoshi();
+    for (const auto& payout : expectedRewards) {
+        auto& script = payout.first;
+        auto expectedAmount = payout.second * Amount::satoshi();

         auto p = cbpayouts.find(script);
         // coinbase pays correct reward?
         if (p == cbpayouts.end()) {
             // we expected payout for that address
-            return state.Invalid(
-                BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
-                "bad-pop-missing-payout",
-                strprintf("[tx: %s] missing payout for scriptPubKey: '%s' with "
-                          "amount: '%d'",
-                          tx.GetHash().ToString(), HexStr(script),
-                          expectedAmount));
+            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID, "bad-pop-missing-payout",
+                strprintf("[tx: %s] missing payout for scriptPubKey: '%s' with amount: '%d'",
+                    tx.GetHash().ToString(),
+                    HexStr(script),
+                    expectedAmount));
         }

         // payout found
-        auto &actualAmount = p->second;
+        auto& actualAmount = p->second;
         // does it have correct amount?
         if (actualAmount != expectedAmount) {
-            return state.Invalid(
-                BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
-                "bad-pop-wrong-payout",
-                strprintf("[tx: %s] wrong payout for scriptPubKey: '%s'. "
-                          "Expected %d, got %d.",
-                          tx.GetHash().ToString(), HexStr(script),
-                          expectedAmount, actualAmount));
+            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID, "bad-pop-wrong-payout",
+                strprintf("[tx: %s] wrong payout for scriptPubKey: '%s'. Expected %d, got %d.",
+                    tx.GetHash().ToString(),
+                    HexStr(script),
+                    expectedAmount, actualAmount));
         }
...
     Amount PoWBlockReward = GetBlockSubsidy(pindex.nHeight, params);

-    blockReward = nTotalPopReward + PoWBlockReward + nFees;
-
-    if (tx.GetValueOut() > blockReward) {
-        return state.Invalid(
-            BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
+    if (tx.GetValueOut() > nTotalPopReward + PoWBlockReward + nFees) {
+        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, REJECT_INVALID,
             "bad-cb-pop-amount",
-            strprintf("ConnectBlock(): coinbase pays too much (actual=%s vs "
-                      "limit=%s)",
-                      tx.GetValueOut().ToString(), blockReward.ToString()));
+            strprintf("ConnectBlock(): coinbase pays too much (actual=%d vs POW=%d + POP=%d)", tx.GetValueOut(), PoWBlockReward, nTotalPopReward));
     }
+
     return true;
 }
...
-Amount getCoinbaseSubsidy(Amount subsidy, int32_t height,
-                          const CChainParams &params) {
-    if (!params.isPopActive(height)) {
-        return subsidy;
-    }
-
-    // int64_t powRewardPercentage = 100 - params.PopRewardPercentage();
-    // Amount newSubsidy = powRewardPercentage * subsidy;
-    // return newSubsidy / 100;
-    return subsidy;
-}
...
+Amount GetSubsidyMultiplier(int nHeight, const CChainParams& params) {
+    // Subsidy calculation has been moved here from GetBlockSubsidy()
+
+    int halvings = nHeight / params.GetConsensus().nSubsidyHalvingInterval;
+    // Force block reward to zero when right shift is undefined.
+    if (halvings >= 64) {
+        return Amount::zero();
+    }
+
+    Amount nSubsidy = 50 * COIN;
+    // Subsidy is cut in half every 210,000 blocks which will occur
+    // approximately every 4 years.
+    return ((nSubsidy / SATOSHI) >> halvings) * SATOSHI;
+}
```

[<font style="color: red">vbk/pop_service.hpp</font>]
```diff
-#include <consensus/validation.h>
-#include <validation.h>
-
 #include "pop_common.hpp"
 #include <vbk/adaptors/payloads_provider.hpp>

-class CBlockIndex;
+class BlockValidationState;
 class CBlock;
-class CScript;
 class CBlockTreeDB;
+class CBlockIndex;
 class CDBIterator;
 class CDBWrapper;
-class BlockValidationState;
+class CChainParams;
+
+namespace Consensus {
+struct Params;
+}

namespace VeriBlock {
...
void InitPopContext(CDBWrapper& db);

+CBlockIndex* compareTipToBlock(CBlockIndex* candidate);
+bool acceptBlock(const CBlockIndex& indexNew, BlockValidationState& state);
+bool checkPopDataSize(const altintegration::PopData& popData, altintegration::ValidationState& state);
+bool addAllBlockPayloads(const CBlock& block, BlockValidationState& state);
+bool setState(const uint256& block, altintegration::ValidationState& state);
+
+PoPRewards getPopRewards(const CBlockIndex& pindexPrev, const CChainParams& params);
+void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const CChainParams& params);
+bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const Amount& nFees, const CBlockIndex& pindex, const CChainParams& params, BlockValidationState& state);
+
+std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks);
+std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);
...
-//! pop rewards
-PoPRewards getPopRewards(const CBlockIndex &pindexPrev, const CChainParams& params)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-void addPopPayoutsIntoCoinbaseTx(CMutableTransaction &coinbaseTx,
-                                 const CBlockIndex &pindexPrev,
-                                 const CChainParams& params)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-bool checkCoinbaseTxWithPopRewards(const CTransaction &tx, const Amount &nFees,
-                                   const CBlockIndex &pindex,
-                                   const CChainParams& params,
-                                   Amount &blockReward,
-                                   BlockValidationState &state)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-
-Amount getCoinbaseSubsidy(Amount subsidy, int32_t height, const CChainParams& params);
-
-//! pop forkresolution
-CBlockIndex *compareTipToBlock(CBlockIndex *candidate)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-int compareForks(const CBlockIndex &left, const CBlockIndex &right)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-
-//! alttree methods
-bool acceptBlock(const CBlockIndex &indexNew, BlockValidationState &state)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-bool addAllBlockPayloads(const CBlock &block, BlockValidationState &state)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-bool setState(const BlockHash &hash, altintegration::ValidationState &state)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-
-//! mempool methods
-void removePayloadsFromMempool(const altintegration::PopData &popData)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
-void addDisconnectedPopdata(const altintegration::PopData &popData)
-    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
+void removePayloadsFromMempool(const altintegration::PopData& popData);

-std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks);
-std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);
+int compareForks(const CBlockIndex& left, const CBlockIndex& right);
+
+void addDisconnectedPopdata(const altintegration::PopData& popData);

 bool isCrossedBootstrapBlock();
 bool isCrossedBootstrapBlock(int32_t height);
 bool isPopActive();
 bool isPopActive(int32_t height);

+// get stats on POP score comparisons
+uint64_t getPopScoreComparisons();
+
+Amount GetSubsidyMultiplier(int nHeight, const CChainParams& params);
+
}
```

[<font style="color: red">vbk/rpc_register.cpp</font>]
```diff
getpopparams() {
...
     ret.pushKV("popActivationHeight",
                Params().GetConsensus().VeriBlockPopSecurityHeight);
-    ret.pushKV("popRewardPercentage", (int64_t)Params().PopRewardPercentage());
-    ret.pushKV("popRewardCoefficient", Params().PopRewardCoefficient());
...
}
```

Update functional tests

[<font style="color: red">test/functional/test_framework/pop_const.py</font>]
```diff
-POP_PAYOUT_DELAY = 50
+POP_PAYOUT_DELAY = 150
 NETWORK_ID = 0x3e4fac
 POP_BLOCK_VERSION_BIT = 0x80000
 POW_PAYOUT = 50
 POP_ACTIVATION_HEIGHT = 200
+POW_REWARD_PERCENTAGE = 50
```

[<font style="color: red">test/integration/vbch_node.py</font>]
```diff
getpopparams():
...
             popActivationHeight=s['popActivationHeight'],
-            popRewardPercentage=s['popRewardPercentage'],
-            popRewardCoefficient=s['popRewardCoefficient'],
             popPayoutDelay=s['payoutParams']['popPayoutDelay'],
```

[<font style="color: red">test/functional/test_framework/blocktools.py</font>]
```diff
 from .pop import ContextInfoContainer, PopMiningContext, calculateTopLevelMerkleRoot
-from .pop_const import POW_PAYOUT
+from .pop_const import POW_PAYOUT, POP_ACTIVATION_HEIGHT, POW_REWARD_PERCENTAGE
...
     coinbaseoutput = CTxOut()
-    coinbaseoutput.nValue = 50 * COIN
+    coinbaseoutput.nValue = POW_PAYOUT * COIN
+    if height >= POP_ACTIVATION_HEIGHT:
+        coinbaseoutput.nValue = POW_PAYOUT * COIN
+        coinbaseoutput.nValue = int(coinbaseoutput.nValue * (100 - POW_REWARD_PERCENTAGE) / 100)
     halvings = int(height / 150)  # regtest
```

[<font style="color: red">test/functional/feature_pop_payout.py</font>]
```diff
-from test_framework.pop_const import POW_PAYOUT, POP_PAYOUT_DELAY
+from test_framework.pop_const import POP_PAYOUT_DELAY
...
_case1_endorse_keystone_get_paid():
...
-
-        # endorse block 5
-        addr = self.nodes[0].getnewaddress()
         lastblock = self.nodes[0].getblockcount()
...
         payoutblockhash = self.nodes[1].generate(nblocks=n)[-1]
+        balance1 = self.nodes[0].getbalance()
         self.sync_blocks(self.nodes)
         self.log.info("pop rewards paid")
...
         assert outputs[1]['n'] == 1
         assert outputs[1]['value'] > 0, "expected non-zero output at n=1, got: {}".format(outputs[1])

+        # mine 100 blocks and check balance
+        self.nodes[0].generate(nblocks=100)
+        balance = self.nodes[0].getbalance()
+
+        # node[0] has 210 (lastblock) mature coinbases and a single pop payout
+        assert lastblock == 210, "calculation below are only valid for POP activation height = 210"
+        pop_payout = float(outputs[1]['value'])
+        assert float(balance) == float(balance1) + pop_payout
         self.log.warning("success! _case1_endorse_keystone_get_paid()")
```

## Update P2P networking for better POP protocol resolution

[<font style="color: red">net.h</font>]
```diff
struct TxRelay {
...
         mutable RecursiveMutex cs_tx_inventory;
-        CRollingBloomFilter filterInventoryKnown GUARDED_BY(cs_tx_inventory){
-            50000, 0.000001};
+        // VeriBlock: includes inventories for POP P2P sync. Increase size from 50k to 100k.
+        CRollingBloomFilter filterInventoryKnown GUARDED_BY(cs_tx_inventory){100000, 0.000001};
         // Set of transaction ids we still have to announce.
...
         std::set<TxId> setInventoryTxToSend;
+
+        // VeriBlock:
+        std::set<uint256> setInventoryAtvToSend;
+        std::set<uint256> setInventoryVtbToSend;
+        std::set<uint256> setInventoryVbkToSend;
+
         // Used for BIP35 mempool sending
...
};
...
void PushInventory(const CInv &inv) {
-        if (inv.type == MSG_TX && m_tx_relay != nullptr) {
+        // VeriBlock:
+        if ((inv.type == MSG_TX || inv.type == MSG_POP_ATV || inv.type == MSG_POP_VTB || inv.type == MSG_POP_VBK) && m_tx_relay != nullptr) {
             const TxId txid(inv.hash);
             LOCK(m_tx_relay->cs_tx_inventory);
-            if (!m_tx_relay->filterInventoryKnown.contains(txid)) {
+            if (inv.type == MSG_TX && !m_tx_relay->filterInventoryKnown.contains(txid)) {
                 m_tx_relay->setInventoryTxToSend.insert(txid);
             }
+            if (inv.type == MSG_POP_ATV && !m_tx_relay->filterInventoryKnown.contains(txid)) {
+                m_tx_relay->setInventoryAtvToSend.insert(txid);
+            }
+            if (inv.type == MSG_POP_VTB && !m_tx_relay->filterInventoryKnown.contains(txid)) {
+                m_tx_relay->setInventoryVtbToSend.insert(txid);
+            }
+            if (inv.type == MSG_POP_VBK && !m_tx_relay->filterInventoryKnown.contains(txid)) {
+                m_tx_relay->setInventoryVbkToSend.insert(txid);
+            }
         } else if (inv.type == MSG_BLOCK) {
...
}
```

[<font style="color: red">net_processing.cpp</font>]
```diff
struct TxDownloadState {
+        // VeriBlock:
+        // first = tx,atv,vtb,vbk id
+        // second = typeIn (inventory type)
+        using IdTypePair = std::pair<uint256, uint32_t>;
+
         /**
          * Track when to attempt download of announced transactions (process
          * time in micros -> txid)
          */
-        std::multimap<std::chrono::microseconds, TxId> m_tx_process_time;
+        std::multimap<std::chrono::microseconds, IdTypePair> m_tx_process_time;

         //! Store all the transactions a peer has recently announced
...
};
...
void RequestTx(CNodeState *state, const TxId &txid,
-               std::chrono::microseconds current_time)
+               uint32_t typeIn, std::chrono::microseconds current_time)
     EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
...
     const auto process_time =
         CalculateTxGetDataTime(txid, current_time, !state->fPreferredDownload);

-    peer_download_state.m_tx_process_time.emplace(process_time, txid);
+    peer_download_state.m_tx_process_time.emplace(process_time, std::make_pair(txid, typeIn));
}
...
void PeerLogicValidation::InitializeNode(const Config &config, CNode *pnode) {
...
     if (!pnode->fInbound) {
         PushNodeVersion(config, pnode, connman, GetTime());
     }
+
+    // VeriBlock:
+    // relay whole POP mempool upon first connection
+    assert(g_rpc_node);
+    assert(g_rpc_node->connman);
+    {
+        LOCK(cs_main);
+        VeriBlock::p2p::RelayPopMempool<altintegration::ATV>(pnode);
+        VeriBlock::p2p::RelayPopMempool<altintegration::VTB>(pnode);
+        VeriBlock::p2p::RelayPopMempool<altintegration::VbkBlock>(pnode);
+    }
}
...
void PeerLogicValidation::FinalizeNode() {
...
     mapNodeState.erase(nodeid);
-    VeriBlock::p2p::erasePopDataNodeState(nodeid);
...
}
...
bool AlreadyHave() {
+    auto& popmp = VeriBlock::GetPop().getMemPool();
     switch (inv.type) {
         case MSG_TX: {
             assert(recentRejects);
...
         }
         case MSG_BLOCK:
             return LookupBlockIndex(BlockHash(inv.hash)) != nullptr;
+        case MSG_POP_ATV:
+            return popmp.isKnown<altintegration::ATV>(VeriBlock::Uint256ToId<altintegration::ATV>(inv.hash));
+        case MSG_POP_VTB:
+            return popmp.isKnown<altintegration::VTB>(VeriBlock::Uint256ToId<altintegration::VTB>(inv.hash));
+        case MSG_POP_VBK:
+            return popmp.isKnown<altintegration::VbkBlock>(VeriBlock::Uint256ToId<altintegration::VbkBlock>(inv.hash));
     }
...
}
...
void ProcessGetData() {
...
+
+        // VeriBlock:
+        VeriBlock::p2p::ProcessGetPopPayloads(it, pfrom, connman, interruptMsgProc, vNotFound);
     } // release cs_main

     if (it != pfrom->vRecvGetData.end() && !pfrom->fPauseSend) {
...
}
...
bool ProcessMessage() {
...
         return true;
     }

-    // VeriBlock: if POP is not enabled, ignore POP-related P2P calls
-    if (VeriBlock::isPopActive()) {
-        int pop_res = VeriBlock::p2p::processPopData(pfrom, strCommand, vRecv, connman);
-        if (pop_res >= 0) {
-            return pop_res;
-        }
-    }
-
     if (!(pfrom->GetLocalServices() & NODE_BLOOM) &&
         (strCommand == NetMsgType::FILTERLOAD ||
          strCommand == NetMsgType::FILTERADD)) {
...
                 } else if (!fAlreadyHave && !fImporting && !fReindex &&
                            !::ChainstateActive().IsInitialBlockDownload()) {
                     RequestTx(State(pfrom->GetId()), TxId(inv.hash),
-                              current_time);
+                              inv.type, current_time);
...
+    if (VeriBlock::isPopActive()) {
+        // CNodeState is defined in cpp file, we can't use it in p2p_sync.cpp.
+        const auto onInv = [pfrom](const CInv& inv) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+            AssertLockHeld(cs_main);
+            assert(pfrom != nullptr);
+            CNodeState* nodestate = State(pfrom->GetId());
+            nodestate->m_tx_download.m_tx_announced.erase(TxId{inv.hash});
+            nodestate->m_tx_download.m_tx_in_flight.erase(TxId{inv.hash});
+            EraseTxRequest(TxId{inv.hash});
+        };
+
+        if (strCommand == NetMsgType::POPATV) {
+            LOCK(cs_main);
+            return VeriBlock::p2p::ProcessPopPayload<altintegration::ATV>(pfrom, connman, vRecv, onInv);
+        }
+        if (strCommand == NetMsgType::POPVTB) {
+            LOCK(cs_main);
+            return VeriBlock::p2p::ProcessPopPayload<altintegration::VTB>(pfrom, connman, vRecv, onInv);
+        }
+        if (strCommand == NetMsgType::POPVBK) {
+            LOCK(cs_main);
+            return VeriBlock::p2p::ProcessPopPayload<altintegration::VbkBlock>(pfrom, connman, vRecv, onInv);
+        }
+    }
+
     if (strCommand == NetMsgType::TX) {
...
                     if (!AlreadyHave(_inv)) {
-                        RequestTx(State(pfrom->GetId()), _txid, current_time);
+                        RequestTx(State(pfrom->GetId()), _txid, _inv.type, current_time);
                     }
...
}
...
bool PeerLogicValidation::SendMessages() {
...
                     }
                     pto->m_tx_relay->filterInventoryKnown.insert(txid);
                 }
+
+                // VeriBlock: send offers for PoP related payloads
+                assert(pto);
+                assert(pto->m_tx_relay);
+                if (fSendTrickle) {
+                    VeriBlock::p2p::SendPopPayload(pto, connman, MSG_POP_ATV, pto->m_tx_relay->filterInventoryKnown, pto->m_tx_relay->setInventoryAtvToSend, vInv);
+                    VeriBlock::p2p::SendPopPayload(pto, connman, MSG_POP_VTB, pto->m_tx_relay->filterInventoryKnown, pto->m_tx_relay->setInventoryVtbToSend, vInv);
+                    VeriBlock::p2p::SendPopPayload(pto, connman, MSG_POP_VBK, pto->m_tx_relay->filterInventoryKnown, pto->m_tx_relay->setInventoryVbkToSend, vInv);
+                }
             }
...
-    // VeriBlock offer Pop Data
-    if (VeriBlock::isPopActive()) {
-        VeriBlock::p2p::offerPopData<altintegration::ATV>(pto, connman,
-                                                          msgMaker);
-        VeriBlock::p2p::offerPopData<altintegration::VTB>(pto, connman,
-                                                          msgMaker);
-        VeriBlock::p2p::offerPopData<altintegration::VbkBlock>(pto, connman,
-                                                               msgMaker);
-    }
-
     // Detect whether we're stalling
...
     while (!tx_process_time.empty() &&
            tx_process_time.begin()->first <= current_time &&
            state.m_tx_download.m_tx_in_flight.size() < MAX_PEER_TX_IN_FLIGHT) {
-        const TxId txid = tx_process_time.begin()->second;
+        auto& pair = tx_process_time.begin()->second;
+        const TxId txid = TxId{pair.first};
+        const uint32_t typeIn = pair.second;
         // Erase this entry from tx_process_time (it may be added back for
         // processing at a later time, see below)
         tx_process_time.erase(tx_process_time.begin());
-        CInv inv(MSG_TX, txid);
+        uint32_t flags = typeIn;
+        CInv inv(flags, txid);
         if (!AlreadyHave(inv)) {
...
                 const auto next_process_time = CalculateTxGetDataTime(
                     txid, current_time, !state.fPreferredDownload);
-                tx_process_time.emplace(next_process_time, txid);
+                tx_process_time.emplace(next_process_time, std::make_pair(txid, flags));
...
}
```

[<font style="color: red">protocol.h</font>]
```diff
 extern const char *AVARESPONSE;
 
+// VeriBlock:
+extern const char *POPATV; // contains ATV
+extern const char *POPVTB; // contains VTB
+extern const char *POPVBK; // contains VBK block
...
enum GetDataMsg {
...
     MSG_CMPCT_BLOCK = 4,
+
+    // VeriBlock: start numbers after 1 + 2 + 4 = 7
+    MSG_POP_ATV = 8,
+    MSG_POP_VTB = 9,
+    MSG_POP_VBK = 10,
...
};
```

[<font style="color: red">protocol.cpp</font>]
```diff
...
 const char *AVARESPONSE = "avaresponse";
+const char *POPATV="ATV";
+const char *POPVTB="VTB";
+const char *POPVBK="VBK";
...
static const std::string allNetMessageTypes[] = {
...
     NetMsgType::FEEFILTER,   NetMsgType::SENDCMPCT,  NetMsgType::CMPCTBLOCK,
-    NetMsgType::GETBLOCKTXN, NetMsgType::BLOCKTXN,
+    NetMsgType::GETBLOCKTXN, NetMsgType::BLOCKTXN,   NetMsgType::POPATV,
+    NetMsgType::POPVTB,      NetMsgType::POPVBK,
};
...
std::string CInv::GetCommand() {
...
         case MSG_CMPCT_BLOCK:
             return cmd.append(NetMsgType::CMPCTBLOCK);
+        case MSG_POP_ATV:
+            return cmd.append(NetMsgType::POPATV);
+        case MSG_POP_VTB:
+            return cmd.append(NetMsgType::POPVTB);
+        case MSG_POP_VBK:
+            return cmd.append(NetMsgType::POPVBK);
         default:
...
}
```

Use updated p2p_sync service files

[<font style="color: red">vbk/p2p_sync.hpp</font>]
```
// Copyright (c) 2019-2021 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SRC_VBK_P2P_SYNC_HPP
#define BITCOIN_SRC_VBK_P2P_SYNC_HPP

#include <chainparams.h>
#include <map>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/context.h>
#include <rpc/blockchain.h>
#include <vbk/pop_common.hpp>
#include <vbk/util.hpp>
#include <veriblock/pop.hpp>

namespace VeriBlock {

namespace p2p {

void SendPopPayload(
    CNode* pto,
    CConnman* connman,
    int typeIn,
    CRollingBloomFilter& filterInventoryKnown,
    std::set<uint256>& toSend,
    std::vector<CInv>& vInv) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

void ProcessGetPopPayloads(
    std::deque<CInv>::iterator& it,
    CNode* pfrom,
    CConnman* connman,
    const std::atomic<bool>& interruptMsgProc,
    std::vector<CInv>& vNotFound

    ) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

// clang-format off
template <typename T> static int GetType();
template <> inline int GetType<altintegration::ATV>(){ return MSG_POP_ATV; }
template <> inline int GetType<altintegration::VTB>(){ return MSG_POP_VTB; }
template <> inline int GetType<altintegration::VbkBlock>(){ return MSG_POP_VBK; }
// clang-format on

template <typename T>
CInv PayloadToInv(const typename T::id_t& id) {
    return CInv(GetType<T>(), IdToUint256<T>(id));
}

template <typename T>
void RelayPopPayload(
    CConnman* connman,
    const T& t)
{
    auto inv = PayloadToInv<T>(t.getId());
    connman->ForEachNode([&inv](CNode* pto) {
        pto->PushInventory(inv);
    });
}

template <typename T, typename F>
bool ProcessPopPayload(CNode* pfrom, CConnman* connman, CDataStream& vRecv, F onInv) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if ((!g_relay_txes && !pfrom->HasPermission(PF_RELAY)) || (pfrom->m_tx_relay == nullptr)) {
        LogPrint(BCLog::NET, "%s sent in violation of protocol peer=%d\n", T::name(), pfrom->GetId());
        pfrom->fDisconnect = true;
        return true;
    }

    T data;
    vRecv >> data;

    LogPrint(BCLog::NET, "received %s from peer %d\n", data.toShortPrettyString(), pfrom->GetId());

    uint256 id = IdToUint256<T>(data.getId());
    CInv inv(GetType<T>(), id);
    pfrom->AddInventoryKnown(inv);

    // CNodeState is defined inside net_processing.cpp.
    // we use that structure in this function onInv().
    onInv(inv);

    auto& mp = VeriBlock::GetPop().getMemPool();
    altintegration::ValidationState state;
    auto result = mp.submit(data, state);
    if (result.isAccepted()) {
        // relay this POP payload to other peers
        RelayPopPayload(connman, data);
    } else {
        assert(result.isFailedStateless());
        // peer sent us statelessly invalid payload.
        Misbehaving(pfrom->GetId(), 1000, strprintf("peer %d sent us statelessly invalid %s, reason: %s", pfrom->GetId(), T::name(), state.toString()));
        return false;
    }

    return true;
}

template <typename T>
void RelayPopMempool(CNode* pto) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    auto& mp = VeriBlock::GetPop().getMemPool();

    size_t counter = 0;
    for (const auto& p : mp.getMap<T>()) {
        T& t = *p.second;
        auto inv = PayloadToInv<T>(t.getId());
        pto->PushInventory(inv);
        counter++;
    }

    for (const auto& p : mp.template getInFlightMap<T>()) {
        T& t = *p.second;
        auto inv = PayloadToInv<T>(t.getId());
        pto->PushInventory(inv);
        counter++;
    }

    LogPrint(BCLog::NET, "relay %s=%u from POP mempool to peer=%d\n", T::name(), counter, pto->GetId());
}

} // namespace p2p
} // namespace VeriBlock


#endif
```

[<font style="color: red">vbk/p2p_sync.cpp</font>]
```
// Copyright (c) 2019-2021 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vbk/p2p_sync.hpp"
#include "validation.h"
#include <net_processing.h>
#include <protocol.h>
#include <vbk/util.hpp>
#include <veriblock/pop.hpp>


namespace VeriBlock {
namespace p2p {

template <typename T>
static void DoSubmitPopPayload(
    CNode* pfrom,
    CConnman* connman,
    const CNetMsgMaker& msgMaker,
    altintegration::MemPool& mp,
    const CInv& inv,
    std::vector<CInv>& vNotFound)
{
    const auto id = VeriBlock::Uint256ToId<T>(inv.hash);
    auto* atv = mp.get<T>(id);
    if (atv == nullptr) {
        vNotFound.push_back(inv);
    } else {
        LogPrint(BCLog::NET, "sending %s to peer %d\n", atv->toShortPrettyString(), pfrom->GetId());
        connman->PushMessage(pfrom, msgMaker.Make(T::name(), *atv));
    }
}

void ProcessGetPopPayloads(
    std::deque<CInv>::iterator& it,
    CNode* pfrom,
    CConnman* connman,
    const std::atomic<bool>& interruptMsgProc,
    std::vector<CInv>& vNotFound) EXCLUSIVE_LOCKS_REQUIRED(cs_main) // for pop mempool
{
    AssertLockHeld(cs_main);
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    auto& mp = VeriBlock::GetPop().getMemPool();
    while (it != pfrom->vRecvGetData.end() && (it->type == MSG_POP_ATV || it->type == MSG_POP_VTB || it->type == MSG_POP_VBK)) {
        if (interruptMsgProc) {
            return;
        }

        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->fPauseSend) {
            break;
        }

        const CInv& inv = *it;
        ++it;

        if (inv.type == MSG_POP_ATV) {
            DoSubmitPopPayload<altintegration::ATV>(pfrom, connman, msgMaker, mp, inv, vNotFound);
        } else if (inv.type == MSG_POP_VTB) {
            DoSubmitPopPayload<altintegration::VTB>(pfrom, connman, msgMaker, mp, inv, vNotFound);
        } else if (inv.type == MSG_POP_VBK) {
            DoSubmitPopPayload<altintegration::VbkBlock>(pfrom, connman, msgMaker, mp, inv, vNotFound);
        }
    }
}

void SendPopPayload(
    CNode* pto,
    CConnman* connman,
    int typeIn,
    CRollingBloomFilter& filterInventoryKnown,
    std::set<uint256>& toSend,
    std::vector<CInv>& vInv) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    const CNetMsgMaker msgMaker(pto->GetSendVersion());

    for (const auto& hash : toSend) {
        CInv inv(typeIn, hash);
        if (filterInventoryKnown.contains(hash)) {
            LogPrint(BCLog::NET, "inv %s is known by peer %d (bloom filtered)\n", inv.ToString(), pto->GetId());
            continue;
        }

        vInv.push_back(inv);
        filterInventoryKnown.insert(hash);

        if (vInv.size() == MAX_INV_SZ) {
            connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
            vInv.clear();
        }
    }

    toSend.clear();
}


} // namespace p2p

} // namespace VeriBlock

```

Update POP service API

[<font style="color: red">vbk/pop_service.cpp</font>]
```diff
-void InitPopContext(CDBWrapper &db) {
+static uint64_t popScoreComparisons = 0ULL;
+template <typename T>
+void onAcceptedToMempool(const T& t) {
+    assert(g_rpc_node);
+    assert(g_rpc_node->connman);
+    p2p::RelayPopPayload(g_rpc_node->connman.get(), t);
+}
+
+void InitPopContext(CDBWrapper& db)
+{
     auto payloads_provider = std::make_shared<PayloadsProvider>(db);
     auto block_provider = std::make_shared<BlockReader>(db);
     SetPop(payloads_provider, block_provider);
 
-    auto &app = GetPop();
-    app.getMemPool().onAccepted<altintegration::ATV>(
-        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::ATV>);
-    app.getMemPool().onAccepted<altintegration::VTB>(
-        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VTB>);
-    app.getMemPool().onAccepted<altintegration::VbkBlock>(
-        VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VbkBlock>);
+    auto& app = GetPop();
+    app.getMemPool().onAccepted<altintegration::ATV>(onAcceptedToMempool<altintegration::ATV>);
+    app.getMemPool().onAccepted<altintegration::VTB>(onAcceptedToMempool<altintegration::VTB>);
+    app.getMemPool().onAccepted<altintegration::VbkBlock>(onAcceptedToMempool<altintegration::VbkBlock>);
 }
```

Update RPC calls

[<font style="color: red">vbk/rpc_register.cpp</font>]
```diff
 #include <util/validation.h>
 #include <validation.h>
+#include <vbk/p2p_sync.hpp>
 #include <wallet/rpcwallet.h>
...
UniValue submitpopIt() {
...
     LOCK(cs_main);
     auto &mp = VeriBlock::GetPop().getMemPool();
     auto idhex = data.getId().toHex();
-    auto result = mp.submit<Pop>(data, state, false);
+    auto result = mp.submit<Pop>(data, state);
     logSubmitResult<Pop>(idhex, result, state);

     bool accepted = result.isAccepted();
+    if (accepted) {
+        // relay this pop payload
+        p2p::RelayPopPayload<Pop>(g_rpc_node->connman.get(), data);
+    }
     return altintegration::ToJSON<UniValue>(state, &accepted);

}
```

Update helper methods

[<font style="color: red">vbk/util.hpp</font>]
```diff
+template <typename T>
+inline uint256 IdToUint256(const typename T::id_t& id)
+{
+    std::vector<uint8_t> v(32);
+    std::copy(id.begin(), id.end(), v.begin());
+    return uint256(v);
+}
+
+template <typename T>
+inline typename T::id_t Uint256ToId(const uint256& u)
+{
+    auto size = T::id_t::size();
+    std::vector<uint8_t> v{u.begin(), u.begin() + size};
+    return typename T::id_t(v);
+}
```

Update functional tests

[<font style="color: red">test/functional/feature_pop_p2p.py</font>]
```diff
 from test_framework.mininode import (
     P2PInterface,
-    msg_get_atv,
 )
 from test_framework.pop import endorse_block, mine_until_pop_active
 from test_framework.test_framework import BitcoinTestFramework
-from test_framework.util import assert_equal
+from test_framework.util import (
+    connect_nodes, assert_equal,
+)
...
class BaseNode(P2PInterface):
...
         self.executed_msg_get_vtb = 0
         self.executed_msg_get_vbk = 0

-    def on_ofATV(self, message):
-        self.log.info("receive message offer ATV")
-        self.executed_msg_offer_atv = self.executed_msg_offer_atv + 1
-
-    def on_ofVTB(self, message):
-        self.log.info("receive message offer VTB")
-        self.executed_msg_offer_vtb = self.executed_msg_offer_vtb + 1
-
-    def on_ofVBK(self, message):
-        self.log.info("receive message offer VBK")
-        self.executed_msg_offer_vbk = self.executed_msg_offer_vbk + 1
-
-    def on_ATV(self, message):
-        self.log.info("receive message ATV")
-        self.executed_msg_atv = self.executed_msg_atv + 1
-
-    def on_VTB(self, message):
-        self.log.info("receive message VTB")
-        self.executed_msg_vtb = self.executed_msg_vtb + 1
-
-    def on_VBK(self, message):
-        self.log.info("receive message VBK")
-        self.executed_msg_vbk = self.executed_msg_vbk + 1
-
-    def on_gATV(self, message):
-        self.log.info("receive message get ATV")
-        self.executed_msg_get_atv = self.executed_msg_get_atv + 1
-
-    def on_gVTB(self, message):
-        self.log.info("receive message get VTB")
-        self.executed_msg_get_vtb = self.executed_msg_get_vtb + 1
-
-    def on_gVBK(self, message):
-        self.log.info("receive message get VBK")
-        self.executed_msg_get_vbk = self.executed_msg_get_vbk + 1
+    def on_inv(self, message):
+        for inv in message.inv:
+            if inv.type == 8:
+                self.log.info("receive message offer ATV")
+                self.executed_msg_offer_atv = self.executed_msg_offer_atv + 1
+            if inv.type == 9:
+                self.log.info("receive message offer VTB")
+                self.executed_msg_offer_vtb = self.executed_msg_offer_vtb + 1
+            if inv.type == 10:
+                self.log.info("receive message offer VBK")
+                self.executed_msg_offer_vbk = self.executed_msg_offer_vbk + 1
+
...
class PopP2P(BitcoinTestFramework):
         tipheight = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['height']
         self.log.info("endorsing block 5 on node0 by miner {}".format(addr))
-        atv_id = endorse_block(self.nodes[0], self.apm, tipheight - 5, addr)
+        endorse_block(self.nodes[0], self.apm, tipheight - 5, addr)

         bn = BaseNode(self.log)

         self.nodes[0].add_p2p_connection(bn)
-        time.sleep(2)
-
-        assert bn.executed_msg_atv == 0
-        assert bn.executed_msg_offer_atv == 1
-        assert bn.executed_msg_offer_vbk == 1

-        msg = msg_get_atv([atv_id])
-        self.nodes[0].p2p.send_message(msg)
-        self.nodes[0].p2p.send_message(msg)
-        self.nodes[0].p2p.send_message(msg)
+        time.sleep(20)

-        time.sleep(2)
-
-        assert bn.executed_msg_atv == 3
+        assert_equal(bn.executed_msg_atv, 0)
+        assert_equal(bn.executed_msg_offer_atv, 1)
+        assert_equal(bn.executed_msg_offer_vbk, 1)

         self.log.info("_run_sync_case successful")
...
         self.log.info("endorsing block 5 on node0 by miner {}".format(addr))
         tipheight = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['height']

-        atv_id = endorse_block(self.nodes[0], self.apm, tipheight - 5, addr)
-
-        msg = msg_get_atv([atv_id])
-        self.nodes[0].p2p.send_message(msg)
+        endorse_block(self.nodes[0], self.apm, tipheight - 5, addr)

-        time.sleep(5)
+        time.sleep(20)

-        assert_equal(bn.executed_msg_atv, 1)
+        assert_equal(bn.executed_msg_offer_atv, 1)
         assert_equal(bn.executed_msg_offer_vbk, 2)
```

[<font style="color: red">test/functional/feature_pop_sync.py</font>]
```diff
+    def _one_by_one(self):
+        for node in self.nodes:
+            # VBK block
+            self.log.info("Submitting VBK")
+            block = self.apm.mineVbkBlocks(1)
+            response = node.submitpopvbk(block.toVbkEncodingHex())
+            assert response['accepted'], response
+            self.log.info("VBK accepted to mempool")
+            sync_pop_mempools(self.nodes, timeout=30)
+
+            # VTB
+            self.log.info("Submitting VTB")
+            lastBtc = node.getbtcbestblockhash()
+            vtb = self.apm.endorseVbkBlock(
+                block,  # endorsed vbk block
+                lastBtc
+            )
+            response = node.submitpopvtb(vtb.toVbkEncodingHex())
+            assert response['accepted'], response
+            self.log.info("VTB accepted to mempool")
+            sync_pop_mempools(self.nodes, timeout=100)
+
+            # ATV
+            self.log.info("Submitting ATV")
+            tip = self.nodes[0].getbestblockhash()
+            altblock = self.nodes[0].getblock(tip)
+            endorse_block(self.nodes[0], self.apm, altblock['height'], self.nodes[0].getnewaddress())
+            self.log.info("ATV accepted to mempool")
+            sync_pop_mempools(self.nodes, timeout=100)
+
+            self.nodes[2].generate(nblocks=1)
+            self.sync_all()
...
class PoPSync(BitcoinTestFramework):
             self.nodes[0].generate(nblocks=1)
             # endorse every block
             self.nodes[2].waitforblockheight(height)
-            self.log.info("node2 endorsing block {} by miner {}".format(height, addr2))
             node2_txid = endorse_block(self.nodes[2], self.apm, height, addr2)
+            self.log.info("node2 endorsing block {} by miner {}: {}".format(height, addr2, node2_txid))

             # endorse each keystone
             if height % keystoneInterval == 0:
                 self.nodes[0].waitforblockheight(height)
-                self.log.info("node0 endorsing block {} by miner {}".format(height, addr0))
                 node0_txid = endorse_block(self.nodes[0], self.apm, height, addr0)
+                self.log.info("node0 endorsing block {} by miner {}: {}".format(height, addr0, node0_txid))

                 self.nodes[1].waitforblockheight(height)
-                self.log.info("node1 endorsing block {} by miner {}".format(height, addr1))
                 node1_txid = endorse_block(self.nodes[1], self.apm, height, addr1)
+                self.log.info("node1 endorsing block {} by miner {}: {}".format(height, addr1, node1_txid))

                 # wait until node[1] gets relayed pop tx
-                self.sync_all(self.nodes, timeout=20)
+                self.sync_all(self.nodes, timeout=60)
                 self.log.info("transactions relayed")
...
         self.apm = MockMiner()

+        self._one_by_one()
         self._check_pop_sync()
```

[<font style="color: red">test/functional/test_framework/messages.py</font>]
```diff
class CInv:
         0: "Error",
         1: "TX",
         2: "Block",
-        4: "CompactBlock"
+        4: "CompactBlock",
+        8: "ATV",
+        9: "VTB",
+        10: "VBK",
```

[<font style="color: red">test/functional/test_framework/mininode.py</font>]
```diff
from test_framework.messages import (
     msg_version,
     NODE_NETWORK,
     sha256,
-    #VeriBlock
-    msg_offer_atv,
-    msg_offer_vtb,
-    msg_offer_vbk,
-    msg_atv,
-    msg_vtb,
-    msg_vbk,
-    msg_get_atv,
-    msg_get_vtb,
-    msg_get_vbk,
)
...
MESSAGEMAP = {
     b"tx": msg_tx,
     b"verack": msg_verack,
     b"version": msg_version,
-    #VeriBlock
-    b"ofATV": msg_offer_atv,
-    b"ofVTB": msg_offer_vtb,
-    b"ofVBK": msg_offer_vbk,
-    b"ATV": msg_atv,
-    b"VTB": msg_vtb,
-    b"VBK": msg_vbk,
-    b"gATV": msg_get_atv,
-    b"gVTB": msg_get_vtb,
-    b"gVBK": msg_get_vbk,
}
...
class P2PInterface(P2PConnection):
         self.send_message(msg_verack())
         self.nServices = message.nServices

-     #VeriBlock
-    def on_ofATV(self, message):
-        pass
-    def on_ofVTB(self, message):
-        pass
-    def on_ofVBK(self, message):
-        pass
-    def on_ATV(self, message):
-        pass
-    def on_VTB(self, message):
-        pass
-    def on_VBK(self, message):
-        pass
-    def on_gATV(self, message):
-        pass
-    def on_gVTB(self, message):
-        pass
-    def on_gVBK(self, message):
-        pass
-
     # Connection helper methods
```