#include <chainparams.h>
#include <consensus/merkle.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <serialize.h>
#include <util/validation.h>
#include <validation.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h> // for CWallet

#include <fstream>
#include <set>

#include <vbk/adaptors/univalue_json.hpp>
#include <vbk/merkle.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/rpc_register.hpp>
#include <vbk/util.hpp>

namespace VeriBlock {

namespace {
    void EnsurePopEnabled() {
        if (!VeriBlock::isPopEnabled()) {
            throw JSONRPCError(RPC_MISC_ERROR,
                               strprintf("POP protocol is not enabled. "
                                         "Current=%d, bootstrap height=%d",
                                         ChainActive().Height(),
                                         VeriBlock::GetPop()
                                             .getConfig()
                                             .getAltParams()
                                             .getBootstrapBlock()
                                             .getHeight()));
        }
    }

    void EnsurePopActive() {
        auto tipheight = ChainActive().Height();
        if (!Params().isPopActive(tipheight)) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                strprintf("POP protocol is not active. Current=%d, activation "
                          "height=%d",
                          tipheight,
                          Params().GetConsensus().VeriBlockPopSecurityHeight)

            );
        }
    }
} // namespace

namespace {
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

namespace {

    UniValue getpopdata(const Config &config, const CBlockIndex *index) {
        if (!index) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        UniValue result(UniValue::VOBJ);

        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << index->GetBlockHeader();
        result.pushKV("block_header", HexStr(ssBlock));

        auto block = GetBlockChecked(index);

        auto txRoot = BlockMerkleRoot(block).asVector();
        using altintegration::AuthenticatedContextInfoContainer;
        auto authctx = AuthenticatedContextInfoContainer::createFromPrevious(
            txRoot, block.popData.getMerkleRoot(),
            // we build authctx based on previous block
            VeriBlock::GetAltBlockIndex(index->pprev),
            VeriBlock::GetPop().getConfig().getAltParams());
        result.pushKV("authenticated_context",
                      altintegration::ToJSON<UniValue>(authctx));

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

    UniValue getpopdatabyheight(const Config &config,
                                const JSONRPCRequest &request) {
        if (request.fHelp || request.params.size() != 1)
            throw std::runtime_error(
                "getpopdatabyheight block_height\n"
                "\nFetches the data relevant to PoP-mining the given block.\n"
                "\nArguments:\n"
                "1. block_height         (numeric, required) Endorsed block "
                "height from active chain\n"
                "\nResult:\n"
                "TODO: write docs\n"
                "}\n"
                "\nExamples:\n" +
                HelpExampleCli("getpopdatabyheight", "1000") +
                HelpExampleRpc("getpopdatabyheight", "1000"));

        EnsurePopEnabled();

        auto wallet = GetWalletForJSONRPCRequest(request);
        if (!EnsureWalletIsAvailable(wallet.get(), request.fHelp)) {
            return NullUniValue;
        }

        // Make sure the results are valid at least up to the most recent block
        // the user could have gotten from another RPC command prior to now
        wallet->BlockUntilSyncedToCurrentChain();

        int height = request.params[0].get_int();

        LOCK(cs_main);
        return getpopdata(config, ChainActive()[height]);
    }

    UniValue getpopdatabyhash(const Config &config,
                              const JSONRPCRequest &request) {
        if (request.fHelp || request.params.size() != 1)
            throw std::runtime_error(
                "getpopdatabyhash block_height\n"
                "\nFetches the data relevant to PoP-mining the given block.\n"
                "\nArguments:\n"
                "1. hash         (string, required) Endorsed block hash.\n"
                "\nResult:\n"
                "TODO: write docs\n"
                "}\n"
                "\nExamples:\n" +
                HelpExampleCli("getpopdatabyhash", "xxx") +
                HelpExampleRpc("getpopdatabyhash", "xxx"));

        EnsurePopEnabled();

        auto wallet = GetWalletForJSONRPCRequest(request);
        if (!EnsureWalletIsAvailable(wallet.get(), request.fHelp)) {
            return NullUniValue;
        }

        // Make sure the results are valid at least up to the most recent block
        // the user could have gotten from another RPC command prior to now
        wallet->BlockUntilSyncedToCurrentChain();

        std::string hex = request.params[0].get_str();
        LOCK(cs_main);

        const auto hash = uint256S(hex);
        return getpopdata(config, LookupBlockIndex(BlockHash(hash)));
    }

} // namespace

template <typename pop_t>
bool parsePayloads(const UniValue &array, std::vector<pop_t> &out,
                   altintegration::ValidationState &state) {
    std::vector<pop_t> payloads;
    for (uint32_t idx = 0u, size = array.size(); idx < size; ++idx) {
        auto &payloads_hex = array[idx];

        auto payloads_bytes =
            ParseHexV(payloads_hex, strprintf("%s[%d]", pop_t::name(), idx));

        pop_t data;
        altintegration::ReadStream stream(payloads_bytes);
        if (!altintegration::DeserializeFromVbkEncoding(stream, data, state)) {
            return state.Invalid("bad-payloads");
        }
        payloads.push_back(data);
    }

    out = payloads;
    return true;
}
template <typename T>
static void logSubmitResult(const std::string idhex,
                            const altintegration::MemPool::SubmitResult &result,
                            const altintegration::ValidationState &state) {
    if (!result.isAccepted()) {
        LogPrintf("rejected to add %s=%s to POP mempool: %s\n", T::name(),
                  idhex, state.toString());
    } else {
        auto s = strprintf("(state: %s)", state.toString());
        LogPrintf("accepted %s=%s to POP mempool %s\n", T::name(), idhex,
                  (state.IsValid() ? "" : s));
    }
}

void check_submitpop(const JSONRPCRequest &request,
                     const std::string &popdata) {
    auto cmdname = strprintf("submitpop%s", popdata);
    RPCHelpMan{
        cmdname,
        "Submit " + popdata,
        {
            {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Serialized " + popdata},
        },
        {},
        RPCExamples{HelpExampleCli(cmdname, "\"<hex>\"") +
                    HelpExampleRpc(cmdname, "\"<hex>\"")},
    }
        .Check(request);
}

template <typename Pop> UniValue submitpopIt(const JSONRPCRequest &request) {
    check_submitpop(request, Pop::name());

    EnsurePopEnabled();
    EnsurePopActive();

    auto payloads_bytes = ParseHexV(request.params[0].get_str(), Pop::name());

    Pop data;
    altintegration::ReadStream stream(payloads_bytes);
    altintegration::ValidationState state;
    if (!altintegration::DeserializeFromVbkEncoding(stream, data, state)) {
        return state.Invalid("bad-data");
    }

    LOCK(cs_main);
    auto &mp = VeriBlock::GetPop().getMemPool();
    auto idhex = data.getId().toHex();
    auto result = mp.submit<Pop>(data, state);
    logSubmitResult<Pop>(idhex, result, state);

    bool accepted = result.isAccepted();
    return altintegration::ToJSON<UniValue>(state, &accepted);
}

UniValue submitpopatv(const Config &config, const JSONRPCRequest &request) {
    return submitpopIt<altintegration::ATV>(request);
}
UniValue submitpopvtb(const Config &config, const JSONRPCRequest &request) {
    return submitpopIt<altintegration::VTB>(request);
}
UniValue submitpopvbk(const Config &config, const JSONRPCRequest &request) {
    return submitpopIt<altintegration::VbkBlock>(request);
}

using VbkTree = altintegration::VbkBlockTree;
using BtcTree = altintegration::VbkBlockTree::BtcTree;

static VbkTree &vbk() {
    return VeriBlock::GetPop().getAltBlockTree().vbk();
}

static BtcTree &btc() {
    return VeriBlock::GetPop().getAltBlockTree().btc();
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

        EnsurePopEnabled();

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

        auto &mp = VeriBlock::GetPop().getMemPool();
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

        auto &mp = pop.getMemPool();
        auto *pl = mp.get<T>(pid);
        if (pl) {
            out = *pl;
            return true;
        }

        // search in the alttree storage
        const auto &containing =
            pop.getAltBlockTree().getPayloadsIndex().getContainingAltBlocks(
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
            return altintegration::ToJSON<UniValue>(
                altintegration::SerializeToHex(out));
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

UniValue getpopparams(const Config &config, const JSONRPCRequest &req) {
    std::string cmdname = "getpopparams";
    // clang-format off
    RPCHelpMan{
        cmdname,
        "\nReturns POP-related parameters set for this altchain.\n",
        {},
        RPCResult{"TODO"},
        RPCExamples{
            HelpExampleCli(cmdname, "") +
            HelpExampleRpc(cmdname, "")},
    }
        .Check(req);
    // clang-format on

    auto &pop_config = VeriBlock::GetPop().getConfig();
    auto ret = altintegration::ToJSON<UniValue>(*pop_config.alt);

    auto *vbkfirst = vbk().getBestChain().first();
    auto *btcfirst = btc().getBestChain().first();
    assert(vbkfirst);
    assert(btcfirst);

    auto _vbk = UniValue(UniValue::VOBJ);
    _vbk.pushKV("hash", vbkfirst->getHash().toHex());
    _vbk.pushKV("height", vbkfirst->getHeight());
    _vbk.pushKV("network", pop_config.vbk.params->networkName());

    auto _btc = UniValue(UniValue::VOBJ);
    _btc.pushKV("hash", btcfirst->getHash().toHex());
    _btc.pushKV("height", btcfirst->getHeight());
    _btc.pushKV("network", pop_config.btc.params->networkName());

    ret.pushKV("vbkBootstrapBlock", _vbk);
    ret.pushKV("btcBootstrapBlock", _btc);

    ret.pushKV("popActivationHeight",
               Params().GetConsensus().VeriBlockPopSecurityHeight);
    ret.pushKV("popRewardPercentage", (int64_t)Params().PopRewardPercentage());
    ret.pushKV("popRewardCoefficient", Params().PopRewardCoefficient());

    return ret;
}

UniValue extractblockinfo(const Config &, const JSONRPCRequest &req) {
    RPCHelpMan{
        "extractblockinfo",
        "Decode provided publication data bytes",
        {
            {"data_array",
             RPCArg::Type::ARR,
             RPCArg::Optional::NO,
             "Serialized publication data",
             {{"data", RPCArg::Type::STR_HEX, "data",
               "Hex serialized publication data"}}},
        },
        {},
        RPCExamples{HelpExampleCli("extractblockinfo", "\"[<hex>]\"") +
                    HelpExampleRpc("extractblockinfo", "\"[<hex>]\"")},
    }
        .Check(req);

    auto encoded_bytes_arr = req.params[0].get_array();
    UniValue res(UniValue::VARR);
    for (size_t i = 0; i < encoded_bytes_arr.size(); ++i) {
        auto encoded_bytes =
            ParseHexV(encoded_bytes_arr[i].get_str(), "publication data bytes");

        // decode publication data
        altintegration::PublicationData pubData;
        {
            altintegration::ValidationState state;
            altintegration::ReadStream stream(encoded_bytes);
            if (!altintegration::DeserializeFromVbkEncoding(stream, pubData,
                                                            state)) {
                return JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "can not deserialize PublicationData err: " +
                        state.toString());
            }
        }

        // decode block header
        CBlockHeader header;
        {
            CDataStream stream(pubData.header, SER_NETWORK, PROTOCOL_VERSION);
            stream >> header;
        }

        // decode AuthenticatedContextInfoContainer
        altintegration::ContextInfoContainer container;
        {
            altintegration::ValidationState state;
            altintegration::ReadStream stream(pubData.contextInfo);
            if (!altintegration::DeserializeFromVbkEncoding(stream, container,
                                                            state)) {
                return JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "can not deserialize ContextInfoContainer err: " +
                        state.toString());
            }
        }

        UniValue val(UniValue::VOBJ);
        val.pushKV("hash", header.GetHash().GetHex());
        val.pushKV("height", container.height);
        val.pushKV("previousHash", header.hashPrevBlock.GetHex());
        val.pushKV("previousKeystone",
                   uint256(container.keystones.firstPreviousKeystone).GetHex());
        val.pushKV(
            "secondPreviousKeystone",
            uint256(container.keystones.secondPreviousKeystone).GetHex());

        res.push_back(val);
    }
    return res;
}

const CRPCCommand commands[] = {
    {"pop_mining", "getpopparams", getpopparams, {}},
    {"pop_mining", "submitpopatv", submitpopatv, {"atv"}},
    {"pop_mining", "submitpopvtb", submitpopvtb, {"vtb"}},
    {"pop_mining", "submitpopvbk", submitpopvbk, {"vbkblock"}},
    {"pop_mining", "getpopdatabyheight", getpopdatabyheight, {"blockheight"}},
    {"pop_mining", "getpopdatabyhash", getpopdatabyhash, {"hash"}},
    {"pop_mining", "getvbkblock", getvbkblock, {"hash"}},
    {"pop_mining", "getbtcblock", getbtcblock, {"hash"}},
    {"pop_mining", "getvbkbestblockhash", getvbkbestblockhash, {}},
    {"pop_mining", "getbtcbestblockhash", getbtcbestblockhash, {}},
    {"pop_mining", "getvbkblockhash", getvbkblockhash, {"height"}},
    {"pop_mining", "getbtcblockhash", getbtcblockhash, {"height"}},
    {"pop_mining", "getrawatv", getrawatv, {"id"}},
    {"pop_mining", "getrawvtb", getrawvtb, {"id"}},
    {"pop_mining", "getrawvbkblock", getrawvbkblock, {"id"}},
    {"pop_mining", "getrawpopmempool", &getrawpopmempool, {}},
    {"pop_mining", "extractblockinfo", &extractblockinfo, {"data_array"}}};

void RegisterPOPMiningRPCCommands(CRPCTable &t) {
    for (const auto &command : VeriBlock::commands) {
        t.appendCommand(command.name, &command);
    }
}

} // namespace VeriBlock
