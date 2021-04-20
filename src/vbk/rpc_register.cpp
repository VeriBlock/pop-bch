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

extern KeystoneArray
getKeystoneHashesForTheNextBlock(const CBlockIndex *pindexPrev);

namespace {
    void checkPopActivation() {
        auto h = ::ChainActive().Height();
        if(!Params().isPopEnabled(h)) {
            throw std::runtime_error("This RPC is disabled, because POP is not activated. Will be active at height=" + std::to_string(h));
        }
    }


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
    auto txRoot = BlockMerkleRoot(block);
    using altintegration::AuthenticatedContextInfoContainer;
    auto authctx = AuthenticatedContextInfoContainer::createFromPrevious(
        std::vector<uint8_t>{txRoot.begin(), txRoot.end()},
        block.popData.getMerkleRoot(),
        // we build authctx based on previous block
        VeriBlock::GetAltBlockIndex(pBlockIndex->pprev),
        VeriBlock::GetPop().getConfig().getAltParams());
    result.pushKV("authenticated_context", altintegration::ToJSON<UniValue>(authctx));

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
        altintegration::ReadStream stream(payloads_bytes);
        if (!altintegration::DeserializeFromVbkEncoding(stream, data, state)) {
            return state.Invalid("bad-payloads");
        }
        payloads.push_back(data);
    }

    out = payloads;
    return true;
}

UniValue submitpop(const Config &config, const JSONRPCRequest &request) {
    checkPopActivation();

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

    //TODO: separate submit RPC
    {
        LOCK(cs_main);
        auto& popmp = VeriBlock::GetPop().getMemPool();
        for (const auto& i : popData.context) {
            popmp.submit(i, state);
        }
        for (const auto& i : popData.vtbs) {
            popmp.submit(i, state);
        }
        for (const auto& i : popData.atvs) {
            popmp.submit(i, state);
        }

        return altintegration::ToJSON<UniValue>(state);
    }
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
            return altintegration::ToJSON<UniValue>(altintegration::SerializeToHex(out));
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
