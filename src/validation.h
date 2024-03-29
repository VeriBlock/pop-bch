// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_H
#define BITCOIN_VALIDATION_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <amount.h>
#include <blockfileinfo.h>
#include <blockindexworkcomparator.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <disconnectresult.h>
#include <flatfile.h>
#include <fs.h>
#include <protocol.h> // For CMessageHeader::MessageMagic
#include <script/script_error.h>
#include <script/script_metrics.h>
#include <sync.h>
#include <versionbits.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

class BlockValidationState;
class CBlockIndex;
class CBlockTreeDB;
class CBlockUndo;
class CChainParams;
class CChain;
class CCoinsViewDB;
class CConnman;
class CInv;
class Config;
class CScriptCheck;
class CTxMemPool;
class CTxUndo;
class DisconnectedBlockTransactions;
class TxValidationState;

struct ChainTxData;
struct FlatFilePos;
struct PrecomputedTransactionData;
struct LockPoints;

namespace Consensus {
struct Params;
}

#define MIN_TRANSACTION_SIZE                                                   \
    (::GetSerializeSize(CTransaction(), PROTOCOL_VERSION))

/** Default for -minrelaytxfee, minimum relay fee for transactions */
static const Amount DEFAULT_MIN_RELAY_TX_FEE_PER_KB(1000 * SATOSHI);
/** Default for -excessutxocharge for transactions transactions */
static const Amount DEFAULT_UTXO_FEE = Amount::zero();
/**
 * Default for -mempoolexpiry, expiration time for mempool transactions in
 * hours.
 */
static const unsigned int DEFAULT_MEMPOOL_EXPIRY = 336;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB

/** Maximum number of dedicated script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 15;
/** -par default (number of script-checking threads, 0 = auto) */
static const int DEFAULT_SCRIPTCHECK_THREADS = 0;
/**
 * Number of blocks that can be requested at any given time from a single peer.
 */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
/**
 * Timeout in seconds during which a peer must stall block download progress
 * before being disconnected.
 */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/**
 * Number of headers sent in one getheaders result. We rely on the assumption
 * that if a peer sends less than this number, we reached its tip. Changing this
 * value is a protocol upgrade.
 */
static const unsigned int MAX_HEADERS_RESULTS = 2000;
/**
 * Maximum depth of blocks we're willing to serve as compact blocks to peers
 * when requested. For older blocks, a regular BLOCK response will be sent.
 */
static const int MAX_CMPCTBLOCK_DEPTH = 5;
/**
 * Maximum depth of blocks we're willing to respond to GETBLOCKTXN requests for.
 */
static const int MAX_BLOCKTXN_DEPTH = 10;
/**
 * Size of the "block download window": how far ahead of our current height do
 * we fetch ? Larger windows tolerate larger download speed differences between
 * peer, but increase the potential degree of disordering of blocks on disk
 * (which make reindexing and in the future perhaps pruning harder). We'll
 * probably want to make this a per-peer adaptive value at some point.
 */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Time to wait (in seconds) between writing blocks/block index to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 60 * 60;
/** Time to wait (in seconds) between flushing chainstate to disk. */
static const unsigned int DATABASE_FLUSH_INTERVAL = 24 * 60 * 60;
/** Maximum length of reject messages. */
static const unsigned int MAX_REJECT_MESSAGE_LENGTH = 111;
/** Block download timeout base, expressed in millionths of the block interval
 * (i.e. 10 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE = 1000000;
/**
 * Additional block download timeout per parallel downloading peer (i.e. 5 min)
 */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 500000;

static const int64_t DEFAULT_MAX_TIP_AGE = 24 * 60 * 60;
/**
 * Maximum age of our tip in seconds for us to be considered current for fee
 * estimation.
 */
static const int64_t MAX_FEE_ESTIMATION_TIP_AGE = 3 * 60 * 60;

static const bool DEFAULT_CHECKPOINTS_ENABLED = true;
static const bool DEFAULT_TXINDEX = false;
static const char *const DEFAULT_BLOCKFILTERINDEX = "0";
static const unsigned int DEFAULT_BANSCORE_THRESHOLD = 100;

/** Default for -persistmempool */
static const bool DEFAULT_PERSIST_MEMPOOL = true;
/** Default for using fee filter */
static const bool DEFAULT_FEEFILTER = true;

/**
 * Maximum number of headers to announce when relaying blocks with headers
 * message.
 */
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;

static const bool DEFAULT_PEERBLOOMFILTERS = true;

/** Default for -stopatheight */
static const int DEFAULT_STOPATHEIGHT = 0;
/** Default for -maxreorgdepth */
static const int DEFAULT_MAX_REORG_DEPTH = 10;
/**
 * Default for -finalizationdelay
 * This is the minimum time between a block header reception and the block
 * finalization.
 * This value should be >> block propagation and validation time
 */
static const int64_t DEFAULT_MIN_FINALIZATION_DELAY = 2 * 60 * 60;

extern CScript COINBASE_FLAGS;
extern RecursiveMutex cs_main;
extern CTxMemPool g_mempool;
extern Mutex g_best_block_mutex;
extern std::condition_variable g_best_block_cv;
extern uint256 g_best_block;
extern std::atomic_bool fImporting;
extern std::atomic_bool fReindex;
extern bool fRequireStandard;
extern bool fCheckBlockIndex;
extern bool fCheckpointsEnabled;
extern size_t nCoinCacheUsage;

/**
 * A fee rate smaller than this is considered zero fee (for relaying, mining and
 * transaction creation)
 */
extern CFeeRate minRelayTxFee;
/**
 * If the tip is older than this (in seconds), the node is considered to be in
 * initial block download.
 */
extern int64_t nMaxTipAge;

/**
 * Block hash whose ancestors we will assume to have valid scripts without
 * checking them.
 */
extern BlockHash hashAssumeValid;

/**
 * Minimum work we will assume exists on some valid chain.
 */
extern arith_uint256 nMinimumChainWork;

/**
 * Best header we've seen so far (used for getheaders queries' starting points).
 */
extern CBlockIndex *pindexBestHeader;

/** Pruning-related variables and constants */
/** True if any block files have ever been pruned. */
extern bool fHavePruned;
/** True if we're running in -prune mode. */
extern bool fPruneMode;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;
/**
 * Block files containing a block-height within MIN_BLOCKS_TO_KEEP of
 * ::ChainActive().Tip() will not be pruned.
 */
static const unsigned int MIN_BLOCKS_TO_KEEP = 288;
/** Minimum blocks required to signal NODE_NETWORK_LIMITED */
static const unsigned int NODE_NETWORK_LIMITED_MIN_BLOCKS = 288;

static const signed int DEFAULT_CHECKBLOCKS = 6;
static const unsigned int DEFAULT_CHECKLEVEL = 3;

/**
 * Require that user allocate at least 550MB for block & undo files (blk???.dat
 * and rev???.dat)
 * At 1MB per block, 288 blocks = 288MB.
 * Add 15% for Undo data = 331MB
 * Add 20% for Orphan block rate = 397MB
 * We want the low water mark after pruning to be at least 397 MB and since we
 * prune in full block file chunks, we need the high water mark which triggers
 * the prune to be one 128MB block file + added 15% undo data = 147MB greater
 * for a total of 545MB. Setting the target to > than 550MB will make it likely
 * we can respect the target.
 */
static const uint64_t MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024;

class BlockValidationOptions {
private:
    uint64_t excessiveBlockSize;
    bool checkPoW : 1;
    bool checkMerkleRoot : 1;

public:
    // Do full validation by default
    explicit BlockValidationOptions(const Config &config);
    explicit BlockValidationOptions(uint64_t _excessiveBlockSize,
                                    bool _checkPow = true,
                                    bool _checkMerkleRoot = true)
        : excessiveBlockSize(_excessiveBlockSize), checkPoW(_checkPow),
          checkMerkleRoot(_checkMerkleRoot) {}

    BlockValidationOptions withCheckPoW(bool _checkPoW = true) const {
        BlockValidationOptions ret = *this;
        ret.checkPoW = _checkPoW;
        return ret;
    }

    BlockValidationOptions
    withCheckMerkleRoot(bool _checkMerkleRoot = true) const {
        BlockValidationOptions ret = *this;
        ret.checkMerkleRoot = _checkMerkleRoot;
        return ret;
    }

    bool shouldValidatePoW() const { return checkPoW; }
    bool shouldValidateMerkleRoot() const { return checkMerkleRoot; }
    uint64_t getExcessiveBlockSize() const { return excessiveBlockSize; }
};

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * If you want to *possibly* get feedback on whether pblock is valid, you must
 * install a CValidationInterface (see validationinterface.h) - this will have
 * its BlockChecked method called whenever *any* block completes validation.
 *
 * Note that we guarantee that either the proof-of-work is valid on pblock, or
 * (and possibly also) BlockChecked will have been called.
 *
 * May not be called in a validationinterface callback.
 *
 * @param[in]   config  The global config.
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used
 * for non-network block sources and whitelisted peers.
 * @param[out]  fNewBlock A boolean which is set to indicate if the block was
 *                        first received via this call.
 * @return True if the block is accepted as a valid block.
 */
bool ProcessNewBlock(const Config &config,
                     const std::shared_ptr<const CBlock> pblock,
                     bool fForceProcessing, bool *fNewBlock)
    LOCKS_EXCLUDED(cs_main);

/**
 * Process incoming block headers.
 *
 * May not be called in a validationinterface callback.
 *
 * @param[in]  config        The config.
 * @param[in]  block         The block headers themselves.
 * @param[out] state         This may be set to an Error state if any error
 *                           occurred processing them.
 * @param[out] ppindex       If set, the pointer will be set to point to the
 *                           last new block index object for the given headers.
 * @return True if block headers were accepted as valid.
 */
bool ProcessNewBlockHeaders(const Config &config,
                            const std::vector<CBlockHeader> &block,
                            BlockValidationState &state,
                            const CBlockIndex **ppindex = nullptr)
    LOCKS_EXCLUDED(cs_main);

/**
 * Open a block file (blk?????.dat).
 */
FILE *OpenBlockFile(const FlatFilePos &pos, bool fReadOnly = false);

/**
 * Translation to a filesystem path.
 */
fs::path GetBlockPosFilename(const FlatFilePos &pos);

/**
 * Import blocks from an external file.
 */
bool LoadExternalBlockFile(const Config &config, FILE *fileIn,
                           FlatFilePos *dbp = nullptr);

/**
 * Ensures we have a genesis block in the block tree, possibly writing one to
 * disk.
 */
bool LoadGenesisBlock(const CChainParams &chainparams);

/**
 * Load the block tree and coins database from disk, initializing state if we're
 * running with -reindex.
 */
bool LoadBlockIndex(const Consensus::Params &params)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Update the chain tip based on database information.
 */
bool LoadChainTip(const Config &config) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Unload database information.
 */
void UnloadBlockIndex();

/**
 * Run an instance of the script checking thread.
 */
void ThreadScriptCheck(int worker_num);

/**
 * Retrieve a transaction (from memory pool, or from disk, if possible).
 */
bool GetTransaction(const TxId &txid, CTransactionRef &txOut,
                    const Consensus::Params &params, BlockHash &hashBlock,
                    const CBlockIndex *const blockIndex = nullptr);

/**
 * Find the best known block, and make it the tip of the block chain
 *
 * May not be called with cs_main held. May not be called in a
 * validationinterface callback.
 */
bool ActivateBestChain(
    const Config &config, BlockValidationState &state,
    std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());
Amount GetBlockSubsidy(int nHeight, const CChainParams& params);

/**
 * Guess verification progress (as a fraction between 0.0=genesis and
 * 1.0=current tip).
 */
double GuessVerificationProgress(const ChainTxData &data,
                                 const CBlockIndex *pindex);

/**
 * Calculate the amount of disk space the block & undo files currently use.
 */
uint64_t CalculateCurrentUsage();

/**
 * Mark one block file as pruned.
 */
void PruneOneBlockFile(const int fileNumber) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Actually unlink the specified files
 */
void UnlinkPrunedFiles(const std::set<int> &setFilesToPrune);

/** Prune block files up to a given height */
void PruneBlockFilesManual(int nManualPruneHeight);

/**
 * (try to) add transaction to memory pool
 */
bool AcceptToMemoryPool(const Config &config, CTxMemPool &pool,
                        TxValidationState &state, const CTransactionRef &tx,
                        bool bypass_limits, const Amount nAbsurdFee,
                        bool test_accept = false)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Simple class for regulating resource usage during CheckInputs (and
 * CScriptCheck), atomic so as to be compatible with parallel validation.
 */
class CheckInputsLimiter {
protected:
    std::atomic<int64_t> remaining;

public:
    explicit CheckInputsLimiter(int64_t limit) : remaining(limit) {}

    bool consume_and_check(int consumed) {
        auto newvalue = (remaining -= consumed);
        return newvalue >= 0;
    }

    bool check() { return remaining >= 0; }
};

class TxSigCheckLimiter : public CheckInputsLimiter {
public:
    TxSigCheckLimiter() : CheckInputsLimiter(MAX_TX_SIGCHECKS) {}

    // Let's make this bad boy copiable.
    TxSigCheckLimiter(const TxSigCheckLimiter &rhs)
        : CheckInputsLimiter(rhs.remaining.load()) {}

    TxSigCheckLimiter &operator=(const TxSigCheckLimiter &rhs) {
        remaining = rhs.remaining.load();
        return *this;
    }

    static TxSigCheckLimiter getDisabled() {
        TxSigCheckLimiter txLimiter;
        // Historically, there has not been a transaction with more than 20k sig
        // checks on testnet or mainnet, so this effectively disable sigchecks.
        txLimiter.remaining = 20000;
        return txLimiter;
    }
};

class ConnectTrace;

/**
 * Check whether all inputs of this transaction are valid (no double spends,
 * scripts & sigs, amounts). This does not modify the UTXO set.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being
 * performed inline. Any script checks which are not necessary (eg due to script
 * execution cache hits) are, obviously, not pushed onto pvChecks/run.
 *
 * Upon success nSigChecksOut will be filled in with either:
 * - correct total for all inputs, or,
 * - 0, in the case when checks were pushed onto pvChecks (i.e., a cache miss
 * with pvChecks non-null), in which case the total can be found by executing
 * pvChecks and adding the results.
 *
 * Setting sigCacheStore/scriptCacheStore to false will remove elements from the
 * corresponding cache which are matched. This is useful for checking blocks
 * where we will likely never need the cache entry again.
 *
 * pLimitSigChecks can be passed to limit the sigchecks count either in parallel
 * or serial validation. With pvChecks null (serial validation), breaking the
 * pLimitSigChecks limit will abort evaluation early and return false. With
 * pvChecks not-null (parallel validation): the cached nSigChecks may itself
 * break the limit in which case false is returned, OR, each entry in the
 * returned pvChecks must be executed exactly once in order to probe the limit
 * accurately.
 */
bool CheckInputs(const CTransaction &tx, TxValidationState &state,
                 const CCoinsViewCache &view, bool fScriptChecks,
                 const uint32_t flags, bool sigCacheStore,
                 bool scriptCacheStore,
                 const PrecomputedTransactionData &txdata, int &nSigChecksOut,
                 TxSigCheckLimiter &txLimitSigChecks,
                 CheckInputsLimiter *pBlockLimitSigChecks,
                 std::vector<CScriptCheck> *pvChecks)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Handy shortcut to full fledged CheckInputs call.
 */
static inline bool
CheckInputs(const CTransaction &tx, TxValidationState &state,
            const CCoinsViewCache &view, bool fScriptChecks,
            const uint32_t flags, bool sigCacheStore, bool scriptCacheStore,
            const PrecomputedTransactionData &txdata, int &nSigChecksOut)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    TxSigCheckLimiter nSigChecksTxLimiter;
    return CheckInputs(tx, state, view, fScriptChecks, flags, sigCacheStore,
                       scriptCacheStore, txdata, nSigChecksOut,
                       nSigChecksTxLimiter, nullptr, nullptr);
}

/** Get the BIP9 state for a given deployment at the current tip. */
ThresholdState VersionBitsTipState(const Consensus::Params &params,
                                   Consensus::DeploymentPos pos);

/** Get the BIP9 state for a given deployment at a given block. */
ThresholdState VersionBitsBlockState(const Consensus::Params &params,
                                     Consensus::DeploymentPos pos,
                                     const CBlockIndex *pindex);

/**
 * Get the numerical statistics for the BIP9 state for a given deployment at the
 * current tip.
 */
BIP9Stats VersionBitsTipStatistics(const Consensus::Params &params,
                                   Consensus::DeploymentPos pos);

/**
 * Get the block height at which the BIP9 deployment switched into the state for
 * the block building on the current tip.
 */
int VersionBitsTipStateSinceHeight(const Consensus::Params &params,
                                   Consensus::DeploymentPos pos);

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction &tx, CCoinsViewCache &inputs, int nHeight);

/**
 * Mark all the coins corresponding to a given transaction inputs as spent.
 */
void SpendCoins(CCoinsViewCache &view, const CTransaction &tx, CTxUndo &txundo,
                int nHeight);

/**
 * Apply the effects of this transaction on the UTXO set represented by view.
 */
void UpdateCoins(CCoinsViewCache &view, const CTransaction &tx, int nHeight);
void UpdateCoins(CCoinsViewCache &view, const CTransaction &tx, CTxUndo &txundo,
                 int nHeight);

/**
 * Test whether the LockPoints height and time are still valid on the current
 * chain.
 */
bool TestLockPointValidity(const LockPoints *lp)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current
 * active chain. Optionally stores in LockPoints the resulting height and time
 * calculated and the hash of the block needed for calculation or skips the
 * calculation and uses the LockPoints passed in for evaluation. The LockPoints
 * should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CTxMemPool &pool, const CTransaction &tx,
                        int flags, LockPoints *lp = nullptr,
                        bool useExistingLockPoints = false)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Closure representing one script verification.
 * Note that this stores references to the spending transaction.
 *
 * Note that if pLimitSigChecks is passed, then failure does not imply that
 * scripts have failed.
 */
class CScriptCheck {
private:
    CTxOut m_tx_out;
    const CTransaction *ptxTo;
    unsigned int nIn;
    uint32_t nFlags;
    bool cacheStore;
    ScriptError error;
    ScriptExecutionMetrics metrics;
    PrecomputedTransactionData txdata;
    TxSigCheckLimiter *pTxLimitSigChecks;
    CheckInputsLimiter *pBlockLimitSigChecks;

public:
    CScriptCheck()
        : ptxTo(nullptr), nIn(0), nFlags(0), cacheStore(false),
          error(ScriptError::UNKNOWN), txdata(), pTxLimitSigChecks(nullptr),
          pBlockLimitSigChecks(nullptr) {}

    CScriptCheck(const CTxOut &outIn, const CTransaction &txToIn,
                 unsigned int nInIn, uint32_t nFlagsIn, bool cacheIn,
                 const PrecomputedTransactionData &txdataIn,
                 TxSigCheckLimiter *pTxLimitSigChecksIn = nullptr,
                 CheckInputsLimiter *pBlockLimitSigChecksIn = nullptr)
        : m_tx_out(outIn), ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn),
          cacheStore(cacheIn), error(ScriptError::UNKNOWN), txdata(txdataIn),
          pTxLimitSigChecks(pTxLimitSigChecksIn),
          pBlockLimitSigChecks(pBlockLimitSigChecksIn) {}

    bool operator()();

    void swap(CScriptCheck &check) {
        std::swap(ptxTo, check.ptxTo);
        std::swap(m_tx_out, check.m_tx_out);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
        std::swap(metrics, check.metrics);
        std::swap(txdata, check.txdata);
        std::swap(pTxLimitSigChecks, check.pTxLimitSigChecks);
        std::swap(pBlockLimitSigChecks, check.pBlockLimitSigChecks);
    }

    ScriptError GetScriptError() const { return error; }

    ScriptExecutionMetrics GetScriptExecutionMetrics() const { return metrics; }
};

/** Functions for disk access for blocks */
bool ReadBlockFromDisk(CBlock &block, const FlatFilePos &pos,
                       const Consensus::Params &params);
bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex,
                       const Consensus::Params &params);

bool UndoReadFromDisk(CBlockUndo &blockundo, const CBlockIndex *pindex);

/** Functions for validating blocks and updating the block tree */

/**
 * Context-independent validity checks.
 *
 * Returns true if the provided block is valid (has valid header,
 * transactions are valid, block is a valid size, etc.)
 */
bool CheckBlock(const CBlock &block, BlockValidationState &state,
                const Consensus::Params &params,
                BlockValidationOptions validationOptions);

bool ContextualCheckBlock(const CBlock &block, BlockValidationState &state,
                          const Consensus::Params &params,
                          const CBlockIndex *pindexPrev, bool fCheckMerkleRoot);

/**
 * This is a variant of ContextualCheckTransaction which computes the
 * contextual check for a transaction based on the chain tip.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool ContextualCheckTransactionForCurrentBlock(const Consensus::Params &params,
                                               const CTransaction &tx,
                                               TxValidationState &state,
                                               int flags = -1);

/**
 * Check a block is completely valid from start to finish (only works on top of
 * our current best block)
 */
bool TestBlockValidity(BlockValidationState &state, const CChainParams &params,
                       const CBlock &block, CBlockIndex *pindexPrev,
                       BlockValidationOptions validationOptions)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * RAII wrapper for VerifyDB: Verify consistency of the block and coin
 * databases.
 */
class CVerifyDB {
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(const Config &config, CCoinsView *coinsview, int nCheckLevel,
                  int nCheckDepth);
};

/** Replay blocks that aren't fully applied to the database. */
bool ReplayBlocks(const Consensus::Params &params, CCoinsView *view);

/** Find the last common block between the parameter chain and a locator. */
CBlockIndex *FindForkInGlobalIndex(const CChain &chain,
                                   const CBlockLocator &locator)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** @see CChainState::FlushStateToDisk */
enum class FlushStateMode { NONE, IF_NEEDED, PERIODIC, ALWAYS };

/**
 * CChainState stores and provides an API to update our local knowledge of the
 * current best chain and header tree.
 *
 * It generally provides access to the current block tree, as well as functions
 * to provide new data, which it will appropriately validate and incorporate in
 * its state as necessary.
 *
 * Eventually, the API here is targeted at being exposed externally as a
 * consumable libconsensus library, so any functions added must only call
 * other class member functions, pure functions in other parts of the consensus
 * library, callbacks via the validation interface, or read/write-to-disk
 * functions (eventually this will also be via callbacks).
 */
class CChainState {
private:
    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for
     * itself and all ancestors) and as good as our current tip or better.
     * Entries may be failed or parked though, and pruning nodes may be missing
     * the data for the block; these will get cleaned during FindMostWorkChain.
     */
    std::set<CBlockIndex *, CBlockIndexWorkComparator> setBlockIndexCandidates;

    /**
     * the ChainState CriticalSection
     * A lock that must be held when modifying this ChainState - held in
     * ActivateBestChain()
     */
    RecursiveMutex m_cs_chainstate;

    /**
     * Every received block is assigned a unique and increasing identifier, so
     * we know which one to give priority in case of a fork.
     * Blocks loaded from disk are assigned id 0, so start the counter at 1.
     */
    std::atomic<int32_t> nBlockSequenceId{1};
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;
    /** chainwork for the last block that preciousblock has been applied to. */
    arith_uint256 nLastPreciousChainwork = 0;

    /**
     * In order to efficiently track invalidity of headers, we keep the set of
     * blocks which we tried to connect and found to be invalid here (ie which
     * were set to BLOCK_FAILED_VALID since the last restart). We can then
     * walk this set and check if a new header is a descendant of something in
     * this set, preventing us from having to walk mapBlockIndex when we try
     * to connect a bad block and fail.
     *
     * While this is more complicated than marking everything which descends
     * from an invalid block as invalid at the time we discover it to be
     * invalid, doing so would require walking all of mapBlockIndex to find all
     * descendants. Since this case should be very rare, keeping track of all
     * BLOCK_FAILED_VALID blocks in a set should be just fine and work just as
     * well.
     *
     * Because we already walk mapBlockIndex in height-order at startup, we go
     * ahead and mark descendants of invalid blocks as FAILED_CHILD at that
     * time, instead of putting things in this set.
     */
    std::set<CBlockIndex *> m_failed_blocks;

    /**
     * Whether this chainstate is undergoing initial block download.
     *
     * Mutable because we need to be able to mark IsInitialBlockDownload()
     * const, which latches this for caching purposes.
     */
    mutable std::atomic<bool> m_cached_finished_ibd{false};

public:
    CChain m_chain;
    BlockMap mapBlockIndex GUARDED_BY(cs_main);
    std::multimap<CBlockIndex *, CBlockIndex *> mapBlocksUnlinked;
    CBlockIndex *pindexBestInvalid = nullptr;
    CBlockIndex *pindexBestParked = nullptr;
    CBlockIndex const *pindexFinalized = nullptr;

    bool LoadBlockIndex(const Consensus::Params &params,
                        CBlockTreeDB &blocktree)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Update the on-disk chain state.
     * The caches and indexes are flushed depending on the mode we're called
     * with if they're too large, if it's been a while since the last write, or
     * always and in all cases if we're in prune mode and are deleting files.
     *
     * If FlushStateMode::NONE is used, then FlushStateToDisk(...) won't do
     * anything besides checking if we need to prune.
     */
    bool FlushStateToDisk(const CChainParams &chainparams,
                          BlockValidationState &state, FlushStateMode mode,
                          int nManualPruneHeight = 0);

    //! Unconditionally flush all changes to disk.
    void ForceFlushStateToDisk();

    //! Prune blockfiles from the disk if necessary and then flush chainstate
    //! changes if we pruned.
    void PruneAndFlush();

    bool ActivateBestChain(
        const Config &config, BlockValidationState &state,
        std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>())
        LOCKS_EXCLUDED(cs_main);

    /**
     * If a block header hasn't already been seen, call CheckBlockHeader on it,
     * ensure that it doesn't descend from an invalid block, and then add it to
     * mapBlockIndex.
     */
    bool AcceptBlockHeader(const Config &config, const CBlockHeader &block,
                           BlockValidationState &state, CBlockIndex **ppindex)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool AcceptBlock(const Config &config,
                     const std::shared_ptr<const CBlock> &pblock,
                     BlockValidationState &state, bool fRequested,
                     const FlatFilePos *dbp, bool *fNewBlock)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Block (dis)connection on a given view:
    DisconnectResult DisconnectBlock(const CBlock &block,
                                     const CBlockIndex *pindex,
                                     CCoinsViewCache &view);
    bool ConnectBlock(const CBlock &block, BlockValidationState &state,
                      CBlockIndex *pindex, CCoinsViewCache &view,
                      const CChainParams &params,
                      BlockValidationOptions options, bool fJustCheck = false)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Block disconnection on our pcoinsTip:
    bool DisconnectTip(const CChainParams &params, BlockValidationState &state,
                       DisconnectedBlockTransactions *disconnectpool)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Manual block validity manipulation:
    bool PreciousBlock(const Config &config, BlockValidationState &state,
                       CBlockIndex *pindex) LOCKS_EXCLUDED(cs_main);
    /** Mark a block as invalid. */
    bool InvalidateBlock(const Config &config, BlockValidationState &state,
                         CBlockIndex *pindex)
        LOCKS_EXCLUDED(cs_main, m_cs_chainstate);
    /** Park a block. */
    bool ParkBlock(const Config &config, BlockValidationState &state,
                   CBlockIndex *pindex)
        LOCKS_EXCLUDED(cs_main, m_cs_chainstate);
    /**
     * Finalize a block.
     * A finalized block can not be reorged in any way.
     */
    bool FinalizeBlock(const Config &config, BlockValidationState &state,
                       CBlockIndex *pindex)
        LOCKS_EXCLUDED(cs_main, m_cs_chainstate);
    void ResetBlockFailureFlags(CBlockIndex *pindex)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    template <typename F>
    bool UpdateFlagsForBlock(CBlockIndex *pindexBase, CBlockIndex *pindex, F f)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    template <typename F, typename C, typename AC>
    void UpdateFlags(CBlockIndex *pindex, CBlockIndex *&pindexReset, F f,
                     C fChild, AC fAncestorWasChanged)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Remove parked status from a block and its descendants. */
    void UnparkBlockImpl(CBlockIndex *pindex, bool fClearChildren)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool ReplayBlocks(const Consensus::Params &params, CCoinsView *view);
    bool LoadGenesisBlock(const CChainParams &chainparams);

    void PruneBlockIndexCandidates();

    void UnloadBlockIndex();

    /**
     * Check whether we are doing an initial block download (synchronizing from
     * disk or network)
     */
    bool IsInitialBlockDownload() const;

private:
    bool ActivateBestChainStep(const Config &config,
                               BlockValidationState &state,
                               CBlockIndex *pindexMostWork,
                               const std::shared_ptr<const CBlock> &pblock,
                               bool &fInvalidFound, ConnectTrace &connectTrace)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool ConnectTip(const Config &config, BlockValidationState &state,
                    CBlockIndex *pindexNew,
                    const std::shared_ptr<const CBlock> &pblock,
                    ConnectTrace &connectTrace,
                    DisconnectedBlockTransactions &disconnectpool)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    CBlockIndex *AddToBlockIndex(const CBlockHeader &block)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool MarkBlockAsFinal(const Config &config, BlockValidationState &state,
                          const CBlockIndex *pindex)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Create a new block index entry for a given block hash */
    CBlockIndex *InsertBlockIndex(const BlockHash &hash)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /**
     * Make various assertions about the state of the block index.
     *
     * By default this only executes fully when using the Regtest chain; see:
     * fCheckBlockIndex.
     */
    void CheckBlockIndex(const Consensus::Params &consensusParams);

    void InvalidBlockFound(CBlockIndex *pindex,
                           const BlockValidationState &state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    CBlockIndex *FindMostWorkChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    CBlockIndex *FindBestChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool TestBlockIndex(CBlockIndex *pindexTest)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    void ReceivedBlockTransactions(const CBlock &block, CBlockIndex *pindexNew,
                                   const FlatFilePos &pos)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool RollforwardBlock(const CBlockIndex *pindex, CCoinsViewCache &inputs,
                          const Consensus::Params &params)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool UnwindBlock(const Config &config, BlockValidationState &state,
                     CBlockIndex *pindex, bool invalidate)
        EXCLUSIVE_LOCKS_REQUIRED(m_cs_chainstate);
};

/**
 * Mark a block as precious and reorganize.
 *
 * May not be called in a validationinterface callback.
 */
bool PreciousBlock(const Config &config, BlockValidationState &state,
                   CBlockIndex *pindex) LOCKS_EXCLUDED(cs_main);

/** Remove invalidity status from a block and its descendants. */
void ResetBlockFailureFlags(CBlockIndex *pindex)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Remove parked status from a block and its descendants. */
void UnparkBlockAndChildren(CBlockIndex *pindex)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Remove parked status from a block. */
void UnparkBlock(CBlockIndex *pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Retrieve the topmost finalized block.
 */
const CBlockIndex *GetFinalizedBlock() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Checks if a block is finalized.
 */
bool IsBlockFinalized(const CBlockIndex *pindex)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** @returns the most-work valid chainstate. */
CChainState &ChainstateActive();

/** @returns the most-work chain. */
CChain &ChainActive();

/**
 * Global variable that points to the coins database (protected by cs_main)
 */
extern std::unique_ptr<CCoinsViewDB> pcoinsdbview;

/**
 * Global variable that points to the active CCoinsView (protected by cs_main)
 */
extern std::unique_ptr<CCoinsViewCache> pcoinsTip;

/**
 * Global variable that points to the active block tree (protected by cs_main)
 */
extern std::unique_ptr<CBlockTreeDB> pblocktree;

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by
 * cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache &inputs);

/**
 * Determine what nVersion a new block should use.
 */
int32_t ComputeBlockVersion(const CBlockIndex *pindexPrev,
                            const Consensus::Params &params);

/**
 * Reject codes greater or equal to this can be returned by AcceptToMemPool or
 * AcceptBlock for blocks/transactions, to signal internal conditions. They
 * cannot and should not be sent over the P2P network.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;
/** Block conflicts with a transaction already known */
static const unsigned int REJECT_AGAINST_FINALIZED = 0x103;

/** Get block file info entry for one block file */
CBlockFileInfo *GetBlockFileInfo(size_t n);

/** Dump the mempool to disk. */
bool DumpMempool(const CTxMemPool &pool);

/** Load the mempool from disk. */
bool LoadMempool(const Config &config, CTxMemPool &pool);

//! Check whether the block associated with this index entry is pruned or not.
bool IsBlockPruned(const CBlockIndex *pblockindex);

#endif // BITCOIN_VALIDATION_H
