// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2014-2017 XDN developers
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2016-2019 The Karbowanec developers
// Copyright (c) 2012-2018 The CryptoNote developers
//
// This file is part of Fuego.
//
// Fuego is free & open source software distributed in the hope
// that it will be useful, but WITHOUT ANY WARRANTY; without even
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. You may redistribute it and/or modify it under the terms
// of the GNU General Public License v3 or later versions as published
// by the Free Software Foundation. Fuego includes elements written
// by third parties. See file labeled LICENSE for more details.
// You should have received a copy of the GNU General Public License
// along with Fuego. If not, see <https://www.gnu.org/licenses/>

#pragma once

#include "Common/Int128.h"

#include <atomic>
#include <deque>

#include "../../external/parallel_hashmap/phmap.h"

#include "../Common/ObserverManager.h"
#include "../Common/Util.h"
#include "BlockIndex.h"
#include "Checkpoints.h"
#include "Currency.h"
#include "BankingIndex.h"
#include "CommitmentIndex.h"
#include "HeatMintEngine.h"
#include "DigmMintEngine.h"
#include "AmmPool.h"
#include "OrderbookTypes.h"
#include "../Common/FixedPoint.h"
#include "Treasury/VaultTypes.h"
#include "Treasury/VaultKeys.h"
#include "Treasury/VaultUtxoSet.h"
#include "Treasury/VaultPolicy.h"
#include "IBlockchainStorageObserver.h"
#include "ITransactionValidator.h"
#include "SwappedVector.h"
#include "UpgradeDetector.h"
#include "CryptoNoteFormatUtils.h"
#include "TransactionPool.h"
#include "AliasIndex.h"
#include "BlockchainIndices.h"
#include "IndexManager.h"

#include "MessageQueue.h"
#include "BlockchainMessages.h"
#include "IntrusiveLinkedList.h"

#include "../Logging/LoggerRef.h"

#include <thread>
#include <atomic>

#undef ERROR
using phmap::parallel_flat_hash_map;
namespace CryptoNote {
  struct NOTIFY_REQUEST_GET_OBJECTS_request;
  struct NOTIFY_RESPONSE_GET_OBJECTS_request;
  struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request;
  struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response;
  struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount;
  struct COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry;
  using CryptoNote::BlockInfo;

  class Blockchain : public CryptoNote::ITransactionValidator {
  public:
    Blockchain(const Currency &currency, tx_memory_pool &tx_pool, Logging::ILogger &logger, bool blockchainIndexesEnabled, bool blockchainAutosaveEnabled);

    bool addObserver(IBlockchainStorageObserver* observer);
    bool removeObserver(IBlockchainStorageObserver* observer);
    void rebuildCache();
    bool storeCache();

    // ITransactionValidator
    virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock) override;
    virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock, BlockInfo& lastFailed) override;
    virtual bool haveSpentKeyImages(const CryptoNote::Transaction& tx) override;
    virtual bool checkTransactionSize(size_t blobSize) override;

    bool init() { return init(Tools::getDefaultDataDirectory(), true); }
    bool init(const std::string& config_folder, bool load_existing);
    bool deinit();

    bool getLowerBound(uint64_t timestamp, uint64_t startOffset, uint32_t& height);
    std::vector<Crypto::Hash> getBlockIds(uint32_t startHeight, uint32_t maxCount);

    void setCheckpoints(Checkpoints&& chk_pts) { m_checkpoints = std::move(chk_pts); }
    bool getBlocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks, std::list<Transaction>& txs);
    bool getBlocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks);
    bool getAlternativeBlocks(std::list<Block>& blocks);
    uint32_t getAlternativeBlocksCount();
    Crypto::Hash getBlockIdByHeight(uint32_t height);
    bool getBlockByHash(const Crypto::Hash &h, Block &blk);
    bool getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight);

    template <class archive_t>
    void serialize(archive_t &ar, const unsigned int version);

    bool haveTransaction(const Crypto::Hash &id);
    bool haveTransactionKeyImagesAsSpent(const Transaction &tx);

    uint32_t getCurrentBlockchainHeight(); //TODO rename to getCurrentBlockchainSize
    Crypto::Hash getTailId();
    Crypto::Hash getTailId(uint32_t& height);
    difficulty_type getDifficultyForNextBlock();
    uint64_t getBlockTimestamp(uint32_t height);
    uint64_t getCoinsInCirculation();
    uint64_t getFeePoolBalance() const { return m_feePoolBalance; }

    // W-3: mints the vault-spend surplus back to the source partition as a
    // change UTXO (indexed above the current block height, so popBlock's
    // removeAboveIndex rolls it back with the block).
    void mintVaultChangeUtxo(const VaultUtxoSet::SpendResult& spendResult,
                             VaultPartition partition, AssetType asset,
                             uint32_t height, const Crypto::Hash& txHash);
    uint64_t getCdApyVaultBalance() const {
      return m_vault.partitionBalance(VaultPartition::CD_APY_POOL, AssetType::HEAT);
    }
    uint64_t getBonusVaultBalance() const { return m_bonusVaultBalance; }
    uint64_t getBonusVaultUtxoBalance() const {
      return m_vault.partitionBalance(VaultPartition::BONUS_VAULT, AssetType::HEAT);
    }
    uint64_t getCurrentEpochSwapFees() const { return m_currentEpochSwapFees; }
    uint64_t getTotalCdLocked() const { return m_totalCdLocked; }
    uint64_t getHeatSupply() const { return m_heatSupply; }
    uint64_t getHeatOnDeposit() const { return m_heatOnDeposit; }
    uint64_t getDigmSupply() const { return m_digmSupply; }
    uint64_t getHeatCdFeePool() const { return m_heatCdFeePool; }
    const HeatMintEngine& getHeatMintEngine() const { return m_heatMintEngine; }
    const DigmMintEngine& getDigmMintEngine() const { return m_digmMintEngine; }
    const AmmPoolState& getAmmPool() const { return m_ammPool; }
    uint64_t getPoolLockedXfg() const { return m_poolLockedXfg; }
    uint64_t getPoolLockedHeat() const { return m_poolLockedHeat; }

    // Orderbook (v11+) — reads from block finalization state
    uint64_t getOrderbookClearingPrice() const;
    bool isOrderbookInBootstrap() const;

    // Hearth spot price: 30-block P_clear average, fallback to pool ratio
    uint64_t getHearthSpotPrice() const;

    // Epoch pool TWAP: time-weighted average pool ratio (10^18 precision).
    // Returns 0 if no blocks accumulated this epoch.
    uint64_t getPoolTwap() const;

    // Rolling 8-block TWAP for HEAT mint price validation.
    // Simple average of the last 8 blocks' hearthPoolRatio.
    // Canonical scale: HEAT atomics per XFG atomic × COIN.
    uint64_t getRollingTwap() const;

    struct OrderbookLevel {
      uint64_t price;
      uint64_t depth;
    };
    std::vector<OrderbookLevel> getOrderbookBidCurve(uint32_t maxLevels) const;
    std::vector<OrderbookLevel> getOrderbookAskCurve(uint32_t maxLevels) const;
    uint32_t getOrderbookNumMatches() const;

    struct OrderbookEstimate {
      uint64_t estimatedFill;
      uint64_t hearthFill;
      uint64_t orderbookFill;
      uint64_t worstCasePrice;
      uint32_t levelsConsumed;
    };
    OrderbookEstimate getOrderbookEstimate(uint8_t side, uint64_t amount) const;
    AssetBalance getTransactionInputAssetAmounts(const Transaction& tx, uint32_t height) const;
    AssetType classifyInputAsset(const TransactionInput& in) const;
    uint64_t getCdYieldPool() const { return m_cdYieldPool; }
    uint64_t getTreasuryLpYield() const { return m_treasuryLpYield; }
    uint64_t getBootstrapRepaymentVault() const { return m_bootstrapRepaymentVault; }
    bool isBootstrapRepaid() const { return m_bootstrapRepaid; }

    // Treasury LP Manager: the protocol's own Hearth LP position, provisioned
    // from the treasury fee share, compounding inside the reserves.
    // Returns the Treasury-owned reserve value in BOTH legs (pro-rata by
    // protocol LP shares) — XFG atomics and HEAT atomics, not converted.
    struct TreasuryLpValue {
      uint64_t xfg = 0;
      uint64_t heat = 0;
    };
    TreasuryLpValue getTreasuryLpValue() const;
    void setBootstrapAmount(uint64_t xfg, uint64_t heat);
    void addSwapFee(uint64_t amount);
    bool bootstrapAmmPool(uint64_t xfgReserve, uint64_t heatReserve);
    uint64_t getTreasuryBalance() const { return m_treasuryBalance; }
    const VaultUtxoSet& getVault() const { return m_vault; }
    uint64_t getSwfBalance() const { return m_swfBurnedXfgPendingHeat; }
    uint64_t getSwfBurnedXfgPendingHeat() const { return m_swfBurnedXfgPendingHeat; }
    uint64_t getPermanentlyBurnedXfg() const { return m_bankingIndex.getPermanentlyBurnedXfg(); }
    uint64_t getTreasuryHeatReserve() const { return m_treasuryHeatReserve; }
    uint64_t getTreasurySwapFeeXfg() const { return m_treasurySwapFeeXfg; }
    uint64_t getTreasuryLpPendingXfg() const { return m_treasuryLpPendingXfg; }
    // Deprecated alias — keep for external consumers until RPC/docs migrated
    uint64_t getTreasuryCounterXFG() const { return getTreasuryLpPendingXfg(); }
    uint64_t getSwfHeatBalance() const { return m_swfHeatBalance; }
    // getTreasuryXfgReserve() removed — m_treasuryXfgReserve is dead code (never incremented, only restored from snapshots)
    uint64_t getProtocolLpShares() const { return m_protocolLpShares; }
    bool withdrawTreasuryLp(uint64_t sharesToBurn);
    uint8_t getBlockMajorVersionForHeight(uint32_t height) const;
    uint8_t blockMajorVersion;
    bool addNewBlock(const Block& bl_, block_verification_context& bvc);
    bool resetAndSetGenesisBlock(const Block& b);
    bool haveBlock(const Crypto::Hash& id);
    size_t getTotalTransactions();
    std::vector<Crypto::Hash> buildSparseChain();
    std::vector<Crypto::Hash> buildSparseChain(const Crypto::Hash& startBlockId);
    uint32_t findBlockchainSupplement(const std::vector<Crypto::Hash>& qblock_ids); // !!!!
    std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds, size_t maxCount,
      uint32_t& totalBlockCount, uint32_t& startBlockIndex);
    bool handleGetObjects(NOTIFY_REQUEST_GET_OBJECTS_request& arg, NOTIFY_RESPONSE_GET_OBJECTS_request& rsp); //Deprecated. Should be removed with CryptoNoteProtocolHandler.
    bool getRandomOutsByAmount(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response& res);
    bool getRandomCommitmentOutputsForAmount(uint64_t amount, uint64_t count, std::vector<COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry>& result, uint32_t max_height = 0);
    // Bulk lookup of creation block heights for (amount, global_index) pairs.
    // heights is sized to queries.size(); 0 for unknown/invalid.
    bool getOutputHeights(const std::vector<std::pair<uint64_t, uint32_t>>& queries,
                          std::vector<uint32_t>& heights);
    // Lookup output keys at explicit per-amount global indexes. keys is sized
    // to indexes.size(); entries with an invalid index are zeroed.
    bool getOutsByAmountAndIndexes(uint64_t amount, const std::vector<uint64_t>& indexes,
                                   std::vector<Crypto::PublicKey>& keys);
    bool getBackwardBlocksSize(size_t from_height, std::vector<size_t>& sz, size_t count);
    bool getTransactionOutputGlobalIndexes(const Crypto::Hash& tx_id, std::vector<uint32_t>& indexs);
    bool get_out_by_msig_gindex(uint64_t amount, uint64_t gindex, MultisignatureOutput& out);
    bool checkTransactionInputs(const Transaction& tx, uint32_t& pmax_used_block_height, Crypto::Hash& max_used_block_id, BlockInfo* tail = 0);
    uint64_t getCurrentCumulativeBlocksizeLimit() const;
    uint64_t blockDifficulty(size_t i);
    bool getBlockContainingTransaction(const Crypto::Hash& txId, Crypto::Hash& blockId, uint32_t& blockHeight);
    bool getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins);
    bool getBlockSize(const Crypto::Hash& hash, size_t& size);
    bool getMultisigOutputReference(const MultisignatureInput& txInMultisig, std::pair<Crypto::Hash, size_t>& outputReference);
    bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions);
    bool getOrphanBlockIdsByHeight(uint32_t height, std::vector<Crypto::Hash>& blockHashes);
    bool getBlockIdsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Crypto::Hash>& hashes, uint32_t& blocksNumberWithinTimestamps);
    bool getTransactionIdsByPaymentId(const Crypto::Hash& paymentId, std::vector<Crypto::Hash>& transactionHashes);
    bool isBlockInMainChain(const Crypto::Hash& blockId);
    uint64_t fullDepositAmount() const;
    uint64_t depositAmountAtHeight(size_t height) const;
    uint64_t depositInterestAtHeight(size_t height) const;
    uint64_t getBurnedXfgAmount() const { return m_bankingIndex.getBurnedXfgAmount(); }
    uint64_t getTotalBurnedXfg() const { return m_bankingIndex.getTotalBurnedXfg(); }
    uint64_t getBurnedXfgAtHeight(size_t height) const;

    uint64_t coinsEmittedAtHeight(uint64_t height);
    uint64_t difficultyAtHeight(uint64_t height);
    bool isInCheckpointZone(const uint32_t height);

    // Commitment index accessors
    std::optional<CommitmentEntry> getCommitmentByHash(const Crypto::Hash& commitment) const;
    bool hasCommitment(const Crypto::Hash& commitment) const;
    size_t getCommitmentCount() const;
    size_t getHeatCommitmentCount() const;
    size_t getColdCommitmentCount() const;
    Crypto::Hash getCommitmentMerkleRoot() const;
    std::vector<Crypto::Hash> getCommitmentMerkleProof(const Crypto::Hash& commitment) const;
    int64_t getCommitmentLeafIndex(const Crypto::Hash& commitment) const;
    std::vector<Crypto::Hash> getCommitmentLeaves() const;
    CommitmentIndex::Height getCommitmentHighestBlock() const;

    // Banking fee computation (0.1% on HEAT commitments)
    static uint64_t computeBankingFeesFromTransactions(const std::vector<Transaction>& txs);

    // Access CommitmentIndex for epoch boundary checks and fee tracking
    CommitmentIndex& getCommitmentIndex() { return m_commitmentIndex; }
    const CommitmentIndex& getCommitmentIndex() const { return m_commitmentIndex; }

    // Data directory (for broadcaster sign-lock file placement)
    const std::string& getConfigFolder() const { return m_config_folder; }

    template <class visitor_t>
    bool scanOutputKeysForIndexes(const KeyInput &tx_in_to_key, visitor_t &vis, uint32_t *pmax_related_block_height = NULL);

    bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue);
    bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue);

    template<class t_ids_container, class t_blocks_container, class t_missed_container>
    bool getBlocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs) {
      std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);

      for (const auto& bl_id : block_ids) {
        uint32_t height = 0;
        if (!m_blockIndex.getBlockHeight(bl_id, height)) {
          missed_bs.push_back(bl_id);
        } else {
          if (!(height < m_blocks.size())) { logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: bl_id=" << Common::podToHex(bl_id)
            << " have index record with offset=" << height << ", bigger then m_blocks.size()=" << m_blocks.size(); return false; }
            blocks.push_back(m_blocks[height].bl);
        }
      }

      return true;
    }

    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void getBlockchainTransactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs) {
      std::lock_guard<decltype(m_blockchain_lock)> bcLock(m_blockchain_lock);

      for (const auto& tx_id : txs_ids) {
        auto it = m_indexManager.transactionMap().find(tx_id);
        if (it == m_indexManager.transactionMap().end()) {
          missed_txs.push_back(tx_id);
        } else {
          txs.push_back(transactionByIndex(it->second).tx);
        }
      }
    }

    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void getTransactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs, bool checkTxPool = false) {
      if (checkTxPool){
        std::lock_guard<decltype(m_tx_pool)> txLock(m_tx_pool);

        getBlockchainTransactions(txs_ids, txs, missed_txs);

        auto poolTxIds = std::move(missed_txs);
        missed_txs.clear();
        m_tx_pool.getTransactions(poolTxIds, txs, missed_txs);

      } else {
        getBlockchainTransactions(txs_ids, txs, missed_txs);
      }
    }

    //debug functions
    void print_blockchain(uint64_t start_index, uint64_t end_index);
    void print_blockchain_index();
    void print_blockchain_outs(const std::string& file);

    // TxIndex, MultisignatureOutputUsage, CommitmentOutputRef,
    // UnifiedOutputRef and container type aliases are now in IndexManager.h.

    bool rollbackBlockchainTo(uint32_t height);
    bool have_tx_keyimg_as_spent(const Crypto::KeyImage &key_im);

    uint64_t getCommitmentConsensusPercentage() const;

    // @ Alias system
    bool aliasExists(const std::string& alias) const;
    std::optional<AliasEntry> getAliasByName(const std::string& alias) const;
    std::optional<AliasEntry> getAliasByAddress(const std::string& address) const;
    std::vector<AliasEntry> getAllAliases() const;

    // Release (void/delete) an alias — caller must have verified ownership first
    bool removeAlias(const std::string& alias);

    // Transfer alias ownership to a new address hash
    bool replaceAliasOwnership(const std::string& alias,
                               const Crypto::Hash& newAddressHash);

    void updateCurrentMerkleRoot(const Crypto::Hash& root);
    uint64_t getConsensusPercentageForCurrentRoot() const;

  private:

    struct TransactionEntry {
      Transaction tx;
      std::vector<uint32_t> m_global_output_indexes;

      void serialize(ISerializer& s) {
        s(tx, "tx");
        s(m_global_output_indexes, "indexes");
      }
    };

    struct BlockEntry {
      Block bl;
      uint32_t height;
      uint64_t block_cumulative_size;
      difficulty_type cumulative_difficulty;
      uint64_t already_generated_coins;
      std::vector<TransactionEntry> transactions;

      void serialize(ISerializer& s) {
        s(bl, "block");
        s(height, "height");
        s(block_cumulative_size, "block_cumulative_size");
        s(cumulative_difficulty, "cumulative_difficulty");
        s(already_generated_coins, "already_generated_coins");
        s(transactions, "transactions");
      }
    };

    // BlockEntry uses TransactionEntry. TxIndex, MultisignatureOutput-
    // Usage, CommitmentOutputRef, UnifiedOutputRef, and all container typedefs
    // (key_images_container, outputs_container, MultisignatureOutputsContainer,
    // CommitmentOutputsContainer, TransactionMap) are now in IndexManager.h.

    const Currency& m_currency;
    tx_memory_pool& m_tx_pool;
    mutable std::recursive_mutex m_blockchain_lock; // TODO: add here reader/writer lock
    Crypto::cn_context m_cn_context;
    Tools::ObserverManager<IBlockchainStorageObserver> m_observerManager;

    typedef parallel_flat_hash_map<Crypto::Hash, BlockEntry> blocks_ext_by_hash;

    size_t m_current_block_cumul_sz_limit;
    blocks_ext_by_hash m_alternative_chains; // Crypto::Hash -> block_extended_info

    std::string m_config_folder;
    Checkpoints m_checkpoints;
    std::atomic<bool> m_is_in_checkpoint_zone;

    typedef SwappedVector<BlockEntry> Blocks;
    typedef parallel_flat_hash_map<Crypto::Hash, uint32_t> BlockMap;
    typedef BasicUpgradeDetector<Blocks> UpgradeDetector;

    // Stores epoch-level state before processing for popBlock reversal
    struct EpochStateSnapshot {
      uint64_t heatSupply;
      uint64_t heatOnDeposit;
      uint64_t heatCdFeePool;
      uint64_t cdYieldPool;
      uint64_t cdReserve;
      uint64_t legacyBondYieldPool;
      uint64_t treasuryBalance;
      uint64_t treasuryHeatReserve;
      uint64_t treasuryXfgReserve;
      uint64_t treasuryLpReserve;
      uint64_t protocolLpShares;
      uint64_t treasuryLpYield;
      uint64_t bootstrapRepaymentVault;
      uint64_t swfBurnedXfgPendingHeat;
      uint64_t twapAccumulatorLo;
      uint64_t twapAccumulatorHi;
      uint64_t twapBlockCount;
      uint64_t ammReserveXfg;
      uint64_t ammReserveHeat;
      uint64_t ammTotalLpShares;
      uint64_t vaultUtxoCount;
      uint64_t vaultSpentCount;
      uint64_t treasurySwapFeeXfg;
      uint64_t treasuryLpPendingXfg;
      uint64_t swfHeatBalance;
      uint64_t feePoolBalance;
      uint64_t cdHearthFeeAccumulator;
      bool bootstrapRepaid;
      uint64_t bonusVaultBalance;
      uint64_t bonusVaultPendingXfg;
      uint64_t bonusWeightedBase;
    };

    friend class BlockCacheSerializer;
    friend class BlockchainIndicesSerializer;
    struct LimitDepositInfo;
    friend void serialize(LimitDepositInfo& value, ISerializer& s);

    Blocks m_blocks;
    CryptoNote::BlockIndex m_blockIndex;
    CryptoNote::BankingIndex m_bankingIndex;
    CryptoNote::CommitmentIndex m_commitmentIndex;
    CryptoNote::AliasIndex m_aliasIndex;

    // HEAT stablecoin state
    uint64_t m_heatSupply = 0;
    uint64_t m_heatOnDeposit = 0;       // HEAT locked in CDs (excludes mint outputs, HEAT_TERM)
    CryptoNote::HeatMintEngine m_heatMintEngine;

    // DIGM stablecoin state (on-chain commitments)
    uint64_t m_digmSupply = 0;
    CryptoNote::DigmMintEngine m_digmMintEngine;

    // Hearth AMM state
    CryptoNote::AmmPoolState m_ammPool;
    uint64_t m_poolLockedXfg = 0;    // sum of DEPOSIT_TERM_POOL_XFG outputs
    uint64_t m_poolLockedHeat = 0;   // sum of DEPOSIT_TERM_POOL_HEAT outputs
    uint128_t m_twapAccumulator = 0;
    uint64_t m_twapBlockCount = 0;

    // Rolling 8-block TWAP for HEAT mint validation (anti-manipulation)
    std::deque<uint64_t> m_rollingPriceWindow;
    uint8_t m_lastTwapVersion = 0;

    // CD yield state
    uint64_t m_cdYieldPool = 0;
    uint64_t m_cdReserve = 0;
    uint64_t m_heatCdFeePool = 0;
    uint64_t m_protocolLpShares = 0;
    uint64_t m_treasuryLpYield = 0;
    bool     m_bootstrapRepaid = false;
    uint64_t m_bootstrapHeatOwed = 0;
    uint64_t m_bonusVaultPendingXfg = 0;  // XFG awaiting conversion (no pool rate at epoch)
    uint64_t m_bootstrapXfgOwed = 0;
    uint64_t m_bootstrapRepaymentVault = 0;
    uint64_t m_swfBurnedXfgPendingHeat = 0; // SWF-owned XFG already burned, pending HEAT conversion
    IndexManager m_indexManager;
    // LP share tracking: maps global commitment output index → LP shares held
    parallel_flat_hash_map<uint64_t, uint64_t> m_lpCommitmentShares;
    struct HashLess { bool operator()(const Crypto::Hash& a, const Crypto::Hash& b) const { return memcmp(a.data, b.data, sizeof(a.data)) < 0; } };
    std::map<Crypto::Hash, uint64_t, HashLess> m_lpCommitTxGidx;

    // Vault UTXO spending: maps tx hash → spent vault UTXO indices (for popBlock reversal)
    // Vault UTXOs spent by a tx, keyed by tx hash, per partition. Restored on
    // popBlock. cdPool = CD_APY_POOL, bonusVault = BONUS_VAULT (v11+).
    struct VaultSpendRecord {
      std::vector<uint64_t> cdPoolIndices;
      std::vector<uint64_t> bonusVaultIndices;
    };
    std::map<Crypto::Hash, VaultSpendRecord, HashLess> m_vaultSpentByTx;

    // Limit order deposit tracking: orderId → (side, amount, addressHash) for withdrawal
    // Persists after order expires from mempool so user can reclaim pending deposit
    struct LimitDepositInfo {
      uint8_t  side;      // 0 = BUY_XFG, 1 = SELL_XFG
      uint64_t amount;    // remaining deposit: XFG for sells, HEAT for buys
      uint64_t targetPrice;
      uint32_t expiration;
      Crypto::Hash addressHash; // cn_fast_hash(spendKey||viewKey) — privacy-preserving
      uint64_t proceedsXfg = 0;  // XFG earned from fills (claimable on withdraw)
      uint64_t proceedsHeat = 0; // HEAT earned from fills (claimable on withdraw)
      uint64_t depositedAmount = 0; // original deposit amount (immutable; pop reversal)
      uint64_t withdrawnAmount = 0; // escrow amount returned by the withdraw (exact pop reversal)
      uint32_t createdHeight = 0;   // block height of the deposit (auction time priority)
      bool withdrawn = false;
      bool expired = false; // auto-returned on expiry (remaining claimable)
    };
    std::map<Crypto::Hash, LimitDepositInfo, HashLess> m_limitDeposits;

    // Rollback-history depth for per-block fill/epoch/orderbook records.
    // Testnet has no checkpoints, so reorg depth is unbounded there; keep the
    // window generous and rely on the loud eviction log in popBlock.
    static constexpr size_t MAX_ROLLBACK_HISTORY = 1000;

    // Per-block OOB fill records for popBlock reversal.
    struct OrderFillRecord {
      Crypto::Hash orderId;
      uint8_t side;
      uint64_t xfg;      // SELL: XFG filled; BUY: grossXfg pool paid out
      uint64_t heat;     // SELL: grossHeat pool paid; BUY: heatCost user paid
      uint64_t feeHeat;  // HEAT-denominated fee credited to accumulator
      uint64_t netXfg = 0; // BUY only: net XFG credited to proceeds
      bool newlyExpired = false;
      bool isAuction = false;  // call-auction fill (no pool/accumulator involvement)
      bool isTaker = false;    // auction: this fill is on the fee-paying side
      uint64_t rebateHeat = 0; // auction maker fills: rebate credited to proceedsHeat
      uint64_t priceHeat = 0;  // auction: fill's price value (fillXfg × p*/COIN)
    };
    std::deque<std::pair<uint32_t, std::vector<OrderFillRecord>>> m_blockOrderFills;
    // Per-block dir-1 swap CD-fee HEAT equivalents (recorded at settle for
    // exact popBlock reversal — the pop-time pool rate differs from push-time).
    std::deque<std::pair<uint32_t, std::vector<uint64_t>>> m_blockSwapCdFeeHeatEq;
    // Per-block LP-removal reserve deltas (recorded at settle for exact
    // popBlock reversal). Recomputing from post-burn state is not the inverse
    // of the forward path: once lpSharesBurned exceeds the post-burn supply
    // the ratio exceeds 1 and the reserves inflate instead of being restored.
    std::deque<std::pair<uint32_t, std::vector<std::pair<uint64_t, uint64_t>>>> m_blockLpRemoveAmounts;

  public:
    const std::map<Crypto::Hash, LimitDepositInfo, HashLess>& getLimitDeposits() const { return m_limitDeposits; }
  private:
    // Track auto-returned deposits for block rollback

    // Fee pool: accumulates swap fees, distributed as interest to CD holders.
    uint64_t m_feePoolBalance = 0;        // total XFG available for CD interest payouts (69% of swap fees)
    uint64_t m_currentEpochSwapFees = 0;  // fees accumulated in current epoch (reset each epoch boundary)
    uint64_t m_totalCdLocked = 0;         // total XFG locked in CDs (for epoch rate calculation)
    uint64_t m_totalLegacyBondLocked = 0;  // total XFG in legacy bonds (for separate CD share split)
    uint64_t m_legacyBondYieldPool = 0;    // accumulated legacy bond share of swap fees

    // Per-block swap-fee contribution tracking — used by popBlock to undo epoch accumulator.
    std::deque<uint64_t> m_blockSwapFeeContributions;
    std::deque<std::pair<uint64_t, uint64_t>> m_blockEpochDistributions;  // <treasuryShare, rolloverShare>
    // Per-block TWAP contribution tracking — used by popBlock to undo non-boundary block TWAP accumulation.
    std::deque<uint128_t> m_blockTwapContributions;
    // Epoch state snapshots for popBlock reversal
    std::deque<std::pair<uint32_t, EpochStateSnapshot>> m_epochSnapshots;

    // Orderbook state snapshot for popBlock reversal (v11+)
    struct OrderbookRollbackSnapshot {
      std::vector<Order> orders;
      std::vector<Order> poolOrders;
      uint64_t lastClearingPrice = 0;
      bool isInBootstrap = true;
      uint32_t bootstrapBlocksRemaining = 0;
      uint32_t lastNumMatches = 0;
      uint32_t blocksSinceLastPoolRegen = 0;
      uint64_t priorPoolRegenPclear = 0;
      uint64_t priorPoolXfgReserve = 0;
      uint64_t priorPoolHeatReserve = 0;
      uint64_t poolBandFilledLastBlock = 0;
    };
    std::deque<std::pair<uint32_t, OrderbookRollbackSnapshot>> m_orderbookSnapshots;

    // Cumulative fee pool accounting (lifetime totals, never reset)
    uint64_t m_totalSwapFeesCollected = 0;    // all swap fees ever entering the pool
    uint64_t m_totalCdInterestPaid = 0;       // total interest paid out to CD holders
    uint64_t m_totalTreasuryAccrued = 0;
    uint64_t m_totalRolloverAccrued = 0;       // deprecated, kept for serialization compat
    uint64_t m_treasuryBalance = 0;
    uint64_t m_treasuryHeatReserve = 0;          // HEAT minted from swap fee share (CD yield floor backstop)
    uint64_t m_treasuryXfgReserve = 0;           // DEPRECATED: dead code, kept for serialization compat only
    uint64_t m_treasuryLpReserve = 0;            // XFG reserved for Hearth LP provision
    uint64_t m_treasurySwapFeeXfg = 0;          // Swap fee XFG pending burn (counted, not yet burned)
    uint64_t m_treasuryLpPendingXfg = 0;          // Unburned treasury XFG reserve (swap-fee share / LP source)
    uint64_t m_swfHeatBalance = 0;              // SWF counter HEAT (off-chain DIGM collateral, never UTXOs)
    uint64_t m_bonusVaultBalance = 0;       // 11% bonus vault (loyalty + tier bonuses)
    // v11+: tier-weighted CD principal created per epoch. The BV bonus share
    // denominator at an epoch boundary is the rolling sum over the last
    // BONUS_WEIGHTED_WINDOW_EPOCHS entries — deterministic, spend-agnostic
    // (ring privacy hides a spent CD's term), and strictly bounded so total
    // bonus payouts can never exceed realized BV inflows.
    std::vector<uint64_t> m_bonusWeightedByEpoch;
    // Autonomous Treasury Vault
    VaultUtxoSet m_vault;
    VaultKeypair m_vaultKeys;
    uint64_t m_vaultUtxoCounter = 0;
    // HEAT stablecoin state
    UpgradeDetector m_upgradeDetectorV2;
    UpgradeDetector m_upgradeDetectorV3;
    UpgradeDetector m_upgradeDetectorV4;
    UpgradeDetector m_upgradeDetectorV5;
    UpgradeDetector m_upgradeDetectorV6;
    UpgradeDetector m_upgradeDetectorV7;
    UpgradeDetector m_upgradeDetectorV8;
    UpgradeDetector m_upgradeDetectorV9;
    UpgradeDetector m_upgradeDetectorV10;
    UpgradeDetector m_upgradeDetectorV11;


    bool m_blockchainIndexesEnabled;
    bool m_blockchainAutosaveEnabled;
    PaymentIdIndex m_paymentIdIndex;
    TimestampBlocksIndex m_timestampIndex;
    GeneratedTransactionsIndex m_generatedTransactionsIndex;
    OrphanBlocksIndex m_orthanBlocksIndex;

    // Phase 3: async background rebuild thread


    IntrusiveLinkedList<MessageQueue<BlockchainMessage>> m_messageQueueList;

    Logging::LoggerRef logger;


    bool switch_to_alternative_blockchain(std::list<blocks_ext_by_hash::iterator> &alt_chain, bool discard_disconnected_chain);
    bool handle_alternative_block(const Block &b, const Crypto::Hash &id, block_verification_context &bvc, bool sendNewAlternativeBlockMessage = true);
    difficulty_type get_next_difficulty_for_alternative_chain(const std::list<blocks_ext_by_hash::iterator> &alt_chain, BlockEntry &bei);
    void pushToBankingIndex(const BlockEntry &block, uint64_t interest);
    bool prevalidate_miner_transaction(const Block &b, uint32_t height);
    bool validate_miner_transaction(const Block &b, uint32_t height, size_t cumulativeBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint64_t &reward, int64_t &emissionChange, const std::vector<Transaction>& blockTransactions = {});
    bool rollback_blockchain_switching(std::list<Block> &original_chain, size_t rollback_height);
    bool get_last_n_blocks_sizes(std::vector<size_t> &sz, size_t count);
    bool add_out_to_get_random_outs(std::vector<std::pair<TxIndex, uint16_t>> &amount_outs, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount &result_outs, uint64_t amount, size_t i);
    bool is_tx_spendtime_unlocked(uint64_t unlock_time);
    size_t find_end_of_allowed_index(const std::vector<std::pair<TxIndex, uint16_t>> &amount_outs);
    bool check_block_timestamp_main(const Block &b);
    bool check_block_timestamp(std::vector<uint64_t> timestamps, const Block &b);
    uint64_t get_adjusted_time();
    bool complete_timestamps_vector(uint8_t blockMajorVersion, uint64_t start_height, std::vector<uint64_t>& timestamps);
    bool checkBlockVersion(const Block& b, const Crypto::Hash& blockHash);
    bool checkParentBlockSize(const Block& b, const Crypto::Hash& blockHash);
    bool checkCumulativeBlockSize(const Crypto::Hash& blockId, size_t cumulativeBlockSize, uint64_t height);
    std::vector<Crypto::Hash> doBuildSparseChain(const Crypto::Hash& startBlockId) const;
    bool getBlockCumulativeSize(const Block& block, size_t& cumulativeSize);
    bool update_next_comulative_size_limit();
    bool check_tx_input(const KeyInput& txin, const Crypto::Hash& tx_prefix_hash, const std::vector<Crypto::Signature>& sig, uint32_t* pmax_related_block_height = NULL);
    bool checkTransactionInputs(const Transaction& tx, const Crypto::Hash& tx_prefix_hash, uint32_t* pmax_used_block_height = NULL);
    bool checkTransactionInputs(const Transaction& tx, uint32_t* pmax_used_block_height = NULL);
    bool check_tx_outputs(const Transaction& tx, uint32_t height) const;
    const TransactionEntry& transactionByIndex(TxIndex index);
    bool pushBlock(const Block &blockData, const Crypto::Hash &id, block_verification_context &bvc, uint32_t height);
     bool pushBlock(const Block &blockData, const std::vector<Transaction> &transactions, const Crypto::Hash &id, block_verification_context &bvc, uint32_t height);

    bool pushBlock(BlockEntry &block);
    void popBlock(const Crypto::Hash &blockHash);
    void processOrderbookForBlock(Block& block, const std::vector<Transaction>& transactions, uint32_t height);
    void rebuildOrderbookFromUtxoSet(uint32_t height);
    bool pushTransaction(BlockEntry &block, const Crypto::Hash &transactionHash, TxIndex transactionIndex);
    bool processBlockEpochWork(const Block& block, uint32_t height, const Crypto::Hash& blockHash);
    void accumulateTwap(const Block& block, uint32_t height);
    void popTransaction(const Transaction &transaction, const Crypto::Hash &transactionHash,
                        uint32_t height, uint8_t majorVersion);
    void popTransactions(const BlockEntry &block, const Crypto::Hash &minerTransactionHash);
    bool validateInput(const MultisignatureInput &input, const Crypto::Hash &transactionHash, const Crypto::Hash &transactionPrefixHash, const std::vector<Crypto::Signature> &transactionSignatures);
    bool validateSwapEscrowInput(const TransactionInputSwapEscrow &input, const Crypto::Hash &transactionHash, const Crypto::Hash &transactionPrefixHash, const std::vector<Crypto::Signature> &transactionSignatures);
    bool checkCommitmentSpendInput(const TransactionInputCommitmentSpend& txin, const Crypto::Hash& tx_prefix_hash, const std::vector<Crypto::Signature>& sig, uint32_t* pmax_related_block_height = nullptr);
    bool checkCommitmentTransferInput(const TransactionInputCommitmentTransfer& txin, const Crypto::Hash& tx_prefix_hash, const std::vector<Crypto::Signature>& sig, uint32_t* pmax_related_block_height = nullptr);
    bool removeLastBlock();
    bool checkCheckpoints(uint32_t &lastValidCheckpointHeight);
    bool checkUpgradeHeight(const UpgradeDetector& upgradeDetector);

    bool storeBlockchainIndices();
    bool loadBlockchainIndices();

    bool loadTransactions(const Block& block, std::vector<Transaction>& transactions, uint32_t height);
    void saveTransactions(const std::vector<Transaction>& transactions, uint32_t height);

    void sendMessage(const BlockchainMessage& message);


    friend class LockedBlockchainStorage;
  };

  class LockedBlockchainStorage: boost::noncopyable {
  public:

    LockedBlockchainStorage(Blockchain& bc)
      : m_bc(bc), m_lock(bc.m_blockchain_lock) {}

    Blockchain* operator -> () {
      return &m_bc;
    }

  private:

    Blockchain& m_bc;
    std::lock_guard<std::recursive_mutex> m_lock;
  };

  template<class visitor_t> bool Blockchain::scanOutputKeysForIndexes(const KeyInput& tx_in_to_key, visitor_t& vis, uint32_t* pmax_related_block_height) {
    std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);
    auto it = m_indexManager.outputs().find(tx_in_to_key.amount);
    if (it == m_indexManager.outputs().end() || !tx_in_to_key.outputIndexes.size())
      return false;

    std::vector<uint32_t> absolute_offsets = relative_output_offsets_to_absolute(tx_in_to_key.outputIndexes);
    std::vector<std::pair<TxIndex, uint16_t>>& amount_outs_vec = it->second;
    size_t count = 0;
    for (uint64_t i : absolute_offsets) {
      if(i >= amount_outs_vec.size() ) {
        logger(Logging::INFO) << "Wrong index in transaction inputs: " << i << ", expected maximum " << amount_outs_vec.size() - 1;
        return false;
      }

      //auto tx_it = m_transactionMap.find(amount_outs_vec[i].first);
      //if (!(tx_it != m_transactionMap.end())) { logger(ERROR, BRIGHT_RED) << "Wrong transaction id in output indexes: " << Common::podToHex(amount_outs_vec[i].first); return false; }

      const TransactionEntry& tx = transactionByIndex(amount_outs_vec[i].first);

      if (!(amount_outs_vec[i].second < tx.tx.outputs.size())) {
        logger(Logging::ERROR, Logging::BRIGHT_RED)
            << "Wrong index in transaction outputs: "
            << amount_outs_vec[i].second << ", expected less then "
            << tx.tx.outputs.size();
        return false;
      }

      if (!vis.handle_output(tx.tx, tx.tx.outputs[amount_outs_vec[i].second], amount_outs_vec[i].second)) {
        logger(Logging::INFO) << "Failed to handle_output for output no = " << count << ", with absolute offset " << i;
        return false;
      }

      if(count++ == absolute_offsets.size()-1 && pmax_related_block_height) {
        if (*pmax_related_block_height < amount_outs_vec[i].first.block) {
          *pmax_related_block_height = amount_outs_vec[i].first.block;
        }
      }
    }

    return true;
  }
}
