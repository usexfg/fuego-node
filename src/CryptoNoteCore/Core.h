// Copyright (c) 2017-2026 Fuego Developers
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

#include <ctime>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "../P2p/NetNodeCommon.h"
#include "../CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"
#include "Currency.h"
#include "TransactionPool.h"
#include "Blockchain.h"
#include "IMinerHandler.h"
#include "MinerConfig.h"
#include "ICore.h"
#include "ICoreObserver.h"
#include "../Common/ObserverManager.h"

#include "System/Dispatcher.h"
#include "MessageQueue.h"
#include "BlockchainMessages.h"
#include "BankingIndex.h"
#include "CommitmentIndex.h"

#include "../Logging/LoggerMessage.h"

namespace CryptoNote {

  struct core_stat_info;
  class miner;
  class CoreConfig;
  class SwapOfferRelay;

  class core : public ICore, public IMinerHandler, public IBlockchainStorageObserver, public ITxPoolObserver {
   public:
     core(const Currency &currency, i_cryptonote_protocol *pprotocol, Logging::ILogger &logger, bool blockchainIndexesEnabled, bool blockchainAutosaveEnabled);
     ~core();

     bool on_idle() override;
     virtual bool handle_incoming_tx(const BinaryArray& tx_blob, tx_verification_context& tvc, bool kept_by_block) override; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
     bool handle_incoming_block_blob(const BinaryArray& block_blob, block_verification_context& bvc, bool control_miner, bool relay_block) override;
     virtual i_cryptonote_protocol* get_protocol() override {return m_pprotocol;}
     virtual const Currency& currency() const override { return m_currency; }

     virtual SwapOfferRelay& getSwapRelay() override { return *m_swapRelay; }
     void setSwapRelay(SwapOfferRelay* relay) { m_swapRelay = relay; }

     virtual CdOfferRelay& getCdRelay() override { return *m_cdRelay; }
     void setCdRelay(CdOfferRelay* relay) { m_cdRelay = relay; }

     //-------------------- IMinerHandler -----------------------
     virtual bool handle_block_found(Block& b) override;
     virtual bool get_block_template(Block& b, const AccountPublicAddress& adr, difficulty_type& diffic, uint32_t& height, const BinaryArray& ex_nonce) override;

     bool addObserver(ICoreObserver* observer) override;
     bool removeObserver(ICoreObserver* observer) override;

     miner& get_miner() { return *m_miner; }
     static void init_options(boost::program_options::options_description& desc);
     bool init(const CoreConfig& config, const MinerConfig& minerConfig, bool load_existing);
     bool set_genesis_block(const Block& b);
     bool deinit();

     // ICore
     virtual bool saveBlockchain() override;
     virtual size_t addChain(const std::vector<const IBlock*>& chain) override;
     virtual bool handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS_request& arg, NOTIFY_RESPONSE_GET_OBJECTS_request& rsp) override; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
     virtual bool getBackwardBlocksSizes(uint32_t fromHeight, std::vector<size_t>& sizes, size_t count) override;
     virtual bool getBlockSize(const Crypto::Hash& hash, size_t& size) override;
     virtual bool getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins) override;
     virtual bool getBlockReward(uint8_t blockMajorVersion, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint32_t height,
                                 uint64_t& reward, int64_t& emissionChange) override;
     virtual bool scanOutputkeysForIndices(const KeyInput& txInToKey, std::list<std::pair<Crypto::Hash, size_t>>& outputReferences) override;
     virtual bool getBlockDifficulty(uint32_t height, difficulty_type& difficulty) override;
     virtual bool getBlockContainingTx(const Crypto::Hash& txId, Crypto::Hash& blockId, uint32_t& blockHeight) override;
     virtual bool getMultisigOutputReference(const MultisignatureInput& txInMultisig, std::pair<Crypto::Hash, size_t>& output_reference) override;
     virtual bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions) override;
     virtual bool getOrphanBlocksByHeight(uint32_t height, std::vector<Block>& blocks) override;
     virtual bool getBlocksByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Block>& blocks, uint32_t& blocksNumberWithinTimestamps) override;
     virtual bool getPoolTransactionsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t transactionsNumberLimit, std::vector<Transaction>& transactions, uint64_t& transactionsNumberWithinTimestamps) override;
     virtual bool getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<Transaction>& transactions) override;
     virtual bool getOutByMSigGIndex(uint64_t amount, uint64_t gindex, MultisignatureOutput& out) override;
     virtual std::unique_ptr<IBlock> getBlock(const Crypto::Hash& blocksId) override;
     virtual bool handleIncomingTransaction(const Transaction& tx, const Crypto::Hash& txHash, size_t blobSize, tx_verification_context& tvc, bool keptByBlock, uint32_t height) override;
     virtual std::error_code executeLocked(const std::function<std::error_code()>& func) override;

     virtual bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) override;
     virtual bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) override;

     virtual std::time_t getStartTime() const;
     uint8_t getCurrentBlockMajorVersion() override;
     uint32_t get_current_blockchain_height();
     bool have_block(const Crypto::Hash& id) override;
     std::vector<Crypto::Hash> buildSparseChain() override;
     std::vector<Crypto::Hash> buildSparseChain(const Crypto::Hash& startBlockId) override;
     void on_synchronized() override;

     virtual void get_blockchain_top(uint32_t& height, Crypto::Hash& top_id) override;
     bool get_blocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks, std::list<Transaction>& txs);
     bool get_blocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks);
     bool rollback_chain_to(uint32_t height);
     template<class t_ids_container, class t_blocks_container, class t_missed_container>
     bool get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs)
     {
       return m_blockchain.getBlocks(block_ids, blocks, missed_bs);
     }
     virtual bool queryBlocks(const std::vector<Crypto::Hash>& block_ids, uint64_t timestamp,
       uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockFullInfo>& entries) override;
    virtual bool queryBlocksLite(const std::vector<Crypto::Hash>& knownBlockIds, uint64_t timestamp,
      uint32_t& resStartHeight, uint32_t& resCurrentHeight, uint32_t& resFullOffset, std::vector<BlockShortInfo>& entries) override;
    virtual Crypto::Hash getBlockIdByHeight(uint32_t height) override;
    virtual bool getTransaction(const Crypto::Hash &id, Transaction &tx, bool checkTxPool = false) override;
    void getTransactions(const std::vector<Crypto::Hash> &txs_ids, std::list<Transaction> &txs, std::list<Crypto::Hash> &missed_txs, bool checkTxPool = false) override;
    virtual bool getBlockByHash(const Crypto::Hash &h, Block &blk) override;
    virtual bool getBlockHeight(const Crypto::Hash &blockId, uint32_t &blockHeight) override;
    //void get_all_known_block_ids(std::list<Crypto::Hash> &main, std::list<Crypto::Hash> &alt, std::list<Crypto::Hash> &invalid);

    bool get_alternative_blocks(std::list<Block> &blocks);
    size_t get_alternative_blocks_count();
    uint64_t coinsEmittedAtHeight(uint64_t height);
    uint64_t difficultyAtHeight(uint64_t height);

    void set_cryptonote_protocol(i_cryptonote_protocol *pprotocol);
    void set_checkpoints(Checkpoints &&chk_pts);

    std::vector<Transaction> getPoolTransactions() override;
    bool getPoolTransaction(const Crypto::Hash &tx_hash, Transaction &transaction) override;
    size_t get_pool_transactions_count();
    size_t get_blockchain_total_transactions();
    //bool get_outs(uint64_t amount, std::list<Crypto::PublicKey>& pkeys);
    virtual std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash> &remoteBlockIds, size_t maxCount,
                                                               uint32_t &totalBlockCount, uint32_t &startBlockIndex) override;
    bool get_stat_info(core_stat_info &st_inf) override;

    virtual bool get_tx_outputs_gindexs(const Crypto::Hash &tx_id, std::vector<uint32_t> &indexs) override;
    virtual bool get_outs_for_amount(uint64_t amount, const std::vector<uint64_t>& indexes,
                                     std::vector<Crypto::PublicKey>& keys) override;
    Crypto::Hash get_tail_id();
    virtual bool get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request &req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response &res) override;
    virtual bool get_random_commitment_outs_for_amount(uint64_t amount, uint64_t count, uint32_t maxHeight, std::vector<COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry>& result) override;
    virtual bool get_output_heights(const std::vector<std::pair<uint64_t, uint32_t>>& queries,
                                    std::vector<uint32_t>& heights) override;
    void pause_mining() override;
    void update_block_template_and_resume_mining() override;
    Blockchain& get_blockchain_storage(){return m_blockchain;}
    uint64_t getFeePoolBalance() override { return m_blockchain.getFeePoolBalance(); }
    uint64_t getCdApyVaultBalance() override { return m_blockchain.getCdApyVaultBalance(); }
    uint64_t getBonusVaultBalance() override { return m_blockchain.getBonusVaultBalance(); }
    uint64_t getBonusVaultUtxoBalance() override { return m_blockchain.getBonusVaultUtxoBalance(); }
    std::error_code calculateCdBonus(uint64_t amount, uint32_t creationHeight,
                                     uint32_t currentHeight, uint64_t& outBonus,
                                     uint32_t term = 0) override {
      outBonus = m_currency.calculateCdBonus(amount, creationHeight, currentHeight,
                                             m_blockchain.getCommitmentIndex(), term);
      return {};
    }
    //debug functions
    void print_blockchain(uint32_t start_index, uint32_t end_index);
    void print_blockchain_index();
    std::string print_pool(bool short_format);
    std::list<CryptoNote::tx_memory_pool::TransactionDetails> getMemoryPool() const;
    void print_blockchain_outs(const std::string &file);
    virtual bool getPoolChanges(const Crypto::Hash &tailBlockId, const std::vector<Crypto::Hash> &knownTxsIds,
                                std::vector<Transaction> &addedTxs, std::vector<Crypto::Hash> &deletedTxsIds) override;
    virtual bool getPoolChangesLite(const Crypto::Hash &tailBlockId, const std::vector<Crypto::Hash> &knownTxsIds,
                                    std::vector<TransactionPrefixInfo> &addedTxs, std::vector<Crypto::Hash> &deletedTxsIds) override;
    virtual void getPoolChanges(const std::vector<Crypto::Hash> &knownTxsIds, std::vector<Transaction> &addedTxs,
                                std::vector<Crypto::Hash> &deletedTxsIds) override;

    uint64_t getNextBlockDifficulty();
    uint64_t getTotalGeneratedAmount();
    uint64_t fullDepositAmount() const;
    uint64_t depositAmountAtHeight(size_t height) const;
    uint64_t getBurnedXfgAtHeight(size_t height) const;
    void addSwapFee(uint64_t amount);
    void setXfgMarketValue(uint64_t val);

    uint8_t getBlockMajorVersionForHeight(uint32_t height) const;

    // Commitment index accessors
    std::optional<CommitmentEntry> getCommitmentByHash(const Crypto::Hash& commitment) const;
    bool hasCommitment(const Crypto::Hash& commitment) const;
    size_t getCommitmentCount() const;
    size_t getHeatCommitmentCount() const;
    uint64_t getTotalCdLocked() const;
    uint64_t getHeatCdFeePool() const;
    size_t getColdCommitmentCount() const;
    Crypto::Hash getCommitmentMerkleRoot() const;
    std::vector<Crypto::Hash> getCommitmentMerkleProof(const Crypto::Hash& commitment) const;
    int64_t getCommitmentLeafIndex(const Crypto::Hash& commitment) const;
    uint64_t getCommitmentHighestBlock() const;
    std::vector<Crypto::Hash> getCommitmentLeaves() const;

    // Direct CommitmentIndex access (for epoch reports, slash queries)
    const CommitmentIndex& getCommitmentIndex() const;

    // ICore overrides: CD interest and epoch fee rate via CommitmentIndex
    virtual std::error_code calculateCdInterest(uint64_t amount, uint32_t creationHeight,
                                                  uint32_t currentHeight,
                                                  uint64_t& outInterest,
                                                  bool isLegacyBond = false,
                                                  uint32_t term = 0,
                                                  bool autoRolled = false) override;
    virtual std::error_code getCommitmentEpochFeeRate(uint32_t epoch,
                                                       uint64_t& outFeeRate) override;
    virtual std::error_code getAmmPoolReserves(AmmPoolReserves& out) override;
    virtual uint64_t getHearthTwap() override;
    virtual std::error_code getAmmPoolInfo(ICore::AmmPoolInfo& info) override;

    // HEAT stablecoin / Hearth AMM metrics (v11+)
    struct HeatMetrics {
      uint64_t heatSupply = 0;
      uint64_t heatOnDeposit = 0;     // HEAT locked in CDs (excludes mint outputs)
      uint64_t digmSupply = 0;
      uint64_t burnedXfg = 0;
      uint64_t totalBurnedXfg = 0;   // overall burn tally (100% of every XFG destroyed)
      uint64_t permanentlyBurnedXfg = 0; // SWF XFG permanently retired when converted to HEAT (removed from total supply)
      uint64_t heatCdFeePool = 0;     // HⲶ∆T in CD fee pool (accrued, not yet distributed)
      uint64_t swfBurnedXfgPendingHeat = 0; // already-burned XFG awaiting SWF HEAT conversion (removed from circulating, not total supply)
      uint64_t redemptionPriceNum = 1;  // pool XFG/HⲶ∆T ratio × 10^6
      uint64_t redemptionPriceDenom = 1000000;
      uint64_t treasuryBalance = 0;
      uint64_t treasuryHeatReserve = 0;  // HⲶ∆T minted from 20% swap fee share (for APY floor)
      uint64_t treasuryLpPendingXfg = 0;    // unburned treasury XFG reserve / LP source
      uint64_t treasuryCounterXFG = 0;       // treasury counter (alias / v12 rename; same source)
      uint64_t swfHeatBalance = 0;        // SWF counter HEAT (off-chain DIGM collateral)
      uint64_t epochSwapFees = 0;
      uint64_t vaultHeatCdFeePool = 0;
      uint64_t vaultHeatLpReserve = 0;
      uint64_t vaultHeatGeneral = 0;
      uint64_t vaultHeatSwf = 0;
      uint64_t vaultXfgCdFeePool = 0;
      uint64_t vaultXfgLpReserve = 0;
      uint64_t vaultXfgGeneral = 0;
    };
    HeatMetrics getHeatMetrics() const;

    struct AmmQuote {
      uint64_t expectedOutput = 0;
      uint64_t priceImpactBps = 0;
      uint64_t fee = 0;
    };
    AmmQuote getAmmQuote(uint64_t inputAmount, uint8_t direction) const;

    struct AmmPoolInfo {
      uint64_t reserveXfg = 0;
      uint64_t reserveHeat = 0;
      uint64_t totalLpShares = 0;
      uint64_t spotPrice = 0;
      uint64_t epochSwapFees = 0;
    };
    AmmPoolInfo getAmmPoolInfo() const;
    uint64_t getPoolTwap() const;

    // Orderbook (v11+)
    struct OrderbookInfo {
      uint64_t clearingPrice = 0;     // P_clear, XFG/HEAT ratio × 10^8
      uint32_t numMatches = 0;
      uint64_t depthBidXfg = 0;      // total bid depth in atomic XFG
      uint64_t depthAskXfg = 0;      // total ask depth in atomic XFG
      uint64_t hearthPoolRatio = 0;  // P_clear avg (pool ratio fallback), HEAT atomics per XFG atomic × COIN
      bool inBootstrap = true;
    };
    OrderbookInfo getOrderbookInfo() const;

    struct OrderbookLevel {
      uint64_t price;                // XFG/HEAT ratio × 10^8
      uint64_t depth;                // aggregate depth at this level (atomic XFG)
    };
    struct OrderbookState {
      uint64_t clearingPrice;
      std::vector<OrderbookLevel> bids;
      std::vector<OrderbookLevel> asks;
    };
    OrderbookState getOrderbookState(uint32_t depth) const;

    struct OrderbookEstimate {
      uint64_t estimatedFill;
      uint64_t hearthFill;
      uint64_t orderbookFill;
      uint64_t worstCasePrice;
      uint32_t levelsConsumed;
    };
    OrderbookEstimate getOrderbookEstimate(uint8_t side, uint64_t amount) const;


    // @ Alias system proxies
    bool aliasExists(const std::string& alias) const;
    std::optional<AliasEntry> getAliasByName(const std::string& alias) const;
    std::optional<AliasEntry> getAliasByAddress(const std::string& address) const;
    std::vector<AliasEntry> getAllAliases() const;
    bool removeAlias(const std::string& alias);
    bool replaceAliasOwnership(const std::string& alias,
                               const Crypto::Hash& newAddressHash);

    bool is_key_image_spent(const Crypto::KeyImage &key_im);

  private:
    bool add_new_tx(const Transaction &tx, const Crypto::Hash &tx_hash, size_t blob_size, tx_verification_context &tvc, bool keeped_by_block, uint32_t height);
    bool load_state_data();
    bool parse_tx_from_blob(Transaction &tx, Crypto::Hash &tx_hash, Crypto::Hash &tx_prefix_hash, const BinaryArray &blob);
    bool handle_incoming_block(const Block &b, block_verification_context &bvc, bool control_miner, bool relay_block) override;

    bool check_tx_syntax(const Transaction &tx);  //check correct values, amounts and all lightweight checks not related with database
    bool check_tx_semantic(const Transaction &tx, bool keeped_by_block, uint32_t &height); //check if tx already in memory pool or in main blockchain
    bool check_tx_mixin(const Transaction& tx, uint8_t blockMajorVersion, bool keeped_by_block = false);   //check if the mixin is not too large
    bool check_tx_fee(const Transaction& tx, size_t blobSize, uint8_t blockMajorVersion, tx_verification_context& tvc); //check for proper tx fee

    bool check_tx_ring_signature(const KeyInput &tx, const Crypto::Hash &tx_prefix_hash, const std::vector<Crypto::Signature> &sig);
    bool is_tx_spendtime_unlocked(uint64_t unlock_time);
    bool update_miner_block_template();
    bool handle_command_line(const boost::program_options::variables_map &vm);
    bool on_update_blocktemplate_interval();
    bool check_tx_inputs_keyimages_diff(const Transaction &tx);
    virtual void blockchainUpdated() override;
    virtual void txDeletedFromPool() override;
    void poolUpdated();

    bool findStartAndFullOffsets(const std::vector<Crypto::Hash> &knownBlockIds, uint64_t timestamp, uint32_t &startOffset, uint32_t &startFullOffset);
    std::vector<Crypto::Hash> findIdsForShortBlocks(uint32_t startOffset, uint32_t startFullOffset);

    const Currency &m_currency;
    Logging::LoggerRef logger;
    CryptoNote::RealTimeProvider m_timeProvider;
    tx_memory_pool m_mempool;
    Blockchain m_blockchain;
    i_cryptonote_protocol *m_pprotocol;
    SwapOfferRelay* m_swapRelay = nullptr;
    CdOfferRelay* m_cdRelay = nullptr;
    std::unique_ptr<miner> m_miner;
    std::string m_config_folder;
    cryptonote_protocol_stub m_protocol_stub;
    friend class tx_validate_inputs;
    std::atomic<bool> m_starter_message_showed;
    Tools::ObserverManager<ICoreObserver> m_observerManager;
     time_t start_time;
   };
}
