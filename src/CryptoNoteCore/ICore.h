// Copyright (c) 2017-2022 Fuego Developers
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2016-2019 The Karbowanec developers
// Copyright (c) 2012-2018 The CryptoNote developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. You can redistribute it and/or modify it under the terms
// of the GNU General Public License v3 or later versions as published
// by the Free Software Foundation. Fuego includes elements written
// by third parties. See file labeled LICENSE for more details.
// You should have received a copy of the GNU General Public License
// along with Fuego. If not, see <https://www.gnu.org/licenses/>.

#pragma once

#include <cstdint>
#include <list>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <CryptoNote.h>
#include "CryptoNoteCore/Difficulty.h"

#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/BlockchainMessages.h"

namespace CryptoNote {

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request;
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response;
struct COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry;
struct NOTIFY_RESPONSE_GET_OBJECTS_request;
struct NOTIFY_REQUEST_GET_OBJECTS_request;

class Currency;
class IBlock;
class ICoreObserver;
struct Block;
struct block_verification_context;
struct BlockFullInfo;
struct BlockShortInfo;
struct core_stat_info;
struct i_cryptonote_protocol;
struct Transaction;
struct MultisignatureInput;
struct KeyInput;
struct TransactionPrefixInfo;
struct tx_verification_context;

class SwapOfferRelay;
class CdOfferRelay;

class ICore {
public:
  virtual ~ICore() {}

  virtual const Currency& currency() const = 0;

  virtual bool addObserver(ICoreObserver* observer) = 0;
  virtual bool removeObserver(ICoreObserver* observer) = 0;
  virtual bool saveBlockchain() = 0;

  virtual bool have_block(const Crypto::Hash& id) = 0;
  virtual std::vector<Crypto::Hash> buildSparseChain() = 0;
  virtual std::vector<Crypto::Hash> buildSparseChain(const Crypto::Hash& startBlockId) = 0;
  virtual bool get_stat_info(CryptoNote::core_stat_info& st_inf) = 0;
  virtual bool on_idle() = 0;
  virtual void pause_mining() = 0;
  virtual void update_block_template_and_resume_mining() = 0;
  virtual bool handle_incoming_block_blob(const CryptoNote::BinaryArray& block_blob, CryptoNote::block_verification_context& bvc, bool control_miner, bool relay_block) = 0;
  virtual bool handle_incoming_block(const Block& b, block_verification_context& bvc, bool control_miner, bool relay_block) = 0;
  virtual bool handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS_request& arg, NOTIFY_RESPONSE_GET_OBJECTS_request& rsp) = 0; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  virtual void on_synchronized() = 0;
  virtual size_t addChain(const std::vector<const IBlock*>& chain) = 0;

  virtual void get_blockchain_top(uint32_t& height, Crypto::Hash& top_id) = 0;
  virtual std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds, size_t maxCount,
    uint32_t& totalBlockCount, uint32_t& startBlockIndex) = 0;
  virtual bool get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response& res) = 0;
  virtual bool get_random_commitment_outs_for_amount(uint64_t amount, uint64_t count, uint32_t maxHeight, std::vector<COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry>& result) = 0;
  // Bulk lookup of creation heights for (amount, global_index) pairs. Used by wallets for OSPEAD decoy filtering.
  virtual bool get_output_heights(const std::vector<std::pair<uint64_t, uint32_t>>& queries,
                                  std::vector<uint32_t>& heights) = 0;
  virtual bool get_tx_outputs_gindexs(const Crypto::Hash& tx_id, std::vector<uint32_t>& indexs) = 0;
  // Lookup output keys at explicit per-amount global indexes.
  virtual bool get_outs_for_amount(uint64_t amount, const std::vector<uint64_t>& indexes,
                                   std::vector<Crypto::PublicKey>& keys) = 0;
  virtual bool getOutByMSigGIndex(uint64_t amount, uint64_t gindex, MultisignatureOutput& out) = 0;
  virtual i_cryptonote_protocol* get_protocol() = 0;
  virtual SwapOfferRelay& getSwapRelay() = 0;
  virtual CdOfferRelay& getCdRelay() = 0;
  virtual bool handle_incoming_tx(const BinaryArray& tx_blob, tx_verification_context& tvc, bool keeped_by_block) = 0; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  virtual std::vector<Transaction> getPoolTransactions() = 0;
  virtual bool getPoolTransaction(const Crypto::Hash &tx_hash, Transaction &transaction) = 0;
  virtual bool getPoolChanges(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds,
                              std::vector<Transaction>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) = 0;
  virtual bool getPoolChangesLite(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds,
                              std::vector<TransactionPrefixInfo>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) = 0;
  virtual void getPoolChanges(const std::vector<Crypto::Hash>& knownTxsIds, std::vector<Transaction>& addedTxs,
                              std::vector<Crypto::Hash>& deletedTxsIds) = 0;
  virtual bool queryBlocks(const std::vector<Crypto::Hash>& block_ids, uint64_t timestamp,
    uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockFullInfo>& entries) = 0;
  virtual bool queryBlocksLite(const std::vector<Crypto::Hash>& block_ids, uint64_t timestamp,
    uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockShortInfo>& entries) = 0;

  virtual Crypto::Hash getBlockIdByHeight(uint32_t height) = 0;
  virtual bool getBlockByHash(const Crypto::Hash &h, Block &blk) = 0;
  virtual bool getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight) = 0;
  virtual void getTransactions(const std::vector<Crypto::Hash>& txs_ids, std::list<Transaction>& txs, std::list<Crypto::Hash>& missed_txs, bool checkTxPool = false) = 0;
  virtual bool getBackwardBlocksSizes(uint32_t fromHeight, std::vector<size_t>& sizes, size_t count) = 0;
  virtual bool getBlockSize(const Crypto::Hash& hash, size_t& size) = 0;
  virtual bool getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins) = 0;
  virtual bool getBlockReward(uint8_t blockMajorVersion, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint32_t height,
                              uint64_t& reward, int64_t& emissionChange) = 0;
  virtual bool scanOutputkeysForIndices(const KeyInput& txInToKey, std::list<std::pair<Crypto::Hash, size_t>>& outputReferences) = 0;
  virtual bool getBlockDifficulty(uint32_t height, difficulty_type& difficulty) = 0;
  virtual bool getBlockContainingTx(const Crypto::Hash& txId, Crypto::Hash& blockId, uint32_t& blockHeight) = 0;
  virtual bool getMultisigOutputReference(const MultisignatureInput& txInMultisig, std::pair<Crypto::Hash, size_t>& outputReference) = 0;
  virtual bool getTransaction(const Crypto::Hash &id, Transaction &tx, bool checkTxPool = false) = 0;
  virtual bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions) = 0;
  virtual bool getOrphanBlocksByHeight(uint32_t height, std::vector<Block>& blocks) = 0;
  virtual bool getBlocksByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Block>& blocks, uint32_t& blocksNumberWithinTimestamps) = 0;
  virtual bool getPoolTransactionsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t transactionsNumberLimit, std::vector<Transaction>& transactions, uint64_t& transactionsNumberWithinTimestamps) = 0;
  virtual bool getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<Transaction>& transactions) = 0;

  virtual uint8_t getCurrentBlockMajorVersion() = 0;
  virtual std::unique_ptr<IBlock> getBlock(const Crypto::Hash& blocksId) = 0;
  virtual bool handleIncomingTransaction(const Transaction& tx, const Crypto::Hash& txHash, size_t blobSize, tx_verification_context& tvc, bool keptByBlock, uint32_t height) = 0;
  virtual std::error_code executeLocked(const std::function<std::error_code()>& func) = 0;

  virtual bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;
  virtual bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;

  // CD interest calculation delegated to Currency + CommitmentIndex.
  // Non-pure so mock/stub ICore implementations compile without changes.
  virtual std::error_code calculateCdInterest(uint64_t amount, uint32_t creationHeight,
                                                uint32_t currentHeight, uint64_t& outInterest,
                                                bool isLegacyBond = false,
                                                uint32_t term = 0,
                                                bool autoRolled = false) {
    outInterest = 0;
    return {};
  }
  virtual std::error_code getCommitmentEpochFeeRate(uint32_t epoch, uint64_t& outFeeRate) {
    outFeeRate = 0;
    return {};
  }

  // AMM pool reserves for HEAT mint rate computation.
  struct AmmPoolReserves {
    uint64_t reserveXfg = 1;
    uint64_t reserveHeat = 1;
  };
  virtual std::error_code getAmmPoolReserves(AmmPoolReserves& out) {
    out = {1, 1};
    return {};
  }
  virtual uint64_t getHearthTwap() { return 0; }
  struct AmmPoolInfo {
    uint64_t reserveXfg = 0;
    uint64_t reserveHeat = 0;
    uint64_t spotPrice = 0;
  };
  virtual std::error_code getAmmPoolInfo(AmmPoolInfo& info) {
    return std::make_error_code(std::errc::not_supported);
  }

  // HEAT backing available for CD interest claims and the CD_APY_POOL vault
  // partition balance. Non-pure so stubs compile; real core overrides.
  virtual uint64_t getFeePoolBalance() { return 0; }
  virtual uint64_t getCdApyVaultBalance() { return 0; }
  // v11+: BV-backed tier bonus (realized Bonus Vault inflows) and the
  // BONUS_VAULT counter. Non-pure so stubs compile.
  virtual std::error_code calculateCdBonus(uint64_t amount, uint32_t creationHeight,
                                           uint32_t currentHeight, uint64_t& outBonus,
                                           uint32_t term = 0) {
    outBonus = 0;
    return {};
  }
  virtual uint64_t getBonusVaultBalance() { return 0; }
  virtual uint64_t getBonusVaultUtxoBalance() { return 0; }
};

} //namespace CryptoNote
