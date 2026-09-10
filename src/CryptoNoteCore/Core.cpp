// Copyright (c) 2017-2026 Fuego Developers
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

#include "Core.h"

#include <sstream>
#include <unordered_set>
#include "../CryptoNoteConfig.h"
#include "../Common/CommandLine.h"
#include "../Common/Util.h"
#include "../Common/MathUtils.h"
#include "../Common/StringTools.h"
#include "../crypto/crypto.h"
#include "../CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "../Logging/LoggerRef.h"
#include "../Rpc/CoreRpcServerCommandsDefinitions.h"
#include "CryptoNoteFormatUtils.h"

#include "CryptoNoteTools.h"
#include "CryptoNoteStatInfo.h"
#include "Miner.h"
#include "TransactionExtra.h"
#include "IBlock.h"
#include "Currency.h"
#include <vector>
#include <functional>
#include <array>
#include <list>
#include <string>
#include <memory>
#include "../CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "../Rpc/CoreRpcServerCommandsDefinitions.h"
#include "../crypto/hash.h"
#include "../CryptoNoteCore/CryptoNoteBasic.h"
#include "../CryptoNoteCore/Difficulty.h"
#include "../../include/CryptoNote.h"

#undef ERROR

using namespace Logging;

#include "CryptoNoteCore/CoreConfig.h"

using namespace  Common;

namespace CryptoNote {

class BlockWithTransactions : public IBlock {
public:
  virtual const Block& getBlock() const override {
    return block;
  }

  virtual size_t getTransactionCount() const override {
    return transactions.size();
  }

  virtual const Transaction& getTransaction(size_t index) const override {
    assert(index < transactions.size());
    return transactions[index];
  }

private:
  Block block;
  std::vector<Transaction> transactions;

  friend class core;
};

core::core(const Currency &currency, i_cryptonote_protocol *pprotocol, Logging::ILogger &logger, bool blockchainIndexesEnabled, bool blockchainAutosaveEnabled) : m_currency(currency),
                                                                                                                                                                  logger(logger, "core"),
                                                                                                                                                                  m_mempool(currency, m_blockchain, m_timeProvider, logger),
                                                                                                                                                                  m_blockchain(currency, m_mempool, logger, blockchainIndexesEnabled, blockchainAutosaveEnabled),
                                                                                                                                                                  m_miner(new miner(currency, *this, logger)),
                                                                                                                                                                  m_starter_message_showed(false)
{

  set_cryptonote_protocol(pprotocol);
  m_blockchain.addObserver(this);
  m_mempool.addObserver(this);
}
  //-----------------------------------------------------------------------------------------------
  core::~core() {
  m_blockchain.removeObserver(this);
}

void core::set_cryptonote_protocol(i_cryptonote_protocol* pprotocol) {
  if (pprotocol) {
    m_pprotocol = pprotocol;
  } else {
    m_pprotocol = &m_protocol_stub;
  }
}
//-----------------------------------------------------------------------------------
void core::set_checkpoints(Checkpoints&& chk_pts) {
  m_blockchain.setCheckpoints(std::move(chk_pts));
}
//-----------------------------------------------------------------------------------
void core::init_options(boost::program_options::options_description& /*desc*/) {
}

bool core::handle_command_line(const boost::program_options::variables_map& vm) {
  m_config_folder = command_line::get_arg(vm, command_line::arg_data_dir);
  return true;
}

uint32_t core::get_current_blockchain_height() {
  return m_blockchain.getCurrentBlockchainHeight();
}
uint8_t core::getCurrentBlockMajorVersion() {
  assert(m_blockchain.getCurrentBlockchainHeight() > 0);
  return m_blockchain.getBlockMajorVersionForHeight(m_blockchain.getCurrentBlockchainHeight());
}
void core::get_blockchain_top(uint32_t& height, Crypto::Hash& top_id) {
  assert(m_blockchain.getCurrentBlockchainHeight() > 0);
  top_id = m_blockchain.getTailId(height);
}

bool core::rollback_chain_to(uint32_t height) {
  return m_blockchain.rollbackBlockchainTo(height);
}

bool core::get_blocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks, std::list<Transaction>& txs) {
  return m_blockchain.getBlocks(start_offset, count, blocks, txs);
}


bool core::get_blocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks) {
  return m_blockchain.getBlocks(start_offset, count, blocks);
}
void core::getTransactions(const std::vector<Crypto::Hash>& txs_ids, std::list<Transaction>& txs, std::list<Crypto::Hash>& missed_txs, bool checkTxPool) {
  m_blockchain.getTransactions(txs_ids, txs, missed_txs, checkTxPool);
}

bool core::getTransaction(const Crypto::Hash &id, Transaction &tx, bool checkTxPool)
{
  std::vector<Crypto::Hash> txs_ids;
  std::list<Transaction> txs;
  std::list<Crypto::Hash> missed_txs;

  txs_ids.push_back(id);
  m_blockchain.getTransactions(txs_ids, txs, missed_txs, checkTxPool);

  if (missed_txs.empty() && !txs.empty() && txs.size() == 1)
  {
    tx = txs.front();
    return true;
  }

  return false;
}

bool core::get_alternative_blocks(std::list<Block>& blocks) {
  return m_blockchain.getAlternativeBlocks(blocks);
}

size_t core::get_alternative_blocks_count() {
  return m_blockchain.getAlternativeBlocksCount();
}

std::time_t core::getStartTime() const {
  return start_time;
}
  //-----------------------------------------------------------------------------------------------
bool core::init(const CoreConfig& config, const MinerConfig& minerConfig, bool load_existing) {
  m_config_folder = config.configFolder;
  bool r = m_mempool.init(m_config_folder);

  if (!(r)) {
    logger(ERROR, BRIGHT_RED) << "Failed to initialize memory pool";
    return false;
  }

  r = m_blockchain.init(m_config_folder, load_existing);
  if (!(r)) {
    logger(ERROR, BRIGHT_RED) << "Failed to initialize blockchain storage";
    return false;
  }

  r = m_miner->init(minerConfig);
  if (!(r)) {
    logger(ERROR, BRIGHT_RED) << "Failed to initialize blockchain storage";
    return false;
  }

  return load_state_data();
}

bool core::set_genesis_block(const Block& b) {
  return m_blockchain.resetAndSetGenesisBlock(b);
}

bool core::load_state_data() {
  // may be some code later
  return true;
}

bool core::deinit() {
  m_miner->stop();
  m_mempool.deinit();
  m_blockchain.deinit();
  return true;
}

size_t core::addChain(const std::vector<const IBlock*>& chain) {
  size_t blocksCounter = 0;

  for (const IBlock* block : chain) {
    bool allTransactionsAdded = true;
    for (size_t txNumber = 0; txNumber < block->getTransactionCount(); ++txNumber) {
      const Transaction& tx = block->getTransaction(txNumber);

      Crypto::Hash txHash = NULL_HASH;
      size_t blobSize = 0;
      getObjectHash(tx, txHash, blobSize);
      tx_verification_context tvc = boost::value_initialized<tx_verification_context>();

      if (!handleIncomingTransaction(tx, txHash, blobSize, tvc, true, get_block_height(block->getBlock()))) {
        logger(ERROR, BRIGHT_RED) << "core::addChain() failed to handle transaction " << txHash << " from block " << blocksCounter << "/" << chain.size();
        allTransactionsAdded = false;
        break;
      }
    }

    if (!allTransactionsAdded) {
      break;
    }

    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    m_blockchain.addNewBlock(block->getBlock(), bvc);
    if (bvc.m_marked_as_orphaned || bvc.m_verification_failed) {
      logger(ERROR, BRIGHT_RED) << "core::addChain() failed to handle incoming block " << get_block_hash(block->getBlock()) <<
        ", " << blocksCounter << "/" << chain.size();

      break;
    }

    ++blocksCounter;
    // TODO m_dispatcher.yield()?
  }

  return blocksCounter;
}

bool core::handle_incoming_tx(const BinaryArray& tx_blob, tx_verification_context& tvc, bool keeped_by_block) { //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  tvc = boost::value_initialized<tx_verification_context>();
  //want to process all transactions sequentially

  if (tx_blob.size() > m_currency.maxTxSize()) {
    logger(INFO) << "WRONG TRANSACTION BLOB, too big size " << tx_blob.size() << ", rejected";
    tvc.m_verification_failed = true;
    return false;
  }

  Crypto::Hash tx_hash = NULL_HASH;
  Crypto::Hash tx_prefixt_hash = NULL_HASH;
  Transaction tx;

  if (!parse_tx_from_blob(tx, tx_hash, tx_prefixt_hash, tx_blob)) {
    logger(INFO) << "WRONG TRANSACTION BLOB, Failed to parse, rejected";
    tvc.m_verification_failed = true;
    return false;
  }
  //std::cout << "!"<< tx.inputs.size() << std::endl;

  Crypto::Hash blockId;
  uint32_t blockHeight;
  bool ok = getBlockContainingTx(tx_hash, blockId, blockHeight);
  if (!ok) blockHeight = this->get_current_blockchain_height(); //this assumption fails for withdrawals
  return handleIncomingTransaction(tx, tx_hash, tx_blob.size(), tvc, keeped_by_block, blockHeight);
}

bool core::get_stat_info(core_stat_info& st_inf) {
  st_inf.mining_speed = m_miner->get_speed();
  st_inf.alternative_blocks = m_blockchain.getAlternativeBlocksCount();
  st_inf.blockchain_height = m_blockchain.getCurrentBlockchainHeight();
  st_inf.tx_pool_size = m_mempool.get_transactions_count();
  st_inf.top_block_id_str = Common::podToHex(m_blockchain.getTailId());
  return true;
}

bool core::check_tx_mixin(const Transaction& tx, uint8_t blockMajorVersion, bool keeped_by_block) {
  size_t inputIndex = 0;
  for (const auto& txin : tx.inputs) {
    assert(inputIndex < tx.signatures.size());
    if (txin.type() == typeid(KeyInput)) {
      uint64_t ringSize = boost::get<KeyInput>(txin).outputIndexes.size();
      if (!keeped_by_block && ringSize > m_currency.maxMixin() + 1) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has too large mixIn count, rejected";
        return false;
      }
      if (!keeped_by_block && blockMajorVersion >= BLOCK_MAJOR_VERSION_7 && ringSize < m_currency.minMixin(blockMajorVersion)) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has mixIn count " << ringSize
                      << " below the required minimum " << m_currency.minMixin(blockMajorVersion)
                      << " for block version " << (int)blockMajorVersion << ", rejected";
        return false;
      }
    } else if (txin.type() == typeid(TransactionInputCommitmentSpend)) {
      uint64_t ringSize = boost::get<TransactionInputCommitmentSpend>(txin).outputIndexes.size();
      if (!keeped_by_block && ringSize > m_currency.maxMixin() + 1) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has too large commitment spend ring size, rejected";
        return false;
      }
      if (!keeped_by_block && blockMajorVersion >= BLOCK_MAJOR_VERSION_10 && ringSize < m_currency.minMixin(blockMajorVersion)) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has commitment spend ring size " << ringSize
                      << " below the required minimum " << m_currency.minMixin(blockMajorVersion)
                      << " for block version " << (int)blockMajorVersion << ", rejected";
        return false;
      }
    } else if (txin.type() == typeid(TransactionInputCommitmentTransfer)) {
      uint64_t ringSize = boost::get<TransactionInputCommitmentTransfer>(txin).outputIndexes.size();
      if (!keeped_by_block && ringSize > m_currency.maxMixin() + 1) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has too large CD transfer ring size, rejected";
        return false;
      }
      if (!keeped_by_block && blockMajorVersion >= BLOCK_MAJOR_VERSION_11 && ringSize < m_currency.minMixin(blockMajorVersion)) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has CD transfer ring size " << ringSize
                      << " below the required minimum " << m_currency.minMixin(blockMajorVersion)
                      << " for block version " << (int)blockMajorVersion << ", rejected";
        return false;
      }
    } else if (txin.type() == typeid(TransactionInputUnified)) {
      uint64_t ringSize = boost::get<TransactionInputUnified>(txin).outputIndexes.size();
      if (!keeped_by_block && ringSize > m_currency.maxMixin() + 1) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has too large unified input ring size, rejected";
        return false;
      }
      if (!keeped_by_block && blockMajorVersion >= BLOCK_MAJOR_VERSION_12 && ringSize < m_currency.minMixin(blockMajorVersion)) {
        logger(ERROR) << "Transaction " << getObjectHash(tx) << " has unified input ring size " << ringSize
                      << " below the required minimum " << m_currency.minMixin(blockMajorVersion)
                      << " for block version " << (int)blockMajorVersion << ", rejected";
        return false;
      }
    }
    inputIndex++;
  }
  return true;
}

bool core::check_tx_fee(const Transaction& tx, size_t blobSize, uint8_t blockMajorVersion, tx_verification_context& tvc) {
	uint64_t inputs_amount = 0;
	if (!get_inputs_money_amount(tx, inputs_amount)) {
		tvc.m_verification_failed = true;
		return false;
	}

	uint64_t outputs_amount = get_outs_money_amount(tx);

	if (outputs_amount > inputs_amount) {
		logger(DEBUGGING) << "transaction uses more money then it has: use " << m_currency.formatAmount(outputs_amount) <<
			", have " << m_currency.formatAmount(inputs_amount);
		tvc.m_verification_failed = true;
		return false;
	}

	Crypto::Hash h = NULL_HASH;
	getObjectHash(tx, h, blobSize);
	const uint64_t fee = inputs_amount - outputs_amount;
	bool isFusionTransaction = fee == 0 && m_currency.isFusionTransaction(tx, blobSize);

	// Use flat minimum fee (no dynamic calculation)
	if (!isFusionTransaction && fee < m_currency.minimumFee(blockMajorVersion)) {
		logger(DEBUGGING) << "transaction fee is not enough: " << m_currency.formatAmount(fee) <<
			", minimum fee: " << m_currency.formatAmount(m_currency.minimumFee(blockMajorVersion));
		tvc.m_verification_failed = true;
		tvc.m_tx_fee_too_small = true;
		return false;
	}

	return true;
}

bool core::check_tx_semantic(const Transaction& tx, bool keeped_by_block, uint32_t &height) {
  if (!tx.inputs.size()) {
    logger(ERROR) << "tx with empty inputs, rejected for tx id= " << getObjectHash(tx);
    return false;
  }

  if (!check_inputs_types_supported(tx)) {
    logger(ERROR) << "unsupported input types for tx id= " << getObjectHash(tx);
    return false;
  }

  std::string errmsg;
  if (!check_outs_valid(tx, &errmsg)) {
    logger(ERROR) << "tx with invalid outputs, rejected for tx id= " << getObjectHash(tx) << ": " << errmsg;
    return false;
  }

  if (!check_money_overflow(tx)) {
    logger(ERROR) << "tx have money overflow, rejected for tx id= " << getObjectHash(tx);
    return false;
  }

  uint64_t amount_in = m_currency.getTransactionAllInputsAmount(tx, height);
  uint64_t amount_out = get_outs_money_amount(tx);

  // Parse extra tags for per-asset conservation check
  bool hasAmmSwapAuth = false;
  uint8_t ammSwapDirection = 0;
  bool hasHeatMintAuth = false;
  std::vector<TransactionExtraField> tx_extra_fields;
  if (parseTransactionExtra(tx.extra, tx_extra_fields)) {
    for (const auto& field : tx_extra_fields) {
      if (field.type() == typeid(TransactionExtraAmmSwapAuth)) {
        hasAmmSwapAuth = true;
        ammSwapDirection = boost::get<TransactionExtraAmmSwapAuth>(field).direction;
        break;
      }
      if (field.type() == typeid(TransactionExtraHeatMintAuth)) {
        hasHeatMintAuth = true;
        break;
      }
    }
  }

  if (hasAmmSwapAuth || hasHeatMintAuth) {
    // AMM swap or HEAT mint: check per-asset conservation instead of aggregate.
    // HEAT mint is equivalent to direction 0 (XFG→HEAT): XFG inputs cover XFG outputs + fee, HEAT is minted.
    // AMM direction 0 (XFG→HEAT): XFG inputs must cover XFG outputs + fee.
    // AMM direction 1 (HEAT→XFG): HEAT inputs must cover HEAT outputs.
    AssetBalance inAssets = get_blockchain_storage().getTransactionInputAssetAmounts(tx, height);
    AssetBalance outAssets = m_currency.getTransactionOutputAssetAmounts(tx);
    uint64_t fee = amount_in < amount_out ? m_currency.minimumFee() : amount_in - amount_out;

    if (hasHeatMintAuth || ammSwapDirection == 0) {
      // XFG→HEAT: XFG conservation (HEAT is minted, no HEAT inputs expected)
      if (inAssets.xfg < outAssets.xfg + fee) {
        logger(ERROR) << "tx XFG conservation violated for " << (hasHeatMintAuth ? "HEAT mint" : "AMM swap")
                      << ": xfg_in=" << inAssets.xfg << " xfg_out=" << outAssets.xfg << " fee=" << fee
                      << " rejected for tx id= " << getObjectHash(tx);
        return false;
      }
    } else {
      // HEAT→XFG: HEAT conservation (XFG is minted, no XFG inputs expected)
      if (inAssets.heat < outAssets.heat) {
        logger(ERROR) << "tx HEAT conservation violated for AMM swap: heat_in=" << inAssets.heat
                      << " heat_out=" << outAssets.heat
                      << " rejected for tx id= " << getObjectHash(tx);
        return false;
      }
    }
  } else if (amount_in < amount_out) {
    logger(ERROR) << "tx with wrong amounts: ins " << amount_in << ", outs " << amount_out << ", rejected for tx id= " << getObjectHash(tx);
    return false;
  }

  //check if tx use different key images
  if (!check_tx_inputs_keyimages_diff(tx)) {
    logger(ERROR) << "tx has a few inputs with identical keyimages";
    return false;
  }

  if (!checkMultisignatureInputsDiff(tx)) {
    logger(ERROR) << "tx has a few multisignature inputs with identical output indexes";
    return false;
  }

  if (!checkSwapEscrowInputsDiff(tx)) {
    logger(ERROR) << "tx has duplicate swap escrow inputs";
    return false;
  }

  // Determine block major version from the given height
  uint8_t blockMajorVersion = BLOCK_MAJOR_VERSION_1;
  uint8_t versionsToCheck[] = {
    BLOCK_MAJOR_VERSION_11, BLOCK_MAJOR_VERSION_10, BLOCK_MAJOR_VERSION_9,
    BLOCK_MAJOR_VERSION_8, BLOCK_MAJOR_VERSION_7, BLOCK_MAJOR_VERSION_6,
    BLOCK_MAJOR_VERSION_5, BLOCK_MAJOR_VERSION_4, BLOCK_MAJOR_VERSION_3,
    BLOCK_MAJOR_VERSION_2
  };
  for (auto v : versionsToCheck) {
    uint32_t uh = m_currency.upgradeHeight(v);
    if (uh != UpgradeDetectorBase::UNDEF_HEIGHT && height >= uh) {
      blockMajorVersion = v;
      break;
    }
  }
  if (!check_tx_mixin(tx, blockMajorVersion, keeped_by_block)) {
    logger(ERROR) << "tx with invalid mixin, rejected for tx id= " << getObjectHash(tx);
    return false;
  }

  // Swap-escrow inputs/outputs are a v11 (HEATWAVE) consensus feature.
  // Reject them on pre-v11 blocks so old nodes and new nodes stay in sync
  // during the upgrade window.
  if (blockMajorVersion < BLOCK_MAJOR_VERSION_11) {
    for (const auto& in : tx.inputs) {
      if (in.type() == typeid(TransactionInputSwapEscrow)) {
        logger(ERROR) << "Swap escrow input before v11 rejected";
        return false;
      }
    }
    for (const auto& out : tx.outputs) {
      if (out.target.type() == typeid(TransactionOutputSwapEscrow)) {
        logger(ERROR) << "Swap escrow output before v11 rejected";
        return false;
      }
    }
  }

  return true;
}

bool core::check_tx_inputs_keyimages_diff(const Transaction& tx) {

  // parameters used for the additional key_image check
 // static const Crypto::KeyImage Z = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
  static const Crypto::KeyImage I = { { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
  static const Crypto::KeyImage L = { { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 } };

  std::unordered_set<Crypto::KeyImage> ki;
  std::set<std::pair<uint64_t, uint32_t>> outputsUsage;
  for (const auto& input : tx.inputs) {
    if (input.type() == typeid(KeyInput)) {
      const KeyInput& in = boost::get<KeyInput>(input);
      if (!ki.insert(in.keyImage).second) {
        logger(ERROR) << "Transaction has identical key images";
          return false;
      }

      if (in.outputIndexes.empty()) {
        logger(ERROR) << "Transaction's input uses empty output";
        return false;
      }

	  // additional key_image check
	  // Fix discovered by Monero Lab and suggested by "fluffypony" (bitcointalk.org)
	  if (!(scalarmultKey(in.keyImage, L) == I)) {
		  logger(ERROR) << "Transaction uses key image not in the valid domain";
		  return false;
	  }

      // outputIndexes are packed here, first is absolute, others are offsets to previous,
      // so first can be zero, others can't
      if (std::find(++std::begin(in.outputIndexes), std::end(in.outputIndexes), 0) != std::end(in.outputIndexes)) {
        logger(ERROR) << "Transaction has identical output indexes";
        return false;
      }
    } else if (input.type() == typeid(TransactionInputCommitmentSpend)) {
      const auto& cin = boost::get<TransactionInputCommitmentSpend>(input);
      if (!ki.insert(cin.keyImage).second) {
        logger(ERROR) << "Transaction has identical commitment spend key images";
        return false;
      }
      if (cin.outputIndexes.empty()) {
        logger(ERROR) << "Transaction's commitment spend input uses empty output";
        return false;
      }
    } else if (input.type() == typeid(TransactionInputCommitmentTransfer)) {
      const auto& xfer = boost::get<TransactionInputCommitmentTransfer>(input);
      if (!ki.insert(xfer.keyImage).second) {
        logger(ERROR) << "Transaction has identical commitment transfer key images";
        return false;
      }
      if (xfer.outputIndexes.empty()) {
        logger(ERROR) << "Transaction's commitment transfer input uses empty output";
        return false;
      }
    } else if (input.type() == typeid(TransactionInputSwapEscrow)) {
      const auto& escrow = boost::get<TransactionInputSwapEscrow>(input);
      if (!ki.insert(escrow.keyImage).second) {
        logger(ERROR) << "Transaction has identical swap escrow key images";
        return false;
      }
      static const Crypto::Hash ZERO_HASH{};
      if (std::memcmp(&escrow.escrowTxId, &ZERO_HASH, sizeof(Crypto::Hash)) == 0) {
        logger(ERROR) << "Swap escrow input with zero escrow tx id";
        return false;
      }
      if (escrow.mode > 1) {
        logger(ERROR) << "Swap escrow input with invalid mode";
        return false;
      }
    }
  }
  return true;
}

size_t core::get_blockchain_total_transactions() {
  return m_blockchain.getTotalTransactions();
}

//bool core::get_outs(uint64_t amount, std::list<Crypto::PublicKey>& pkeys)
//{
//  return m_blockchain.get_outs(amount, pkeys);
//}

bool core::add_new_tx(const Transaction& tx, const Crypto::Hash& tx_hash, size_t blob_size, tx_verification_context& tvc, bool keeped_by_block, uint32_t height) {
  //Locking on m_mempool and m_blockchain closes possibility to add tx to memory pool which is already in blockchain
  std::lock_guard<decltype(m_mempool)> lk(m_mempool);
  LockedBlockchainStorage lbs(m_blockchain);

  if (m_blockchain.haveTransaction(tx_hash)) {
    logger(TRACE) << "tx " << tx_hash << " is already in blockchain";
    return true;
  }

  if (m_mempool.have_tx(tx_hash)) {
    logger(TRACE) << "tx " << tx_hash << " is already in transaction pool";
    return true;
  }
  return m_mempool.add_tx(tx, tx_hash, blob_size, tvc, keeped_by_block, height);
}

bool core::get_block_template(Block& b, const AccountPublicAddress& adr, difficulty_type& diffic, uint32_t& height, const BinaryArray& ex_nonce) {
  size_t median_size;
  uint64_t already_generated_coins;

  {
    LockedBlockchainStorage blockchainLock(m_blockchain);
    height = m_blockchain.getCurrentBlockchainHeight();
    diffic = m_blockchain.getDifficultyForNextBlock();
    if (!(diffic)) {
      logger(ERROR, BRIGHT_RED) << "difficulty overhead.";
      return false;
    }

    b = boost::value_initialized<Block>();
    b.majorVersion = m_blockchain.getBlockMajorVersionForHeight(height);

        if (b.majorVersion == BLOCK_MAJOR_VERSION_1) {
      b.minorVersion = m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_2) == UpgradeDetectorBase::UNDEF_HEIGHT ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
    } else if (b.majorVersion >= BLOCK_MAJOR_VERSION_2) { // upgradekit
            if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_10) == UpgradeDetectorBase::UNDEF_HEIGHT) {
          b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_9 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
             if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_9) == UpgradeDetectorBase::UNDEF_HEIGHT) {
        b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_8 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
      } else if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_8) == UpgradeDetectorBase::UNDEF_HEIGHT) {
        b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_7 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
      } else if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_7) == UpgradeDetectorBase::UNDEF_HEIGHT) {
        b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_6 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
      } else if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_6) == UpgradeDetectorBase::UNDEF_HEIGHT) {
        b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_5 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
      } else if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_5) == UpgradeDetectorBase::UNDEF_HEIGHT) {
        b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_4 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
      } else if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_4) == UpgradeDetectorBase::UNDEF_HEIGHT) {
        b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_3 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
      } else if (m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_3) == UpgradeDetectorBase::UNDEF_HEIGHT) {
        b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_2 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
      } else {
        b.minorVersion = BLOCK_MINOR_VERSION_0;
      }
    }

    b.parentBlock.majorVersion = BLOCK_MAJOR_VERSION_1;
      b.parentBlock.minorVersion = BLOCK_MINOR_VERSION_0;
      b.parentBlock.transactionCount = 1;
      TransactionExtraMergeMiningTag mm_tag = boost::value_initialized<decltype(mm_tag)>();

      if (!appendMergeMiningTagToExtra(b.parentBlock.baseTransaction.extra, mm_tag)) {
        logger(ERROR, BRIGHT_RED) << "Failed to append merge mining tag to extra of the parent block miner transaction";
        return false;
      }
    }

    b.previousBlockHash = get_tail_id();
    b.timestamp = time(NULL);



    // Courtesy of Jagerman
    // https://github.com/graft-project/GraftNetwork/pull/118/commits

    // If some other node has submitted enough blocks with forged future
    // timestamps, legitimate nodes end up providing their pools with a block
    // template that cannot be accepted -- it fails the requirement that a block
    // timestamp be greater than the median of the recent block window.
    //
    // This fix allows the node to increase the timestamp to the median (i.e. the
    // minimum required) if the timestamp would be rejected so that it doesn't
    // end up handing out impossible-to-accept block templates.
    //
    // Most importantly, this prohibits an attacker from stalling all
    // legitimate pools by submitting fake timestamps to the network.


    if(height >= m_currency.timestampCheckWindow(b.majorVersion)) {
      std::vector<uint64_t> timestamps;
      for(size_t offset = height - m_currency.timestampCheckWindow(b.majorVersion); offset < height; ++offset) {

        timestamps.push_back(m_blockchain.getBlockTimestamp(offset));
      }
      uint64_t median_ts = Common::medianValue(timestamps);
      if (b.timestamp < median_ts) {
          b.timestamp = median_ts;
      }
    }
//
    median_size = m_blockchain.getCurrentCumulativeBlocksizeLimit() / 2;
    already_generated_coins = m_blockchain.getCoinsInCirculation();
  }

  size_t txs_size;
  uint64_t fee;
  if (!m_mempool.fill_block_template(b, median_size, m_currency.maxBlockCumulativeSize(height), already_generated_coins, txs_size, fee, height)) {
    logger(ERROR, BRIGHT_RED) << "fill_block_template failed - median_size=" << median_size
      << ", max_block_size=" << m_currency.maxBlockCumulativeSize(height)
      << ", already_generated_coins=" << already_generated_coins;
    return false;
  }
    logger(DEBUGGING) << "Block template: height=" << height << ", majorVersion=" << (int)b.majorVersion
      << ", difficulty=" << diffic << ", txs_size=" << txs_size << ", fee=" << fee;

  /*
     two-phase miner transaction generation: we don't know exact block size until we prepare block, but we don't know reward until we know
     block size, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block size
     */
  // Use deterministic height-indexed burn amount for reward calculation
  // Burns through block N-1 determine the reward for block N
  uint64_t burnedCoins = (height > 0) ? m_blockchain.getBurnedXfgAtHeight(height - 1) : 0;

  // V10+: Compute banking fees from block template transactions for coinbase split
  uint64_t bankingFeesInBlock = 0;
  if (b.majorVersion >= BLOCK_MAJOR_VERSION_10) {
    // Fetch transactions from mempool to compute banking fees
    std::vector<Transaction> blockTxs;
    std::vector<Crypto::Hash> missed;
    m_mempool.getTransactions(b.transactionHashes, blockTxs, missed);
    bankingFeesInBlock = Blockchain::computeBankingFeesFromTransactions(blockTxs);

    if (bankingFeesInBlock > 0) {
      logger(DEBUGGING) << "Block template banking fees: " << bankingFeesInBlock;
    }
  }

  //make block's coinbase tx look more like real coinbase txs to get truthful blob size
  size_t maxCoinbaseOuts = (b.majorVersion >= BLOCK_MAJOR_VERSION_11) ? 33 : 11;
  bool r = m_currency.constructMinerTx(b.majorVersion, height, median_size, already_generated_coins, txs_size, fee, adr, b.baseTransaction, ex_nonce, maxCoinbaseOuts, burnedCoins, bankingFeesInBlock);
  if (!r) {
    logger(ERROR, BRIGHT_RED) << "Failed to construct miner tx, first chance";
    return false;
  }

  size_t cumulative_size = txs_size + getObjectBinarySize(b.baseTransaction);
  size_t try_count = 0;
  for (; try_count != 10; ++try_count) {
    logger(TRACE) << "constructMinerTx attempt " << try_count << ": height=" << height << ", majorVersion=" << (int)b.majorVersion
      << ", median_size=" << median_size << ", cumulative_size=" << cumulative_size
      << ", already_generated_coins=" << already_generated_coins << ", fee=" << fee;
    r = m_currency.constructMinerTx(b.majorVersion, height, median_size, already_generated_coins, cumulative_size, fee, adr, b.baseTransaction, ex_nonce, maxCoinbaseOuts, burnedCoins, bankingFeesInBlock);

    if (!(r)) {
      logger(ERROR, BRIGHT_RED) << "Failed to construct miner tx, second chance. height=" << height
        << ", majorVersion=" << (int)b.majorVersion << ", cumulative_size=" << cumulative_size
        << ", fee=" << fee << ", already_generated_coins=" << already_generated_coins;
      return false;
    }
    size_t coinbase_blob_size = getObjectBinarySize(b.baseTransaction);
    logger(TRACE) << "Try " << try_count << ": coinbase_blob_size=" << coinbase_blob_size << ", cumulative_size=" << cumulative_size << ", txs_size=" << txs_size;
    if (coinbase_blob_size > cumulative_size - txs_size) {
      cumulative_size = txs_size + coinbase_blob_size;
      continue;
    }

    if (coinbase_blob_size < cumulative_size - txs_size) {
      size_t delta = cumulative_size - txs_size - coinbase_blob_size;
      logger(TRACE) << "Try " << try_count << ": coinbase_blob_size=" << coinbase_blob_size << " < expected=" << (cumulative_size - txs_size) << ", delta=" << delta;
      b.baseTransaction.extra.insert(b.baseTransaction.extra.end(), delta, 0);
      //here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len to 2-bytes len.
      if (cumulative_size != txs_size + getObjectBinarySize(b.baseTransaction)) {
        if (!(cumulative_size + 1 == txs_size + getObjectBinarySize(b.baseTransaction))) { logger(ERROR, BRIGHT_RED) << "unexpected case: cumulative_size=" << cumulative_size << " + 1 is not equal txs_cumulative_size=" << txs_size + 1 << " + get_object_blobsize(b.baseTransaction)=" << getObjectBinarySize(b.baseTransaction); return false; }
          b.baseTransaction.extra.resize(b.baseTransaction.extra.size() - 1);
          if (cumulative_size != txs_size + getObjectBinarySize(b.baseTransaction)) {
            //fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with cumulative_size
            logger(TRACE, BRIGHT_RED) <<
              "Miner tx creation have no luck with delta_extra size = " << delta << " and " << delta - 1;

            cumulative_size += delta - 1;
            continue;
        }
        logger(DEBUGGING, BRIGHT_GREEN) <<
          "Setting extra for block: " << b.baseTransaction.extra.size() << ", try_count=" << try_count;
      }
    }

    if (cumulative_size == txs_size + getObjectBinarySize(b.baseTransaction)) {
      // SUCCESS: Sizes match exactly, we're done
      logger(TRACE) << "Mining transaction size adjustment successful for height=" << height;
      break;
    }

    // Unexpected case - sizes don't match after all adjustment attempts
    logger(ERROR, BRIGHT_RED) << "unexpected case: cumulative_size=" << cumulative_size << " is not equal txs_cumulative_size=" << txs_size << " + get_object_blobsize(b.baseTransaction)=" << getObjectBinarySize(b.baseTransaction);
    return false;
  }

  // After loop: check if we used all 10 attempts
  if (try_count >= 10) {
    size_t final_coinbase_size = getObjectBinarySize(b.baseTransaction);
    logger(ERROR, BRIGHT_RED) << "Failed to create_block_template after 10 tries. Last error: cumulative_size=" << cumulative_size
      << " vs txs_size + coinbase_blob=" << (txs_size + final_coinbase_size);
    logger(ERROR, BRIGHT_RED) << "Block info: height=" << height << ", majorVersion=" << (int)b.majorVersion
      << ", median_size=" << median_size << ", already_generated_coins=" << already_generated_coins;
    logger(ERROR, BRIGHT_RED) << "Fee=" << fee << ", txs_size=" << txs_size;
    return false;
  }

  return true;
}



std::vector<Crypto::Hash> core::findBlockchainSupplement(
    const std::vector<Crypto::Hash>& remoteBlockIds,
    size_t maxCount,
    uint32_t& totalBlockCount,
    uint32_t& startBlockIndex) {

  assert(!remoteBlockIds.empty());
  assert(remoteBlockIds.back() == m_blockchain.getBlockIdByHeight(0));

  return m_blockchain.findBlockchainSupplement(remoteBlockIds, maxCount, totalBlockCount, startBlockIndex);
}

void core::print_blockchain(uint32_t start_index, uint32_t end_index) {
  m_blockchain.print_blockchain(start_index, end_index);
}

void core::print_blockchain_index() {
  m_blockchain.print_blockchain_index();
}

void core::print_blockchain_outs(const std::string& file) {
  m_blockchain.print_blockchain_outs(file);
}

bool core::get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) {
  return m_blockchain.getRandomOutsByAmount(req, res);
}

bool core::get_random_commitment_outs_for_amount(uint64_t amount, uint64_t count, uint32_t maxHeight, std::vector<COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry>& result) {
  return m_blockchain.getRandomCommitmentOutputsForAmount(amount, count, result, maxHeight);
}

bool core::get_output_heights(const std::vector<std::pair<uint64_t, uint32_t>>& queries,
                              std::vector<uint32_t>& heights) {
  return m_blockchain.getOutputHeights(queries, heights);
}

bool core::get_tx_outputs_gindexs(const Crypto::Hash& tx_id, std::vector<uint32_t>& indexs) {
  return m_blockchain.getTransactionOutputGlobalIndexes(tx_id, indexs);
}

bool core::get_outs_for_amount(uint64_t amount, const std::vector<uint64_t>& indexes,
                               std::vector<Crypto::PublicKey>& keys) {
  return m_blockchain.getOutsByAmountAndIndexes(amount, indexes, keys);
}

bool core::getOutByMSigGIndex(uint64_t amount, uint64_t gindex, MultisignatureOutput& out) {
  return m_blockchain.get_out_by_msig_gindex(amount, gindex, out);
}

void core::pause_mining() {
  m_miner->pause();
}

void core::update_block_template_and_resume_mining() {
  update_miner_block_template();
  m_miner->resume();
}

bool core::saveBlockchain()
{
  return m_blockchain.storeCache();
}

bool core::handle_block_found(Block& b) {
  block_verification_context bvc = boost::value_initialized<block_verification_context>();
  handle_incoming_block(b, bvc, true, true);

  if (bvc.m_verification_failed) {
    logger(ERROR) << "mined block failed verification";
  }

  return bvc.m_added_to_main_chain;
}

void core::on_synchronized() {
  m_miner->on_synchronized();
}

bool core::getPoolChanges(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds,
                          std::vector<Transaction>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) {

  getPoolChanges(knownTxsIds, addedTxs, deletedTxsIds);
  return tailBlockId == m_blockchain.getTailId();
}

bool core::getPoolChangesLite(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds,
        std::vector<TransactionPrefixInfo>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) {

  std::vector<Transaction> added;
  bool returnStatus = getPoolChanges(tailBlockId, knownTxsIds, added, deletedTxsIds);

  for (const auto& tx: added) {
    TransactionPrefixInfo tpi;
    tpi.txPrefix = tx;
    tpi.txHash = getObjectHash(tx);

    addedTxs.push_back(std::move(tpi));
  }

  return returnStatus;
}

void core::getPoolChanges(const std::vector<Crypto::Hash>& knownTxsIds, std::vector<Transaction>& addedTxs,
                          std::vector<Crypto::Hash>& deletedTxsIds) {

  std::vector<Crypto::Hash> addedTxsIds;
  auto guard = m_mempool.obtainGuard();
  m_mempool.get_difference(knownTxsIds, addedTxsIds, deletedTxsIds);
  std::vector<Crypto::Hash> misses;
  m_mempool.getTransactions(addedTxsIds, addedTxs, misses);
  assert(misses.empty());
}

bool core::handle_incoming_block_blob(const BinaryArray& block_blob, block_verification_context& bvc, bool control_miner, bool relay_block) {
  if (block_blob.size() > m_currency.maxBlockBlobSize()) {
    logger(INFO) << "WRONG BLOCK BLOB, too big size " << block_blob.size() << ", rejected";
    bvc.m_verification_failed = true;
    return false;
  }

  Block b;
  if (!fromBinaryArray(b, block_blob)) {
    logger(INFO) << "Failed to parse and validate new block";
    bvc.m_verification_failed = true;
    return false;
  }

  return handle_incoming_block(b, bvc, control_miner, relay_block);
}

bool core::handle_incoming_block(const Block& b, block_verification_context& bvc, bool control_miner, bool relay_block) {
  if (control_miner) {
    pause_mining();
  }

  m_blockchain.addNewBlock(b, bvc);

  if (control_miner) {
    update_block_template_and_resume_mining();
  }

  if (relay_block && bvc.m_added_to_main_chain) {
    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    m_blockchain.getTransactions(b.transactionHashes, txs, missed_txs);
    if (!missed_txs.empty() && getBlockIdByHeight(get_block_height(b)) != get_block_hash(b)) {
      logger(INFO) << "Block added, but it seems that reorganize just happened after that, do not relay this block";
    } else {
      if (!(txs.size() == b.transactionHashes.size() && missed_txs.empty())) {
        logger(ERROR, BRIGHT_RED) << "can't find some transactions in found block:" <<
          get_block_hash(b) << " txs.size()=" << txs.size() << ", b.transactionHashes.size()=" << b.transactionHashes.size() << ", missed_txs.size()" << missed_txs.size(); return false;
      }

      NOTIFY_NEW_BLOCK::request arg;
      arg.hop = 0;
      arg.current_blockchain_height = m_blockchain.getCurrentBlockchainHeight();
      BinaryArray blockBa;
      bool r = toBinaryArray(b, blockBa);
      if (!(r)) { logger(ERROR, BRIGHT_RED) << "failed to serialize block"; return false; }
      arg.b.block = asString(blockBa);

              for (auto& tx : txs) {
                arg.b.txs.push_back(asString(toBinaryArray(tx)));
              }

      m_pprotocol->relay_block(arg);
    }
  }

  return true;
}

Crypto::Hash core::get_tail_id() {
  return m_blockchain.getTailId();
}

size_t core::get_pool_transactions_count() {
  return m_mempool.get_transactions_count();
}

bool core::have_block(const Crypto::Hash& id) {
  return m_blockchain.haveBlock(id);
}

bool core::parse_tx_from_blob(Transaction& tx, Crypto::Hash& tx_hash, Crypto::Hash& tx_prefix_hash, const BinaryArray& blob) {
  return parseAndValidateTransactionFromBinaryArray(blob, tx, tx_hash, tx_prefix_hash);
}

bool core::check_tx_syntax(const Transaction& tx) {
  return true;
}

std::vector<Transaction> core::getPoolTransactions() {
  std::list<Transaction> txs;
  m_mempool.get_transactions(txs);

  std::vector<Transaction> result;
  for (auto& tx : txs) {
    result.emplace_back(std::move(tx));
  }
  return result;
}


std::vector<Crypto::Hash> core::buildSparseChain() {
  assert(m_blockchain.getCurrentBlockchainHeight() != 0);
  return m_blockchain.buildSparseChain();
}

std::vector<Crypto::Hash> core::buildSparseChain(const Crypto::Hash& startBlockId) {
  LockedBlockchainStorage lbs(m_blockchain);
  assert(m_blockchain.haveBlock(startBlockId));
  return m_blockchain.buildSparseChain(startBlockId);
}

bool core::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp) { //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  return m_blockchain.handleGetObjects(arg, rsp);
}

Crypto::Hash core::getBlockIdByHeight(uint32_t height) {
  LockedBlockchainStorage lbs(m_blockchain);
  if (height < m_blockchain.getCurrentBlockchainHeight()) {
    return m_blockchain.getBlockIdByHeight(height);
  } else {
    return NULL_HASH;
  }
}

bool core::getBlockByHash(const Crypto::Hash &h, Block &blk) {
  return m_blockchain.getBlockByHash(h, blk);
}

bool core::getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight) {
  return m_blockchain.getBlockHeight(blockId, blockHeight);
}

uint64_t core::coinsEmittedAtHeight(uint64_t height) {
  return m_blockchain.coinsEmittedAtHeight(height);
}

uint64_t core::difficultyAtHeight(uint64_t height) {
  return m_blockchain.difficultyAtHeight(height);
}

//void core::get_all_known_block_ids(std::list<Crypto::Hash> &main, std::list<Crypto::Hash> &alt, std::list<Crypto::Hash> &invalid) {
//  m_blockchain.get_all_known_block_ids(main, alt, invalid);
//}

std::string core::print_pool(bool short_format) {
  return m_mempool.print_pool(short_format);
}

bool core::update_miner_block_template() {
  m_miner->on_block_chain_update();
  return true;
}

bool core::on_idle() {
  if (!m_starter_message_showed) {
    logger(INFO, BRIGHT_YELLOW)
      << "**********************************************************************" << ENDL
      << "Your Fuego daemon will now begin synchronizing with the network's historical chain of data blocks. It may take some time." << ENDL
      << "Bootstrap file of Fuego blockchain is available at https://github.com/usexfg/fuego-data/releases - though, full sync using network peers is best practice. "<< ENDL
      << "You can use \"set_log <level>\" command for a more detailed view of the process."<< ENDL
      << "Using <level> option from 0 (no details) up to 4 (very verbose)." << ENDL
      << "Use \"help\" command to see a list of available commands." << ENDL
      << "Note: in case you need to interrupt the process, use \"exit\" command,"<<ENDL
      << "Otherwise the current progress won't be saved." << ENDL;
      logger(INFO, BRIGHT_YELLOW)
      << "**********************************************************************";
    m_starter_message_showed = true;
  }

  m_miner->on_idle();
  m_mempool.on_idle();
  return true;
}

bool core::addObserver(ICoreObserver* observer) {
  return m_observerManager.add(observer);
}

bool core::removeObserver(ICoreObserver* observer) {
  return m_observerManager.remove(observer);
}

void core::blockchainUpdated() {
  m_observerManager.notify(&ICoreObserver::blockchainUpdated);
}

void core::txDeletedFromPool() {
  poolUpdated();
}

void core::poolUpdated() {
  m_observerManager.notify(&ICoreObserver::poolUpdated);
}

bool core::queryBlocks(const std::vector<Crypto::Hash>& knownBlockIds, uint64_t timestamp,
  uint32_t& resStartHeight, uint32_t& resCurrentHeight, uint32_t& resFullOffset, std::vector<BlockFullInfo>& entries) {

  LockedBlockchainStorage lbs(m_blockchain);

  uint32_t currentHeight = lbs->getCurrentBlockchainHeight();
  uint32_t startOffset = 0;
  uint32_t startFullOffset = 0;

  if (!findStartAndFullOffsets(knownBlockIds, timestamp, startOffset, startFullOffset)) {
    return false;
  }

  resFullOffset = startFullOffset;
  std::vector<Crypto::Hash> blockIds = findIdsForShortBlocks(startOffset, startFullOffset);
  entries.reserve(blockIds.size());

  for (const auto& id : blockIds) {
    entries.push_back(BlockFullInfo());
    entries.back().block_id = id;
  }

  resCurrentHeight = currentHeight;
  resStartHeight = startOffset;

  uint32_t blocksLeft = static_cast<uint32_t>(std::min(BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT - entries.size(), size_t(BLOCKS_SYNCHRONIZING_DEFAULT_COUNT)));

  if (blocksLeft == 0) {
    return true;
  }

  std::list<Block> blocks;
  lbs->getBlocks(startFullOffset, blocksLeft, blocks);

  for (auto& b : blocks) {
    BlockFullInfo item;

    item.block_id = get_block_hash(b);

    if (b.timestamp >= timestamp) {
      // query transactions
      std::list<Transaction> txs;
      std::list<Crypto::Hash> missedTxs;
      lbs->getTransactions(b.transactionHashes, txs, missedTxs);

      // fill data
      block_complete_entry& completeEntry = item;
      completeEntry.block = asString(toBinaryArray(b));
      for (auto& tx : txs) {
        completeEntry.txs.push_back(asString(toBinaryArray(tx)));
      }
    }

    entries.push_back(std::move(item));
  }

  return true;
}

bool core::findStartAndFullOffsets(const std::vector<Crypto::Hash>& knownBlockIds, uint64_t timestamp, uint32_t& startOffset, uint32_t& startFullOffset) {
  LockedBlockchainStorage lbs(m_blockchain);

  if (knownBlockIds.empty()) {
    logger(ERROR, BRIGHT_RED) << "knownBlockIds is empty";
    return false;
  }

  if (knownBlockIds.back() != m_blockchain.getBlockIdByHeight(0)) {
    logger(ERROR, BRIGHT_RED) << "knownBlockIds doesn't end with genesis block hash: " << knownBlockIds.back();
    return false;
  }

  startOffset = lbs->findBlockchainSupplement(knownBlockIds);
  if (!lbs->getLowerBound(timestamp, startOffset, startFullOffset)) {
    startFullOffset = startOffset;
  }

  return true;
}

std::vector<Crypto::Hash> core::findIdsForShortBlocks(uint32_t startOffset, uint32_t startFullOffset) {
  assert(startOffset <= startFullOffset);

  LockedBlockchainStorage lbs(m_blockchain);

  std::vector<Crypto::Hash> result;
  if (startOffset < startFullOffset) {
    result = lbs->getBlockIds(startOffset, std::min(static_cast<uint32_t>(BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT), startFullOffset - startOffset));
  }

  return result;
}

bool core::queryBlocksLite(const std::vector<Crypto::Hash>& knownBlockIds, uint64_t timestamp, uint32_t& resStartHeight,
  uint32_t& resCurrentHeight, uint32_t& resFullOffset, std::vector<BlockShortInfo>& entries) {
  LockedBlockchainStorage lbs(m_blockchain);

  resCurrentHeight = lbs->getCurrentBlockchainHeight();
  resStartHeight = 0;
  resFullOffset = 0;

  if (!findStartAndFullOffsets(knownBlockIds, timestamp, resStartHeight, resFullOffset)) {
    return false;
  }

  std::vector<Crypto::Hash> blockIds = findIdsForShortBlocks(resStartHeight, resFullOffset);
  entries.reserve(blockIds.size());

  for (const auto& id : blockIds) {
    entries.push_back(BlockShortInfo());
    entries.back().blockId = id;
  }

  uint32_t blocksLeft = static_cast<uint32_t>(std::min(BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT - entries.size(), size_t(BLOCKS_SYNCHRONIZING_DEFAULT_COUNT)));

  if (blocksLeft == 0) {
    return true;
  }

  std::list<Block> blocks;
  lbs->getBlocks(resFullOffset, blocksLeft, blocks);

  for (auto& b : blocks) {
    BlockShortInfo item;

    item.blockId = get_block_hash(b);

    if (b.timestamp >= timestamp) {
      std::list<Transaction> txs;
      std::list<Crypto::Hash> missedTxs;
      lbs->getTransactions(b.transactionHashes, txs, missedTxs);

      item.block = asString(toBinaryArray(b));

      for (const auto& tx: txs) {
        TransactionPrefixInfo info;
        info.txPrefix = tx;
        info.txHash = getObjectHash(tx);

        item.txPrefixes.push_back(std::move(info));
      }
    }

    entries.push_back(std::move(item));
  }

  return true;
}

bool core::getBackwardBlocksSizes(uint32_t fromHeight, std::vector<size_t>& sizes, size_t count) {
  return m_blockchain.getBackwardBlocksSize(fromHeight, sizes, count);
}

bool core::getPoolTransaction(const Crypto::Hash &tx_hash, Transaction &transaction)
{
  if (!m_mempool.have_tx(tx_hash))
  {
    return false;
  }

  return m_mempool.getTransaction(tx_hash, transaction);
}

bool core::getBlockSize(const Crypto::Hash& hash, size_t& size) {
  return m_blockchain.getBlockSize(hash, size);
}

bool core::getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins) {
  return m_blockchain.getAlreadyGeneratedCoins(hash, generatedCoins);
}

bool core::getBlockReward(uint8_t blockMajorVersion, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint32_t height,
                          uint64_t& reward, int64_t& emissionChange) {
  return m_currency.getBlockReward(blockMajorVersion, medianSize, currentBlockSize, alreadyGeneratedCoins, fee, height, reward, emissionChange);
}

bool core::scanOutputkeysForIndices(const KeyInput& txInToKey, std::list<std::pair<Crypto::Hash, size_t>>& outputReferences) {
  struct outputs_visitor
  {
    std::list<std::pair<Crypto::Hash, size_t>>& m_resultsCollector;
    outputs_visitor(std::list<std::pair<Crypto::Hash, size_t>>& resultsCollector):m_resultsCollector(resultsCollector){}
    bool handle_output(const Transaction& tx, const TransactionOutput& out, size_t transactionOutputIndex)
    {
      m_resultsCollector.push_back(std::make_pair(getObjectHash(tx), transactionOutputIndex));
      return true;
    }
  };

  outputs_visitor vi(outputReferences);

  return m_blockchain.scanOutputKeysForIndexes(txInToKey, vi);
}

bool core::getBlockDifficulty(uint32_t height, difficulty_type& difficulty) {
  difficulty = m_blockchain.blockDifficulty(height);
  return true;
}

bool core::getBlockContainingTx(const Crypto::Hash& txId, Crypto::Hash& blockId, uint32_t& blockHeight) {
  return m_blockchain.getBlockContainingTransaction(txId, blockId, blockHeight);
}

bool core::getMultisigOutputReference(const MultisignatureInput& txInMultisig, std::pair<Crypto::Hash, size_t>& outputReference) {
  return m_blockchain.getMultisigOutputReference(txInMultisig, outputReference);
}

bool core::getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions) {
  return m_blockchain.getGeneratedTransactionsNumber(height, generatedTransactions);
}

bool core::getOrphanBlocksByHeight(uint32_t height, std::vector<Block>& blocks) {
  std::vector<Crypto::Hash> blockHashes;
  if (!m_blockchain.getOrphanBlockIdsByHeight(height, blockHashes)) {
    return false;
  }

  for (const Crypto::Hash& hash : blockHashes) {
    Block blk;
    if (!getBlockByHash(hash, blk)) {
      return false;
    }
    blocks.push_back(std::move(blk));
  }
  return true;
}

bool core::getBlocksByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Block>& blocks, uint32_t& blocksNumberWithinTimestamps) {
  std::vector<Crypto::Hash> blockHashes;
  if (!m_blockchain.getBlockIdsByTimestamp(timestampBegin, timestampEnd, blocksNumberLimit, blockHashes, blocksNumberWithinTimestamps)) {
    return false;
  }
  for (const Crypto::Hash& hash : blockHashes) {
    Block blk;
    if (!getBlockByHash(hash, blk)) {
      return false;
    }
    blocks.push_back(std::move(blk));
  }
  return true;
}

bool core::getPoolTransactionsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t transactionsNumberLimit, std::vector<Transaction>& transactions, uint64_t& transactionsNumberWithinTimestamps) {
  std::vector<Crypto::Hash> poolTransactionHashes;
  if (!m_mempool.getTransactionIdsByTimestamp(timestampBegin, timestampEnd, transactionsNumberLimit, poolTransactionHashes, transactionsNumberWithinTimestamps)) {
    return false;
  }

  std::list<Transaction> txs;
  std::list<Crypto::Hash> missed_txs;

  getTransactions(poolTransactionHashes, txs, missed_txs, true);
  if (missed_txs.size() > 0) {
    return false;
  }

  transactions.insert(transactions.end(), txs.begin(), txs.end());
  return true;
}

bool core::getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<Transaction>& transactions) {
  std::vector<Crypto::Hash> blockchainTransactionHashes;
  if (!m_blockchain.getTransactionIdsByPaymentId(paymentId, blockchainTransactionHashes)) {
    return false;
  }

  std::vector<Crypto::Hash> poolTransactionHashes;
  if (!m_mempool.getTransactionIdsByPaymentId(paymentId, poolTransactionHashes)) {
    return false;
  }

  std::list<Transaction> txs;
  std::list<Crypto::Hash> missed_txs;
  blockchainTransactionHashes.insert(blockchainTransactionHashes.end(), poolTransactionHashes.begin(), poolTransactionHashes.end());

  getTransactions(blockchainTransactionHashes, txs, missed_txs, true);
  if (missed_txs.size() > 0) {
    return false;
  }

  transactions.insert(transactions.end(), txs.begin(), txs.end());
  return true;
}

std::error_code core::executeLocked(const std::function<std::error_code()>& func) {
  std::lock_guard<decltype(m_mempool)> lk(m_mempool);
  LockedBlockchainStorage lbs(m_blockchain);

  return func();
}

uint64_t core::getNextBlockDifficulty() {
  return m_blockchain.getDifficultyForNextBlock();
}

uint64_t core::getTotalGeneratedAmount() {
  return m_blockchain.getCoinsInCirculation();
}
uint8_t core::getBlockMajorVersionForHeight(uint32_t height) const {
  return m_blockchain.getBlockMajorVersionForHeight(height);
}

uint64_t core::fullDepositAmount() const {
  return m_blockchain.fullDepositAmount();
}

uint64_t core::depositAmountAtHeight(size_t height) const {
  return m_blockchain.depositAmountAtHeight(height);
}

bool core::handleIncomingTransaction(const Transaction& tx, const Crypto::Hash& txHash, size_t blobSize, tx_verification_context& tvc, bool keptByBlock, uint32_t height) {
  if (!check_tx_syntax(tx)) {
    logger(ERROR) << "WRONG TRANSACTION BLOB, Failed to check tx " << txHash << " syntax, rejected";
    tvc.m_verification_failed = true;
    return false;
  }

  if (!check_tx_semantic(tx, keptByBlock, height)) {
    logger(ERROR) << "WRONG TRANSACTION BLOB, Failed to check tx " << txHash << " semantic, rejected";
    tvc.m_verification_failed = true;
    return false;
  }

  bool r = add_new_tx(tx, txHash, blobSize, tvc, keptByBlock, height);
  if (tvc.m_verification_failed) {
    if (!tvc.m_tx_fee_too_small) {
      logger(ERROR) << "Transaction verification failed: " << txHash;
    } else {
      logger(ERROR) << "Transaction verification failed: " << txHash;
    }
  } else if (tvc.m_verification_impossible) {
    logger(ERROR) << "Transaction verification impossible: " << txHash;
  }

  if (tvc.m_added_to_pool) {
    logger(DEBUGGING) << "tx added: " << txHash;
    poolUpdated();
  }

  return r;
}

std::unique_ptr<IBlock> core::getBlock(const Crypto::Hash& blockId) {
  std::lock_guard<decltype(m_mempool)> lk(m_mempool);
  LockedBlockchainStorage lbs(m_blockchain);

  std::unique_ptr<BlockWithTransactions> blockPtr(new BlockWithTransactions());
  if (!lbs->getBlockByHash(blockId, blockPtr->block)) {
    logger(DEBUGGING) << "Can't find block: " << blockId;
    return std::unique_ptr<BlockWithTransactions>(nullptr);
  }

  blockPtr->transactions.reserve(blockPtr->block.transactionHashes.size());
  std::vector<Crypto::Hash> missedTxs;
  lbs->getTransactions(blockPtr->block.transactionHashes, blockPtr->transactions, missedTxs, true);
  assert(missedTxs.empty() || !lbs->isBlockInMainChain(blockId)); //if can't find transaction for blockchain block -> error

  if (!missedTxs.empty()) {
    logger(DEBUGGING) << "Can't find transactions for block: " << blockId;
    return std::unique_ptr<BlockWithTransactions>(nullptr);
  }

  return std::move(blockPtr);
}

bool core::is_key_image_spent(const Crypto::KeyImage& key_im) {
  return m_blockchain.have_tx_keyimg_as_spent(key_im);
}

bool core::addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) {
  return m_blockchain.addMessageQueue(messageQueue);
}

bool core::removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) {
  return m_blockchain.removeMessageQueue(messageQueue);
}

uint64_t core::getBurnedXfgAtHeight(size_t height) const {
  return m_blockchain.getBurnedXfgAtHeight(height);
}

void core::addSwapFee(uint64_t amount) {
  m_blockchain.addSwapFee(amount);
}

void core::setXfgMarketValue(uint64_t val) {
  // PI controller removed — XFG price is unrestrained via Hearth AMM.
  // Callers (SwapDaemon oracle, testnet sim) still invoke this but the value is ignored.
}

// --- Commitment Index Accessors ---

std::optional<CommitmentEntry> core::getCommitmentByHash(const Crypto::Hash& commitment) const {
  return m_blockchain.getCommitmentByHash(commitment);
}

bool core::hasCommitment(const Crypto::Hash& commitment) const {
  return m_blockchain.hasCommitment(commitment);
}

const CommitmentIndex& core::getCommitmentIndex() const {
  return m_blockchain.getCommitmentIndex();
}

std::error_code core::calculateCdInterest(uint64_t amount, uint32_t creationHeight,
                                           uint32_t currentHeight, uint64_t& outInterest,
                                           bool isLegacyBond, uint32_t term,
                                           bool autoRolled) {
  outInterest = m_currency.calculateCdInterest(amount, creationHeight, currentHeight,
                                               m_blockchain.getCommitmentIndex(),
                                               isLegacyBond, term, autoRolled);
  return {};
}

std::error_code core::getCommitmentEpochFeeRate(uint32_t epoch, uint64_t& outFeeRate) {
  outFeeRate = m_blockchain.getCommitmentIndex().getEpochFeeRate(epoch);
  return {};
}

std::error_code core::getAmmPoolReserves(AmmPoolReserves& out) {
  const auto& pool = m_blockchain.getAmmPool();
  out.reserveXfg = pool.reserveXfg;
  out.reserveHeat = pool.reserveHeat;
  return {};
}

uint64_t core::getHearthTwap() {
  return m_blockchain.getRollingTwap();
}

size_t core::getCommitmentCount() const {
  return m_blockchain.getCommitmentCount();
}

size_t core::getHeatCommitmentCount() const {
  return m_blockchain.getHeatCommitmentCount();
}

uint64_t core::getTotalCdLocked() const {
  return m_blockchain.getTotalCdLocked();
}

uint64_t core::getHeatCdFeePool() const {
  return m_blockchain.getHeatCdFeePool();
}

size_t core::getColdCommitmentCount() const {
  return m_blockchain.getColdCommitmentCount();
}

Crypto::Hash core::getCommitmentMerkleRoot() const {
  return m_blockchain.getCommitmentMerkleRoot();
}

std::vector<Crypto::Hash> core::getCommitmentMerkleProof(const Crypto::Hash& commitment) const {
  return m_blockchain.getCommitmentMerkleProof(commitment);
}

int64_t core::getCommitmentLeafIndex(const Crypto::Hash& commitment) const {
  return m_blockchain.getCommitmentLeafIndex(commitment);
}

uint64_t core::getCommitmentHighestBlock() const {
  return m_blockchain.getCommitmentHighestBlock();
}

std::vector<Crypto::Hash> core::getCommitmentLeaves() const {
  return m_blockchain.getCommitmentLeaves();
}

// @ Alias system proxies
bool core::aliasExists(const std::string& alias) const {
  return m_blockchain.aliasExists(alias);
}

std::optional<AliasEntry> core::getAliasByName(const std::string& alias) const {
  return m_blockchain.getAliasByName(alias);
}

std::optional<AliasEntry> core::getAliasByAddress(const std::string& address) const {
  return m_blockchain.getAliasByAddress(address);
}

std::vector<AliasEntry> core::getAllAliases() const {
  return m_blockchain.getAllAliases();
}

bool core::removeAlias(const std::string& alias) {
  return m_blockchain.removeAlias(alias);
}

bool core::replaceAliasOwnership(const std::string& alias,
                                 const Crypto::Hash& newAddressHash) {
  return m_blockchain.replaceAliasOwnership(alias, newAddressHash);
}

core::HeatMetrics core::getHeatMetrics() const {
  HeatMetrics m;
  m.heatSupply = m_blockchain.getHeatSupply();
  m.heatOnDeposit = m_blockchain.getHeatOnDeposit();
  m.digmSupply = m_blockchain.getDigmSupply();
  m.burnedXfg = m_blockchain.getBurnedXfgAmount();
  m.totalBurnedXfg = m_blockchain.getTotalBurnedXfg();
  m.permanentlyBurnedXfg = m_blockchain.getPermanentlyBurnedXfg();
  m.heatCdFeePool = m_blockchain.getHeatCdFeePool();
  m.swfBurnedXfgPendingHeat = m_blockchain.getSwfBurnedXfgPendingHeat();
  const auto& pool = m_blockchain.getAmmPool();
  if (!pool.isEmpty() && pool.reserveHeat > 0) {
    // Pool ratio × 10^6 for precision
    m.redemptionPriceNum = (pool.reserveXfg * 1000000ULL) / pool.reserveHeat;
    m.redemptionPriceDenom = 1000000;
  } else {
    m.redemptionPriceNum = 0;
    m.redemptionPriceDenom = 1;
  }
  m.treasuryBalance = m_blockchain.getTreasuryBalance();
  m.treasuryHeatReserve = m_blockchain.getTreasuryHeatReserve();
  m.treasuryLpPendingXfg = m_blockchain.getTreasuryLpPendingXfg();
  m.treasuryCounterXFG = m.treasuryLpPendingXfg;  // v12 alias — same source, both fields for compat
  m.swfHeatBalance = m_blockchain.getSwfHeatBalance();
  m.epochSwapFees = m_blockchain.getCurrentEpochSwapFees();
  {
    VaultBalance vb = m_blockchain.getVault().allBalances();
    m.vaultHeatCdFeePool = vb.heatCdFeePool;
    m.vaultHeatLpReserve = vb.heatLpReserve;
    m.vaultHeatGeneral    = vb.heatGeneral;
    m.vaultHeatSwf        = vb.heatSwf;
    m.vaultXfgCdFeePool  = vb.xfgCdFeePool;
    m.vaultXfgLpReserve   = vb.xfgLpReserve;
    m.vaultXfgGeneral     = vb.xfgGeneral;
  }
  return m;
}

core::AmmQuote core::getAmmQuote(uint64_t inputAmount, uint8_t direction) const {
  AmmQuote q;
  auto est = m_blockchain.getOrderbookEstimate(direction, inputAmount);
  q.expectedOutput = est.estimatedFill;
  q.fee = std::max<uint64_t>(1, (inputAmount * parameters::HEARTH_FEE_BPS) / parameters::HEARTH_FEE_DIVISOR);
  uint64_t spotPrice = m_blockchain.getHearthSpotPrice();
  if (spotPrice > 0) {
    if (est.worstCasePrice > 0 && spotPrice > 0) {
      if (direction == 0) {
        uint64_t delta = (est.worstCasePrice > spotPrice) ? (est.worstCasePrice - spotPrice) : (spotPrice - est.worstCasePrice);
        q.priceImpactBps = (delta * 10000) / spotPrice;
      }
    }
  }
  return q;
}

core::AmmPoolInfo core::getAmmPoolInfo() const {
  AmmPoolInfo info;
  const auto& pool = m_blockchain.getAmmPool();
  info.reserveXfg = pool.reserveXfg;
  info.reserveHeat = pool.reserveHeat;
  info.totalLpShares = pool.totalLpShares;
  info.epochSwapFees = m_blockchain.getCurrentEpochSwapFees();
  info.spotPrice = m_blockchain.getHearthSpotPrice();
  return info;
}

uint64_t core::getPoolTwap() const {
  return m_blockchain.getPoolTwap();
}

std::error_code core::getAmmPoolInfo(ICore::AmmPoolInfo& info) {
  const auto& pool = m_blockchain.getAmmPool();
  info.reserveXfg = pool.reserveXfg;
  info.reserveHeat = pool.reserveHeat;
   info.spotPrice = m_blockchain.getHearthSpotPrice();
   return {};
}

core::OrderbookInfo core::getOrderbookInfo() const {
  OrderbookInfo info;
  info.clearingPrice = m_blockchain.getOrderbookClearingPrice();
  info.inBootstrap = m_blockchain.isOrderbookInBootstrap();
  info.hearthPoolRatio = m_blockchain.getHearthSpotPrice();
  // Depth and numMatches read from the latest block header — populated in processOrderbookForBlock
  return info;
}

core::OrderbookState core::getOrderbookState(uint32_t depth) const {
  OrderbookState state;
  state.clearingPrice = m_blockchain.getOrderbookClearingPrice();

  auto bids = m_blockchain.getOrderbookBidCurve(depth);
  for (const auto& b : bids) {
    state.bids.push_back({b.price, b.depth});
  }

  auto asks = m_blockchain.getOrderbookAskCurve(depth);
  for (const auto& a : asks) {
    state.asks.push_back({a.price, a.depth});
  }

  return state;
}

core::OrderbookEstimate core::getOrderbookEstimate(uint8_t side, uint64_t amount) const {
  auto est = m_blockchain.getOrderbookEstimate(side, amount);
  return {est.estimatedFill, est.hearthFill, est.orderbookFill, est.worstCasePrice, est.levelsConsumed};
}

}
