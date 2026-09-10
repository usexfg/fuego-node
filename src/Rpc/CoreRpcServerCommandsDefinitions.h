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

#pragma once

#include "../CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "../CryptoNoteCore/CryptoNoteBasic.h"
#include "../CryptoNoteCore/Difficulty.h"
#include "../crypto/hash.h"

#include "../Serialization/SerializationOverloads.h"

namespace CryptoNote {
//-----------------------------------------------
#define CORE_RPC_STATUS_OK "OK"
#define CORE_RPC_STATUS_BUSY "BUSY"

struct EMPTY_STRUCT {
  void serialize(ISerializer &s) {}
};

struct STATUS_STRUCT {
  std::string status;

  void serialize(ISerializer &s) {
    KV_MEMBER(status)
  }
};

struct COMMAND_RPC_GET_HEIGHT {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t height;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(height)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_BLOCKS_FAST {

  struct request {
    std::vector<Crypto::Hash> block_ids; //*first 10 blocks id goes sequential, next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on, and the last one is always genesis block */

    void serialize(ISerializer &s) {
      serializeAsBinary(block_ids, "block_ids", s);
    }
  };

  struct response {
    std::vector<block_complete_entry> blocks;
    uint64_t start_height;
    uint64_t current_height;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(blocks)
      KV_MEMBER(start_height)
      KV_MEMBER(current_height)
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_GET_TRANSACTIONS {
  struct request {
    std::vector<std::string> txs_hashes;

    void serialize(ISerializer &s) {
      KV_MEMBER(txs_hashes)
    }
  };

  struct response {
    std::vector<std::string> txs_as_hex; //transactions blobs as hex
    std::vector<std::string> missed_tx;  //not found transactions
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(txs_as_hex)
      KV_MEMBER(missed_tx)
      KV_MEMBER(status)
    }
  };
};

//-----------------------------------------------
struct COMMAND_RPC_IS_KEY_IMAGE_SPENT {
  struct request {
    std::string key_image; // 64 hex chars

    void serialize(ISerializer &s) {
      KV_MEMBER(key_image)
    }
  };

  struct response {
    bool spent;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(spent)
      KV_MEMBER(status)
    }
  };
};
struct DepositRpcInfo {
  uint64_t id;
  uint64_t amount;
  uint64_t term;
  uint64_t interest;
  std::string creatingTransactionHash;
  std::string spendingTransactionHash;
  bool locked;
  uint64_t height;
  uint64_t unlockHeight;
  std::string address;

  void serialize(ISerializer &s) {
    KV_MEMBER(id)
    KV_MEMBER(amount)
    KV_MEMBER(term)
    KV_MEMBER(interest)
    KV_MEMBER(creatingTransactionHash)
    KV_MEMBER(spendingTransactionHash)
    KV_MEMBER(locked)
    KV_MEMBER(height)
    KV_MEMBER(unlockHeight)
    KV_MEMBER(address)
  }
};
struct COMMAND_RPC_GET_DEPOSITS {
  struct request {
    std::vector<std::string> addresses;
    std::string blockHash;
    uint32_t firstBlockIndex;
    uint32_t blockCount;
    std::string paymentId;

    void serialize(ISerializer &s) {
      KV_MEMBER(addresses)
      KV_MEMBER(blockHash)
      KV_MEMBER(firstBlockIndex)
      KV_MEMBER(blockCount)
      KV_MEMBER(paymentId)
    }
  };

  struct response {
    std::vector<DepositRpcInfo> deposits;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(deposits)
      KV_MEMBER(status)
    }
  };
};

struct block_short_response
{
  uint64_t timestamp;
  uint32_t height;
  std::string hash;
  uint64_t transactions_count;
  uint64_t cumulative_size;
  difficulty_type difficulty;

  void serialize(ISerializer &s)
  {
    KV_MEMBER(timestamp)
    KV_MEMBER(height)
    KV_MEMBER(hash)
    KV_MEMBER(cumulative_size)
    KV_MEMBER(transactions_count)
    KV_MEMBER(difficulty)
  }
};

//-----------------------------------------------
struct COMMAND_RPC_GET_POOL_CHANGES {
  struct request {
    Crypto::Hash tailBlockId;
    std::vector<Crypto::Hash> knownTxsIds;

    void serialize(ISerializer &s) {
      KV_MEMBER(tailBlockId)
      serializeAsBinary(knownTxsIds, "knownTxsIds", s);
    }
  };

  struct response {
    bool isTailBlockActual;
    std::vector<BinaryArray> addedTxs;          // Added transactions blobs
    std::vector<Crypto::Hash> deletedTxsIds; // IDs of not found transactions
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(isTailBlockActual)
      KV_MEMBER(addedTxs)
      serializeAsBinary(deletedTxsIds, "deletedTxsIds", s);
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_ALT_BLOCKS_LIST
{
  typedef EMPTY_STRUCT request;

  struct response
  {
    std::vector<block_short_response> alt_blocks;
    std::string status;

    void serialize(ISerializer &s)
    {
      KV_MEMBER(alt_blocks)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_POOL_CHANGES_LITE {
  struct request {
    Crypto::Hash tailBlockId;
    std::vector<Crypto::Hash> knownTxsIds;

    void serialize(ISerializer &s) {
      KV_MEMBER(tailBlockId)
      serializeAsBinary(knownTxsIds, "knownTxsIds", s);
    }
  };

  struct response {
    bool isTailBlockActual;
    std::vector<TransactionPrefixInfo> addedTxs;          // Added transactions blobs
    std::vector<Crypto::Hash> deletedTxsIds; // IDs of not found transactions
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(isTailBlockActual)
      KV_MEMBER(addedTxs)
      serializeAsBinary(deletedTxsIds, "deletedTxsIds", s);
      KV_MEMBER(status)
    }
  };
};

//-----------------------------------------------
struct COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES {

  struct request {
    Crypto::Hash txid;

    void serialize(ISerializer &s) {
      KV_MEMBER(txid)
    }
  };

  struct response {
    std::vector<uint64_t> o_indexes;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(o_indexes)
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request {
  std::vector<uint64_t> amounts;
  uint64_t outs_count;

  void serialize(ISerializer &s) {
    KV_MEMBER(amounts)
    KV_MEMBER(outs_count)
  }
};

#pragma pack(push, 1)
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_out_entry {
  uint64_t global_amount_index;
  Crypto::PublicKey out_key;
};
#pragma pack(pop)

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount {
  uint64_t amount;
  std::vector<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_out_entry> outs;

  void serialize(ISerializer &s) {
    KV_MEMBER(amount)
    serializeAsBinary(outs, "outs", s);
  }
};

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response {
  std::vector<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount> outs;
  std::string status;

  void serialize(ISerializer &s) {
    KV_MEMBER(outs);
    KV_MEMBER(status)
  }
};

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS {
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request request;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response response;

  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_out_entry out_entry;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount outs_for_amount;
};

//-----------------------------------------------
// Random commitment outputs for ring-signature deposit withdrawals.
// Works like COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS but indexes m_commitmentOutputs.
#pragma pack(push, 1)
struct COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry {
  uint32_t global_amount_index;
  Crypto::PublicKey commit_key;
};
#pragma pack(pop)

struct COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS {
  struct request {
    uint64_t amount;
    uint64_t outs_count;
    uint32_t max_height = 0;

    void serialize(ISerializer& s) {
      KV_MEMBER(amount)
      KV_MEMBER(outs_count)
      KV_MEMBER(max_height)
    }
  };

  struct response {
    std::vector<COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry> outs;
    std::string status;

    void serialize(ISerializer& s) {
      serializeAsBinary(outs, "outs", s);
      KV_MEMBER(status)
    }
  };

  typedef COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS_out_entry out_entry;
};

//-----------------------------------------------
struct COMMAND_RPC_SEND_RAW_TX {
  struct request {
    std::string tx_as_hex;

    request() {}
    explicit request(const Transaction &);

    void serialize(ISerializer &s) {
      KV_MEMBER(tx_as_hex)
    }
  };

  struct response {
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_START_MINING {
  struct request {
    std::string miner_address;
    uint64_t threads_count;

    void serialize(ISerializer &s) {
      KV_MEMBER(miner_address)
      KV_MEMBER(threads_count)
    }
  };

  struct response {
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_GET_INFO {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    std::string version;
    std::string fee_address;
    std::string top_block_hash;
    uint64_t height;
    uint64_t difficulty;
    uint64_t tx_count;
    uint64_t tx_pool_size;
    uint64_t alt_blocks_count;
    uint64_t outgoing_connections_count;
    uint64_t incoming_connections_count;
    uint64_t white_peerlist_size;
    uint64_t grey_peerlist_size;
    uint8_t block_major_version;
    uint8_t block_minor_version;
    uint32_t last_known_block_index;
    uint64_t full_deposit_amount;
    uint64_t ethereal_xfg;
    uint64_t last_block_reward;
    uint64_t last_block_timestamp;
    uint64_t last_block_difficulty;
    std::vector<std::string> connections;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(height)
      KV_MEMBER(version)
      KV_MEMBER(difficulty)
      KV_MEMBER(top_block_hash)
      KV_MEMBER(tx_count)
      KV_MEMBER(tx_pool_size)
      KV_MEMBER(alt_blocks_count)
      KV_MEMBER(outgoing_connections_count)
      KV_MEMBER(fee_address)
      KV_MEMBER(block_major_version)
      KV_MEMBER(block_minor_version)
      KV_MEMBER(incoming_connections_count)
      KV_MEMBER(white_peerlist_size)
      KV_MEMBER(grey_peerlist_size)
      KV_MEMBER(last_known_block_index)
      KV_MEMBER(full_deposit_amount)
      KV_MEMBER(ethereal_xfg)
      KV_MEMBER(last_block_reward)
      KV_MEMBER(last_block_timestamp)
      KV_MEMBER(last_block_difficulty)
      KV_MEMBER(connections)
    }
  };
};

//-----------------------------------------------
struct COMMAND_RPC_GET_PEER_LIST {
	typedef EMPTY_STRUCT request;

	struct response {
		std::vector<std::string> peers;
		std::string status;

		void serialize(ISerializer &s) {
			KV_MEMBER(peers)
			KV_MEMBER(status)
		}
	};
};

//-----------------------------------------------
struct COMMAND_RPC_STOP_MINING {
  typedef EMPTY_STRUCT request;
  typedef STATUS_STRUCT response;
};

//-----------------------------------------------
struct COMMAND_RPC_STOP_DAEMON {
  typedef EMPTY_STRUCT request;
  typedef STATUS_STRUCT response;
};

//
struct COMMAND_RPC_GETBLOCKCOUNT {
  typedef std::vector<std::string> request;

  struct response {
    uint64_t count;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(count)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_PROVE_COLLATERAL {
  struct request {
    std::string transactionHash;
    uint8_t commitment_type;  // 136=Burn(0x08), 7=CIA(0x07), 205=CD(0xCD)
    bool commitment;          // Whether to verify commitment

    void serialize(ISerializer &s) {
      KV_MEMBER(transactionHash)
      KV_MEMBER(commitment_type)
      KV_MEMBER(commitment)
    }
  };

  struct response {
    bool exists;
    uint64_t amount;          // Actual transaction amount (atomic units)
    bool hasCommitment;
    uint8_t commitmentType;
    std::string status;
    std::string errorMessage;

    void serialize(ISerializer &s) {
      KV_MEMBER(exists)
      KV_MEMBER(amount)
      KV_MEMBER(hasCommitment)
      KV_MEMBER(commitmentType)
      KV_MEMBER(status)
      KV_MEMBER(errorMessage)
    }
  };
};

struct COMMAND_RPC_GET_FEE_ADDRESS {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string fee_address;
	std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(fee_address)
	  KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GETBLOCKHASH {
  typedef std::vector<uint64_t> request;
  typedef std::string response;
};

struct COMMAND_RPC_GETBLOCKTEMPLATE {
  struct request {
    uint64_t reserve_size; //max 255 bytes
    std::string wallet_address;

    void serialize(ISerializer &s) {
      KV_MEMBER(reserve_size)
      KV_MEMBER(wallet_address)
    }
  };

  struct response {
    uint64_t difficulty;
    uint32_t height;
    uint64_t reserved_offset;
    std::string blocktemplate_blob;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(difficulty)
      KV_MEMBER(height)
      KV_MEMBER(reserved_offset)
      KV_MEMBER(blocktemplate_blob)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_CURRENCY_ID {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string currency_id_blob;

    void serialize(ISerializer &s) {
      KV_MEMBER(currency_id_blob)
    }
  };
};

struct COMMAND_RPC_SUBMITBLOCK {
  typedef std::vector<std::string> request;
  typedef STATUS_STRUCT response;
};

struct block_header_response {
  uint8_t major_version;
  uint8_t minor_version;
  uint64_t timestamp;
  std::string prev_hash;
  uint32_t nonce;
  bool orphan_status;
  uint64_t height;
  uint64_t depth;
  uint64_t deposits;
  std::string hash;
  difficulty_type difficulty;
  uint64_t reward;

  void serialize(ISerializer &s) {
    KV_MEMBER(major_version)
    KV_MEMBER(minor_version)
    KV_MEMBER(timestamp)
    KV_MEMBER(prev_hash)
    KV_MEMBER(nonce)
    KV_MEMBER(orphan_status)
    KV_MEMBER(height)
    KV_MEMBER(depth)
    KV_MEMBER(deposits)
    KV_MEMBER(hash)
    KV_MEMBER(difficulty)
    KV_MEMBER(reward)
  }
};

struct BLOCK_HEADER_RESPONSE {
  std::string status;
  block_header_response block_header;

  void serialize(ISerializer &s) {
    KV_MEMBER(block_header)
    KV_MEMBER(status)
  }
};


struct f_transaction_short_response {
  std::string hash;
  uint64_t fee;
  uint64_t amount_out;
  uint64_t size;

  void serialize(ISerializer &s) {
    KV_MEMBER(hash)
    KV_MEMBER(fee)
    KV_MEMBER(amount_out)
    KV_MEMBER(size)
  }
};

struct f_transaction_details_response {
  std::string hash;
  size_t size;
  std::string paymentId;
  uint64_t mixin;
  uint64_t fee;
  uint64_t amount_out;
  std::string networkId;  // Added for STARK proof validation

  void serialize(ISerializer &s) {
    KV_MEMBER(hash)
    KV_MEMBER(size)
    KV_MEMBER(paymentId)
    KV_MEMBER(mixin)
    KV_MEMBER(fee)
    KV_MEMBER(amount_out)
    KV_MEMBER(networkId)
  }
};

struct f_block_short_response {
  uint64_t timestamp;
  uint32_t height;
  difficulty_type difficulty;
  std::string hash;
  uint64_t tx_count;
  uint64_t cumul_size;

  void serialize(ISerializer &s) {
    KV_MEMBER(timestamp)
    KV_MEMBER(height)
    KV_MEMBER(difficulty)
    KV_MEMBER(hash)
    KV_MEMBER(cumul_size)
    KV_MEMBER(tx_count)
  }
};

struct f_block_details_response {
  uint8_t major_version;
  uint8_t minor_version;
  uint64_t timestamp;
  std::string prev_hash;
  uint32_t nonce;
  bool orphan_status;
  uint64_t height;
  uint64_t depth;
  std::string hash;
  difficulty_type difficulty;
  uint64_t reward;
  uint64_t blockSize;
  size_t sizeMedian;
  uint64_t effectiveSizeMedian;
  uint64_t transactionsCumulativeSize;
  std::string alreadyGeneratedCoins;
  uint64_t alreadyGeneratedTransactions;
  uint64_t baseReward;
  double penalty;
  uint64_t totalFeeAmount;
  std::vector<f_transaction_short_response> transactions;

  void serialize(ISerializer &s) {
    KV_MEMBER(major_version)
    KV_MEMBER(minor_version)
    KV_MEMBER(timestamp)
    KV_MEMBER(prev_hash)
    KV_MEMBER(nonce)
    KV_MEMBER(orphan_status)
    KV_MEMBER(height)
    KV_MEMBER(depth)
    KV_MEMBER(hash)
    KV_MEMBER(difficulty)
    KV_MEMBER(reward)
    KV_MEMBER(blockSize)
    KV_MEMBER(sizeMedian)
    KV_MEMBER(effectiveSizeMedian)
    KV_MEMBER(transactionsCumulativeSize)
    KV_MEMBER(alreadyGeneratedCoins)
    KV_MEMBER(alreadyGeneratedTransactions)
    KV_MEMBER(baseReward)
    KV_MEMBER(penalty)
    KV_MEMBER(transactions)
    KV_MEMBER(totalFeeAmount)
  }
};
struct currency_base_coin {
  std::string name;
  std::string git;

  void serialize(ISerializer &s) {
    KV_MEMBER(name)
    KV_MEMBER(git)
  }
};

struct currency_core {
  std::vector<std::string> SEED_NODES;
  uint64_t EMISSION_SPEED_FACTOR;
  uint64_t DIFFICULTY_TARGET;
  uint64_t CRYPTONOTE_DISPLAY_DECIMAL_POINT;
  std::string MONEY_SUPPLY;
 // uint64_t GENESIS_BLOCK_REWARD;
  uint64_t DEFAULT_DUST_THRESHOLD;
  uint64_t MINIMUM_FEE;
  uint64_t CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
  uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
//  uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
  uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
  uint64_t P2P_DEFAULT_PORT;
  uint64_t RPC_DEFAULT_PORT;
  uint64_t MAX_BLOCK_SIZE_INITIAL;
  uint64_t EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;
  uint64_t UPGRADE_HEIGHT;
  uint64_t DIFFICULTY_CUT;
  uint64_t DIFFICULTY_LAG;
  //std::string BYTECOIN_NETWORK;
  std::string CRYPTONOTE_NAME;
  std::string GENESIS_COINBASE_TX_HEX;
  std::vector<std::string> CHECKPOINTS;

  void serialize(ISerializer &s) {
    KV_MEMBER(SEED_NODES)
    KV_MEMBER(EMISSION_SPEED_FACTOR)
    KV_MEMBER(DIFFICULTY_TARGET)
    KV_MEMBER(CRYPTONOTE_DISPLAY_DECIMAL_POINT)
    KV_MEMBER(MONEY_SUPPLY)
 //   KV_MEMBER(GENESIS_BLOCK_REWARD)
    KV_MEMBER(DEFAULT_DUST_THRESHOLD)
    KV_MEMBER(MINIMUM_FEE)
    KV_MEMBER(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW)
    KV_MEMBER(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE)
//    KV_MEMBER(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1)
    KV_MEMBER(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX)
    KV_MEMBER(P2P_DEFAULT_PORT)
    KV_MEMBER(RPC_DEFAULT_PORT)
    KV_MEMBER(MAX_BLOCK_SIZE_INITIAL)
    KV_MEMBER(EXPECTED_NUMBER_OF_BLOCKS_PER_DAY)
    KV_MEMBER(UPGRADE_HEIGHT)
    KV_MEMBER(DIFFICULTY_CUT)
    KV_MEMBER(DIFFICULTY_LAG)
    KV_MEMBER(CRYPTONOTE_NAME)
    KV_MEMBER(GENESIS_COINBASE_TX_HEX)
    KV_MEMBER(CHECKPOINTS)
  }
};


struct COMMAND_RPC_GET_LAST_BLOCK_HEADER {
  typedef EMPTY_STRUCT request;
  typedef BLOCK_HEADER_RESPONSE response;
};

struct COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH {
  struct request {
    std::string hash;

    void serialize(ISerializer &s) {
      KV_MEMBER(hash)
    }
  };

  typedef BLOCK_HEADER_RESPONSE response;
};

struct COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT {
  struct request {
    uint64_t height;

    void serialize(ISerializer &s) {
      KV_MEMBER(height)
    }
  };

  typedef BLOCK_HEADER_RESPONSE response;
};



struct F_COMMAND_RPC_GET_BLOCKS_LIST {
  struct request {
    uint64_t height;

    void serialize(ISerializer &s) {
      KV_MEMBER(height)
    }
  };

  struct response {
    std::vector<f_block_short_response> blocks; //transactions blobs as hex
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(blocks)
      KV_MEMBER(status)
    }
  };
};

struct F_COMMAND_RPC_GET_BLOCK_DETAILS {
  struct request {
    std::string hash;

    void serialize(ISerializer &s) {
      KV_MEMBER(hash)
    }
  };

  struct response {
    f_block_details_response block;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(block)
      KV_MEMBER(status)
    }
  };
};

struct F_COMMAND_RPC_GET_TRANSACTION_DETAILS {
  struct request {
    std::string hash;

    void serialize(ISerializer &s) {
      KV_MEMBER(hash)
    }
  };

  struct response {
    Transaction tx;
    f_transaction_details_response txDetails;
    f_block_short_response block;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(tx)
      KV_MEMBER(txDetails)
      KV_MEMBER(block)
      KV_MEMBER(status)
    }
  };
};

struct F_COMMAND_RPC_GET_POOL {
    typedef EMPTY_STRUCT request;

    struct response {
        std::vector<f_transaction_short_response> transactions; //transactions blobs as hex
        std::string status;

        void serialize(ISerializer &s) {
            KV_MEMBER(transactions)
            KV_MEMBER(status)
        }
    };
};

struct F_COMMAND_RPC_GET_BLOCKCHAIN_SETTINGS {
  typedef EMPTY_STRUCT request;
  struct response {
    currency_base_coin base_coin;
    currency_core core;
    std::vector<std::string> extensions;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(base_coin)
      KV_MEMBER(core)
      KV_MEMBER(extensions)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_QUERY_BLOCKS {
  struct request {
    std::vector<Crypto::Hash> block_ids; //*first 10 blocks id goes sequential, next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on, and the last one is always genesis block */
    uint64_t timestamp;

    void serialize(ISerializer &s) {
      serializeAsBinary(block_ids, "block_ids", s);
      KV_MEMBER(timestamp)
    }
  };

  struct response {
    std::string status;
    uint64_t start_height;
    uint64_t current_height;
    uint64_t full_offset;
    std::vector<BlockFullInfo> items;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(start_height)
      KV_MEMBER(current_height)
      KV_MEMBER(full_offset)
      KV_MEMBER(items)
    }
  };
};

struct COMMAND_RPC_QUERY_BLOCKS_LITE {
  struct request {
    std::vector<Crypto::Hash> blockIds;
    uint64_t timestamp;

    void serialize(ISerializer &s) {
      serializeAsBinary(blockIds, "block_ids", s);
      KV_MEMBER(timestamp)
    }
  };

  struct response {
    std::string status;
    uint64_t startHeight;
    uint64_t currentHeight;
    uint64_t fullOffset;
    std::vector<BlockShortInfo> items;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(startHeight)
      KV_MEMBER(currentHeight)
      KV_MEMBER(fullOffset)
      KV_MEMBER(items)
    }
  };
};

struct COMMAND_RPC_GEN_PAYMENT_ID {
  typedef EMPTY_STRUCT request;

  struct response {
	  std::string payment_id;

	  void serialize(ISerializer &s) {
		  KV_MEMBER(payment_id)
	  }
  };
};

// v11+ Hearth Orderbook commands
struct COMMAND_RPC_GET_ORDERBOOK_INFO {
  typedef EMPTY_STRUCT request;
  struct response {
    uint64_t clearing_price;
    uint32_t num_matches;
    uint32_t depth_bid_xfg;
    uint32_t depth_ask_xfg;
    uint64_t hearth_pool_ratio;
    bool in_bootstrap;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(clearing_price)
      KV_MEMBER(num_matches)
      KV_MEMBER(depth_bid_xfg)
      KV_MEMBER(depth_ask_xfg)
      KV_MEMBER(hearth_pool_ratio)
      KV_MEMBER(in_bootstrap)
      KV_MEMBER(status)
    }
  };
};
struct COMMAND_RPC_GET_ORDERBOOK_STATE {
  struct request {
    uint32_t depth;
    void serialize(ISerializer &s) { KV_MEMBER(depth) }
  };
  struct response {
    uint64_t clearing_price;
    std::vector<uint64_t> bid_prices;
    std::vector<uint64_t> bid_depths;
    std::vector<uint64_t> ask_prices;
    std::vector<uint64_t> ask_depths;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(clearing_price)
      KV_MEMBER(bid_prices)
      KV_MEMBER(bid_depths)
      KV_MEMBER(ask_prices)
      KV_MEMBER(ask_depths)
      KV_MEMBER(status)
    }
  };
};

// New P2P swap orderbook commands (Phase 1)
struct COMMAND_RPC_GET_ORDER_BOOK {
  struct request {
    uint8_t pair;
    int     depth;

    request() : pair(0), depth(20) {}

    void serialize(ISerializer &s) {
      KV_MEMBER(pair);
      KV_MEMBER(depth);
    }
  };

  struct response {
    struct OrderBookLevelJson {
      uint64_t price;
      uint64_t amount;
      int      orderCount;

      void serialize(ISerializer &s) {
        KV_MEMBER(price);
        KV_MEMBER(amount);
        KV_MEMBER(orderCount);
      }
    };

    std::vector<OrderBookLevelJson> bids;
    std::vector<OrderBookLevelJson> asks;
    uint64_t spread;
    uint64_t height;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(bids);
      KV_MEMBER(asks);
      KV_MEMBER(spread);
      KV_MEMBER(height);
      KV_MEMBER(status);
    }
  };
};

struct COMMAND_RPC_PLACE_ORDER {
  // Fully signed order only — unsigned placement is rejected.
  struct request {
    uint8_t     side;
    uint8_t     pair;
    uint64_t    price;
    uint64_t    amount;
    uint32_t    ttlBlocks;
    std::string orderId;      // hex, from wallet sign_order
    std::string makerPubKey;  // hex
    std::string signature;    // hex
    uint64_t    nonce;
    uint64_t    timestamp;    // optional; 0 = daemon fills

    void serialize(ISerializer &s) {
      KV_MEMBER(side);
      KV_MEMBER(pair);
      KV_MEMBER(price);
      KV_MEMBER(amount);
      KV_MEMBER(ttlBlocks);
      KV_MEMBER(orderId);
      KV_MEMBER(makerPubKey);
      KV_MEMBER(signature);
      KV_MEMBER(nonce);
      KV_MEMBER(timestamp);
    }
  };

  struct response {
    std::string orderId;
    std::string status;
    uint64_t    filled;
    std::string statusMsg;

    void serialize(ISerializer &s) {
      KV_MEMBER(orderId);
      KV_MEMBER(status);
      KV_MEMBER(filled);
      KV_MEMBER(statusMsg);
    }
  };
};

struct COMMAND_RPC_CANCEL_ORDER {
  // Signed cancel — orderId alone is insufficient
  struct request {
    std::string orderId;
    std::string makerPubKey; // hex
    std::string signature;   // hex, signs "cancel:"+orderId+":"+timestamp
    uint64_t    timestamp;   // anti-replay

    void serialize(ISerializer &s) {
      KV_MEMBER(orderId);
      KV_MEMBER(makerPubKey);
      KV_MEMBER(signature);
      KV_MEMBER(timestamp);
    }
  };

  struct response {
    std::string status;

    void serialize(ISerializer &s) { KV_MEMBER(status); }
  };
};

struct COMMAND_RPC_GET_OPEN_ORDERS {
  struct request {
    std::string address;

    void serialize(ISerializer &s) { KV_MEMBER(address); }
  };

  struct response {
    struct OrderJson {
      std::string orderId;
      std::string side;
      uint8_t     pair;
      uint64_t    price;
      uint64_t    amount;
      uint64_t    filled;
      uint64_t    timestamp;
      uint32_t    ttlBlocks;

      void serialize(ISerializer &s) {
        KV_MEMBER(orderId);
        KV_MEMBER(side);
        KV_MEMBER(pair);
        KV_MEMBER(price);
        KV_MEMBER(amount);
        KV_MEMBER(filled);
        KV_MEMBER(timestamp);
        KV_MEMBER(ttlBlocks);
      }
    };

    std::vector<OrderJson> orders;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(orders);
      KV_MEMBER(status);
    }
  };
};

struct COMMAND_RPC_GET_ORDERBOOK_ESTIMATES {
  struct request {
    uint8_t side;
    uint64_t amount;
    void serialize(ISerializer &s) {
      KV_MEMBER(side)
      KV_MEMBER(amount)
    }
  };
  struct response {
    uint64_t estimated_fill;
    uint64_t hearth_fill;
    uint64_t orderbook_fill;
    uint64_t worst_case_price;
    uint32_t levels_consumed;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(estimated_fill)
      KV_MEMBER(hearth_fill)
      KV_MEMBER(orderbook_fill)
      KV_MEMBER(worst_case_price)
      KV_MEMBER(levels_consumed)
      KV_MEMBER(status)
    }
  };
};
struct COMMAND_RPC_PLACE_LIMIT_ORDER {
  struct request {
    uint8_t side;
    uint64_t amount;
    uint64_t target_price;
    uint32_t expiration;
    void serialize(ISerializer &s) {
      KV_MEMBER(side)
      KV_MEMBER(amount)
      KV_MEMBER(target_price)
      KV_MEMBER(expiration)
    }
  };
  struct response {
    std::string order_id;
    std::string tx_hash;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(order_id)
      KV_MEMBER(tx_hash)
      KV_MEMBER(status)
    }
  };
};
struct COMMAND_RPC_CANCEL_LIMIT_ORDER {
  struct request {
    std::string order_id;
    void serialize(ISerializer &s) { KV_MEMBER(order_id) }
  };
  struct response {
    std::string tx_hash;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(tx_hash)
      KV_MEMBER(status)
    }
  };
};
struct COMMAND_RPC_GET_LIMIT_ORDERS {
  struct request {
    bool active_only;
    uint32_t limit;
    uint32_t offset;
    void serialize(ISerializer &s) {
      KV_MEMBER(active_only)
      KV_MEMBER(limit)
      KV_MEMBER(offset)
    }
  };
  struct LimitOrderInfo {
    std::string order_id;
    std::string address_hash; // cn_fast_hash(spendKey||viewKey) — wallet filters by this
    uint8_t side;
    uint64_t amount;
    uint64_t proceeds_xfg;
    uint64_t proceeds_heat;
    uint64_t target_price;
    uint32_t expiration;
    bool withdrawn;
    void serialize(ISerializer &s) {
      KV_MEMBER(order_id)
      KV_MEMBER(address_hash)
      KV_MEMBER(side)
      KV_MEMBER(amount)
      KV_MEMBER(proceeds_xfg)
      KV_MEMBER(proceeds_heat)
      KV_MEMBER(target_price)
      KV_MEMBER(expiration)
      KV_MEMBER(withdrawn)
    }
  };
  struct response {
    std::vector<LimitOrderInfo> orders;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(orders)
      KV_MEMBER(status)
    }
  };
};

struct reserve_proof_entry
{
	Crypto::Hash txid;
	uint64_t index_in_tx;
	Crypto::PublicKey shared_secret;
	Crypto::KeyImage key_image;
	Crypto::Signature shared_secret_sig;
	Crypto::Signature key_image_sig;

	void serialize(ISerializer& s)
	{
		KV_MEMBER(txid)
		KV_MEMBER(index_in_tx)
		KV_MEMBER(shared_secret)
		KV_MEMBER(key_image)
		KV_MEMBER(shared_secret_sig)
		KV_MEMBER(key_image_sig)
	}
};

struct reserve_proof {
	std::vector<reserve_proof_entry> proofs;
	Crypto::Signature signature;

	void serialize(ISerializer &s) {
		KV_MEMBER(proofs)
		KV_MEMBER(signature)
	}
};

struct K_COMMAND_RPC_CHECK_TX_PROOF {
    struct request {
        std::string tx_id;
        std::string dest_address;
        std::string signature;

        void serialize(ISerializer &s) {
            KV_MEMBER(tx_id)
            KV_MEMBER(dest_address)
            KV_MEMBER(signature)
        }
    };

    struct response {
        bool signature_valid;
        uint64_t received_amount;
		std::vector<TransactionOutput> outputs;
		uint32_t confirmations = 0;
        std::string status;
        uint64_t total;
        uint64_t spent;
        bool good;

        void serialize(ISerializer &s) {
            KV_MEMBER(signature_valid)
            KV_MEMBER(received_amount)
            KV_MEMBER(outputs)
            KV_MEMBER(confirmations)
            KV_MEMBER(status)
        }
    };
};

struct K_COMMAND_RPC_CHECK_RESERVE_PROOF {
	struct request {
		std::string address;
		std::string message;
		std::string signature;

		void serialize(ISerializer &s) {
			KV_MEMBER(address)
			KV_MEMBER(message)
			KV_MEMBER(signature)
		}
	};

	struct response	{
		bool good;
		uint64_t total;
		uint64_t spent;

		void serialize(ISerializer &s) {
			KV_MEMBER(good)
			KV_MEMBER(total)
			KV_MEMBER(spent)
		}
	};
};




// ============================================================================
// @ ALIAS SYSTEM RPC ENDPOINTS
// ============================================================================

struct COMMAND_RPC_GET_ALIAS {
	struct request {
		std::string alias;

		void serialize(ISerializer& s) {
			KV_MEMBER(alias)
		}
	};

	struct response {
		std::string alias;
		std::string address;
		std::string address_hash;
		uint32_t registered_block;
		uint8_t alias_type;
		bool found;
		std::string status;

		void serialize(ISerializer& s) {
			KV_MEMBER(alias)
			KV_MEMBER(address)
			KV_MEMBER(address_hash)
			KV_MEMBER(registered_block)
			KV_MEMBER(alias_type)
			KV_MEMBER(found)
			KV_MEMBER(status)
		}
	};
};

struct COMMAND_RPC_GET_ALIAS_BY_ADDRESS {
	struct request {
		std::string address;

		void serialize(ISerializer& s) {
			KV_MEMBER(address)
		}
	};

	struct response {
		std::string alias;
		std::string address;
		uint32_t registered_block;
		uint8_t alias_type;
		bool found;
		std::string status;

		void serialize(ISerializer& s) {
			KV_MEMBER(alias)
			KV_MEMBER(address)
			KV_MEMBER(registered_block)
			KV_MEMBER(alias_type)
			KV_MEMBER(found)
			KV_MEMBER(status)
		}
	};
};

struct COMMAND_RPC_GET_ALL_ALIASES {
	typedef EMPTY_STRUCT request;

	struct alias_entry {
		std::string alias;
		std::string address;
		uint32_t registered_block;
		uint8_t alias_type;

		void serialize(ISerializer& s) {
			KV_MEMBER(alias)
			KV_MEMBER(address)
			KV_MEMBER(registered_block)
			KV_MEMBER(alias_type)
		}
	};

	struct response {
		std::vector<alias_entry> aliases;
		uint32_t total;
		std::string status;

		void serialize(ISerializer& s) {
			KV_MEMBER(aliases)
			KV_MEMBER(total)
			KV_MEMBER(status)
		}
	};
};

// ============================================================
// Commitment Index RPC endpoints (Fuego → EVM bridge support)
// Used by xfg-stark-cli to fetch commitment data + merkle proofs
// ============================================================

struct COMMAND_RPC_GET_COMMITMENT {
  struct request {
    std::string commitment_hash;  // Hex-encoded commitment hash (64 chars)

    void serialize(ISerializer& s) {
      KV_MEMBER(commitment_hash)
    }
  };

  struct response {
    bool found;
    std::string commitment_hash;
    std::string tx_hash;
    uint32_t block_height;
    uint64_t amount;
    uint32_t term;
    uint8_t type;               // 0=HEAT, 1=YIELD
    uint32_t target_chain_id;
    uint32_t leaf_index;
    bool is_legacy;         // true only for 0xCE migrations (original tx had MultisignatureOutput)
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(found)
      KV_MEMBER(commitment_hash)
      KV_MEMBER(tx_hash)
      KV_MEMBER(block_height)
      KV_MEMBER(amount)
      KV_MEMBER(term)
      KV_MEMBER(type)
      KV_MEMBER(target_chain_id)
      KV_MEMBER(leaf_index)
      KV_MEMBER(is_legacy)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_COMMITMENT_STATS {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t total_commitments;
    uint64_t heat_commitments;
    uint64_t cold_commitments;  // legacy field — kept for wire compatibility; always 0
    uint32_t highest_block;
    std::string merkle_root;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(total_commitments)
      KV_MEMBER(heat_commitments)
      KV_MEMBER(cold_commitments)   // legacy — serialization compat
      KV_MEMBER(highest_block)
      KV_MEMBER(merkle_root)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_COMMITMENT_MERKLE_ROOT {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string merkle_root;    // Hex-encoded current merkle root
    uint64_t total_leaves;
    uint32_t highest_block;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(merkle_root)
      KV_MEMBER(total_leaves)
      KV_MEMBER(highest_block)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_COMMITMENT_MERKLE_PROOF {
  struct request {
    std::string commitment_hash;  // Hex-encoded commitment hash

    void serialize(ISerializer& s) {
      KV_MEMBER(commitment_hash)
    }
  };

  struct response {
    bool found;
    std::string merkle_root;              // Current root
    std::string leaf_hash;                // The commitment being proved
    std::vector<std::string> proof_path;  // Sibling hashes in hex
    std::vector<uint32_t> proof_indices;  // Left(0) or right(1) at each level
    uint32_t leaf_index;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(found)
      KV_MEMBER(merkle_root)
      KV_MEMBER(leaf_hash)
      KV_MEMBER(proof_path)
      KV_MEMBER(proof_indices)
      KV_MEMBER(leaf_index)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_CHECK_COMMITMENT_EXISTS {
  struct request {
    std::string commitment_hash;

    void serialize(ISerializer& s) {
      KV_MEMBER(commitment_hash)
    }
  };

  struct response {
    bool exists;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(exists)
      KV_MEMBER(status)
    }
  };
};


// ============================================================================
// SWAP ORDERBOOK RPC ENDPOINTS
// ============================================================================

struct swap_offer_rpc_entry {
  std::string offerId;
  uint64_t xfgAmount;
  uint64_t rateNum;
  uint8_t pair;
  std::string makerPubKey;    // hex
  uint64_t timestamp;
  uint32_t ttlBlocks;
  uint32_t postedHeight;

  void serialize(ISerializer& s) {
    KV_MEMBER(offerId)
    KV_MEMBER(xfgAmount)
    KV_MEMBER(rateNum)
    KV_MEMBER(pair)
    KV_MEMBER(makerPubKey)
    KV_MEMBER(timestamp)
    KV_MEMBER(ttlBlocks)
    KV_MEMBER(postedHeight)
  }
};

struct COMMAND_RPC_GET_SWAP_OFFERS {
  struct request {
    uint8_t pair;

    void serialize(ISerializer& s) {
      KV_MEMBER(pair)
    }
  };

  struct response {
    std::vector<swap_offer_rpc_entry> offers;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(offers)
      KV_MEMBER(status)
    }
  };
};

// One soft-order fill result published by the maker's SwapDaemon.
struct swap_request_result_entry {
  std::string offerId;
  std::string lockId;         // maker's AFK lock id (= the AFK swap id)
  std::string makerEndpoint;  // maker's swap P2P endpoint (host:port)
  std::string adaptorPoint;   // hex, T = t*G
  std::string hashLock;       // hex, H(t) — counterparty-family hash
  std::string preSig;         // hex, maker's adaptor pre-signature
  std::string ctrAddress;     // maker's counterparty-chain receive address
  uint64_t    createdAt;

  void serialize(ISerializer& s) {
    KV_MEMBER(offerId)
    KV_MEMBER(lockId)
    KV_MEMBER(makerEndpoint)
    KV_MEMBER(adaptorPoint)
    KV_MEMBER(hashLock)
    KV_MEMBER(preSig)
    KV_MEMBER(ctrAddress)
    KV_MEMBER(createdAt)
  }
};

/** @brief Query fill-request results for a taker (keyed by takerPubKey). */
struct COMMAND_RPC_GET_SWAP_REQUESTS {
  struct request {
    std::string takerPubKey;  // 64-char hex Ed25519 identity sent in /requestswap

    void serialize(ISerializer& s) {
      KV_MEMBER(takerPubKey)
    }
  };

  struct response {
    std::vector<swap_request_result_entry> requests;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(requests)
      KV_MEMBER(status)
    }
  };
};

// Individual price source in composite breakdown
struct price_source_rpc_entry {
  std::string name;
  uint8_t     pair;
  std::string weight;
  std::string rate;
  uint64_t    updatedAt;
  bool        stale;

  void serialize(ISerializer& s) {
    KV_MEMBER(name)
    KV_MEMBER(pair)
    KV_MEMBER(weight)
    KV_MEMBER(rate)
    KV_MEMBER(updatedAt)
    KV_MEMBER(stale)
  }
};

// Per-pair implied USD price
struct pair_implied_rpc_entry {
  uint8_t     pair;
  std::string impliedUsd;

  void serialize(ISerializer& s) {
    KV_MEMBER(pair)
    KV_MEMBER(impliedUsd)
  }
};

struct COMMAND_RPC_GET_SWAP_PRICE {
  struct request {
    uint8_t pair;

    void serialize(ISerializer& s) {
      KV_MEMBER(pair)
    }
  };

  struct response {
    std::string twap;             // atomic swap TWAP (double as string)
    std::string seedRate;         // bootstrap seed rate
    std::string compositeRate;    // weighted avg across all sources
    uint32_t    sourceCount;      // how many sources contributed
    std::vector<price_source_rpc_entry> sources;  // source breakdown

    // Cross-pair native XFG price range (USD)
    std::string xfgUsdLow;
    std::string xfgUsdHigh;
    std::string xfgUsdMid;
    std::vector<pair_implied_rpc_entry> pairImplied;

    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(twap)
      KV_MEMBER(seedRate)
      KV_MEMBER(compositeRate)
      KV_MEMBER(sourceCount)
      KV_MEMBER(sources)
      KV_MEMBER(xfgUsdLow)
      KV_MEMBER(xfgUsdHigh)
      KV_MEMBER(xfgUsdMid)
      KV_MEMBER(pairImplied)
      KV_MEMBER(status)
    }
  };
};

struct swap_trade_rpc_entry {
  uint8_t pair;
  uint64_t xfgAmount;
  uint64_t ctrAmount;
  std::string rate;       // double as string
  uint32_t blockHeight;
  uint64_t timestamp;

  void serialize(ISerializer& s) {
    KV_MEMBER(pair)
    KV_MEMBER(xfgAmount)
    KV_MEMBER(ctrAmount)
    KV_MEMBER(rate)
    KV_MEMBER(blockHeight)
    KV_MEMBER(timestamp)
  }
};

struct COMMAND_RPC_GET_SWAP_TRADES {
  struct request {
    uint8_t pair;
    uint32_t limit;

    void serialize(ISerializer& s) {
      KV_MEMBER(pair)
      KV_MEMBER(limit)
    }
  };

  struct response {
    std::vector<swap_trade_rpc_entry> trades;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(trades)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_SUBMIT_SWAP_OFFER {
  struct request {
    std::string offerId;
    uint64_t xfgAmount;
    uint64_t rateNum;
    uint8_t pair;
    std::string makerPubKey;  // hex
    std::string signature;    // hex
    uint32_t ttlBlocks;

    // Optional fields for soft orders
    bool isSoftOrder = false;
    // Client-side signing timestamp. The offer signature covers the
    // timestamp (offerCanonicalHash), so the submitter MUST be able to
    // predict it: honor a nonzero client timestamp; fall back to server
    // time only when absent (legacy callers that predate canonical hashing).
    uint64_t timestamp = 0;

    void serialize(ISerializer& s) {
      KV_MEMBER(offerId)
      KV_MEMBER(xfgAmount)
      KV_MEMBER(rateNum)
      KV_MEMBER(pair)
      KV_MEMBER(makerPubKey)
      KV_MEMBER(signature)
      KV_MEMBER(ttlBlocks)
      KV_MEMBER(isSoftOrder)
      KV_MEMBER(timestamp)
    }
  };

  struct response {
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_CANCEL_SWAP_OFFER {
  struct request {
    std::string offerId;
    std::string makerPubKey;  // hex
    std::string signature;    // hex, signs "cancel:"+offerId+":"+timestamp
    uint64_t    timestamp;    // anti-replay

    void serialize(ISerializer& s) {
      KV_MEMBER(offerId)
      KV_MEMBER(makerPubKey)
      KV_MEMBER(signature)
      KV_MEMBER(timestamp)
    }
  };

  struct response {
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(status)
    }
  };
};

/** @brief Take (fill) a soft order. Queues a PendingSwapRequest for the
 * local maker's SwapDaemon, which verifies the reserve proof and creates
 * the AFK lock. proofOfFunds format per chain (see chain client
 * verifyReserveProof): EVM "0xaddr:130hexSig:offerId" (EIP-191),
 * SOL "b58pub:b58sig:offerId" (Ed25519), Bitcoin-family
 * "address:signature:offerId" (signmessage). */
struct COMMAND_RPC_REQUEST_SWAP {
  struct request {
    std::string offerId;
    uint64_t amount = 0;      // XFG atomic amount to fill (0 = full remaining)
    std::string takerPubKey;   // 64-char hex Ed25519 pubkey — taker's swap identity
    std::string proofOfFunds;  // chain reserve proof bound to this offerId

    void serialize(ISerializer& s) {
      KV_MEMBER(offerId)
      KV_MEMBER(amount)
      KV_MEMBER(takerPubKey)
      KV_MEMBER(proofOfFunds)
    }
  };

  struct response {
    std::string status;      // "pending" on success
    std::string offerId;
    uint8_t pair = 0;
    uint64_t xfgAmount = 0;  // offer amount being locked (echo)

    void serialize(ISerializer& s) {
      KV_MEMBER(status)
      KV_MEMBER(offerId)
      KV_MEMBER(pair)
      KV_MEMBER(xfgAmount)
    }
  };
};

/** @brief Current fee pool state snapshot */
struct COMMAND_RPC_GET_FEE_POOL_INFO {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t fee_pool_balance;          // 69% CD yield pool
    uint64_t treasury_balance;          // 20% treasury reserve
    uint64_t bonus_vault_balance;       // 11% bonus vault (loyalty + tier bonuses)
    uint64_t rollover_vault_balance;    // deprecated, kept for compat
    uint64_t current_epoch_swap_fees;
    uint64_t total_cd_locked;
    uint64_t current_epoch_number;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(fee_pool_balance)
      KV_MEMBER(treasury_balance)
      KV_MEMBER(bonus_vault_balance)
      KV_MEMBER(rollover_vault_balance)
      KV_MEMBER(current_epoch_swap_fees)
      KV_MEMBER(total_cd_locked)
      KV_MEMBER(current_epoch_number)
      KV_MEMBER(status)
    }
  };
};

/** @brief List of past epoch summaries */
struct COMMAND_RPC_GET_EPOCH_HISTORY {
  struct request {
    uint32_t count = 10;

    void serialize(ISerializer& s) {
      KV_MEMBER(count)
    }
  };

  struct epoch_summary {
    uint64_t epoch_number;
    uint64_t swap_fees_collected;
    uint64_t total_cd_locked_at_start;
    uint64_t fee_rate_fixed_point;
    uint64_t total_fees_distributed;
    uint64_t active_efier_count;

    void serialize(ISerializer& s) {
      KV_MEMBER(epoch_number)
      KV_MEMBER(swap_fees_collected)
      KV_MEMBER(total_cd_locked_at_start)
      KV_MEMBER(fee_rate_fixed_point)
      KV_MEMBER(total_fees_distributed)
      KV_MEMBER(active_efier_count)
    }
  };

  struct response {
    std::vector<epoch_summary> epochs;
    uint64_t total_epochs;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(epochs)
      KV_MEMBER(total_epochs)
      KV_MEMBER(status)
    }
  };
};

/** @brief Estimate interest for a given CD */
struct COMMAND_RPC_ESTIMATE_CD_YIELD {
  struct request {
    uint64_t amount;
    uint32_t creation_height;
    uint32_t current_height = 0;
    uint32_t term = 0;  // v11+: CD term (blocks) — applies the tier weight to the bonus estimate

    void serialize(ISerializer& s) {
      KV_MEMBER(amount)
      KV_MEMBER(creation_height)
      KV_MEMBER(current_height)
      KV_MEMBER(term)
    }
  };

  struct response {
    uint64_t estimated_interest;
    uint64_t effective_epochs;
    uint64_t fee_pool_balance = 0;       // HEAT backing available for CD interest claims
    uint64_t cd_apy_vault_balance = 0;   // CD_APY_POOL vault partition, HEAT
    uint64_t claimable_interest = 0;     // min(estimated, pool, vault) — what consensus accepts
    uint64_t base_interest = 0;          // v13+: pool-backed base portion (no loyalty)
    uint64_t bonus_interest = 0;         // v13+: BV-backed tier bonus (realized inflows)
    uint64_t bonus_vault_balance = 0;    // v13+: BONUS_VAULT counter, HEAT
    uint64_t claimable_bonus = 0;        // v13+: min(bonus_interest, bonus vault)
    bool pool_info_present = false;      // false when the daemon predates pool-aware estimates
    std::string note;                    // estimate disclaimer (real yield, no printed interest)
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(estimated_interest)
      KV_MEMBER(effective_epochs)
      KV_MEMBER(fee_pool_balance)
      KV_MEMBER(cd_apy_vault_balance)
      KV_MEMBER(claimable_interest)
      KV_MEMBER(base_interest)
      KV_MEMBER(bonus_interest)
      KV_MEMBER(bonus_vault_balance)
      KV_MEMBER(claimable_bonus)
      KV_MEMBER(pool_info_present)
      KV_MEMBER(note)
      KV_MEMBER(status)
    }
  };
};

/** @brief Treasury balance snapshot */
struct COMMAND_RPC_GET_TREASURY_INFO {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t treasury_balance;      // legacy counter (deprecated, ~0)
    uint64_t treasury_counter_xfg;  // unconverted treasury fee share (LP pairing source)
    uint64_t treasury_heat_reserve; // HEAT leg for Treasury LP Manager
    uint64_t swf_burned_xfg_pending_heat; // already-burned XFG held only by SWF
    uint64_t bonus_vault_balance;   // HEAT-denominated CD loyalty vault (v12+)
    uint64_t fee_pool_balance;      // HEAT backing CD interest claims
    uint64_t total_burned_xfg;      // overall burn tally
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(treasury_balance)
      KV_MEMBER(treasury_counter_xfg)
      KV_MEMBER(treasury_heat_reserve)
      KV_MEMBER(swf_burned_xfg_pending_heat)
      KV_MEMBER(bonus_vault_balance)
      KV_MEMBER(fee_pool_balance)
      KV_MEMBER(total_burned_xfg)
      KV_MEMBER(status)
    }
  };
};

// Phase 5: Wallet Auto-Rollover + Compound Interest

/** @brief Get deposits that are maturing or will mature within N blocks */
struct COMMAND_RPC_GET_MATURING_DEPOSITS {
  struct request {
    uint32_t current_height = 0;
    uint32_t maturing_in = 0;  // blocks (0 = already mature)

    void serialize(ISerializer& s) {
      KV_MEMBER(current_height)
      KV_MEMBER(maturing_in)
    }
  };

  struct response {
    struct deposit_info {
      uint64_t deposit_id;
      uint64_t amount;
      uint32_t unlock_height;
      uint32_t term_blocks;
      std::string status;  // "mature" or "maturing_in_N_blocks"

      void serialize(ISerializer& s) {
        KV_MEMBER(deposit_id)
        KV_MEMBER(amount)
        KV_MEMBER(unlock_height)
        KV_MEMBER(term_blocks)
        KV_MEMBER(status)
      }
    };

    std::vector<deposit_info> deposits;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(deposits)
      KV_MEMBER(status)
    }
  };
};

/** @brief Rollover a mature CD to capture compound interest */
struct COMMAND_RPC_ROLLOVER_DEPOSIT {
  struct request {
    uint64_t deposit_id;
    uint32_t new_term = 0;  // in epochs (0 = same as current)

    void serialize(ISerializer& s) {
      KV_MEMBER(deposit_id)
      KV_MEMBER(new_term)
    }
  };

  struct response {
    std::string tx_hash;
    uint64_t new_amount;  // amount + interest
    uint64_t claimed_interest;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(tx_hash)
      KV_MEMBER(new_amount)
      KV_MEMBER(claimed_interest)
      KV_MEMBER(status)
    }
  };
};

/** @brief List all persisted swaps (from SwapDaemon database) */
struct COMMAND_RPC_LIST_SWAPS {
  struct request { void serialize(ISerializer&) {} };
  struct response {
    struct swap_summary {
      std::string swap_id;
      std::string state;
      std::string pair;
      std::string role;
      uint64_t xfg_amount = 0;
      uint64_t created_at = 0;
      uint64_t updated_at = 0;
      bool is_terminal = false;
      void serialize(ISerializer& s) {
        KV_MEMBER(swap_id)
        KV_MEMBER(state)
        KV_MEMBER(pair)
        KV_MEMBER(role)
        KV_MEMBER(xfg_amount)
        KV_MEMBER(created_at)
        KV_MEMBER(updated_at)
        KV_MEMBER(is_terminal)
      }
    };
    std::vector<swap_summary> swaps;
    std::string status;
    void serialize(ISerializer& s) {
      KV_MEMBER(swaps)
      KV_MEMBER(status)
    }
  };
};

/** @brief Get status of a single persisted swap by swap_id */
struct COMMAND_RPC_GET_SWAP_STATUS {
  struct request {
    std::string swap_id;
    void serialize(ISerializer& s) { KV_MEMBER(swap_id) }
  };
  struct response {
    std::string swap_id;
    std::string state;
    std::string pair;
    std::string role;
    uint64_t xfg_amount = 0;
    std::string ctr_address;
    std::string peer_endpoint;
    uint64_t created_at = 0;
    uint64_t updated_at = 0;
    bool is_terminal = false;
    bool found = false;
    std::string status;
    void serialize(ISerializer& s) {
      KV_MEMBER(swap_id)
      KV_MEMBER(state)
      KV_MEMBER(pair)
      KV_MEMBER(role)
      KV_MEMBER(xfg_amount)
      KV_MEMBER(ctr_address)
      KV_MEMBER(peer_endpoint)
      KV_MEMBER(created_at)
      KV_MEMBER(updated_at)
      KV_MEMBER(is_terminal)
      KV_MEMBER(found)
      KV_MEMBER(status)
    }
  };
};

// ── Swap execution RPC structs ───────────────────────────────────────────────

struct COMMAND_RPC_GET_ACTIVE_SWAPS {
  typedef EMPTY_STRUCT request;

  struct swap_entry {
    std::string swap_id;
    std::string state;
    std::string pair;
    std::string role;
    uint64_t    xfg_amount = 0;
    std::string ctr_address;
    std::string peer_endpoint;
    uint64_t    created_at = 0;
    uint64_t    updated_at = 0;
    bool        is_terminal = false;

    void serialize(ISerializer& s) {
      KV_MEMBER(swap_id)
      KV_MEMBER(state)
      KV_MEMBER(pair)
      KV_MEMBER(role)
      KV_MEMBER(xfg_amount)
      KV_MEMBER(ctr_address)
      KV_MEMBER(peer_endpoint)
      KV_MEMBER(created_at)
      KV_MEMBER(updated_at)
      KV_MEMBER(is_terminal)
    }
  };

  struct response {
    std::vector<swap_entry> swaps;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(swaps)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_INITIATE_SWAP {
  struct request {
    std::string pair;          // "SOL", "ETH", "XMR", "BCH"
    uint64_t    xfg_amount = 0;
    uint64_t    ctr_amount = 0;
    std::string ctr_address;   // counterparty chain address
    std::string peer_endpoint; // counterparty network endpoint
    std::string peer_pub_key;  // counterparty Musig2 pubkey (hex)

    void serialize(ISerializer& s) {
      KV_MEMBER(pair)
      KV_MEMBER(xfg_amount)
      KV_MEMBER(ctr_amount)
      KV_MEMBER(ctr_address)
      KV_MEMBER(peer_endpoint)
      KV_MEMBER(peer_pub_key)
    }
  };

  struct response {
    std::string swap_id;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(swap_id)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_ACCEPT_SWAP {
  struct request {
    std::string swap_id;
    void serialize(ISerializer& s) { KV_MEMBER(swap_id) }
  };

  struct response {
    std::string status;
    void serialize(ISerializer& s) { KV_MEMBER(status) }
  };
};

struct COMMAND_RPC_PROCESS_SWAP {
  struct request {
    std::string swap_id;
    void serialize(ISerializer& s) { KV_MEMBER(swap_id) }
  };

  struct response {
    bool        advanced = false;
    std::string new_state;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(advanced)
      KV_MEMBER(new_state)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_REFUND_SWAP {
  struct request {
    std::string swap_id;
    void serialize(ISerializer& s) { KV_MEMBER(swap_id) }
  };

  struct response {
    std::string status;
    void serialize(ISerializer& s) { KV_MEMBER(status) }
  };
};

/** @brief Get total burned XFG amount (eternal flame)
  */
 struct COMMAND_RPC_GET_ETHERNAL_FLAME {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t ethereal_xfg;
    std::string formattedAmount;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(ethereal_xfg)
      KV_MEMBER(formattedAmount)
      KV_MEMBER(status)
    }
  };
 };

struct COMMAND_RPC_GET_BLOCK_RANGE {
  struct request {
    uint64_t start_height;
    uint64_t end_height;

    void serialize(ISerializer &s) {
      KV_MEMBER(start_height)
      KV_MEMBER(end_height)
    }
  };

  struct block_entry {
    // Block header fields
    uint8_t  major_version;
    uint8_t  minor_version;
    uint32_t nonce;
    uint64_t timestamp;
    std::string previous_block_hash; // hex string

    // Per-transaction tx_extra bytes (hex encoded)
    std::vector<std::string> tx_extras;

    void serialize(ISerializer &s) {
      KV_MEMBER(major_version)
      KV_MEMBER(minor_version)
      KV_MEMBER(nonce)
      KV_MEMBER(timestamp)
      KV_MEMBER(previous_block_hash)
      KV_MEMBER(tx_extras)
    }
  };

  struct response {
    std::vector<block_entry> blocks;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(blocks)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_COMMITMENT_LEAVES {
  typedef EMPTY_STRUCT request;

  struct response {
    std::vector<std::string> leaves; // hex-encoded keccak256 commitment hashes
    uint64_t count;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(leaves)
      KV_MEMBER(count)
      KV_MEMBER(status)
    }
  };
};

//-----------------------------------------------
// JSON-friendly random outputs for SwapDaemon decoy selection.
// Wraps the same core logic as /getrandom_outs.bin but uses per-field
// JSON serialization instead of packed binary blobs.
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_JSON {
  struct request {
    uint64_t amount;
    uint64_t count;

    void serialize(ISerializer& s) {
      KV_MEMBER(amount)
      KV_MEMBER(count)
    }
  };

  struct out_entry {
    uint64_t global_index;
    std::string out_key;  // hex-encoded PublicKey

    void serialize(ISerializer& s) {
      KV_MEMBER(global_index)
      KV_MEMBER(out_key)
    }
  };

  struct response {
    std::vector<out_entry> outs;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(outs)
      KV_MEMBER(status)
    }
  };
};

// Lookup output keys at explicit per-amount global indexes. Used by
// SwapDaemon to verify a peer's agreed ring descriptor entry-by-entry.
struct COMMAND_RPC_GET_OUTPUTS_JSON {
  struct request {
    uint64_t amount;
    std::vector<uint64_t> indexes;

    void serialize(ISerializer& s) {
      KV_MEMBER(amount)
      KV_MEMBER(indexes)
    }
  };

  struct out_entry {
    uint64_t global_index;
    std::string out_key;  // hex-encoded PublicKey; zeroed for unknown indexes

    void serialize(ISerializer& s) {
      KV_MEMBER(global_index)
      KV_MEMBER(out_key)
    }
  };

  struct response {
    std::vector<out_entry> outs;
    std::string status;

    void serialize(ISerializer& s) {
      KV_MEMBER(outs)
      KV_MEMBER(status)
    }
  };
};

// HEAT metrics
struct COMMAND_RPC_GET_HEAT_METRICS {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t heat_supply;
    uint64_t heat_on_deposit;
    uint64_t burned_xfg;
    uint64_t total_burned_xfg;
    uint64_t redemption_price_num;
    uint64_t redemption_price_denom;
    uint64_t redemption_rate_num;
    uint64_t redemption_rate_denom;
    uint64_t treasury_balance;
    uint64_t treasury_counter_xfg;
    uint64_t swf_burned_xfg_pending_heat;
    uint64_t epoch_swap_fees;
    uint64_t vault_heat_cd_fee_pool;
    uint64_t vault_heat_lp_reserve;
    uint64_t vault_heat_general;
    uint64_t vault_heat_swf;
    uint64_t vault_xfg_cd_fee_pool;
    uint64_t vault_xfg_lp_reserve;
    uint64_t vault_xfg_general;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(heat_supply)
      KV_MEMBER(heat_on_deposit)
      KV_MEMBER(burned_xfg)
      KV_MEMBER(total_burned_xfg)
      KV_MEMBER(redemption_price_num)
      KV_MEMBER(redemption_price_denom)
      KV_MEMBER(redemption_rate_num)
      KV_MEMBER(redemption_rate_denom)
      KV_MEMBER(treasury_balance)
      KV_MEMBER(treasury_counter_xfg)
      KV_MEMBER(swf_burned_xfg_pending_heat)
      KV_MEMBER(epoch_swap_fees)
      KV_MEMBER(vault_heat_cd_fee_pool)
      KV_MEMBER(vault_heat_lp_reserve)
      KV_MEMBER(vault_heat_general)
      KV_MEMBER(vault_heat_swf)
      KV_MEMBER(vault_xfg_cd_fee_pool)
      KV_MEMBER(vault_xfg_lp_reserve)
      KV_MEMBER(vault_xfg_general)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_AMM_QUOTE {
  struct request {
    uint64_t input_amount;
    uint8_t  direction;
    void serialize(ISerializer &s) {
      KV_MEMBER(input_amount)
      KV_MEMBER(direction)
    }
  };

  struct response {
    uint64_t expected_output;
    uint64_t price_impact_bps;
    uint64_t fee;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(expected_output)
      KV_MEMBER(price_impact_bps)
      KV_MEMBER(fee)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_AMM_POOL_INFO {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t reserve_xfg;
    uint64_t reserve_heat;
    uint64_t total_lp_shares;
    uint64_t spot_price;
    uint64_t epoch_swap_fees;
    uint64_t hearth_twap;
    uint64_t height;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(reserve_xfg)
      KV_MEMBER(reserve_heat)
      KV_MEMBER(total_lp_shares)
      KV_MEMBER(spot_price)
      KV_MEMBER(epoch_swap_fees)
      KV_MEMBER(hearth_twap)
      KV_MEMBER(height)
      KV_MEMBER(status)
    }
  };
};

// Combined XFG/HEAT price snapshot for the wallet and xfg-swapd.
// spot_price is the canonical hearth price (HEAT atomics per XFG atomic * COIN);
// xfg_heat_ratio / heat_peg_usd / xfg_spot_usd are human-readable doubles.
struct COMMAND_RPC_GET_FUEGO_PRICE {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t reserve_xfg;
    uint64_t reserve_heat;
    uint64_t spot_price;
    uint64_t redemption_price_num;
    uint64_t redemption_price_denom;
    std::string xfg_heat_ratio;
    std::string heat_peg_usd;
    std::string xfg_spot_usd;
    uint64_t height;
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(reserve_xfg)
      KV_MEMBER(reserve_heat)
      KV_MEMBER(spot_price)
      KV_MEMBER(redemption_price_num)
      KV_MEMBER(redemption_price_denom)
      KV_MEMBER(xfg_heat_ratio)
      KV_MEMBER(heat_peg_usd)
      KV_MEMBER(xfg_spot_usd)
      KV_MEMBER(height)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_ADD_SWAP_FEE {
  struct request {
    uint64_t amount;
    void serialize(ISerializer &s) {
      KV_MEMBER(amount)
    }
  };

  struct response {
    std::string status;
    void serialize(ISerializer &s) {
      KV_MEMBER(status)
    }
  };
};

}
