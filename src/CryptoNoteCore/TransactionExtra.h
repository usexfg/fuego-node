// Copyright (c) 2017-2025 Fuego Developers
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

#include <algorithm>
#include <string>
#include <vector>
#include <boost/variant.hpp>

#include <CryptoNote.h>

#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255

#define TX_EXTRA_TAG_PADDING                0x00
#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02
#define TX_EXTRA_MERGE_MINING_TAG           0x03
#define TX_EXTRA_MESSAGE_TAG                0x04
#define TX_EXTRA_TTL                        0x05
#define TX_EXTRA_HEAT_COMMITMENT            0x08
#define TX_EXTRA_YIELD_COMMITMENT           0x07

#define TX_EXTRA_NONCE_PAYMENT_ID           0x00

namespace CryptoNote {

class ISerializer;

struct TransactionExtraPadding {
  size_t size;
};

struct TransactionExtraPublicKey {
  Crypto::PublicKey publicKey;
};

struct TransactionExtraNonce {
  std::vector<uint8_t> nonce;
};

struct TransactionExtraMergeMiningTag {
  size_t depth;
  Crypto::Hash merkleRoot;
};

struct tx_extra_message {
  std::string data;

  bool encrypt(std::size_t index, const std::string &message, const AccountPublicAddress* recipient, const KeyPair &txkey);
  bool decrypt(std::size_t index, const Crypto::PublicKey &txkey, const Crypto::SecretKey *recepient_secret_key, std::string &message) const;

  bool serialize(ISerializer& serializer);
};

struct TransactionExtraTTL {
  uint64_t ttl;
};

struct TransactionExtraHeatCommitment {
  Crypto::Hash commitment;
  uint64_t amount;
  std::vector<uint8_t> metadata;
  
  bool serialize(ISerializer& serializer);
};

struct TransactionExtraYieldCommitment {
  Crypto::Hash commitment;
  uint64_t amount;
  uint32_t term_months;
  std::string yield_scheme;
  std::vector<uint8_t> metadata;
  
  bool serialize(ISerializer& serializer);
};

// tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
//   varint tag;
//   varint size;
//   varint data[];
typedef boost::variant<TransactionExtraPadding, TransactionExtraPublicKey, TransactionExtraNonce, TransactionExtraMergeMiningTag, tx_extra_message, TransactionExtraTTL, TransactionExtraHeatCommitment, TransactionExtraYieldCommitment> TransactionExtraField;



template<typename T>
bool findTransactionExtraFieldByType(const std::vector<TransactionExtraField>& tx_extra_fields, T& field) {
  auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(),
    [](const TransactionExtraField& f) { return typeid(T) == f.type(); });

  if (tx_extra_fields.end() == it)
    return false;

  field = boost::get<T>(*it);
  return true;
}

bool parseTransactionExtra(const std::vector<uint8_t>& tx_extra, std::vector<TransactionExtraField>& tx_extra_fields);
bool writeTransactionExtra(std::vector<uint8_t>& tx_extra, const std::vector<TransactionExtraField>& tx_extra_fields);

Crypto::PublicKey getTransactionPublicKeyFromExtra(const std::vector<uint8_t>& tx_extra);
bool addTransactionPublicKeyToExtra(std::vector<uint8_t>& tx_extra, const Crypto::PublicKey& tx_pub_key);
bool addExtraNonceToTransactionExtra(std::vector<uint8_t>& tx_extra, const BinaryArray& extra_nonce);
void setPaymentIdToTransactionExtraNonce(BinaryArray& extra_nonce, const Crypto::Hash& payment_id);
bool getPaymentIdFromTransactionExtraNonce(const BinaryArray& extra_nonce, Crypto::Hash& payment_id);
bool appendMergeMiningTagToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraMergeMiningTag& mm_tag);
bool append_message_to_extra(std::vector<uint8_t>& tx_extra, const tx_extra_message& message);
std::vector<std::string> get_messages_from_extra(const std::vector<uint8_t>& extra, const Crypto::PublicKey &txkey, const Crypto::SecretKey *recepient_secret_key);
void appendTTLToExtra(std::vector<uint8_t>& tx_extra, uint64_t ttl);
bool getMergeMiningTagFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraMergeMiningTag& mm_tag);

bool createTxExtraWithPaymentId(const std::string& paymentIdString, std::vector<uint8_t>& extra);
//returns false if payment id is not found or parse error
bool getPaymentIdFromTxExtra(const std::vector<uint8_t>& extra, Crypto::Hash& paymentId);
bool parsePaymentId(const std::string& paymentIdString, Crypto::Hash& paymentId);

// HEAT commitment helper functions
bool createTxExtraWithHeatCommitment(const Crypto::Hash& commitment, uint64_t amount, const std::vector<uint8_t>& metadata, std::vector<uint8_t>& extra);
bool addHeatCommitmentToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraHeatCommitment& commitment);
bool getHeatCommitmentFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraHeatCommitment& commitment);

// Yield commitment helper functions
bool createTxExtraWithYieldCommitment(const Crypto::Hash& commitment, uint64_t amount, uint32_t term_months, const std::string& yield_scheme, const std::vector<uint8_t>& metadata, std::vector<uint8_t>& extra);
bool addYieldCommitmentToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraYieldCommitment& commitment);
bool getYieldCommitmentFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraYieldCommitment& commitment);

}
