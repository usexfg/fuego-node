// Copyright (c) 2026 Fuego Developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. You can redistribute it and/or modify it under the terms
// of the GNU General Public License v3 or later versions as published
// by the Free Software Foundation.
// You should have received a copy of the GNU General Public License
// along with Fuego. If not, see <https://www.gnu.org/licenses/>.

#pragma once

#include <map>
#include <vector>

#include <boost/functional/hash.hpp>

#include "../../include/CryptoNote.h"
#include "OrderbookTypes.h"

namespace CryptoNote {

struct HashLess {
  bool operator()(const Crypto::Hash& a, const Crypto::Hash& b) const {
    return memcmp(a.data, b.data, sizeof(a.data)) < 0;
  }
};

struct HashHasher {
  size_t operator()(const Crypto::Hash& h) const {
    return boost::hash_range(h.data, h.data + sizeof(h.data));
  }
};

struct HashEqual {
  bool operator()(const Crypto::Hash& a, const Crypto::Hash& b) const {
    return memcmp(a.data, b.data, sizeof(a.data)) == 0;
  }
};

struct OrderEntry {
  Crypto::Hash orderId;
  uint8_t  side;
  uint64_t price;
  uint64_t amount;
  uint64_t targetPrice;
  uint32_t expiration;
  Crypto::Hash addressHash; // cn_fast_hash(spendKey||viewKey)
  uint32_t blockHeight;
};

class OrderbookIndex {
public:
  OrderbookIndex() {}
  explicit OrderbookIndex(uint32_t maxOrdersPerBlock, uint32_t maxOrdersPerSender)
    : m_maxOrdersPerBlock(maxOrdersPerBlock), m_maxOrdersPerSender(maxOrdersPerSender) {}

  // Dynamic limits derived from current block size.
  // ~400 bytes per order → block_size/400 orders max; per-sender = 1/20 of that.
  explicit OrderbookIndex(uint64_t blockSizeBytes)
    : m_maxOrdersPerBlock(std::max<uint32_t>(50, static_cast<uint32_t>(blockSizeBytes / 400))),
      m_maxOrdersPerSender(std::max<uint32_t>(5, m_maxOrdersPerBlock / 20)) {}

  void addOrder(const OrderEntry& entry);
  void removeOrder(const Crypto::Hash& orderId);
  size_t removeOutOfBandOrders();

  const std::map<uint64_t, std::vector<OrderEntry>, std::greater<uint64_t>>& getBidCurve() const { return m_bidCurve; }
  const std::map<uint64_t, std::vector<OrderEntry>>& getAskCurve() const { return m_askCurve; }

  uint64_t getBidLevelDepth(uint64_t price) const {
    auto it = m_bidLevelDepths.find(price);
    return (it != m_bidLevelDepths.end()) ? it->second : 0;
  }
  uint64_t getAskLevelDepth(uint64_t price) const {
    auto it = m_askLevelDepths.find(price);
    return (it != m_askLevelDepths.end()) ? it->second : 0;
  }

  uint32_t getSenderOpenOrderCount(const SenderKey& sender) const;
  size_t getTotalOpenOrders() const { return m_bidCount + m_askCount; }
  uint32_t getMaxOrdersPerBlock() const { return m_maxOrdersPerBlock; }

  bool canPlaceOrder(const SenderKey& sender) const;

  void clear();

private:
  std::map<uint64_t, std::vector<OrderEntry>, std::greater<uint64_t>> m_bidCurve;
  std::map<uint64_t, std::vector<OrderEntry>> m_askCurve;
  std::map<uint64_t, uint64_t, std::greater<uint64_t>> m_bidLevelDepths;
  std::map<uint64_t, uint64_t> m_askLevelDepths;
  std::map<SenderKey, uint32_t> m_perSenderCount;
  std::map<Crypto::Hash, uint64_t, HashLess> m_orderIdToPrice;
  std::map<Crypto::Hash, uint8_t, HashLess> m_orderIdToSide;

  size_t m_bidCount = 0;
  size_t m_askCount = 0;

  uint32_t m_maxOrdersPerBlock = 1000;
  uint32_t m_maxOrdersPerSender = 50;
};

} // namespace CryptoNote
