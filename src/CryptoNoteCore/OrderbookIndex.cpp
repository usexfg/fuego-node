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

#include "OrderbookIndex.h"
#include <algorithm>
#include <algorithm>

namespace CryptoNote {

void OrderbookIndex::addOrder(const OrderEntry& entry) {
  if (entry.side == 0) {
    m_bidCurve[entry.price].push_back(entry);
    m_bidLevelDepths[entry.price] += entry.amount;
    m_orderIdToSide[entry.orderId] = 0;
    m_bidCount++;
  } else {
    m_askCurve[entry.price].push_back(entry);
    m_askLevelDepths[entry.price] += entry.amount;
    m_orderIdToSide[entry.orderId] = 1;
    m_askCount++;
  }
  m_orderIdToPrice[entry.orderId] = entry.price;

  SenderKey sender{entry.addressHash};
  m_perSenderCount[sender]++;
}

void OrderbookIndex::removeOrder(const Crypto::Hash& orderId) {
  auto priceIt = m_orderIdToPrice.find(orderId);
  if (priceIt == m_orderIdToPrice.end())
    return;

  auto sideIt = m_orderIdToSide.find(orderId);
  if (sideIt == m_orderIdToSide.end())
    return;

  uint64_t price = priceIt->second;
  uint8_t side = sideIt->second;

  std::vector<OrderEntry>* curve = nullptr;
  std::map<uint64_t, uint64_t, std::greater<uint64_t>>* depthMapBi = nullptr;
  std::map<uint64_t, uint64_t>* depthMapAs = nullptr;
  if (side == 0) {
    auto it = m_bidCurve.find(price);
    if (it != m_bidCurve.end()) curve = &it->second;
    depthMapBi = &m_bidLevelDepths;
    m_bidCount--;
  } else {
    auto it = m_askCurve.find(price);
    if (it != m_askCurve.end()) curve = &it->second;
    depthMapAs = &m_askLevelDepths;
    m_askCount--;
  }

  if (curve) {
    for (auto it = curve->begin(); it != curve->end(); ++it) {
      if (memcmp(it->orderId.data, orderId.data, sizeof(orderId.data)) == 0) {
        SenderKey sender{it->addressHash};
        auto sc = m_perSenderCount.find(sender);
        if (sc != m_perSenderCount.end()) {
          if (sc->second <= 1) m_perSenderCount.erase(sc);
          else sc->second--;
        }
        if (depthMapBi) {
          auto& d = (*depthMapBi)[price];
          if (d >= it->amount) d -= it->amount;
          else d = 0;
        } else if (depthMapAs) {
          auto& d = (*depthMapAs)[price];
          if (d >= it->amount) d -= it->amount;
          else d = 0;
        }
        curve->erase(it);
        break;
      }
    }
  }

  m_orderIdToPrice.erase(priceIt);
  m_orderIdToSide.erase(sideIt);
}

uint32_t OrderbookIndex::getSenderOpenOrderCount(const SenderKey& sender) const {
  auto it = m_perSenderCount.find(sender);
  return (it != m_perSenderCount.end()) ? it->second : 0;
}

bool OrderbookIndex::canPlaceOrder(const SenderKey& sender) const {
  return getSenderOpenOrderCount(sender) < m_maxOrdersPerSender;
}

void OrderbookIndex::clear() {
  m_bidCurve.clear();
  m_askCurve.clear();
  m_bidLevelDepths.clear();
  m_askLevelDepths.clear();
  m_perSenderCount.clear();
  m_orderIdToPrice.clear();
  m_orderIdToSide.clear();
  m_bidCount = 0;
  m_askCount = 0;
}

size_t OrderbookIndex::removeOutOfBandOrders() {
  size_t removed = 0;

  // Remove from bids
  for (auto it = m_bidCurve.begin(); it != m_bidCurve.end(); ) {
    auto& vec = it->second;
    size_t before = vec.size();
    vec.erase(std::remove_if(vec.begin(), vec.end(), [&](const OrderEntry& e) {
      if (e.targetPrice != 0) {
        SenderKey sender{e.addressHash};
        auto sc = m_perSenderCount.find(sender);
        if (sc != m_perSenderCount.end()) {
          if (sc->second <= 1) m_perSenderCount.erase(sc);
          else sc->second--;
        }
        m_orderIdToPrice.erase(e.orderId);
        m_orderIdToSide.erase(e.orderId);
        return true;
      }
      return false;
    }), vec.end());
    removed += before - vec.size();
    if (vec.empty()) it = m_bidCurve.erase(it);
    else ++it;
  }

  // Remove from asks
  for (auto it = m_askCurve.begin(); it != m_askCurve.end(); ) {
    auto& vec = it->second;
    size_t before = vec.size();
    vec.erase(std::remove_if(vec.begin(), vec.end(), [&](const OrderEntry& e) {
      if (e.targetPrice != 0) {
        SenderKey sender{e.addressHash};
        auto sc = m_perSenderCount.find(sender);
        if (sc != m_perSenderCount.end()) {
          if (sc->second <= 1) m_perSenderCount.erase(sc);
          else sc->second--;
        }
        m_orderIdToPrice.erase(e.orderId);
        m_orderIdToSide.erase(e.orderId);
        return true;
      }
      return false;
    }), vec.end());
    removed += before - vec.size();
    if (vec.empty()) it = m_askCurve.erase(it);
    else ++it;
  }

  // Recount for accuracy after bulk removal
  m_bidCount = 0;
  m_bidLevelDepths.clear();
  for (const auto& lvl : m_bidCurve) {
    m_bidCount += lvl.second.size();
    for (const auto& e : lvl.second) m_bidLevelDepths[lvl.first] += e.amount;
  }
  m_askCount = 0;
  m_askLevelDepths.clear();
  for (const auto& lvl : m_askCurve) {
    m_askCount += lvl.second.size();
    for (const auto& e : lvl.second) m_askLevelDepths[lvl.first] += e.amount;
  }

  return removed;
}

} // namespace CryptoNote
