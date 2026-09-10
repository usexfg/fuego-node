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

#include "OrderbookMatcher.h"

#include "../Common/Int128.h"
#include <algorithm>
#include <set>
#include <cstring>

namespace CryptoNote {

namespace {

  bool isNonNullHash(const Crypto::Hash& h) {
    static const Crypto::Hash zero{};
    return memcmp(&h, &zero, sizeof(Crypto::Hash)) != 0;
  }

}

void OrderbookMatcher::expireOrders(OrderbookIndex& index, uint32_t currentBlockHeight,
                                     std::vector<RemainderRecord>& remainders) {
  for (const auto& [price, entries] : index.getBidCurve()) {
    for (const auto& entry : entries) {
      if (entry.expiration > 0 && currentBlockHeight >= entry.expiration) {
        RemainderRecord r;
        r.orderId = entry.orderId;
        r.remainingAmount = entry.amount;
        r.addressHash = entry.addressHash;
        r.price = entry.price;
        r.side = entry.side;
        r.expiration = entry.expiration;
        remainders.push_back(r);
      }
    }
  }
  for (const auto& [price, entries] : index.getAskCurve()) {
    for (const auto& entry : entries) {
      if (entry.expiration > 0 && currentBlockHeight >= entry.expiration) {
        RemainderRecord r;
        r.orderId = entry.orderId;
        r.remainingAmount = entry.amount;
        r.addressHash = entry.addressHash;
        r.price = entry.price;
        r.side = entry.side;
        r.expiration = entry.expiration;
        remainders.push_back(r);
      }
    }
  }
  for (const auto& r : remainders) {
    index.removeOrder(r.orderId);
  }
}

uint32_t OrderbookMatcher::countDistinctParties(const std::vector<FillRecord>& fills,
                                                  const OrderbookIndex& /*index*/) {
  std::set<Crypto::Hash, HashLess> parties;
  for (const auto& fill : fills) {
    if (isNonNullHash(fill.bidAddressHash)) {
      parties.insert(fill.bidAddressHash);
    }
    if (isNonNullHash(fill.askAddressHash)) {
      parties.insert(fill.askAddressHash);
    }
  }
  return static_cast<uint32_t>(parties.size());
}

MatchResult OrderbookMatcher::match(OrderbookIndex& index, uint64_t prevPclear,
                                     uint32_t currentBlockHeight) {
  MatchResult result;
  result.P_clear = prevPclear;
  result.clearingValid = false;

  expireOrders(index, currentBlockHeight, result.remainders);

  // Phase 1 — collect all overlapping candidate matches without removing from index.
  // Phase 2 will handle UTXO destruction/creation for actual settlement.

  struct CandidateMatch {
    Crypto::Hash bidOrderId;
    Crypto::Hash askOrderId;
    uint64_t bidPrice;
    uint64_t askPrice;
    uint64_t matchAmount;
    uint64_t bidRemaining;
    uint64_t askRemaining;
    OrderEntry bidEntry;
    OrderEntry askEntry;
  };

  std::vector<CandidateMatch> candidates;
  size_t ordersProcessed = 0;
  size_t numSettled = 0;    // tracks fills that survive P_clear filter
  uint64_t totalMatchedVolume = 0;
  // Prices are COIN-scaled (HEAT atomics per XFG atomic x COIN), not Q64.64:
  // accumulate the full 128-bit product and divide once at the end.
  uint128_t volumeTimesPrice = 0;

  // Build mutable copies of curves
  auto bidCurve = index.getBidCurve();
  auto askCurve = index.getAskCurve();

  if (bidCurve.empty() || askCurve.empty())
    return result;

  auto bidIt = bidCurve.begin();
  auto askIt = askCurve.begin();

  while (bidIt != bidCurve.end() && askIt != askCurve.end()) {
    uint64_t bidPrice = bidIt->first;
    uint64_t askPrice = askIt->first;

    if (bidPrice < askPrice)
      break;

    auto& bidEntries = bidIt->second;
    auto& askEntries = askIt->second;
    size_t bi = 0, ai = 0;

    while (bi < bidEntries.size() && ai < askEntries.size() &&
           numSettled < static_cast<size_t>(m_maxOrdersPerBlock)) {
      OrderEntry& bid = bidEntries[bi];
      OrderEntry& ask = askEntries[ai];

      uint64_t matchAmount = std::min(bid.amount, ask.amount);

      CandidateMatch cm;
      cm.bidOrderId = bid.orderId;
      cm.askOrderId = ask.orderId;
      cm.bidPrice = bidPrice;
      cm.askPrice = askPrice;
      cm.matchAmount = matchAmount;
      cm.bidRemaining = bid.amount - matchAmount;
      cm.askRemaining = ask.amount - matchAmount;
      cm.bidEntry = bid;
      cm.askEntry = ask;
      candidates.push_back(cm);

      volumeTimesPrice += static_cast<uint128_t>(matchAmount) * askPrice;
      totalMatchedVolume += matchAmount;
      ordersProcessed++;

      bid.amount -= matchAmount;
      ask.amount -= matchAmount;

      if (bid.amount == 0) bi++;
      if (ask.amount == 0) ai++;
    }

    if (bi >= bidEntries.size()) bidIt++;
    if (ai >= askEntries.size()) askIt++;

    if (numSettled >= static_cast<size_t>(m_maxOrdersPerBlock))
      break;
  }

  if (totalMatchedVolume == 0)
    return result;

  result.P_clear = static_cast<uint64_t>(volumeTimesPrice / totalMatchedVolume);

  // Filter: only keep fills where P_clear is favorable
  for (auto& cm : candidates) {
    // ask price must be <= P_clear for seller to receive favorable price
    if (cm.askPrice > result.P_clear) {
      // Ask is unfavorable — exclude. Both bid and ask remainders go back.
      RemainderRecord br;
      br.orderId = cm.bidOrderId;
      br.remainingAmount = cm.matchAmount + cm.bidRemaining;
      br.addressHash = cm.bidEntry.addressHash;
      br.price = cm.bidPrice;
      br.side = 0;
      br.expiration = cm.bidEntry.expiration;
      result.remainders.push_back(br);

      RemainderRecord ar;
      ar.orderId = cm.askOrderId;
      ar.remainingAmount = cm.matchAmount + cm.askRemaining;
      ar.addressHash = cm.askEntry.addressHash;
      ar.price = cm.askPrice;
      ar.side = 1;
      ar.expiration = cm.askEntry.expiration;
      result.remainders.push_back(ar);
      continue;
    }

    FillRecord fill;
    fill.bidOrderId = cm.bidOrderId;
    fill.askOrderId = cm.askOrderId;
    fill.bidAddressHash = cm.bidEntry.addressHash;
    fill.askAddressHash = cm.askEntry.addressHash;
    fill.amount = cm.matchAmount;
    fill.price = cm.askPrice;
    result.fills.push_back(fill);
    result.numMatches++;
    numSettled++;

    // Remove matched orders from index
    index.removeOrder(cm.bidOrderId);
    index.removeOrder(cm.askOrderId);

    // Create remainders for partially filled orders
    if (cm.bidRemaining > 0) {
      RemainderRecord r;
      r.orderId = cm.bidOrderId;
      r.remainingAmount = cm.bidRemaining;
      r.addressHash = cm.bidEntry.addressHash;
      r.price = cm.bidPrice;
      r.side = 0;
      r.expiration = cm.bidEntry.expiration;
      result.remainders.push_back(r);
    }
    if (cm.askRemaining > 0) {
      RemainderRecord r;
      r.orderId = cm.askOrderId;
      r.remainingAmount = cm.askRemaining;
      r.addressHash = cm.askEntry.addressHash;
      r.price = cm.askPrice;
      r.side = 1;
      r.expiration = cm.askEntry.expiration;
      result.remainders.push_back(r);
    }
  }

  if (!result.fills.empty()) {
    // Recompute P_clear from actual fills (excluding unfavorable)
    uint64_t actualVolume = 0;
    uint128_t actualVxP = 0;
    for (const auto& fill : result.fills) {
      actualVolume += fill.amount;
      actualVxP += static_cast<uint128_t>(fill.amount) * fill.price;
    }
    if (actualVolume > 0)
      result.P_clear = static_cast<uint64_t>(actualVxP / actualVolume);

    result.numDistinctParties = countDistinctParties(result.fills, index);
    if (result.numDistinctParties >= m_minDistinctParties) {
      result.clearingValid = true;
    }
  }

  return result;
}

} // namespace CryptoNote
