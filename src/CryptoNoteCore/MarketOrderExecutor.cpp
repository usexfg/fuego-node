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

#include "MarketOrderExecutor.h"
#include "../Common/Int128.h"
#include "CryptoNoteConfig.h"

#include <algorithm>

namespace CryptoNote {

MarketOrderExecutor::MarketOrderExecutor(uint32_t maxPriceDeviationPct)
  : m_maxPriceDeviationPct(maxPriceDeviationPct) {}

uint64_t MarketOrderExecutor::computeMaxPrice(uint64_t P_clear, bool buying) const {
  if (buying) {
    return P_clear + static_cast<uint64_t>((static_cast<uint128_t>(P_clear) * m_maxPriceDeviationPct) / 100);
  } else {
    uint64_t reduction = static_cast<uint64_t>((static_cast<uint128_t>(P_clear) * m_maxPriceDeviationPct) / 100);
    if (reduction >= P_clear) return 1;
    return P_clear - reduction;
  }
}

MarketOrderExecutor::CascadeState MarketOrderExecutor::cascadeIntoOrderbook(
    uint64_t remaining,
    uint64_t P_clear,
    OrderbookIndex& orderbook,
    bool isBuy) {

  CascadeState state = {0, 0, 0, 0, false};
  if (remaining == 0) return state;

  uint64_t maxPrice = computeMaxPrice(P_clear, isBuy);

  if (isBuy) {
    const auto& askCurve = orderbook.getAskCurve();
    for (auto it = askCurve.begin(); it != askCurve.end() && remaining > 0; ++it) {
      uint64_t askPrice = it->first;
      if (askPrice > maxPrice) {
        state.halted = true;
        break;
      }

      uint64_t levelDepth = orderbook.getAskLevelDepth(askPrice);

      uint64_t takeAmount = std::min(remaining, levelDepth);
      uint64_t cost = static_cast<uint64_t>((static_cast<uint128_t>(takeAmount) * askPrice) / parameters::COIN);
      state.filled += takeAmount;
      state.cost += cost;
      state.peakPrice = std::max(state.peakPrice, askPrice);
      state.levels++;
      remaining -= takeAmount;
    }
  } else {
    const auto& bidCurve = orderbook.getBidCurve();
    for (auto it = bidCurve.begin(); it != bidCurve.end() && remaining > 0; ++it) {
      uint64_t bidPrice = it->first;
      if (bidPrice < maxPrice) {
        state.halted = true;
        break;
      }

      uint64_t levelDepth = orderbook.getBidLevelDepth(bidPrice);

      uint64_t takeAmount = std::min(remaining, levelDepth);
      uint64_t cost = static_cast<uint64_t>((static_cast<uint128_t>(takeAmount) * bidPrice) / parameters::COIN);
      state.filled += takeAmount;
      state.cost += cost;
      state.peakPrice = std::max(state.peakPrice, bidPrice);
      state.levels++;
      remaining -= takeAmount;
    }
  }

  return state;
}

MarketOrderResult MarketOrderExecutor::executeMarketBuy(
    uint64_t xfgWanted,
    uint64_t maxHeatCost,
    uint64_t P_clear,
    OrderbookIndex& orderbook) {

  MarketOrderResult result = {0, 0, 0, 0, false};
  if (xfgWanted == 0) return result;

  CascadeState cascade = cascadeIntoOrderbook(xfgWanted, P_clear, orderbook, true);
  if (cascade.cost <= maxHeatCost || maxHeatCost == 0) {
    result.filledAmount = cascade.filled;
    result.totalCost = cascade.cost;
    result.levelsConsumed = cascade.levels;
    result.halted = cascade.halted;
    result.maxPriceDeviation = cascade.peakPrice;
  }

  return result;
}

MarketOrderResult MarketOrderExecutor::executeMarketSell(
    uint64_t xfgToSell,
    uint64_t minHeatReceive,
    uint64_t P_clear,
    OrderbookIndex& orderbook) {

  MarketOrderResult result = {0, 0, 0, 0, false};
  if (xfgToSell == 0) return result;

  CascadeState cascade = cascadeIntoOrderbook(xfgToSell, P_clear, orderbook, false);
  if (cascade.cost >= minHeatReceive || minHeatReceive == 0) {
    result.filledAmount = cascade.filled;
    result.totalCost = cascade.cost;
    result.levelsConsumed = cascade.levels;
    result.halted = cascade.halted;
    result.maxPriceDeviation = cascade.peakPrice;
  }

  return result;
}

} // namespace CryptoNote
