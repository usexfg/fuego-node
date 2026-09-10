// Copyright (c) 2026 Fuego Developers
//
// Per-block call auction: deterministic max-volume clearing price with
// price-time priority and tie-breaks (volume → imbalance → prev-price
// proximity → lower price). Integer math only.

#include "OrderbookAuction.h"
#include "CryptoNoteConfig.h"
#include "Common/Int128.h"

#include <algorithm>
#include <map>
#include <cstring>

namespace CryptoNote {

// Pool-generated order ids are stamped with this prefix by generatePoolOrders().
const uint8_t POOL_ORDER_ID_PREFIX = 0xF0;

namespace {

bool lessByHash(const Crypto::Hash& a, const Crypto::Hash& b) {
  return memcmp(a.data, b.data, sizeof(a.data)) < 0;
}

// Price-time priority: better price first, then earlier deposit, then
// orderId as the deterministic final tie-break.
bool bidBefore(const AuctionOrder& a, const AuctionOrder& b) {
  if (a.price != b.price) return a.price > b.price;
  if (a.createdHeight != b.createdHeight) return a.createdHeight < b.createdHeight;
  return lessByHash(a.orderId, b.orderId);
}

bool askBefore(const AuctionOrder& a, const AuctionOrder& b) {
  if (a.price != b.price) return a.price < b.price;
  if (a.createdHeight != b.createdHeight) return a.createdHeight < b.createdHeight;
  return lessByHash(a.orderId, b.orderId);
}

bool laterOrder(const AuctionOrder& a, const AuctionOrder& b) {
  // "Later" for self-trade exclusion: higher height; ties by hash order.
  if (a.createdHeight != b.createdHeight) return a.createdHeight > b.createdHeight;
  return lessByHash(b.orderId, a.orderId);
}

} // anonymous namespace

AuctionResult runAuction(const std::vector<AuctionOrder>& bidsIn,
                         const std::vector<AuctionOrder>& asksIn,
                         uint64_t prevPclear) {
  AuctionResult result;

  if (bidsIn.empty() || asksIn.empty()) return result;

  // Self-trade exclusion: an addressHash may participate on ONE side only.
  // For any hash present on both sides, drop all its orders on the side of
  // its latest order (deterministic).
  std::vector<AuctionOrder> bids, asks;
  {
    // Per-hash: track latest order and which side it is on.
    struct HashState {
      bool has = false;
      AuctionOrder latest;
      bool latestIsAsk = false;
    };
    // Keyed lookup rather than a linear scan: this pass runs every block over
    // attacker-influenceable mempool input, and scanning made it quadratic in
    // order count. Only ever looked up by key, so ordering does not affect the
    // outcome; HashCmp keeps the container itself deterministic regardless.
    struct HashCmp {
      bool operator()(const Crypto::Hash& a, const Crypto::Hash& b) const {
        return lessByHash(a, b);
      }
    };
    std::map<Crypto::Hash, HashState, HashCmp> states;
    auto findState = [&](const Crypto::Hash& h) -> HashState& {
      return states[h];
    };
    // Pool orders are the protocol's own two-sided quotes, not a user trading
    // against themselves: they share one zeroed addressHash by construction.
    auto isPool = [](const AuctionOrder& o) {
      return o.orderId.data[0] == POOL_ORDER_ID_PREFIX;
    };
    for (const auto& o : bidsIn) {
      if (isPool(o)) continue;
      auto& st = findState(o.addressHash);
      if (!st.has || laterOrder(o, st.latest)) { st.latest = o; st.latestIsAsk = false; st.has = true; }
    }
    for (const auto& o : asksIn) {
      if (isPool(o)) continue;
      auto& st = findState(o.addressHash);
      if (!st.has || laterOrder(o, st.latest)) { st.latest = o; st.latestIsAsk = true; st.has = true; }
    }
    auto keepsBids = [&](const Crypto::Hash& h) -> bool {
      auto it = states.find(h);
      return it == states.end() ? true : !it->second.latestIsAsk;
    };
    auto keepsAsks = [&](const Crypto::Hash& h) -> bool {
      auto it = states.find(h);
      return it == states.end() ? true : it->second.latestIsAsk;
    };
    for (const auto& o : bidsIn) if (isPool(o) || keepsBids(o.addressHash)) bids.push_back(o);
    for (const auto& o : asksIn) if (isPool(o) || keepsAsks(o.addressHash)) asks.push_back(o);
    if (bids.empty() || asks.empty()) return result;
  }

  std::sort(bids.begin(), bids.end(), bidBefore);
  std::sort(asks.begin(), asks.end(), askBefore);

  // Candidate prices: every distinct bid price and ask price where crossing
  // is possible (best bid >= best ask).
  if (bids.front().price < asks.front().price) return result;

  std::vector<uint64_t> bidPrices, askPrices;
  for (const auto& o : bids) if (bidPrices.empty() || bidPrices.back() != o.price) bidPrices.push_back(o.price);
  for (const auto& o : asks) if (askPrices.empty() || askPrices.back() != o.price) askPrices.push_back(o.price);

  // Prefix volumes.
  std::vector<uint64_t> bidCum(bids.size() + 1, 0), askCum(asks.size() + 1, 0);
  for (size_t i = 0; i < bids.size(); ++i) bidCum[i + 1] = bidCum[i] + bids[i].volumeXfg;
  for (size_t i = 0; i < asks.size(); ++i) askCum[i + 1] = askCum[i] + asks[i].volumeXfg;

  auto bidVolAt = [&](uint64_t p) -> uint64_t {
    // bids sorted desc; count bids with price >= p
    size_t lo = 0, hi = bids.size();
    while (lo < hi) {
      size_t mid = (lo + hi) / 2;
      if (bids[mid].price >= p) lo = mid + 1; else hi = mid;
    }
    return bidCum[lo];
  };
  auto askVolAt = [&](uint64_t p) -> uint64_t {
    // asks sorted asc; count asks with price <= p
    size_t lo = 0, hi = asks.size();
    while (lo < hi) {
      size_t mid = (lo + hi) / 2;
      if (asks[mid].price <= p) lo = mid + 1; else hi = mid;
    }
    return askCum[lo];
  };

  uint64_t bestP = 0, bestVol = 0, bestImbalance = UINT64_MAX;
  uint64_t bestDist = UINT64_MAX;
  std::vector<uint64_t> candidates = bidPrices;
  candidates.insert(candidates.end(), askPrices.begin(), askPrices.end());
  std::sort(candidates.begin(), candidates.end());
  candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());

  for (uint64_t p : candidates) {
    uint64_t bv = bidVolAt(p);
    uint64_t av = askVolAt(p);
    if (bv == 0 || av == 0) continue;
    uint64_t vol = bv < av ? bv : av;
    uint64_t imb = bv > av ? bv - av : av - bv;
    // Unsigned distance: prices are full-width uint64, so signed casts are
    // implementation-defined and INT64_MIN negation is UB.
    uint64_t dist = p > prevPclear ? p - prevPclear : prevPclear - p;
    bool better = (vol > bestVol) ||
                  (vol == bestVol && imb < bestImbalance) ||
                  (vol == bestVol && imb == bestImbalance && dist < bestDist) ||
                  (vol == bestVol && imb == bestImbalance && dist == bestDist && p < bestP);
    if (better) {
      bestP = p; bestVol = vol; bestImbalance = imb; bestDist = dist;
    }
  }

  if (bestP == 0 || bestVol == 0) return result;

  result.crossed = true;
  result.clearingPrice = bestP;
  result.matchedVolume = bestVol;

  // Taker = the rationed side (aggregate eligible volume exceeded matched
  // volume). Exact tie → no taker, no fee, no rebate (pure exchange).
  {
    uint64_t bidVol = bidVolAt(bestP);
    uint64_t askVol = askVolAt(bestP);
    if (bidVol > bestVol) { result.takerIsBid = true; result.hasTaker = true; }
    else if (askVol > bestVol) { result.takerIsBid = false; result.hasTaker = true; }
  }

  // Settlement: both sides ration in price-time priority up to matchedVolume.
  // A side whose aggregate eligible volume exceeds matchedVolume rations at
  // EVERY eligible level (never "fill fully" shortcuts — that over-fills when
  // the winning price is the other side's).
  //
  // Heat per fill uses CUMULATIVE floors per side so both sides sum to
  // exactly floor(matchedVolume × p*/COIN) — no cross-side rounding drift.
  auto heatCum = [&](uint64_t cumXfg) {
    return static_cast<uint64_t>(((uint128_t)cumXfg * bestP) / parameters::COIN);
  };

  // Bid fills: eligible = price >= p*; priority = price desc, time asc.
  {
    uint64_t remaining = bestVol;
    uint64_t cumXfg = 0;
    for (const auto& o : bids) {
      if (o.price < bestP) break;
      if (remaining == 0) break;
      uint64_t fill = std::min(o.volumeXfg, remaining);
      remaining -= fill;
      uint64_t prevCum = cumXfg;
      cumXfg += fill;
      uint64_t heat = heatCum(cumXfg) - heatCum(prevCum);
      result.fills.push_back({o.orderId, 0, fill, heat, 0, 0});
    }
  }
  // Ask fills: eligible = price <= p*; priority = price asc, time asc.
  {
    uint64_t remaining = bestVol;
    uint64_t cumXfg = 0;
    for (const auto& o : asks) {
      if (o.price > bestP) break;
      if (remaining == 0) break;
      uint64_t fill = std::min(o.volumeXfg, remaining);
      remaining -= fill;
      uint64_t prevCum = cumXfg;
      cumXfg += fill;
      uint64_t heat = heatCum(cumXfg) - heatCum(prevCum);
      result.fills.push_back({o.orderId, 1, fill, heat, 0, 0});
    }
  }

  // Fee assignment: the taker side pays the full 1% (70% → CD yield, 30% into
  // the rebate pool); the maker side receives the pool pro-rata by fill value.
  // Conservation: Σ fee = Σ cd + Σ reb (cumulative floors per side).
  if (result.hasTaker) {
    uint8_t takerSide = result.takerIsBid ? 0 : 1;
    auto feeCum = [&](uint64_t cumHeat) {
      return static_cast<uint64_t>(
          ((uint128_t)cumHeat * parameters::HEARTH_FEE_BPS) / parameters::HEARTH_FEE_DIVISOR);
    };
    uint64_t rebPool = 0;
    uint64_t takerCum = 0;
    for (auto& f : result.fills) {
      if (f.side != takerSide) continue;
      uint64_t prev = takerCum;
      takerCum += f.heat;
      uint64_t fee = feeCum(takerCum) - feeCum(prev);
      f.cdFeeHeat = static_cast<uint64_t>(
          ((uint128_t)fee * parameters::HEARTH_CD_SHARE_PCT) / 100);
      uint64_t reb = fee - f.cdFeeHeat;
      f.rebateHeat = reb;   // taker pays the rebate into the pool
      rebPool += reb;
    }
    uint64_t makerTotal = 0;
    for (const auto& f : result.fills) if (f.side != takerSide) makerTotal += f.heat;
    if (makerTotal > 0 && rebPool > 0) {
      uint64_t makerCum = 0;
      for (auto& f : result.fills) {
        if (f.side == takerSide) continue;
        uint64_t prev = makerCum;
        makerCum += f.heat;
        auto share = [&](uint64_t x) {
          return static_cast<uint64_t>(((uint128_t)rebPool * x) / makerTotal);
        };
        f.rebateHeat = share(makerCum) - share(prev);
      }
    }
  }

  return result;
}

} // namespace CryptoNote
