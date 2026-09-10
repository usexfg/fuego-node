// Copyright (c) 2026 Fuego Developers
//
// Per-block call auction over tx-extra-backed limit deposits.
// Matches user-vs-user at a single clearing price that maximizes executed
// volume (exchange opening-auction rules), with deterministic tie-breaks,
// price-time priority, and same-key self-trade exclusion. Pure integer math;
// no pool involvement — price discovery comes from the crossing of committed
// orders, not from the AMM ratio.

#pragma once

#include <cstdint>
#include <vector>
#include "crypto/hash.h"

namespace CryptoNote {

struct AuctionOrder {
  Crypto::Hash orderId;
  uint64_t price;        // canonical: HEAT atomics per XFG atomic × COIN
  uint64_t volumeXfg;    // XFG atomics
  uint32_t createdHeight;
  Crypto::Hash addressHash;
};

struct AuctionFill {
  Crypto::Hash orderId;
  uint8_t side;      // 0 = bid (BUY_XFG), 1 = ask (SELL_XFG)
  uint64_t fillXfg;  // XFG atomics exchanged
  uint64_t heat;     // fillXfg × clearingPrice / COIN (price value of the fill)
  uint64_t cdFeeHeat = 0;   // taker fills: 70% of the 1% fee → CD yield (HEAT)
  uint64_t rebateHeat = 0;  // maker fills: 30% of the 1% fee → maker rebate (HEAT)
};

struct AuctionResult {
  bool crossed = false;
  uint64_t clearingPrice = 0;
  uint64_t matchedVolume = 0;
  bool takerIsBid = false;   // which side was rationed (paid the fee); false on exact tie
  bool hasTaker = false;
  std::vector<AuctionFill> fills;
};


// Bids (BUY_XFG) sorted price-desc; asks (SELL_XFG) sorted price-asc.
// prevPclear: last block's clearing price, used only for tie-breaks.
// Pool-generated orders (0xF0 id prefix) all carry the same zeroed addressHash,
// so they are exempt from self-trade exclusion: without that, the two-sided
// market maker reads as one party and a whole side is dropped.
AuctionResult runAuction(const std::vector<AuctionOrder>& bids,
                         const std::vector<AuctionOrder>& asks,
                         uint64_t prevPclear);

} // namespace CryptoNote
