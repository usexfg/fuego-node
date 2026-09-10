// Copyright (c) 2026 Fuego Developers
//
// Unit tests for the per-block call auction (OrderbookAuction).

#include "CryptoNoteCore/OrderbookAuction.h"
#include "CryptoNoteConfig.h"
#include "Common/Int128.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace CryptoNote;

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
  tests_run++; \
  if (!(name)) { \
    fprintf(stderr, "FAIL: %s (%s:%d)\n", #name, __FILE__, __LINE__); \
  } else { \
    tests_passed++; \
  } \
} while(0)

static Crypto::Hash makeHash(uint8_t v) {
  Crypto::Hash h;
  memset(h.data, v, sizeof(h.data));
  return h;
}

static AuctionOrder bid(uint8_t id, uint64_t price, uint64_t vol, uint32_t height, uint8_t hashByte = 0) {
  AuctionOrder o;
  o.orderId = makeHash(id);
  o.price = price;
  o.volumeXfg = vol;
  o.createdHeight = height;
  o.addressHash = makeHash(hashByte);
  return o;
}

static AuctionOrder ask(uint8_t id, uint64_t price, uint64_t vol, uint32_t height, uint8_t hashByte = 0) {
  return bid(id, price, vol, height, hashByte);
}

static uint64_t P = parameters::COIN; // price unit (1 HEAT per XFG × COIN)

void testNoCrossing() {
  std::vector<AuctionOrder> bids = { bid(1, 2 * P, 100, 10, 1) };
  std::vector<AuctionOrder> asks = { ask(2, 3 * P, 100, 10, 2) };
  AuctionResult r = runAuction(bids, asks, P);
  TEST(!r.crossed);
  TEST(r.matchedVolume == 0);
}

void testBasicCrossingMaxVolume() {
  // Bids: 3.0×100, 2.0×100 ; Asks: 1.0×100, 2.5×50
  // bidVol(p): 1P→200, 2P→200, 2.5P→100, 3P→100
  // askVol(p): 1P→100, 2P→100, 2.5P→150, 3P→150
  // vol(p):    100,      100,      100,        100  (all tied)
  // imbalance: 100,      100,       50,         50  → 2.5P or 3P
  // prevPclear = 1P → closest is 2.5P.
  std::vector<AuctionOrder> bids = { bid(1, 3 * P, 100, 10, 1), bid(2, 2 * P, 100, 10, 2) };
  std::vector<AuctionOrder> asks = { ask(3, 1 * P, 100, 10, 3), ask(4, (uint64_t)(2.5 * P), 50, 10, 4) };
  AuctionResult r = runAuction(bids, asks, P);
  TEST(r.crossed);
  TEST(r.clearingPrice == (uint64_t)(2.5 * P));
  TEST(r.matchedVolume == 100);
  // Bid@3.0 fills 100 (only bid ≥ p*); ask@1.0 fills 100 (< p*), ask@2.5 unrationed (0).
  uint64_t bidFill = 0, askFill = 0;
  for (const auto& f : r.fills) {
    if (f.side == 0) bidFill += f.fillXfg; else askFill += f.fillXfg;
  }
  TEST(bidFill == 100);
  TEST(askFill == 100);
}

void testTimePriorityRationing() {
  // One price level on both sides; asks larger — bids fill fully, asks ration by time.
  std::vector<AuctionOrder> bids = { bid(1, 2 * P, 100, 10, 1) };
  std::vector<AuctionOrder> asks = { ask(2, 2 * P, 60, 20, 2), ask(3, 2 * P, 60, 30, 3) };
  AuctionResult r = runAuction(bids, asks, P);
  TEST(r.crossed);
  TEST(r.matchedVolume == 100);
  uint64_t earlyFill = 0, lateFill = 0;
  for (const auto& f : r.fills) {
    if (f.side != 1) continue;
    if (memcmp(f.orderId.data, makeHash(2).data, 32) == 0) earlyFill += f.fillXfg;
    else lateFill += f.fillXfg;
  }
  TEST(earlyFill == 60);   // older order (height 20) fills fully first
  TEST(lateFill == 40);    // remainder from the younger order
}

void testOverFillRegression() {
  // Regression for the rationing underflow: the winning price is an ASK price
  // with bid volume above it exceeding matchedVolume. Bids must ration.
  std::vector<AuctionOrder> bids = { bid(1, 100 * P, 90, 10, 1) };
  std::vector<AuctionOrder> asks = { ask(2, 40 * P, 50, 10, 2) };
  AuctionResult r = runAuction(bids, asks, 0);
  TEST(r.crossed);
  TEST(r.matchedVolume == 50);
  uint64_t bidFill = 0, askFill = 0;
  for (const auto& f : r.fills) {
    if (f.side == 0) bidFill += f.fillXfg; else askFill += f.fillXfg;
  }
  TEST(bidFill == 50);
  TEST(askFill == 50);

  // Mirror: winning price is a BID price, asks above it exceed matchedVolume.
  std::vector<AuctionOrder> bids2 = { bid(3, 200 * P, 50, 10, 3) };
  std::vector<AuctionOrder> asks2 = { ask(4, 100 * P, 90, 10, 4) };
  AuctionResult r2 = runAuction(bids2, asks2, 200 * P);
  TEST(r2.crossed);
  TEST(r2.matchedVolume == 50);
  uint64_t bidFill2 = 0, askFill2 = 0;
  for (const auto& f : r2.fills) {
    if (f.side == 0) bidFill2 += f.fillXfg; else askFill2 += f.fillXfg;
  }
  TEST(bidFill2 == 50);
  TEST(askFill2 == 50);
}

void testMaxVolumeSelection() {
  // Bids 3P×100, 2.5P×100 ; Asks 1P×100, 2P×200.
  // vol(p): 1P→100, 2P→200, 2.5P→200, 3P→100 → max 200 at {2P, 2.5P}
  // imbalance: 2P→100, 2.5P→100 → prevPclear=2P → 2P wins (dist 0).
  std::vector<AuctionOrder> bids = { bid(1, 3 * P, 100, 10, 1), bid(2, (uint64_t)(2.5 * P), 100, 10, 2) };
  std::vector<AuctionOrder> asks = { ask(3, 1 * P, 100, 10, 3), ask(4, 2 * P, 200, 10, 4) };
  AuctionResult r = runAuction(bids, asks, 2 * P);
  TEST(r.crossed);
  TEST(r.clearingPrice == 2 * P);
  TEST(r.matchedVolume == 200);
  uint64_t bidFill = 0, askFill = 0;
  for (const auto& f : r.fills) {
    if (f.side == 0) bidFill += f.fillXfg; else askFill += f.fillXfg;
  }
  TEST(bidFill == 200);
  TEST(askFill == 200);
}

void testTieBreakImbalanceThenPrice() {
  // Two candidate prices with equal volume; the less-imbalanced one wins.
  std::vector<AuctionOrder> bids = { bid(1, 2 * P, 100, 10, 1), bid(2, 3 * P, 100, 10, 2) };
  std::vector<AuctionOrder> asks = { ask(3, 1 * P, 100, 10, 3) };
  // p=1: bidVol=200, askVol=100 → vol 100, imb 100
  // p=2: bidVol=200, askVol=100 → vol 100, imb 100
  // p=3: bidVol=100, askVol=100 → vol 100, imb 0 ← wins
  AuctionResult r = runAuction(bids, asks, P);
  TEST(r.crossed);
  TEST(r.clearingPrice == 3 * P);
  TEST(r.matchedVolume == 100);
}

void testSelfTradeExclusion() {
  // Same addressHash on both sides — only the side of the LATEST order survives.
  std::vector<AuctionOrder> bids = { bid(1, 2 * P, 100, 10, 7) };   // hash 7, height 10
  std::vector<AuctionOrder> asks = { ask(2, 1 * P, 100, 20, 7) };   // hash 7, height 20 (later, ask side)
  AuctionResult r = runAuction(bids, asks, P);
  // Latest order is the ask → the hash keeps ONLY asks → no bids → no crossing.
  TEST(!r.crossed);

  // Reverse: latest is the bid → keeps bids only → no crossing.
  std::vector<AuctionOrder> bids2 = { bid(3, 2 * P, 100, 30, 8) };
  std::vector<AuctionOrder> asks2 = { ask(4, 1 * P, 100, 20, 8) };
  AuctionResult r2 = runAuction(bids2, asks2, P);
  TEST(!r2.crossed);
}

void testFeeConservation() {
  // Taker side pays the full 1%: Σ fee = Σ cd (accumulator) + Σ reb (rebate
  // pool); the maker side receives exactly the pool. Conservation across sides.
  std::vector<AuctionOrder> bids = {
    bid(1, 2 * P, 100, 10, 1),
    bid(2, 2 * P, 200, 11, 2),   // bids aggregate 300
  };
  std::vector<AuctionOrder> asks = {
    ask(3, 2 * P, 100, 20, 3),   // asks aggregate 100 → asks are the maker side
  };
  AuctionResult r = runAuction(bids, asks, P);
  TEST(r.crossed);
  TEST(r.matchedVolume == 100);
  TEST(r.hasTaker);
  TEST(r.takerIsBid == true);

  uint64_t cdSum = 0, rebTakerSum = 0, rebMakerSum = 0;
  for (const auto& f : r.fills) {
    cdSum += f.cdFeeHeat;
    if (f.side == 0) rebTakerSum += f.rebateHeat;   // taker bids pay the rebate
    else rebMakerSum += f.rebateHeat;               // maker asks receive it
  }
  // Conservation: taker paid rebates == maker received rebates.
  TEST(rebTakerSum == rebMakerSum);
  // Total fee charged ≈ 1% of matched notional (floor tolerance ± #fills).
  uint64_t expectedFee = static_cast<uint64_t>(
      ((uint128_t)r.matchedVolume * 2 * P * parameters::HEARTH_FEE_BPS)
        / (parameters::HEARTH_FEE_DIVISOR * parameters::COIN));
  uint64_t totalFee = cdSum + rebTakerSum;
  TEST(totalFee <= expectedFee);
  TEST(expectedFee - totalFee < 4);
  // 70/30 split of the collected fee.
  uint64_t expectCd = static_cast<uint64_t>(
      ((uint128_t)expectedFee * parameters::HEARTH_CD_SHARE_PCT) / 100);
  TEST(cdSum <= expectCd);
}

void testFeeAskTakerAndTie() {
  // Ask-taker case: asks aggregate exceeds bids → asks pay the fee, bids
  // (makers) receive the rebate pool.
  {
    std::vector<AuctionOrder> bids = { bid(1, 2 * P, 50, 10, 1) };
    std::vector<AuctionOrder> asks = { ask(2, 2 * P, 100, 20, 2), ask(3, 2 * P, 100, 21, 3) };
    AuctionResult r = runAuction(bids, asks, P);
    TEST(r.crossed);
    TEST(r.hasTaker);
    TEST(r.takerIsBid == false);
    uint64_t rebTaker = 0, rebMaker = 0;
    for (const auto& f : r.fills) {
      if (f.side == 1) rebTaker += f.rebateHeat;   // taker asks pay
      else rebMaker += f.rebateHeat;               // maker bids receive
    }
    TEST(rebTaker == rebMaker);
  }
  // Exact tie: no taker → no fee, no rebate.
  {
    std::vector<AuctionOrder> bids = { bid(4, 2 * P, 100, 10, 4) };
    std::vector<AuctionOrder> asks = { ask(5, 2 * P, 100, 20, 5) };
    AuctionResult r = runAuction(bids, asks, P);
    TEST(r.crossed);
    TEST(!r.hasTaker);
    for (const auto& f : r.fills) {
      TEST(f.cdFeeHeat == 0);
      TEST(f.rebateHeat == 0);
    }
  }
}

void testHeatBalanceAcrossSides() {
  // Σ bid heat == Σ ask heat == floor(matchedVolume × p*/COIN) regardless of
  // how fills split into chunks (regression for cumulative-floor rounding).
  std::vector<AuctionOrder> bids = {
    bid(1, 2 * P, 33, 10, 1),
    bid(2, 2 * P, 33, 11, 2),
    bid(3, 2 * P, 34, 12, 3),
  };
  std::vector<AuctionOrder> asks = {
    ask(4, 2 * P, 50, 20, 4),
    ask(5, 2 * P, 50, 21, 5),
  };
  AuctionResult r = runAuction(bids, asks, P);
  TEST(r.crossed);
  TEST(r.matchedVolume == 100);
  uint64_t bidHeat = 0, askHeat = 0;
  for (const auto& f : r.fills) {
    if (f.side == 0) bidHeat += f.heat; else askHeat += f.heat;
  }
  uint64_t expect = static_cast<uint64_t>((static_cast<uint128_t>(100) * 2 * P) / parameters::COIN);
  TEST(bidHeat == expect);
  TEST(askHeat == expect);
}

void testHeatConversionExact() {
  // fill.heat == floor(fillXfg × clearingPrice / COIN)
  std::vector<AuctionOrder> bids = { bid(1, 2 * P, 100, 10, 1) };
  std::vector<AuctionOrder> asks = { ask(2, 2 * P, 50, 10, 2) };
  AuctionResult r = runAuction(bids, asks, P);
  TEST(r.crossed);
  for (const auto& f : r.fills) {
    uint64_t expect = static_cast<uint64_t>((static_cast<uint128_t>(f.fillXfg) * 2 * P) / parameters::COIN);
    TEST(f.heat == expect);
  }
}

void testPrevPclearTieBreak() {
  // Equal volume and imbalance at two prices → closest to prevPclear wins.
  std::vector<AuctionOrder> bids = { bid(1, 2 * P, 100, 10, 1) };
  std::vector<AuctionOrder> asks = { ask(2, 2 * P, 100, 10, 2) };
  // Only one candidate price here (2P) — construct a second candidate via an extra ask.
  std::vector<AuctionOrder> asks2 = { ask(2, 2 * P, 100, 10, 2), ask(3, 3 * P, 100, 10, 3) };
  // p=2: bidVol=100, askVol=200 → 100; p=3: bidVol=0 → skip.
  // Single candidate — prevPclear irrelevant. Test tie via two distinct single prices:
  std::vector<AuctionOrder> bids3 = { bid(4, 2 * P, 100, 10, 4) };
  std::vector<AuctionOrder> asks3 = { ask(5, 1 * P, 100, 10, 5) };
  // p=1: bidVol 100, askVol 100 → 100, imb 0
  // p=2: bidVol 100, askVol 100 → 100, imb 0 — tie on volume+imbalance → prevPclear.
  AuctionResult r = runAuction(bids3, asks3, 2 * P);
  TEST(r.crossed);
  TEST(r.clearingPrice == 2 * P);   // closest to prevPclear
  AuctionResult r2 = runAuction(bids3, asks3, 1 * P);
  TEST(r2.clearingPrice == 1 * P);  // closest to prevPclear
}

int main() {
  testNoCrossing();
  testBasicCrossingMaxVolume();
  testMaxVolumeSelection();
  testOverFillRegression();
  testTimePriorityRationing();
  testTieBreakImbalanceThenPrice();
  testSelfTradeExclusion();
  testHeatConversionExact();
  testHeatBalanceAcrossSides();
  testFeeConservation();
  testFeeAskTakerAndTie();
  testPrevPclearTieBreak();
  fprintf(stderr, "=== Auction Tests ===\nPassed: %d / %d\n", tests_passed, tests_run);
  return tests_passed == tests_run ? 0 : 1;
}
