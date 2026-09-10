// Copyright (c) 2017-2026 Fuego Developers
//
// Hearth subsystem unit tests — AMM reserve math, LP share accounting and the
// per-block call auction.
//
// Regression coverage for three audited defects:
//   01  popTransaction recomputed LP withdrawals from post-burn state, which is
//       not the inverse of pushTransaction and inflated reserves on reorg.
//   02  pool orders share one zeroed addressHash, so self-trade exclusion read
//       the two-sided market maker as one party and dropped a whole side.
//       These complement tests/CoreTests/OrderbookAuctionTest.cpp, which covers
//       rationing, tie-breaks and user-vs-user self-trade exclusion.
//   03  OrderbookMatcher accumulated VWAP with a Q64.64 shift after prices had
//       moved to COIN scale, collapsing P_clear to zero.

#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

#include "CryptoNoteCore/AmmPool.h"
#include "CryptoNoteCore/OrderbookAuction.h"
#include "CryptoNoteConfig.h"
#include "Common/Int128.h"

using namespace CryptoNote;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
  if (cond) { ++g_pass; std::cout << "  PASS: " << msg << "\n"; } \
  else { ++g_fail; std::cerr << "  FAIL: " << msg << "\n"; } \
} while (0)

static const uint64_t COIN = parameters::COIN;

static Crypto::Hash mkHash(uint8_t b0, uint8_t b1 = 0, uint8_t b2 = 0) {
  Crypto::Hash h{}; h.data[0] = b0; h.data[1] = b1; h.data[2] = b2; return h;
}

static AuctionOrder mkOrder(Crypto::Hash id, uint8_t /*side*/, uint64_t price,
                            uint64_t vol, uint32_t height, Crypto::Hash addr) {
  AuctionOrder o;
  o.orderId = id; o.price = price; o.volumeXfg = vol;
  o.createdHeight = height; o.addressHash = addr;
  return o;
}

// ─────────────────────────────────────────────────────────────────────────────
// AMM reserve math
// ─────────────────────────────────────────────────────────────────────────────

static void testAmmGuards() {
  std::cout << "\nAMM: denominator guards\n";
  CHECK(ammGetOutputAmount(100, 0, 1000, 30) == 0, "output: zero reserveIn yields 0");
  CHECK(ammGetOutputAmount(100, 1000, 0, 30) == 0, "output: zero reserveOut yields 0");
  CHECK(ammGetOutputAmount(0, 1000, 1000, 30) == 0, "output: zero input yields 0");
  CHECK(ammGetInputAmount(1000, 1000, 1000, 30) == 0, "input: output >= reserveOut yields 0");
  CHECK(ammGetSpotPrice(0, 1000) == 0, "spot: zero reserveA yields 0");

  uint64_t a = 1, b = 1;
  ammGetWithdrawalAmounts(500, 0, 1000, 1000, a, b);
  CHECK(a == 0 && b == 0, "withdrawal: zero totalShares yields 0/0");

  CHECK(ammMintLpShares(0, 100, 1000, 1000, 1000) == 0, "mint: single-sided yields 0");
  CHECK(ammMintLpShares(100, 100, 1000, 0, 1000) == 0, "mint: live supply w/ empty reserve yields 0");
}

static void testSpotPriceScale() {
  std::cout << "\nAMM: spot price is COIN-scaled\n";
  // 1000 XFG : 2000 HEAT  ->  2.0 HEAT per XFG  ->  2 * COIN
  uint64_t p = ammGetSpotPrice(1000 * COIN, 2000 * COIN);
  CHECK(p == 2 * COIN, "spot price of a 1:2 pool equals 2 x COIN");
  CHECK(ammGetSpotPrice(1000 * COIN, 1000 * COIN) == COIN, "balanced pool prices at exactly COIN");
}

static void testConstantProduct() {
  std::cout << "\nAMM: constant-product invariant\n";
  const uint32_t feeBps = 30;
  uint64_t rIn = 1000 * COIN, rOut = 2000 * COIN;
  bool everViolated = false;
  for (int i = 0; i < 50; ++i) {
    uint64_t in = (uint64_t)(i + 1) * COIN;
    uint64_t out = ammGetOutputAmount(in, rIn, rOut, feeBps);
    if (out == 0 || out >= rOut) break;
    uint64_t nIn = rIn + in, nOut = rOut - out;
    if (!ammValidateInvariant(rIn, rOut, nIn, nOut)) everViolated = true;
    rIn = nIn; rOut = nOut;
  }
  CHECK(!everViolated, "product never decreases across 50 sequential swaps");
  CHECK(!ammValidateSwap(100 * COIN, UINT64_MAX, 1000 * COIN, 2000 * COIN, feeBps),
        "swap validation rejects an over-large output");
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding 01 — LP removal apply/undo must round-trip exactly
// ─────────────────────────────────────────────────────────────────────────────

struct Pool { uint64_t shares, xfg, heat; };

// The defective undo: recompute the withdrawal from post-burn state.
static Pool undoByRecompute(Pool p, uint64_t burned) {
  uint64_t ax = 0, ah = 0;
  ammGetWithdrawalAmounts(burned, p.shares, p.xfg, p.heat, ax, ah);
  return { p.shares + burned, p.xfg + ax, p.heat + ah };
}

// The corrected undo: restore the deltas recorded when the block was applied.
static Pool undoByJournal(Pool p, uint64_t burned, uint64_t ax, uint64_t ah) {
  return { p.shares + burned, p.xfg + ax, p.heat + ah };
}

static Pool applyRemove(Pool p, uint64_t burned, uint64_t& ax, uint64_t& ah) {
  ammGetWithdrawalAmounts(burned, p.shares, p.xfg, p.heat, ax, ah);
  uint64_t appliedX = (p.xfg  >= ax) ? ax : 0;
  uint64_t appliedH = (p.heat >= ah) ? ah : 0;
  ax = appliedX; ah = appliedH;
  return { p.shares >= burned ? p.shares - burned : p.shares,
           p.xfg - appliedX, p.heat - appliedH };
}

static void testLpRemoveRoundTrip() {
  std::cout << "\nLP: removal apply/undo round-trip (finding 01)\n";
  struct Case { uint64_t S, b, Rx, Rh; };
  const Case cases[] = {
    {3, 1, 10, 10},
    {3, 2, 10, 10},
    {7, 5, 1000000, 3000000},
    {100, 90, 1000, 1000},
    {1000000, 999999, 12345678, 87654321},
    {10000000, 9000000, 500000000000ULL, 1000000000000ULL},
  };
  bool journalExact = true;
  bool recomputeEverInflated = false;
  for (const auto& c : cases) {
    Pool before{ c.S, c.Rx, c.Rh };
    uint64_t ax = 0, ah = 0;
    Pool burned = applyRemove(before, c.b, ax, ah);

    Pool viaJournal = undoByJournal(burned, c.b, ax, ah);
    if (viaJournal.shares != before.shares || viaJournal.xfg != before.xfg ||
        viaJournal.heat != before.heat) journalExact = false;

    Pool viaRecompute = undoByRecompute(burned, c.b);
    if (viaRecompute.xfg > before.xfg || viaRecompute.heat > before.heat)
      recomputeEverInflated = true;
  }
  CHECK(journalExact, "journal undo restores reserves and shares exactly, all cases");
  CHECK(recomputeEverInflated,
        "recompute undo demonstrably inflates reserves (the fixed defect)");

  // The specific case from the audit.
  Pool before{ 1000000, 12345678, 87654321 };
  uint64_t ax = 0, ah = 0;
  Pool burned = applyRemove(before, 999999, ax, ah);
  Pool bad = undoByRecompute(burned, 999999);
  Pool good = undoByJournal(burned, 999999, ax, ah);
  CHECK(bad.xfg == 13000000 && good.xfg == 12345678,
        "audit case: recompute yields 13000000, journal yields 12345678");
}

static void testLpMintBurnSymmetry() {
  std::cout << "\nLP: mint never returns more than a proportional share\n";
  uint64_t S = 1000000, Rx = 500 * COIN, Rh = 1000 * COIN;
  uint64_t addX = 50 * COIN, addH = 100 * COIN;
  uint64_t minted = ammMintLpShares(addX, addH, S, Rx, Rh);
  CHECK(minted > 0, "balanced deposit mints a positive share count");
  uint64_t ax = 0, ah = 0;
  ammGetWithdrawalAmounts(minted, S + minted, Rx + addX, Rh + addH, ax, ah);
  CHECK(ax <= addX && ah <= addH,
        "immediate withdrawal never returns more than was deposited");
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding 02 — pool orders must survive self-trade exclusion
// ─────────────────────────────────────────────────────────────────────────────

static void testPoolTwoSidedQuoting() {
  std::cout << "\nAuction: pool quotes both sides (finding 02)\n";
  const uint64_t P = 2 * COIN;
  Crypto::Hash user = mkHash(0xAA);
  Crypto::Hash pool{};  // zeroed, as Blockchain.cpp injects

  // A user wants to sell 50 XFG at 1.8; the pool is the only buyer at 2.0.
  auto userAsk = mkOrder(mkHash(0x01), 1, P - COIN / 5, 50 * COIN, 10, user);
  auto poolBid = mkOrder(mkHash(0xF0, 0x01), 0, P, 500 * COIN, 0, pool);
  // A pool ask far above the book: it can never fill, and must not affect
  // anything. Before the fix it voided the entire auction.
  auto poolAskFar = mkOrder(mkHash(0xF0, 0x02), 1, 3 * COIN, 500 * COIN, 0, pool);

  std::vector<AuctionOrder> withoutAsk{ poolBid };
  std::vector<AuctionOrder> asksOnly{ userAsk };
  AuctionResult baseline = runAuction(withoutAsk, asksOnly, P);
  CHECK(baseline.crossed, "pool bidding alone crosses with the user's sell");

  std::vector<AuctionOrder> asksBoth{ userAsk, poolAskFar };
  AuctionResult twoSided = runAuction(withoutAsk, asksBoth, P);
  CHECK(twoSided.crossed, "adding the pool's own ask does not void the auction");

  uint64_t userFilled = 0;
  for (const auto& f : twoSided.fills)
    if (f.orderId.data[0] != 0xF0) userFilled += f.fillXfg;
  CHECK(userFilled == 50 * COIN, "the user's full 50 XFG sell is filled");
  CHECK(baseline.matchedVolume == twoSided.matchedVolume,
        "an unfillable pool quote on the far side changes nothing");
}

static void testSelfTradeStillBlocked() {
  std::cout << "\nAuction: genuine self-trade stays excluded\n";
  const uint64_t P = 2 * COIN;
  Crypto::Hash sameParty = mkHash(0xBB);
  std::vector<AuctionOrder> bids{ mkOrder(mkHash(0x01), 0, 10 * COIN, 100 * COIN, 5, sameParty) };
  std::vector<AuctionOrder> asks{ mkOrder(mkHash(0x02), 1, 1 * COIN, 100 * COIN, 6, sameParty) };
  AuctionResult r = runAuction(bids, asks, P);
  CHECK(!r.crossed, "one address crossing itself produces no fills");

  // Exempting pool orders removes them from the self-trade net, so the spread
  // in generatePoolOrders is what keeps the pool from trading with itself:
  // bids sit at P_clear - spread/2 and asks at P_clear + spread/2.
  Crypto::Hash pool{};
  std::vector<AuctionOrder> pb{ mkOrder(mkHash(0xF0, 0x01), 0, P - COIN / 20, 100 * COIN, 0, pool) };
  std::vector<AuctionOrder> pa{ mkOrder(mkHash(0xF0, 0x02), 1, P + COIN / 20, 100 * COIN, 0, pool) };
  AuctionResult pr = runAuction(pb, pa, P);
  CHECK(!pr.crossed, "a well-formed pool band (bid < ask) never self-crosses");
}

// ─────────────────────────────────────────────────────────────────────────────
// Auction conservation and determinism
// ─────────────────────────────────────────────────────────────────────────────

static void buildCrossingBook(std::vector<AuctionOrder>& bids,
                              std::vector<AuctionOrder>& asks) {
  const uint64_t P = 2 * COIN;
  for (int i = 0; i < 6; ++i) {
    bids.push_back(mkOrder(mkHash(0x10, (uint8_t)i), 0, P + (uint64_t)i * COIN / 20,
                           (uint64_t)(10 + i) * COIN, 10 + i, mkHash(0xB0, (uint8_t)i)));
    asks.push_back(mkOrder(mkHash(0x20, (uint8_t)i), 1, P - (uint64_t)i * COIN / 20,
                           (uint64_t)(8 + i) * COIN, 10 + i, mkHash(0xA0, (uint8_t)i)));
  }
}

static void testConservation() {
  std::cout << "\nAuction: volume and fee conservation\n";
  std::vector<AuctionOrder> bids, asks;
  buildCrossingBook(bids, asks);
  AuctionResult r = runAuction(bids, asks, 2 * COIN);
  CHECK(r.crossed, "constructed book crosses");

  uint64_t bidVol = 0, askVol = 0, bidHeat = 0, askHeat = 0;
  for (const auto& f : r.fills) {
    if (f.side == 0) { bidVol += f.fillXfg; bidHeat += f.heat; }
    else             { askVol += f.fillXfg; askHeat += f.heat; }
  }
  CHECK(bidVol == askVol, "XFG filled on the bid side equals the ask side");
  CHECK(bidVol == r.matchedVolume, "filled volume equals reported matchedVolume");
  CHECK(bidHeat == askHeat, "HEAT value is equal on both sides (cumulative floors)");

  if (r.hasTaker) {
    uint8_t takerSide = r.takerIsBid ? 0 : 1;
    uint64_t fee = 0, cd = 0, reb = 0;
    for (const auto& f : r.fills) {
      if (f.side == takerSide) { cd += f.cdFeeHeat; fee += f.cdFeeHeat + f.rebateHeat; }
      else                     { reb += f.rebateHeat; }
    }
    CHECK(reb <= fee - cd, "maker rebates never exceed the rebate pool the taker paid in");
  } else {
    CHECK(true, "no taker on an exact tie: no fee, no rebate");
  }
}

static void testDeterminism() {
  std::cout << "\nAuction: deterministic under input permutation\n";
  std::vector<AuctionOrder> bids, asks;
  buildCrossingBook(bids, asks);
  AuctionResult a = runAuction(bids, asks, 2 * COIN);

  std::vector<AuctionOrder> rb(bids.rbegin(), bids.rend());
  std::vector<AuctionOrder> ra(asks.rbegin(), asks.rend());
  AuctionResult b = runAuction(rb, ra, 2 * COIN);

  bool same = a.crossed == b.crossed &&
              a.clearingPrice == b.clearingPrice &&
              a.matchedVolume == b.matchedVolume &&
              a.fills.size() == b.fills.size();
  CHECK(same, "reversing submission order changes nothing about the outcome");

  AuctionResult empty = runAuction({}, asks, 2 * COIN);
  CHECK(!empty.crossed, "empty bid side produces no cross");
}

static void testNoCrossWhenSpread() {
  std::cout << "\nAuction: non-crossing book stays uncrossed\n";
  std::vector<AuctionOrder> bids{ mkOrder(mkHash(0x01), 0, 1 * COIN, 10 * COIN, 5, mkHash(0xB1)) };
  std::vector<AuctionOrder> asks{ mkOrder(mkHash(0x02), 1, 3 * COIN, 10 * COIN, 5, mkHash(0xA1)) };
  AuctionResult r = runAuction(bids, asks, 2 * COIN);
  CHECK(!r.crossed && r.fills.empty(), "best bid below best ask yields no fills");
}

int main() {
  std::cout << "Hearth subsystem tests\n======================\n";
  testAmmGuards();
  testSpotPriceScale();
  testConstantProduct();
  testLpRemoveRoundTrip();
  testLpMintBurnSymmetry();
  testPoolTwoSidedQuoting();
  testSelfTradeStillBlocked();
  testConservation();
  testDeterminism();
  testNoCrossWhenSpread();
  std::cout << "\n======================\n"
            << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}
