// Copyright (c) 2017-2026 Fuego Developers
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

#include <string>
#include <vector>
#include <map>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <tuple>
#include <chrono>
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "P2p/P2pProtocolDefinitions.h"

namespace CryptoNote {

class core;
class NodeServer;
class IP2pEndpoint;

// ═══════════════════════════════════════════════════════════════════════════════
// Legacy v1 types — used by existing RPC handlers, OfferManager, SwapDaemon
// ═══════════════════════════════════════════════════════════════════════════════

struct SwapOfferMsg {
  std::string offerId;
  bool        isSell      = true;
  uint64_t    xfgAmount   = 0;
  uint64_t    rateNum     = 0;   // XFG per 1 CTR, scaled by 1e7
  uint8_t     pair        = 0;   // 0=XMR, 1=ETH, 2=BCH, 3=SOL, 4=ARB, 5=BASE
  Crypto::PublicKey makerPubKey;
  Crypto::Signature signature;
  uint64_t    timestamp   = 0;
  uint32_t    ttlBlocks   = 0;
  uint32_t    postedHeight = 0;
  bool        isSoftOrder = false;
  uint8_t     allowedSlippagePct = 0;
  uint64_t    filledAmount = 0;
};

struct SwapTradeRecord {
  uint8_t     pair        = 0;
  uint64_t    xfgAmount   = 0;
  uint64_t    ctrAmount   = 0;
  double      rate        = 0.0;
  uint32_t    blockHeight = 0;
  uint64_t    timestamp   = 0;
};

struct PriceSource {
  std::string name;
  uint8_t     pair    = 0;
  double      weight  = 0.0;
  double      rate    = 0.0;
  uint64_t    updatedAt = 0;
  bool        stale   = false;
};

struct CompositePrice {
  double rate        = 0.0;
  size_t sourceCount = 0;
  std::vector<PriceSource> sources;
};

struct NativeXfgPriceRange {
  double lowUsd  = 0.0;
  double highUsd = 0.0;
  double midUsd  = 0.0;
  std::vector<std::pair<uint8_t, double>> pairImplied;
};

// ═══════════════════════════════════════════════════════════════════════════════
// v2 Orderbook types — price-ladder CLOB for cross-chain swap pairs
// ═══════════════════════════════════════════════════════════════════════════════

struct SwapOrder {
  enum class Side : uint8_t { BID = 0, ASK = 1 };

  std::string  orderId;       // daemon-generated: cn_fast_hash(canonical fields)
  Side         side       = Side::BID;
  uint8_t      pair       = 0;  // 0=XMR..5=BASE
  uint64_t     price      = 0;  // XFG per 1 CTR, scaled by 1e7
  uint64_t     amount     = 0;  // total order size in XFG atomic units
  uint64_t     filled     = 0;  // amount filled so far
  Crypto::PublicKey makerPubKey{};
  Crypto::Signature signature{};  // signs canonical(orderId+side+pair+price+amount+nonce)
  uint64_t     nonce      = 0;  // maker monotonic counter (replay protection)
  uint64_t     timestamp  = 0;
  uint32_t     ttlBlocks  = 0;
  uint32_t     postedHeight = 0;
};

struct PriceLevel {
  std::deque<SwapOrder> orders;  // FIFO at same price

  uint64_t totalDepth() const {
    uint64_t d = 0;
    for (const auto& o : orders) d += (o.amount - o.filled);
    return d;
  }
};

struct PairOrderBook {
  std::map<uint64_t, PriceLevel> bids;  // highest first (operator> for uint64_t)
  std::map<uint64_t, PriceLevel> asks;  // lowest first

  uint64_t bestBid() const { return bids.empty() ? 0 : bids.rbegin()->first; }
  uint64_t bestAsk() const { return asks.empty() ? 0 : asks.begin()->first; }

  void clear() { bids.clear(); asks.clear(); }
};

struct Reservation {
  std::string reservationId;
  std::string takerOrderId;
  std::string makerOrderId;
  uint64_t    amount     = 0;
  uint64_t    expiresAt  = 0;  // unix timestamp
  std::string takerPubKey;
};

struct OrderBookSnapshot {
  struct LevelJson {
    uint64_t price      = 0;
    uint64_t amount     = 0;
    int      orderCount = 0;
  };
  std::vector<LevelJson> bids;
  std::vector<LevelJson> asks;
  uint64_t spread  = 0;
  uint64_t height  = 0;
};

struct PendingSwapRequest {
  std::string offerId;
  uint64_t    amount      = 0;
  std::string takerPubKey;
  std::string proofOfFunds;
};

// Result of a soft-order fill request, published by the maker's SwapDaemon
// after it creates the AFK lock. The taker polls for it (keyed by the
// takerPubKey it sent in /requestswap) to learn the lockId, the maker's
// P2P endpoint, and the pre-lock material it needs to lock the counterparty
// HTLC (adaptor point T, hashlock H(t), the maker's pre-sig, and the
// maker's counterparty receive address).
struct SwapRequestResult {
  std::string offerId;
  std::string lockId;
  std::string makerEndpoint;
  std::string adaptorPoint;   // hex, T = t*G
  std::string hashLock;       // hex, H(t) — counterparty-family hash
  std::string preSig;         // hex, maker's adaptor pre-signature
  std::string ctrAddress;     // maker's counterparty-chain receive address
  time_t      createdAt = 0;
};

// ═══════════════════════════════════════════════════════════════════════════════
// SwapOfferRelay — unified relay for legacy v1 + v2 orderbook
// ═══════════════════════════════════════════════════════════════════════════════

class SwapOfferRelay {
public:
  SwapOfferRelay(core& ccore, NodeServer& p2psrv, IP2pEndpoint* p2pEndpoint = nullptr);
  ~SwapOfferRelay();

  void start();
  void stop();

  // ── Legacy v1 interface (used by CryptoNoteProtocolHandler, RpcServer, SwapDaemon) ──

  void handleOfferMessage(const COMMAND_SWAP_OFFER::request& msg);
  void handleCancelMessage(const std::string& offerId,
                           const Crypto::PublicKey& pubkey,
                           const Crypto::Signature& sig,
                           uint64_t timestamp);
  void handleSwapRequest(const std::string& offerId, uint64_t amount,
                         const std::string& takerPubKey, const std::string& proofOfFunds);

  // RPC-originated request: store locally AND gossip to all peers so the
  // maker's node (wherever it is) queues it for its SwapDaemon.
  void submitSwapRequest(const std::string& offerId, uint64_t amount,
                         const std::string& takerPubKey, const std::string& proofOfFunds);

  // P2P-received fill result (gossiped by the maker's node). Stored locally,
  // keyed by takerPubKey, so the taker can poll its own fuegod.
  void handleSwapRequestResult(const std::string& takerPubKey,
                               const std::string& offerId,
                               const std::string& lockId,
                               const std::string& makerEndpoint,
                               const std::string& adaptorPoint,
                               const std::string& hashLock,
                               const std::string& preSig,
                               const std::string& ctrAddress,
                               uint64_t createdAt);

  // Called by the maker's SwapDaemon once the AFK lock is created.
  // Stores locally AND gossips the result to all peers.
  void recordSwapRequestResult(const std::string& takerPubKey,
                               const SwapRequestResult& result);

  // Results pending pickup by a taker (oldest first, bounded).
  std::vector<SwapRequestResult> getSwapRequestResults(const std::string& takerPubKey);

  // P2P gossip path: intentionally ignored (unsigned, manipulable). Use
  // recordLocalTrade() when a swap is observed completing on this node.
  void handleTradeCompleted(const SwapTradeRecord& trade);
  // Authenticated local path: updates TWAP from a real completed swap.
  void recordLocalTrade(const SwapTradeRecord& trade);

  std::vector<SwapOfferMsg> getOffers(uint8_t pair) const;
  std::vector<SwapOfferMsg> getAllOffers() const;
  bool submitOffer(const SwapOfferMsg& offer);
  bool cancelOffer(const std::string& offerId,
                   const Crypto::PublicKey& pubkey,
                   const Crypto::Signature& sig,
                   uint64_t timestamp);
  bool updateOfferAmount(const std::string& offerId, uint64_t newRemaining);

  double getTwap(uint8_t pair) const;
  CompositePrice getCompositePrice(uint8_t pair) const;
  NativeXfgPriceRange getNativeXfgPrice() const;
  std::vector<SwapTradeRecord> getRecentTrades(uint8_t pair, uint32_t limit) const;

  static double getSeedRate(uint8_t pair);

  std::vector<PendingSwapRequest> getPendingSwapRequests();

  // ── v2 Orderbook interface ──

  // Handle incoming COMMAND_ORDER_OPEN from P2P
  void handleOrderOpen(const COMMAND_ORDER_OPEN::request& msg);
  // Handle incoming COMMAND_ORDER_CANCEL from P2P
  void handleOrderCancel(const COMMAND_ORDER_CANCEL::request& msg);
  // Handle incoming COMMAND_ORDER_FILL from P2P (replay protection only)
  void handleOrderFill(const COMMAND_ORDER_FILL::request& msg);
  // Handle incoming COMMAND_ORDER_RESERVE from P2P
  void handleOrderReserve(const COMMAND_ORDER_RESERVE::request& msg);
  // Handle incoming COMMAND_ORDER_RESERVE_ACK from P2P
  void handleOrderReserveAck(const COMMAND_ORDER_RESERVE_ACK::request& msg);

  // RPC handlers — require fully signed orders / cancels
  OrderBookSnapshot getOrderBookSnapshot(uint8_t pair, int depth) const;
  // Place a fully signed order (orderId, makerPubKey, signature, nonce must be set).
  // Returns false on invalid pair/sig/replay/limits. outOrderId set to order.orderId on success.
  bool placeSignedOrder(const SwapOrder& order, uint64_t* outFilled = nullptr);
  // Cancel with maker signature over "cancel:"+orderId+":"+timestamp
  bool cancelOrderByClient(const std::string& orderId,
                           const Crypto::PublicKey& makerPubKey,
                           const Crypto::Signature& signature,
                           uint64_t timestamp);

  // Match an incoming taker order against the book
  // Returns fills: vector of (makerOrderId, fillPrice, fillAmount)
  struct Fill {
    std::string makerOrderId;
    uint64_t    fillPrice;
    uint64_t    fillAmount;
  };
  std::vector<Fill> matchOrder(SwapOrder::Side takerSide, uint8_t pair,
                               uint64_t takerPrice, uint64_t takerAmount);

private:
  // ── Legacy v1 internals ──
  bool validateOffer(const SwapOfferMsg& offer) const;
  void cleanupLegacyOffers();

  // ── v2 Orderbook internals ──
  static constexpr uint8_t MAX_PAIR_INDEX = 11; // m_orderBooks[12] valid indices 0..11 (SwapPair core set)
  bool isValidPair(uint8_t pair) const { return pair <= MAX_PAIR_INDEX; }
  std::string generateOrderId(const SwapOrder& o) const;
  bool validateOrderSignature(const SwapOrder& o) const;
  bool validateCancelSignature(const std::string& orderId,
                               const Crypto::PublicKey& makerPubKey,
                               const Crypto::Signature& signature,
                               uint64_t timestamp) const;
  bool isTombstoned(const std::string& orderId) const;
  void tombstoneOrder(const std::string& orderId);
  std::string makeFillReplayKey(const COMMAND_ORDER_FILL::request& msg) const;
  void insertOrderIntoBook(SwapOrder order); // by value — copy into ladder, keep original for map
  void broadcastOrderOpen(const COMMAND_ORDER_OPEN::request& msg);
  void broadcastOrderCancel(const COMMAND_ORDER_CANCEL::request& msg);
  void broadcastOrderFill(const COMMAND_ORDER_FILL::request& msg);
  void broadcastReserveAck(const COMMAND_ORDER_RESERVE_ACK::request& msg);
  void cleanupExpiredOrders();
  void cleanupExpiredReservations();
  static constexpr uint32_t RESERVATION_TTL_SECS = 30;
  static constexpr size_t MAX_ORDERS_PER_PAIR = 50000;
  static constexpr size_t MAX_TRADES = 10000;
  static constexpr size_t MAX_TOMBSTONES = 100000;
  static constexpr size_t MAX_FILL_REPLAY = 100000;

  // ── Cleanup thread ──
  void cleanupThread();

  core& m_core;
  NodeServer& m_p2p;
  IP2pEndpoint* m_p2pEndpoint;
  mutable std::mutex m_mutex;
  std::atomic<bool> m_running{false};
  std::thread m_cleanupThread;

  // ── Legacy v1 state ──
  static constexpr size_t MAX_LEGACY_OFFERS = 10000;
  std::map<std::string, SwapOfferMsg> m_offers;
  std::vector<SwapTradeRecord> m_trades;
  std::vector<PendingSwapRequest> m_pendingRequests;
  static constexpr size_t MAX_PENDING_REQUESTS = 256;
  static constexpr size_t MAX_REQUEST_RESULTS_PER_TAKER = 64;
  std::map<std::string, std::vector<SwapRequestResult>> m_requestResults;  // takerPubKey → results

  // TWAP state per pair
  struct TwapState {
    double sumProduct = 0.0;  // sum of (rate * volume)
    double sumVolume  = 0.0;
    uint32_t windowStart = 0;
    static constexpr uint32_t WINDOW_BLOCKS = 33;
  };
  std::map<uint8_t, TwapState> m_twap;

  // Composite price state per pair
  struct CompositeState {
    std::vector<PriceSource> sources;
    double rate = 0.0;
  };
  std::map<uint8_t, CompositeState> m_composite;

  // Native XFG price
  NativeXfgPriceRange m_nativeXfgPrice;

  // ── v2 Orderbook state ──
  PairOrderBook m_orderBooks[12];  // indexed by pair (0..11) — ALWAYS bounds-check pair first
  std::map<std::string, SwapOrder> m_allOrders;  // orderId → order (all orders across all pairs)
  // Fill replay keys: hash(taker|maker|amount|price|height) — not maker-only
  std::map<std::string, uint64_t> m_fillReplay; // key → insert time (unix)
  // Cancelled / fully filled orderIds — reject re-open of same signed payload
  std::map<std::string, uint64_t> m_tombstones; // orderId → insert time
  std::map<std::string, Reservation> m_reservations;  // reservationId → Reservation
  // Amount already reserved per maker order (prevents double-reserve)
  std::map<std::string, uint64_t> m_reservedByMaker;

  // Client pubkey → orderId lookup (for cancel-by-client)
  std::map<Crypto::PublicKey, std::vector<std::string>> m_clientOrders;
};

} // namespace CryptoNote
