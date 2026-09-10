// Copyright (c) 2017-2026 Fuego Developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even
// the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. You can redistribute it and/or modify it under the terms
// of the GNU General Public License v3 or later versions as published
// by the Free Software Foundation. Fuego includes elements written
// by third parties. See file labeled LICENSE for more details.
// You should have received a copy of the GNU General Public License
// along with Fuego. If not, see <https://www.gnu.org/licenses/>.

#include "RpcServer.h"
#include "SwapDaemon.h"
#include "SwapTypes.h"
#include "Common/JsonValue.h"
#include "Common/StringTools.h"
#include <HTTP/httplib.h>
#include <sstream>
#include <mutex>
#include <stdexcept>

namespace XfgSwap {

RpcServer::RpcServer(SwapDaemon& daemon, Logging::ILogger& logger,
                     const std::string& controlToken)
  : m_daemon(daemon)
  , m_logger(logger, "RpcServer")
  , m_controlToken(controlToken) {
}

RpcServer::~RpcServer() {
  stop();
}

bool RpcServer::start(uint16_t port) {
  m_server = std::make_unique<httplib::Server>();
  registerRoutes();

  // Bind to loopback only
  if (!m_server->bind_to_port("127.0.0.1", port)) {
    m_logger(Logging::ERROR) << "Failed to bind RPC server to port " << port;
    return false;
  }

  m_running = true;
  m_thread = std::thread([this, port]() {
    m_logger(Logging::INFO) << "JSON-RPC server listening on 127.0.0.1:" << port;
    m_server->listen_after_bind();
    m_running = false;
  });

  // Give the server a moment to start
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  return m_running.load();
}

void RpcServer::stop() {
  if (m_server) {
    m_server->stop();
  }
  if (m_thread.joinable()) {
    m_thread.join();
  }
  m_running = false;
}

bool RpcServer::authorize(const httplib::Request& req) const {
  if (m_controlToken.empty()) {
    // Loopback-only server without a configured token: local trust domain.
    return true;
  }
  auto it = req.headers.find("X-Swap-Token");
  if (it != req.headers.end() && it->second == m_controlToken) return true;
  auto auth = req.headers.find("Authorization");
  if (auth != req.headers.end()) {
    const std::string& v = auth->second;
    const std::string bearer = "Bearer ";
    if (v.size() > bearer.size() && v.compare(0, bearer.size(), bearer) == 0 &&
        v.substr(bearer.size()) == m_controlToken) {
      return true;
    }
  }
  return false;
}

void RpcServer::registerRoutes() {
  m_server->Post("/", [this](const httplib::Request& req, httplib::Response& res) {
    if (!authorize(req)) {
      res.status = 401;
      res.set_content(R"({"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized"},"id":null})",
                      "application/json");
      return;
    }
    std::string response = dispatch(req.body);
    res.set_content(response, "application/json");
    res.set_header("Access-Control-Allow-Origin", "*");
  });

  m_server->Options(".*", [](const httplib::Request&, httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, X-Swap-Token, Authorization");
    res.status = 204;
  });

  // Health check (no auth)
  m_server->Get("/health", [](const httplib::Request&, httplib::Response& res) {
    res.set_content(R"({"status":"ok"})", "application/json");
    res.set_header("Access-Control-Allow-Origin", "*");
  });
}

std::string RpcServer::dispatch(const std::string& body) {
  int id = 0;
  std::string method;
  std::string params;

  try {
    auto root = Common::JsonValue::fromString(body);
    if (!root.isObject()) {
      return rpcError(-32600, "Invalid Request");
    }

    if (root.contains("id")) {
      id = static_cast<int>(root("id").getInteger());
    }

    if (!root.contains("method") || !root("method").isString()) {
      return rpcError(-32600, "Missing method", id);
    }
    method = root("method").getString();

    if (root.contains("params")) {
      params = root("params").toString();
    } else {
      params = "{}";
    }
  } catch (const std::exception&) {
    return rpcError(-32700, "Parse error", id);
  }

  m_logger(Logging::INFO) << "RPC method: " << method;

  // Token enforcement happens in authorize() at the route level: when
  // --rpc-token is configured, every POST (including mutating methods)
  // requires the X-Swap-Token / Bearer header. The server binds loopback
  // only, so a token-less daemon trusts localhost (same domain as the
  // wallet RPC the local wallet already exposes).

  std::string result;
  if (method == "initiate_swap") {
    result = handleInitiateSwap(params);
  } else if (method == "accept") {
    result = handleAccept(params);
  } else if (method == "get_reserve_proof") {
    result = handleGetReserveProof(params);
  } else if (method == "list_swaps") {
    result = handleListSwaps(params);
  } else if (method == "swap_status") {
    result = handleSwapStatus(params);
  } else if (method == "refund") {
    result = handleRefund(params);
  } else if (method == "check_timeouts") {
    result = handleCheckTimeouts(params);
  } else {
    return rpcError(-32601, "Method not found: " + method, id);
  }

  // If the handler returned an error (starts with '{"error"'), pass through
  if (result.find("\"error\"") != std::string::npos) {
    return result;
  }

  return rpcSuccess(result, id);
}

std::string RpcServer::handleInitiateSwap(const std::string& params) {
  try {
    auto root = Common::JsonValue::fromString(params);
    if (!root.isObject()) {
      return rpcError(-32602, "Invalid params");
    }

    SwapPair pair = SwapPair::SOL;
    uint64_t xfgAmount = 0;
    uint64_t ctrAmount = 0;
    std::string peer;

    if (root.contains("pair")) {
      std::string pairStr = root("pair").getString();
      if (!swapPairFromString(pairStr, pair)) {
        return rpcError(-32602, "Invalid pair: " + pairStr);
      }
    }
    if (root.contains("xfg_amount")) {
      xfgAmount = static_cast<uint64_t>(root("xfg_amount").getInteger());
    }
    if (root.contains("ctr_amount")) {
      ctrAmount = static_cast<uint64_t>(root("ctr_amount").getInteger());
    }
    if (root.contains("peer")) {
      peer = root("peer").getString();
    }
    std::string expectedPeerHex;
    if (root.contains("expected_peer_pubkey")) {
      expectedPeerHex = root("expected_peer_pubkey").getString();
    }

    // Role: "alice" (taker — has counterparty coin, wants XFG) or "bob"
    // (maker — has XFG). Defaults to bob (the CLI's historic default).
    SwapRole role = SwapRole::BOB;
    if (root.contains("role")) {
      std::string roleStr = root("role").getString();
      if (roleStr == "alice" || roleStr == "ALICE") {
        role = SwapRole::ALICE;
      } else if (roleStr == "bob" || roleStr == "BOB") {
        role = SwapRole::BOB;
      } else {
        return rpcError(-32602, "Invalid role (use 'alice' or 'bob'): " + roleStr);
      }
    }

    if (xfgAmount == 0) {
      return rpcError(-32602, "xfg_amount must be > 0");
    }
    if (ctrAmount == 0) {
      return rpcError(-32602, "ctr_amount must be > 0");
    }
    if (peer.empty()) {
      return rpcError(-32602, "peer endpoint is required");
    }
    // expected_peer_pubkey is optional: when absent, the first KEY_EXCHANGE
    // binds the peer (the daemon logs an anti-griefing warning). Wallets
    // that have the counterparty key (from an offer) SHOULD pass it.
    if (!expectedPeerHex.empty() && expectedPeerHex.size() != 64) {
      return rpcError(-32602,
        "expected_peer_pubkey must be empty or 64-char hex Ed25519 pubkey of counterparty swap key");
    }

    SwapParams swapParams;
    swapParams.pair = pair;
    swapParams.role = role;
    swapParams.xfgAmount = xfgAmount;
    swapParams.ctrAmount = ctrAmount;
    swapParams.peerEndpoint = peer;

    // Zero-init crypto fields
    std::memset(&swapParams.aliceXfgPubKey, 0, sizeof(swapParams.aliceXfgPubKey));
    std::memset(&swapParams.bobXfgPubKey, 0, sizeof(swapParams.bobXfgPubKey));
    std::memset(&swapParams.ourSwapSecKey, 0, sizeof(swapParams.ourSwapSecKey));
    std::memset(&swapParams.ourSwapPubKey, 0, sizeof(swapParams.ourSwapPubKey));
    std::memset(&swapParams.peerSwapPubKey, 0, sizeof(swapParams.peerSwapPubKey));
    std::memset(&swapParams.expectedPeerSwapPubKey, 0, sizeof(swapParams.expectedPeerSwapPubKey));
    std::memset(&swapParams.escrowPubKey, 0, sizeof(swapParams.escrowPubKey));
    std::memset(&swapParams.adaptorPoint, 0, sizeof(swapParams.adaptorPoint));
    std::memset(&swapParams.adaptorSecret, 0, sizeof(swapParams.adaptorSecret));
    std::memset(&swapParams.adaptorDleqQ, 0, sizeof(swapParams.adaptorDleqQ));
    std::memset(&swapParams.escrowTxHash, 0, sizeof(swapParams.escrowTxHash));
    std::memset(&swapParams.hashLock, 0, sizeof(swapParams.hashLock));
    std::memset(&swapParams.preimage, 0, sizeof(swapParams.preimage));
    swapParams.xfgTimeoutHeight = 0;
    swapParams.ctrTimeoutBlock = 0;
    swapParams.escrowOutputIndex = 0;
    swapParams.htlcOutputIndex = 0;

    if (!Common::podFromHex(expectedPeerHex, swapParams.expectedPeerSwapPubKey)) {
      if (!expectedPeerHex.empty()) {
        return rpcError(-32602, "expected_peer_pubkey must be 64-char hex");
      }
    }

    // Optional taker identity injection: an AFK taker publishes an Ed25519
    // identity in /requestswap; the maker binds it as the expected peer key.
    // Inject the same secret here so this daemon's messages sign under the
    // exact key the maker expects.
    std::string ourSwapSecHex;
    if (root.contains("our_swap_secret_key")) {
      ourSwapSecHex = root("our_swap_secret_key").getString();
    }
    if (!ourSwapSecHex.empty()) {
      if (ourSwapSecHex.size() != 64) {
        return rpcError(-32602, "our_swap_secret_key must be 64-char hex");
      }
      if (!Common::podFromHex(ourSwapSecHex, swapParams.ourSwapSecKey) ||
          !Crypto::secret_key_to_public_key(swapParams.ourSwapSecKey, swapParams.ourSwapPubKey)) {
        return rpcError(-32602, "our_swap_secret_key is not a valid Ed25519 secret key");
      }
    }

    // Optional swap id (AFK takers pass the maker's lockId so both daemons
    // track the same swap).
    if (root.contains("swap_id") && !root("swap_id").getString().empty()) {
      swapParams.swapId = root("swap_id").getString();
      if (swapParams.swapId.size() > 64) {
        return rpcError(-32602, "swap_id too long (max 64 chars)");
      }
    }

    // AFK mode: after initiate, park the record at AFK_OFFER_LOCKED so
    // accept() drives it to AFK_OFFER_ACCEPTED (non-interactive flow).
    bool afkMode = false;
    if (root.contains("afk")) {
      afkMode = root("afk").getBool();
    }

    // AFK pre-lock material (from the maker's fill result): adaptor point T,
    // hashlock H(t), the maker's pre-signature, and the maker's CTR receive
    // address. Required for the taker to lock the counterparty HTLC.
    if (root.contains("adaptor_point")) {
      if (!Common::podFromHex(root("adaptor_point").getString(), swapParams.adaptorPoint)) {
        return rpcError(-32602, "adaptor_point must be 64-char hex");
      }
    }
    if (root.contains("hash_lock")) {
      if (!Common::podFromHex(root("hash_lock").getString(), swapParams.hashLock)) {
        return rpcError(-32602, "hash_lock must be 64-char hex");
      }
    }
    if (root.contains("pre_sig")) {
      swapParams.afkPreSigHex = root("pre_sig").getString();
    }
    if (root.contains("ctr_address")) {
      swapParams.ctrAddress = root("ctr_address").getString();
    }

    if (!m_daemon.initiate(swapParams)) {
      return rpcError(-32000, "Failed to initiate swap");
    }

    // AFK mode: park at AFK_OFFER_LOCKED so accept() drives the record to
    // AFK_OFFER_ACCEPTED (the non-interactive flow's taker-side entry).
    if (afkMode) {
      SwapStateMachine sm;
      if (!m_daemon.database().loadSwap(swapParams.swapId, sm)) {
        return rpcError(-32000, "AFK initiate failed: record not found");
      }
      if (!sm.transition(SwapState::AFK_OFFER_LOCKED) ||
          !m_daemon.database().saveSwap(sm)) {
        return rpcError(-32000, "AFK initiate failed: transition to AFK_OFFER_LOCKED rejected");
      }
    }

    std::ostringstream oss;
    oss << R"({"swap_id": ")" << swapParams.swapId
        << R"(", "our_swap_pubkey": ")" << Common::podToHex(swapParams.ourSwapPubKey)
        << R"("})";
    return oss.str();
  } catch (const std::exception& e) {
    return rpcError(-32602, std::string("Parameter error: ") + e.what());
  }
}

std::string RpcServer::handleGetReserveProof(const std::string& params) {
  try {
    auto root = Common::JsonValue::fromString(params);
    if (!root.isObject() || !root.contains("address") || !root.contains("message")) {
      return rpcError(-32602, "Missing address or message");
    }
    std::string address = root("address").getString();
    std::string message = root("message").getString();
    if (address.empty() || message.empty()) {
      return rpcError(-32602, "address and message must be non-empty");
    }

    std::string signature;
    if (!m_daemon.getXmrReserveProof(address, message, signature)) {
      return rpcError(-32000,
        "XMR reserve proof unavailable — is monero-wallet-rpc configured in the swap config?");
    }
    return R"({"signature": ")" + signature + R"("})";
  } catch (const std::exception& e) {
    return rpcError(-32602, std::string("Parameter error: ") + e.what());
  }
}

std::string RpcServer::handleAccept(const std::string& params) {  try {
    auto root = Common::JsonValue::fromString(params);
    if (!root.isObject() || !root.contains("swap_id")) {
      return rpcError(-32602, "Missing swap_id");
    }
    std::string swapId = root("swap_id").getString();

    auto result = m_daemon.accept(swapId);
    if (!result.success) {
      return rpcError(-32000, result.warning.empty() ? "Accept failed" : result.warning);
    }

    SwapStateMachine sm;
    std::string stateName = "UNKNOWN";
    if (m_daemon.database().loadSwap(swapId, sm)) {
      stateName = swapStateToString(sm.currentState());
    }
    return R"({"success": true, "swap_id": ")" + swapId +
           R"(", "state": ")" + stateName + R"("})";
  } catch (const std::exception& e) {
    return rpcError(-32602, std::string("Parameter error: ") + e.what());
  }
}

std::string RpcServer::handleListSwaps(const std::string& /*params*/) {
  auto ids = m_daemon.database().listSwaps();

  std::ostringstream oss;
  oss << R"({"swaps": [)";
  bool first = true;
  for (const auto& id : ids) {
    SwapStateMachine sm;
    if (m_daemon.database().loadSwap(id, sm)) {
      if (!first) oss << ",";
      first = false;
      sm.setEncryptionKey("");
      std::string json = sm.serialize();
      Common::JsonValue rec = Common::JsonValue::fromString(json);
      rec.insert("stateName", std::string(swapStateToString(sm.currentState())));
      rec.insert("pairName", std::string(swapPairToString(sm.params().pair)));
      const SwapParams& p = sm.params();
      if (!p.ctrLockTxId.empty()) {
        rec.insert("ctrLockTxId", p.ctrLockTxId);
        rec.insert("requiredConfirmations", static_cast<int64_t>(p.requiredConfirmations ? p.requiredConfirmations : 6));
        auto* client = m_daemon.getChainClient(p.pair);
        if (client) {
          ChainClientResult r;
          client->getTransactionDetails(p.ctrLockTxId, r);
          rec.insert("confirmations", static_cast<int64_t>(r.confirmations));
          rec.insert("blockHeight", static_cast<int64_t>(r.blockHeight));
          rec.insert("spvVerified", static_cast<int64_t>(r.spvVerified ? 1 : 0));
          rec.insert("confirmed", static_cast<int64_t>(r.confirmed ? 1 : 0));
          if (!r.success && !r.error.empty()) rec.insert("spvError", r.error);
          uint64_t tip = 0;
          if (client->getCurrentHeight(tip)) rec.insert("currentHeight", static_cast<int64_t>(tip));
        } else {
          rec.insert("confirmations", static_cast<int64_t>(0));
          rec.insert("blockHeight", static_cast<int64_t>(0));
          rec.insert("spvVerified", static_cast<int64_t>(false ? 1 : 0));
          rec.insert("confirmed", static_cast<int64_t>(false ? 1 : 0));
          rec.insert("spvError", std::string("chain client not configured"));
        }
      } else {
        rec.insert("confirmations", static_cast<int64_t>(0));
        rec.insert("blockHeight", static_cast<int64_t>(0));
        rec.insert("spvVerified", static_cast<int64_t>(false ? 1 : 0));
        rec.insert("confirmed", static_cast<int64_t>(false ? 1 : 0));
        rec.insert("requiredConfirmations", static_cast<int64_t>(p.requiredConfirmations ? p.requiredConfirmations : 6));
      }
      oss << rec.toString();
    }
  }
  oss << R"(]})";
  return oss.str();
}

std::string RpcServer::handleSwapStatus(const std::string& params) {
  try {
    auto root = Common::JsonValue::fromString(params);
    if (!root.isObject() || !root.contains("swap_id")) {
      return rpcError(-32602, "Missing swap_id");
    }
    std::string swapId = root("swap_id").getString();

    SwapStateMachine sm;
    if (!m_daemon.database().loadSwap(swapId, sm)) {
      return rpcError(-32000, "Swap not found: " + swapId);
    }

    sm.setEncryptionKey("");
    Common::JsonValue rec = Common::JsonValue::fromString(sm.serialize());
    rec.insert("stateName", std::string(swapStateToString(sm.currentState())));
    rec.insert("pairName", std::string(swapPairToString(sm.params().pair)));
    const SwapParams& p = sm.params();
    if (!p.ctrLockTxId.empty()) {
      rec.insert("ctrLockTxId", p.ctrLockTxId);
      rec.insert("requiredConfirmations", static_cast<int64_t>(p.requiredConfirmations ? p.requiredConfirmations : 6));
      auto* client = m_daemon.getChainClient(p.pair);
      if (client) {
        ChainClientResult r;
        client->getTransactionDetails(p.ctrLockTxId, r);
        rec.insert("confirmations", static_cast<int64_t>(r.confirmations));
        rec.insert("blockHeight", static_cast<int64_t>(r.blockHeight));
        rec.insert("spvVerified", static_cast<int64_t>(r.spvVerified ? 1 : 0));
        rec.insert("confirmed", static_cast<int64_t>(r.confirmed ? 1 : 0));
        if (!r.success && !r.error.empty()) rec.insert("spvError", r.error);
        uint64_t tip = 0;
        if (client->getCurrentHeight(tip)) rec.insert("currentHeight", static_cast<int64_t>(tip));
      } else {
        rec.insert("confirmations", static_cast<int64_t>(0));
        rec.insert("blockHeight", static_cast<int64_t>(0));
        rec.insert("spvVerified", static_cast<int64_t>(false ? 1 : 0));
        rec.insert("confirmed", static_cast<int64_t>(false ? 1 : 0));
        rec.insert("spvError", std::string("chain client not configured"));
      }
    } else {
      rec.insert("confirmations", static_cast<int64_t>(0));
      rec.insert("blockHeight", static_cast<int64_t>(0));
      rec.insert("spvVerified", static_cast<int64_t>(false ? 1 : 0));
      rec.insert("confirmed", static_cast<int64_t>(false ? 1 : 0));
      rec.insert("requiredConfirmations", static_cast<int64_t>(p.requiredConfirmations ? p.requiredConfirmations : 6));
    }
    return R"({"swap": )" + rec.toString() + "}";
  } catch (const std::exception& e) {
    return rpcError(-32602, std::string("Parameter error: ") + e.what());
  }
}

std::string RpcServer::handleRefund(const std::string& params) {
  try {
    auto root = Common::JsonValue::fromString(params);
    if (!root.isObject() || !root.contains("swap_id")) {
      return rpcError(-32602, "Missing swap_id");
    }
    std::string swapId = root("swap_id").getString();

    if (!m_daemon.refund(swapId)) {
      return rpcError(-32000, "Refund failed for swap: " + swapId);
    }

    return R"({"success": true, "swap_id": ")" + swapId + R"("})";
  } catch (const std::exception& e) {
    return rpcError(-32602, std::string("Parameter error: ") + e.what());
  }
}

std::string RpcServer::handleCheckTimeouts(const std::string& /*params*/) {
  // Process all active swaps and refund any that timed out
  auto ids = m_daemon.database().listSwaps();
  std::vector<std::string> refunded;

  for (const auto& id : ids) {
    SwapStateMachine sm;
    if (m_daemon.database().loadSwap(id, sm)) {
      if (!sm.isTerminal()) {
        m_daemon.processSwap(sm);
        // Check if it transitioned to REFUNDED
        if (sm.currentState() == SwapState::ADAPTOR_REFUNDED ||
            sm.currentState() == SwapState::XFG_REFUNDED) {
          refunded.push_back(id);
        }
      }
    }
  }

  // Also run the dedicated timeout check
  m_daemon.checkTimeouts();

  std::ostringstream oss;
  oss << R"({"processed": )" << ids.size()
      << R"(, "refunded": [)";
  bool first = true;
  for (const auto& id : refunded) {
    if (!first) oss << ",";
    first = false;
    oss << R"(")" << id << R"(")";
  }
  oss << R"(]})";
  return oss.str();
}

std::string RpcServer::rpcError(int code, const std::string& message, int id) {
  std::ostringstream oss;
  oss << R"({"jsonrpc":"2.0","error":{"code":)" << code
      << R"(,"message":")" << message << R"("},"id":)" << id << "}";
  return oss.str();
}

std::string RpcServer::rpcSuccess(const std::string& result, int id) {
  std::ostringstream oss;
  oss << R"({"jsonrpc":"2.0","result":)" << result
      << R"(,"id":)" << id << "}";
  return oss.str();
}

} // namespace XfgSwap
