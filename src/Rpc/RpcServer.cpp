// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2016-2019 The Karbowanec developers
// Copyright (c) 2012-2018 The CryptoNote developers
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

#include "RpcServer.h"

#include <future>
#include <unordered_map>
#include <cctype>
#include <ctime>

// CryptoNote
#include "BlockchainExplorerData.h"
#include "Common/StringTools.h"
#include "Common/Base58.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"

#include "P2p/NetNode.h"
#include "CryptoNoteCore/SwapOfferRelay.h"
#include "SwapDaemon/SwapTypes.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"
#include "version.h"

#undef ERROR

using namespace Logging;
using namespace Crypto;
using namespace Common;

namespace CryptoNote {

namespace {

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToBinaryKeyValue(static_cast<typename Command::response&>(res)));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToJson(static_cast<typename Command::response&>(res)));
    return result;
  };
}

// Swap control endpoints that require optional X-Swap-Token when configured.
template <typename Command>
RpcServer::HandlerFunction jsonMethodSwapAuth(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {
    if (!obj->checkSwapControlAuth(request)) {
      response.setStatus(HttpResponse::STATUS_401);
      response.setBody("{\"status\":\"Unauthorized: missing or invalid X-Swap-Token\"}");
      return true;
    }

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToJson(static_cast<typename Command::response&>(res)));
    return result;
  };
}

}

// ── Rate limiting helper ───────────────────────────────────────────────────
// Fixed 1-second window token bucket. `windowStart` is the Unix time of the
// current window; `count` is the number of requests accepted in it. When the
// window rolls over, both are reset. Not per-IP (that would require client
// address plumbing through HttpRequest); this bounds the total per-node rate,
// which defeats the flood vector the findings describe.
bool RpcServer::rateLimit(std::atomic<uint64_t>& windowStart,
                          std::atomic<uint32_t>& count,
                          uint32_t maxPerWindow) {
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  uint64_t start = windowStart.load(std::memory_order_relaxed);

  if (now != start) {
    // New window (or first request). CAS so concurrent requests don't clobber.
    uint64_t expected = start;
    if (windowStart.compare_exchange_strong(expected, now, std::memory_order_relaxed)) {
      count.store(1, std::memory_order_relaxed);
      return true;
    }
    // Lost the race: another thread opened the window; fall through to count.
  }

  uint32_t c = count.load(std::memory_order_relaxed);
  while (c < maxPerWindow) {
    if (count.compare_exchange_weak(c, c + 1, std::memory_order_relaxed)) {
      return true;
    }
    // c was reloaded by compare_exchange_weak on failure; retry.
  }
  return false;
}

std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {

  // binary handlers
  { "/getblocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), false } },
  { "/queryblocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), false } },
  { "/queryblockslite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), false } },
  { "/get_o_indexes.bin", { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), false } },
  { "/getrandom_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::on_get_random_outs), false } },
  { "/getrandom_commitment_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS>(&RpcServer::on_get_random_commitment_outs), false } },
  { "/getrandom_outs_json", { jsonMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_JSON>(&RpcServer::on_get_random_outs_json), true } },
  { "/get_outs_json", { jsonMethod<COMMAND_RPC_GET_OUTPUTS_JSON>(&RpcServer::on_get_outputs_json), true } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::onGetPoolChanges), false } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::onGetPoolChangesLite), false } },

  // json handlers
  { "/getinfo", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::on_get_info), true } },
  { "/peers", { jsonMethod<COMMAND_RPC_GET_PEER_LIST>(&RpcServer::on_get_peer_list), true } },
  { "/getdeposits", { jsonMethod<COMMAND_RPC_GET_DEPOSITS>(&RpcServer::on_get_deposits), true } },
  { "/is_key_image_spent", { jsonMethod<COMMAND_RPC_IS_KEY_IMAGE_SPENT>(&RpcServer::on_is_key_image_spent), true } },
  { "/getheight", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::on_get_height), true } },
  { "/gettransactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::on_get_transactions), false } },
  { "/sendrawtransaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TX>(&RpcServer::on_send_raw_tx), false } },
  { "/feeaddress", { jsonMethod<COMMAND_RPC_GET_FEE_ADDRESS>(&RpcServer::on_get_fee_address), true } },
  { "/getethereal", { jsonMethod<COMMAND_RPC_GET_ETHERNAL_FLAME>(&RpcServer::on_get_ethereal_flame), true } },
  { "/paymentid", { jsonMethod<COMMAND_RPC_GEN_PAYMENT_ID>(&RpcServer::on_get_payment_id), true } },

  // swap state persistence endpoints
  { "/listswaps",      { jsonMethod<COMMAND_RPC_LIST_SWAPS>(&RpcServer::on_list_swaps), true } },
  { "/getswapstatus",  { jsonMethod<COMMAND_RPC_GET_SWAP_STATUS>(&RpcServer::on_get_swap_status), true } },

  // swap execution endpoints (SwapDaemon bridge) — token-gated when configured
  { "/getactiveswaps", { jsonMethod<COMMAND_RPC_GET_ACTIVE_SWAPS>(&RpcServer::on_get_active_swaps), true } },
  { "/initiate",       { jsonMethodSwapAuth<COMMAND_RPC_INITIATE_SWAP>(&RpcServer::on_initiate_swap), false } },
  { "/accept",         { jsonMethodSwapAuth<COMMAND_RPC_ACCEPT_SWAP>(&RpcServer::on_accept_swap), false } },
  { "/processswap",    { jsonMethodSwapAuth<COMMAND_RPC_PROCESS_SWAP>(&RpcServer::on_process_swap), false } },
  { "/refundswap",     { jsonMethodSwapAuth<COMMAND_RPC_REFUND_SWAP>(&RpcServer::on_refund_swap), false } },

  // swap orderbook endpoints
  { "/getswapoffers", { jsonMethod<COMMAND_RPC_GET_SWAP_OFFERS>(&RpcServer::on_get_swap_offers), true } },
  { "/getswapprice", { jsonMethod<COMMAND_RPC_GET_SWAP_PRICE>(&RpcServer::on_get_swap_price), true } },
  { "/getswaptrades", { jsonMethod<COMMAND_RPC_GET_SWAP_TRADES>(&RpcServer::on_get_swap_trades), true } },
  { "/submitswap", { jsonMethodSwapAuth<COMMAND_RPC_SUBMIT_SWAP_OFFER>(&RpcServer::on_submit_swap_offer), false } },
  { "/cancelswap", { jsonMethodSwapAuth<COMMAND_RPC_CANCEL_SWAP_OFFER>(&RpcServer::on_cancel_swap_offer), false } },
  { "/requestswap", { jsonMethodSwapAuth<COMMAND_RPC_REQUEST_SWAP>(&RpcServer::on_request_swap), false } },
  { "/getswaprequests", { jsonMethod<COMMAND_RPC_GET_SWAP_REQUESTS>(&RpcServer::on_get_swap_requests), true } },

  // v2 orderbook endpoints
  { "/getorderbook", { jsonMethod<COMMAND_RPC_GET_ORDER_BOOK>(&RpcServer::on_get_order_book), true } },
  { "/placeorder", { jsonMethodSwapAuth<COMMAND_RPC_PLACE_ORDER>(&RpcServer::on_place_order), false } },
  { "/cancelorder", { jsonMethodSwapAuth<COMMAND_RPC_CANCEL_ORDER>(&RpcServer::on_cancel_order), false } },
  { "/openorders", { jsonMethod<COMMAND_RPC_GET_OPEN_ORDERS>(&RpcServer::on_get_open_orders), true } },

  // disabled in restricted rpc mode
  { "/start_mining", { jsonMethod<COMMAND_RPC_START_MINING>(&RpcServer::on_start_mining), false } },
  { "/stop_mining", { jsonMethod<COMMAND_RPC_STOP_MINING>(&RpcServer::on_stop_mining), false } },
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::on_stop_daemon), true } },
  { "/addswapfee",  { jsonMethodSwapAuth<COMMAND_RPC_ADD_SWAP_FEE>(&RpcServer::on_add_swap_fee), false } },

  // HEAT / Hearth AMM endpoints (v11+)
  { "/heat_metrics", { jsonMethod<COMMAND_RPC_GET_HEAT_METRICS>(&RpcServer::on_get_heat_metrics), true } },
  { "/amm_quote",    { jsonMethod<COMMAND_RPC_AMM_QUOTE>(&RpcServer::on_amm_quote), true } },
  { "/amm_pool_info", { jsonMethod<COMMAND_RPC_AMM_POOL_INFO>(&RpcServer::on_amm_pool_info), true } },
  { "/get_fuego_price", { jsonMethod<COMMAND_RPC_GET_FUEGO_PRICE>(&RpcServer::on_get_fuego_price), true } },

  // Limit order endpoints
  { "/get_limit_orders", { jsonMethod<COMMAND_RPC_GET_LIMIT_ORDERS>(&RpcServer::on_get_limit_orders), true } },


  { "/get_alias", { jsonMethod<COMMAND_RPC_GET_ALIAS>(&RpcServer::on_get_alias), true } },
  { "/get_alias_by_address", { jsonMethod<COMMAND_RPC_GET_ALIAS_BY_ADDRESS>(&RpcServer::on_get_alias_by_address), true } },
  { "/get_all_aliases", { jsonMethod<COMMAND_RPC_GET_ALL_ALIASES>(&RpcServer::on_get_all_aliases), true } },

  // ZK prover data endpoints
  { "/get_block_range", { jsonMethod<COMMAND_RPC_GET_BLOCK_RANGE>(&RpcServer::on_get_block_range), false } },
  { "/get_commitment_leaves", { jsonMethod<COMMAND_RPC_GET_COMMITMENT_LEAVES>(&RpcServer::on_get_commitment_leaves), false } },

  // Commitment Index endpoints (bridge support)
  { "/get_commitment", { jsonMethod<COMMAND_RPC_GET_COMMITMENT>(&RpcServer::on_get_commitment), true } },
  { "/get_commitment_stats", { jsonMethod<COMMAND_RPC_GET_COMMITMENT_STATS>(&RpcServer::on_get_commitment_stats), true } },
  { "/get_commitment_merkle_root", { jsonMethod<COMMAND_RPC_GET_COMMITMENT_MERKLE_ROOT>(&RpcServer::on_get_commitment_merkle_root), true } },
  { "/get_commitment_merkle_proof", { jsonMethod<COMMAND_RPC_GET_COMMITMENT_MERKLE_PROOF>(&RpcServer::on_get_commitment_merkle_proof), true } },
  { "/check_commitment_exists", { jsonMethod<COMMAND_RPC_CHECK_COMMITMENT_EXISTS>(&RpcServer::on_check_commitment_exists), true } },

  // Fee pool analytics + treasury
  { "/get_fee_pool_info", { jsonMethod<COMMAND_RPC_GET_FEE_POOL_INFO>(&RpcServer::on_get_fee_pool_info), true } },
  { "/get_epoch_history", { jsonMethod<COMMAND_RPC_GET_EPOCH_HISTORY>(&RpcServer::on_get_epoch_history), true } },
  { "/estimate_cd_yield", { jsonMethod<COMMAND_RPC_ESTIMATE_CD_YIELD>(&RpcServer::on_estimate_cd_yield), true } },
  { "/get_treasury_info", { jsonMethod<COMMAND_RPC_GET_TREASURY_INFO>(&RpcServer::on_get_treasury_info), true } },

  // Wallet Auto-Rollover + Compound Interest
  { "/get_maturing_deposits", { jsonMethod<COMMAND_RPC_GET_MATURING_DEPOSITS>(&RpcServer::on_get_maturing_deposits), true } },
  { "/rollover_deposit", { jsonMethod<COMMAND_RPC_ROLLOVER_DEPOSIT>(&RpcServer::on_rollover_deposit), true } },

  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, core& c, NodeServer& p2p, const ICryptoNoteProtocolQuery& protocolQuery) :
  HttpServer(dispatcher, log), logger(log, "RpcServer"), m_core(c), m_p2p(p2p), m_protocolQuery(protocolQuery) {
}

RpcServer::~RpcServer() {
}

void RpcServer::start(const std::string& address, uint16_t port) {
  HttpServer::start(address, port);
}

void RpcServer::stop() {
  HttpServer::stop();
}

void RpcServer::processRequest(const HttpRequest& request, HttpResponse& response) {
  auto url = request.getUrl();

  // Configurable CORS (opt-in). Never emit a wildcard allow-origin; browsers
  // could otherwise reach the daemon RPC cross-site (CSRF wallet/order actions).
  if (!m_cors_domain.empty()) {
    response.addHeader("Access-Control-Allow-Origin", m_cors_domain);
    response.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Swap-Token");
  }

  auto it = s_handlers.find(url);
  if (it == s_handlers.end()) {
    response.setStatus(HttpResponse::STATUS_404);
    return;
  }

  if (!it->second.allowBusyCore && !isCoreReady()) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody("Core is busy");
    return;
  }

  it->second.handler(this, request, response);
}

bool RpcServer::processJsonRpcRequest(const HttpRequest& request, HttpResponse& response) {

  using namespace JsonRpc;

  response.addHeader("Content-Type", "application/json");
  if (!m_cors_domain.empty()) {
    response.addHeader("Access-Control-Allow-Origin", m_cors_domain);
    response.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Swap-Token");
  }

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  try {
    logger(TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonMemberMethod>> jsonRpcHandlers = {
        {"getaltblockslist", {makeMemberMethod(&RpcServer::on_alt_blocks_list_json), true}},
        {"f_blocks_list_json", {makeMemberMethod(&RpcServer::f_on_blocks_list_json), false}},
        {"f_block_json", {makeMemberMethod(&RpcServer::f_on_block_json), false}},
        {"f_transaction_json", {makeMemberMethod(&RpcServer::f_on_transaction_json), false}},
        {"f_on_transactions_pool_json", {makeMemberMethod(&RpcServer::f_on_transactions_pool_json), false}},
        {"check_tx_proof", {makeMemberMethod(&RpcServer::k_on_check_tx_proof), false}},
        {"check_reserve_proof", {makeMemberMethod(&RpcServer::k_on_check_reserve_proof), false}},
        {"getblockcount", {makeMemberMethod(&RpcServer::on_getblockcount), true}},
        {"on_getblockhash", {makeMemberMethod(&RpcServer::on_getblockhash), false}},
        {"getblocktemplate", {makeMemberMethod(&RpcServer::on_getblocktemplate), false}},
        {"getcurrencyid", {makeMemberMethod(&RpcServer::on_get_currency_id), true}},
        {"submitblock", {makeMemberMethod(&RpcServer::on_submitblock), false}},
        {"getlastblockheader", {makeMemberMethod(&RpcServer::on_get_last_block_header), false}},
        {"getblockheaderbyhash", {makeMemberMethod(&RpcServer::on_get_block_header_by_hash), false}},
        {"getblockheaderbyheight", {makeMemberMethod(&RpcServer::on_get_block_header_by_height), false}}};

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.setBody(jsonResponse.getBody());
  logger(TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

bool RpcServer::restrictRPC(const bool is_restricted) {
  m_restricted_rpc = is_restricted;
  return true;
}

bool RpcServer::checkSwapControlAuth(const HttpRequest& request) const {
  // Fail-closed: if no swap-control token is configured, deny all swap-control
  // access. Operators must explicitly opt in via --swap-control-token.
  // This prevents unauthenticated placement of swap offers / orders / fee
  // changes on a daemon exposed to the network (or via CSRF).
  if (m_swapControlToken.empty()) return false;
  const auto& headers = request.getHeaders();
  auto it = headers.find("x-swap-token");
  if (it != headers.end() && it->second == m_swapControlToken) return true;
  it = headers.find("authorization");
  if (it != headers.end()) {
    const std::string& v = it->second;
    const std::string prefix = "Bearer ";
    if (v.size() > prefix.size() &&
        (v.compare(0, prefix.size(), prefix) == 0 ||
         v.compare(0, 7, "bearer ") == 0) &&
        v.substr(v.find(' ') + 1) == m_swapControlToken) {
      return true;
    }
  }
  return false;
}

bool RpcServer::enableCors(const std::string domain) {
  m_cors_domain = domain;
  return true;
}

bool RpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_p2p.get_payload_object().isSynchronized();
}

//
// Binary handlers
//

bool RpcServer::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (req.block_ids.empty()) {
    res.status = "Failed";
    return false;
  }

  // DoS guard: cap the number of block IDs accepted per request. Each ID is
  // looked up and the response can embed a full block per supplied ID.
  static const size_t MAX_BLOCK_IDS = 1000;
  if (req.block_ids.size() > MAX_BLOCK_IDS) {
    res.status = "Failed";
    return false;
  }

  if (req.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    res.status = "Failed";
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(req.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  res.current_height = totalBlockCount;
  res.start_height = startBlockIndex;

  for (const auto& blockId : supplement) {
    assert(m_core.have_block(blockId));
    auto completeBlock = m_core.getBlock(blockId);
    assert(completeBlock != nullptr);

    res.blocks.resize(res.blocks.size() + 1);
    res.blocks.back().block = asString(toBinaryArray(completeBlock->getBlock()));

    res.blocks.back().txs.reserve(completeBlock->getTransactionCount());
    for (size_t i = 0; i < completeBlock->getTransactionCount(); ++i) {
      res.blocks.back().txs.push_back(asString(toBinaryArray(completeBlock->getTransaction(i))));
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}


bool RpcServer::k_on_check_tx_proof(const K_COMMAND_RPC_CHECK_TX_PROOF::request& req, K_COMMAND_RPC_CHECK_TX_PROOF::response& res) {
	// parse txid
	Crypto::Hash txid;
	if (!parse_hash256(req.tx_id, txid)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
	}
	// parse address
	CryptoNote::AccountPublicAddress address;
	if (!m_core.currency().parseAccountAddressString(req.dest_address, address)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.dest_address + '.' };
	}
	// parse pubkey r*A & signature
	const size_t header_len = strlen("ProofV1");
	if (req.signature.size() < header_len || req.signature.substr(0, header_len) != "ProofV1") {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature header check error" };
	}
	Crypto::PublicKey rA;
	Crypto::Signature sig;
	const size_t rA_len = Tools::Base58::encode(std::string((const char *)&rA, sizeof(Crypto::PublicKey))).size();
	const size_t sig_len = Tools::Base58::encode(std::string((const char *)&sig, sizeof(Crypto::Signature))).size();
	std::string rA_decoded;
	std::string sig_decoded;
	if (!Tools::Base58::decode(req.signature.substr(header_len, rA_len), rA_decoded)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature decoding error" };
	}
	if (!Tools::Base58::decode(req.signature.substr(header_len + rA_len, sig_len), sig_decoded)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature decoding error" };
	}
	if (sizeof(Crypto::PublicKey) != rA_decoded.size() || sizeof(Crypto::Signature) != sig_decoded.size()) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature decoding error" };
	}
	memcpy(&rA, rA_decoded.data(), sizeof(Crypto::PublicKey));
	memcpy(&sig, sig_decoded.data(), sizeof(Crypto::Signature));

	// fetch tx pubkey
	Transaction tx;

	std::vector<uint32_t> out;
	std::vector<Crypto::Hash> tx_ids;
	tx_ids.push_back(txid);
	std::list<Crypto::Hash> missed_txs;
	std::list<Transaction> txs;
	m_core.getTransactions(tx_ids, txs, missed_txs, true);

	if (1 == txs.size()) {
		tx = txs.front();
	}
	else {
		throw JsonRpc::JsonRpcError{
			CORE_RPC_ERROR_CODE_WRONG_PARAM,
			"transaction wasn't found. Hash = " + req.tx_id + '.' };
	}
	CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

	Crypto::PublicKey R = getTransactionPublicKeyFromExtra(transaction.extra);
	if (R == NULL_PUBLIC_KEY)
	{
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Tx pubkey was not found" };
	}

	// check signature
	bool r = Crypto::check_tx_proof(txid, R, address.viewPublicKey, rA, sig);
	res.signature_valid = r;

	if (r) {

		// obtain key derivation by multiplying scalar 1 to the pubkey r*A included in the signature
		Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(rA, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation))
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }

    // get tx pub key
		Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(transaction.extra);

		// look for outputs
		uint64_t received(0);
		size_t keyIndex(0);
		std::vector<TransactionOutput> outputs;
		try {
			for (const TransactionOutput& o : transaction.outputs) {
				if (o.target.type() == typeid(KeyOutput)) {
					const KeyOutput out_key = boost::get<KeyOutput>(o.target);
					Crypto::PublicKey pubkey;
					derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
					if (pubkey == out_key.key) {
						received += o.amount;
						outputs.push_back(o);
					}
				}
				++keyIndex;
			}
		}
		catch (...)
		{
			throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
		}
		res.received_amount = received;
		res.outputs = outputs;

		Crypto::Hash blockHash;
		uint32_t blockHeight;
		if (m_core.getBlockContainingTx(txid, blockHash, blockHeight)) {
			res.confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
		}
	}
	else {
		res.received_amount = 0;
	}

	res.status = CORE_RPC_STATUS_OK;
	return true;
}

bool RpcServer::k_on_check_reserve_proof(const K_COMMAND_RPC_CHECK_RESERVE_PROOF::request& req, K_COMMAND_RPC_CHECK_RESERVE_PROOF::response& res) {

	// parse address
	CryptoNote::AccountPublicAddress address;
	if (!m_core.currency().parseAccountAddressString(req.address, address)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
	}

	// parse signature
	static constexpr char header[] = "ReserveProofV1";
	const size_t header_len = strlen(header);
	if (req.signature.size() < header_len || req.signature.substr(0, header_len) != header) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Signature header check error" };
	}

	std::string sig_decoded;
	if (!Tools::Base58::decode(req.signature.substr(header_len), sig_decoded)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Signature decoding error" };
	}

	BinaryArray ba;
	if (!Common::fromHex(sig_decoded, ba)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Proof decoding error" };
	}
	reserve_proof proof_decoded;
	if (!fromBinaryArray(proof_decoded, ba)) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "BinaryArray decoding error" };
	}

	std::vector<reserve_proof_entry>& proofs = proof_decoded.proofs;

	// compute signature prefix hash
	std::string prefix_data = req.message;
	prefix_data.append((const char*)&address, sizeof(CryptoNote::AccountPublicAddress));
	for (size_t i = 0; i < proofs.size(); ++i) {
		prefix_data.append((const char*)&proofs[i].key_image, sizeof(Crypto::PublicKey));
	}
	Crypto::Hash prefix_hash;
	Crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

	// fetch txes
	std::vector<Crypto::Hash> transactionHashes;
	for (size_t i = 0; i < proofs.size(); ++i) {
		transactionHashes.push_back(proofs[i].txid);
	}
	std::list<Hash> missed_txs;
	std::list<Transaction> txs;
	m_core.getTransactions(transactionHashes, txs, missed_txs);
	std::vector<Transaction> transactions;
	std::copy(txs.begin(), txs.end(), std::inserter(transactions, transactions.end()));

	// check spent status
	res.total = 0;
	res.spent = 0;
	for (size_t i = 0; i < proofs.size(); ++i) {
		const reserve_proof_entry& proof = proofs[i];

		CryptoNote::TransactionPrefix tx = *static_cast<const TransactionPrefix*>(&transactions[i]);

		if (proof.index_in_tx >= tx.outputs.size()) {
			throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "index_in_tx is out of bound" };
		}

		const KeyOutput out_key = boost::get<KeyOutput>(tx.outputs[proof.index_in_tx].target);

		// get tx pub key
		Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);

		// check singature for shared secret
		if (!Crypto::check_tx_proof(prefix_hash, address.viewPublicKey, txPubKey, proof.shared_secret, proof.shared_secret_sig)) {
			//throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check singature for shared secret" };
			res.good = false;
			return true;
		}

		// check signature for key image
		const std::vector<const Crypto::PublicKey *>& pubs = { &out_key.key };
		if (!Crypto::check_ring_signature(prefix_hash, proof.key_image, &pubs[0], 1, &proof.key_image_sig)) {
			//throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check signature for key image" };
			res.good = false;
			return true;
		}

		// check if the address really received the funds
		Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(proof.shared_secret, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation))
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }
    try {
			Crypto::PublicKey pubkey;
			derive_public_key(derivation, proof.index_in_tx, address.spendPublicKey, pubkey);
			if (pubkey == out_key.key) {
				uint64_t amount = tx.outputs[proof.index_in_tx].amount;
				res.total += amount;

				if (m_core.is_key_image_spent(proof.key_image)) {
					res.spent += amount;
				}
			}
		}
		catch (...)
		{
			throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
		}

	}

	// check signature for address spend keys
	Crypto::Signature sig = proof_decoded.signature;
	if (!Crypto::check_signature(prefix_hash, address.spendPublicKey, sig)) {
		res.good = false;
		return true;
	}

  res.good = true;

	return true;
}
bool RpcServer::on_get_deposits(const COMMAND_RPC_GET_DEPOSITS::request& req, COMMAND_RPC_GET_DEPOSITS::response& res) {
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_is_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res) {
  if (req.key_image.size() != 64) {
    res.status = "Failed";
    return true;
  }
  Crypto::KeyImage image;
  size_t size;
  if (!Common::fromHex(req.key_image, &image, sizeof(image), size) || size != sizeof(image)) {
    res.status = "Failed";
    return true;
  }
  res.spent = m_core.is_key_image_spent(image);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(req.block_ids, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.start_height = startHeight;
  res.current_height = currentHeight;
  res.full_offset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;
  if (!m_core.queryBlocksLite(req.blockIds, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.startHeight = startHeight;
  res.currentHeight = currentHeight;
  res.fullOffset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::setFeeAddress(const std::string& fee_address, const AccountPublicAddress& fee_acc) {
  m_fee_address = fee_address;
  m_fee_acc = fee_acc;
  return true;
}

bool RpcServer::setViewKey(const std::string& view_key) {
  Crypto::Hash private_view_key_hash;
  size_t size;
  if (!Common::fromHex(view_key, &private_view_key_hash, sizeof(private_view_key_hash), size) || size != sizeof(private_view_key_hash)) {
    logger(INFO) << "<< rpcserver.cpp << " << "Could not parse private view key";
    return false;
  }
  m_view_key = *(struct Crypto::SecretKey *) &private_view_key_hash;
  return true;
}

bool RpcServer::on_get_fee_address(const COMMAND_RPC_GET_FEE_ADDRESS::request& req, COMMAND_RPC_GET_FEE_ADDRESS::response& res) {
  if (m_fee_address.empty()) {
	  res.status = CORE_RPC_STATUS_OK;
	  return false;
  }
  res.fee_address = m_fee_address;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res) {
  std::vector<uint32_t> outputIndexes;
  if (!m_core.get_tx_outputs_gindexs(req.txid, outputIndexes)) {
    res.status = "Failed";
    return true;
  }

  res.o_indexes.assign(outputIndexes.begin(), outputIndexes.end());
  res.status = CORE_RPC_STATUS_OK;
  logger(TRACE) << "COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]";
  return true;
}

bool RpcServer::on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) {
  res.status = "Failed";
  if (!m_core.get_random_outs_for_amounts(req, res)) {
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;

  std::stringstream ss;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;

  std::for_each(res.outs.begin(), res.outs.end(), [&](outs_for_amount& ofa)  {
    ss << "[" << ofa.amount << "]:";

    assert(ofa.outs.size() && "internal error: ofa.outs.size() is empty");

    std::for_each(ofa.outs.begin(), ofa.outs.end(), [&](out_entry& oe)
    {
      ss << oe.global_amount_index << " ";
    });
    ss << ENDL;
  });
  std::string s = ss.str();
  logger(TRACE) << "COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS: " << ENDL << s;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_random_commitment_outs(const COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::request& req,
                                                COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::response& res) {
  res.status = "Failed";
  if (!m_core.get_random_commitment_outs_for_amount(req.amount, req.outs_count, req.max_height, res.outs)) {
    return true;
  }
  res.status = CORE_RPC_STATUS_OK;
  logger(TRACE) << "COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS: amount=" << req.amount
                << " requested=" << req.outs_count << " returned=" << res.outs.size()
                << " max_height=" << req.max_height;
  return true;
}

bool RpcServer::on_get_random_outs_json(const COMMAND_RPC_GET_RANDOM_OUTPUTS_JSON::request& req,
                                         COMMAND_RPC_GET_RANDOM_OUTPUTS_JSON::response& res) {
  res.status = "Failed";

  // Delegate to the same core logic as the binary endpoint.
  COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request binReq;
  binReq.amounts.push_back(req.amount);
  binReq.outs_count = req.count;

  COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response binRes;
  if (!m_core.get_random_outs_for_amounts(binReq, binRes)) {
    return true;
  }

  // Convert packed binary entries to JSON-friendly format.
  for (const auto& ofa : binRes.outs) {
    for (const auto& entry : ofa.outs) {
      COMMAND_RPC_GET_RANDOM_OUTPUTS_JSON::out_entry je;
      je.global_index = entry.global_amount_index;
      je.out_key = Common::podToHex(entry.out_key);
      res.outs.push_back(std::move(je));
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_outputs_json(const COMMAND_RPC_GET_OUTPUTS_JSON::request& req,
                                    COMMAND_RPC_GET_OUTPUTS_JSON::response& res) {
  res.status = "Failed";
  if (req.indexes.size() > 64) {
    res.status = "Too many indexes";
    return true;
  }

  std::vector<Crypto::PublicKey> keys;
  if (!m_core.get_outs_for_amount(req.amount, req.indexes, keys)) {
    return true;
  }

  res.outs.reserve(keys.size());
  for (size_t i = 0; i < keys.size(); ++i) {
    COMMAND_RPC_GET_OUTPUTS_JSON::out_entry entry;
    entry.global_index = req.indexes[i];
    entry.out_key = Common::podToHex(keys[i]);
    res.outs.push_back(std::move(entry));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetPoolChanges(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  std::vector<CryptoNote::Transaction> addedTransactions;
  rsp.isTailBlockActual = m_core.getPoolChanges(req.tailBlockId, req.knownTxsIds, addedTransactions, rsp.deletedTxsIds);
  for (auto& tx : addedTransactions) {
    BinaryArray txBlob;
    if (!toBinaryArray(tx, txBlob)) {
      rsp.status = "Internal error";
      break;;
    }

    rsp.addedTxs.emplace_back(std::move(txBlob));
  }
  return true;
}


bool RpcServer::onGetPoolChangesLite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  rsp.isTailBlockActual = m_core.getPoolChangesLite(req.tailBlockId, req.knownTxsIds, rsp.addedTxs, rsp.deletedTxsIds);

  return true;
}

//
// JSON handlers
//


bool RpcServer::on_get_peer_list(
    const COMMAND_RPC_GET_PEER_LIST::request& req,
    COMMAND_RPC_GET_PEER_LIST::response& res) {
  // Peer IPs are sensitive: exposes node topology for targeted DDoS/Eclipse.
  // Only expose when the daemon is not in restricted mode.
  if (m_restricted_rpc) {
    res.status = "Failed, restricted handle";
    return false;
  }

	std::list<PeerlistEntry> pl_wite;
	std::list<PeerlistEntry> pl_gray;
	m_p2p.getPeerlistManager().get_peerlist_full(pl_gray, pl_wite);
	for (const auto& pe : pl_wite) {
		std::stringstream ss;
		ss << pe.adr;
		res.peers.push_back(ss.str());
	}
	res.status = CORE_RPC_STATUS_OK;
	return true;
}

bool RpcServer::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res) {
  res.height = m_core.get_current_blockchain_height();
  res.difficulty = m_core.getNextBlockDifficulty();
  res.tx_count = m_core.get_blockchain_total_transactions() - res.height; //without coinbase
  res.tx_pool_size = m_core.get_pool_transactions_count();
  res.alt_blocks_count = m_core.get_alternative_blocks_count();
  res.fee_address = m_fee_address.empty() ? std::string() : m_fee_address;
  uint64_t total_conn = m_p2p.get_connections_count();
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = total_conn - res.outgoing_connections_count;
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  res.full_deposit_amount = m_core.fullDepositAmount();
  res.ethereal_xfg = m_core.getBurnedXfgAtHeight(m_core.get_current_blockchain_height() - 1);
  res.status = CORE_RPC_STATUS_OK;
  Crypto::Hash last_block_hash = m_core.getBlockIdByHeight(m_core.get_current_blockchain_height() - 1);
  res.top_block_hash = Common::podToHex(last_block_hash);
  res.version = PROJECT_VERSION;

  Block blk;
  if (!m_core.getBlockByHash(last_block_hash, blk)) {
	  throw JsonRpc::JsonRpcError{
		CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
		"Internal error: can't get last block by hash." };
  }

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
	  throw JsonRpc::JsonRpcError{
		CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
		"Internal error: coinbase transaction in the block has the wrong type" };
  }

  block_header_response block_header;
  uint32_t last_block_height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;

  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(last_block_height);
  bool is_orphaned = last_block_hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, last_block_height, last_block_hash, block_header);

  res.block_major_version = block_header.major_version;
  res.block_minor_version = block_header.minor_version;
  res.last_block_timestamp = block_header.timestamp;
  res.last_block_reward = block_header.reward;
  m_core.getBlockDifficulty(static_cast<uint32_t>(last_block_height), res.last_block_difficulty);

  res.connections = m_p2p.get_payload_object().all_connections();
  return true;
}

bool RpcServer::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res) {
  res.height = m_core.get_current_blockchain_height();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

//-----------------------------------------------
// Swap orderbook RPC handlers
//-----------------------------------------------

void RpcServer::setSwapRelay(SwapOfferRelay* relay) {
  m_swapRelay = relay;
}

void RpcServer::setSwapDb(XfgSwap::SwapDatabase* db) {
  m_swapDb = db;
}

void RpcServer::setSwapDaemon(XfgSwap::SwapDaemon* daemon) {
  m_swapDaemon = daemon;
}

bool RpcServer::on_get_active_swaps(const COMMAND_RPC_GET_ACTIVE_SWAPS::request& /*req*/, COMMAND_RPC_GET_ACTIVE_SWAPS::response& res) {
  if (!m_swapDb) {
    res.status = "Swap database not available";
    return true;
  }

  auto swapIds = m_swapDb->listSwaps();
  for (const auto& id : swapIds) {
    XfgSwap::SwapStateMachine sm;
    if (!m_swapDb->loadSwap(id, sm)) continue;
    if (sm.isTerminal()) continue;

    const auto& p = sm.params();
    COMMAND_RPC_GET_ACTIVE_SWAPS::swap_entry entry;
    entry.swap_id    = p.swapId;
    entry.state      = XfgSwap::swapStateToString(sm.currentState());
    entry.pair       = XfgSwap::swapPairToString(p.pair);
    entry.role       = (p.role == XfgSwap::SwapRole::BOB) ? "BOB" : "ALICE";
    entry.xfg_amount    = p.xfgAmount;
    entry.ctr_address   = p.ctrAddress;
    entry.peer_endpoint = p.peerEndpoint;
    entry.updated_at    = static_cast<uint64_t>(sm.updatedAt());
    res.swaps.push_back(std::move(entry));
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_initiate_swap(const COMMAND_RPC_INITIATE_SWAP::request& req, COMMAND_RPC_INITIATE_SWAP::response& res) {
  if (!m_swapDaemon) {
    res.status = "Swap daemon not available";
    return true;
  }

  XfgSwap::SwapParams params;
  params.pair        = XfgSwap::swapPairFromString(req.pair);
  params.role        = XfgSwap::SwapRole::BOB;
  params.xfgAmount   = req.xfg_amount;
  params.ctrAmount   = req.ctr_amount;
  params.ctrAddress  = req.ctr_address;
  params.peerEndpoint = req.peer_endpoint;

  if (!req.peer_pub_key.empty()) {
    if (!Common::fromHex(req.peer_pub_key,
                         &params.peerSwapPubKey,
                         sizeof(params.peerSwapPubKey))) {
      res.status = "Invalid peer_pub_key";
      return true;
    }
  }

  if (!m_swapDaemon->initiate(params)) {
    res.status = "Failed to initiate swap";
    return true;
  }

  res.swap_id = params.swapId;
  res.status  = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_accept_swap(const COMMAND_RPC_ACCEPT_SWAP::request& req, COMMAND_RPC_ACCEPT_SWAP::response& res) {
  if (!m_swapDaemon) {
    res.status = "Swap daemon not available";
    return true;
  }

  XfgSwap::SwapDaemon::AcceptResult result = m_swapDaemon->accept(req.swap_id);
  if (!result.success) {
    res.status = result.warning.empty() ? "Failed to accept swap" : result.warning;
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_process_swap(const COMMAND_RPC_PROCESS_SWAP::request& req, COMMAND_RPC_PROCESS_SWAP::response& res) {
  if (!m_swapDaemon) {
    res.status = "Swap daemon not available";
    return true;
  }

  bool advanced = m_swapDaemon->processSwap(req.swap_id);
  res.advanced = advanced;

  if (m_swapDb) {
    XfgSwap::SwapStateMachine sm;
    if (m_swapDb->loadSwap(req.swap_id, sm)) {
      res.new_state = XfgSwap::swapStateToString(sm.currentState());
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_refund_swap(const COMMAND_RPC_REFUND_SWAP::request& req, COMMAND_RPC_REFUND_SWAP::response& res) {
  if (!m_swapDaemon) {
    res.status = "Swap daemon not available";
    return true;
  }

  if (!m_swapDaemon->refund(req.swap_id)) {
    res.status = "Failed to refund swap (timeout may not have elapsed)";
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_list_swaps(const COMMAND_RPC_LIST_SWAPS::request& /*req*/, COMMAND_RPC_LIST_SWAPS::response& res) {
  if (!m_swapDb) {
    res.status = "Swap database not available";
    return true;
  }

  auto swapIds = m_swapDb->listSwaps();
  res.swaps.reserve(swapIds.size());

  for (const auto& id : swapIds) {
    XfgSwap::SwapStateMachine sm;
    if (!m_swapDb->loadSwap(id, sm)) continue;

    const auto& p = sm.params();
    COMMAND_RPC_LIST_SWAPS::response::swap_summary entry;
    entry.swap_id    = p.swapId;
    entry.state      = XfgSwap::swapStateToString(sm.currentState());
    entry.pair       = XfgSwap::swapPairToString(p.pair);
    entry.role       = (p.role == XfgSwap::SwapRole::BOB) ? "BOB" : "ALICE";
    entry.xfg_amount = p.xfgAmount;
    entry.created_at = static_cast<uint64_t>(sm.createdAt());
    entry.updated_at = static_cast<uint64_t>(sm.updatedAt());
    entry.is_terminal = sm.isTerminal();
    res.swaps.push_back(std::move(entry));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_swap_status(const COMMAND_RPC_GET_SWAP_STATUS::request& req, COMMAND_RPC_GET_SWAP_STATUS::response& res) {
  if (!m_swapDb) {
    res.status = "Swap database not available";
    res.found = false;
    return true;
  }

  XfgSwap::SwapStateMachine sm;
  if (!m_swapDb->loadSwap(req.swap_id, sm)) {
    res.swap_id = req.swap_id;
    res.found   = false;
    res.status  = "Swap not found";
    return true;
  }

  const auto& p = sm.params();
  res.swap_id       = p.swapId;
  res.state         = XfgSwap::swapStateToString(sm.currentState());
  res.pair          = XfgSwap::swapPairToString(p.pair);
  res.role          = (p.role == XfgSwap::SwapRole::BOB) ? "BOB" : "ALICE";
  res.xfg_amount    = p.xfgAmount;
  res.ctr_address   = p.ctrAddress;
  res.peer_endpoint = p.peerEndpoint;
  res.created_at    = static_cast<uint64_t>(sm.createdAt());
  res.updated_at    = static_cast<uint64_t>(sm.updatedAt());
  res.is_terminal   = sm.isTerminal();
  res.found         = true;
  res.status        = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_swap_offers(const COMMAND_RPC_GET_SWAP_OFFERS::request& req, COMMAND_RPC_GET_SWAP_OFFERS::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }

  auto offers = m_swapRelay->getOffers(req.pair);
  res.offers.reserve(offers.size());
  for (const auto& o : offers) {
    swap_offer_rpc_entry entry;
    entry.offerId     = o.offerId;
    entry.xfgAmount   = o.xfgAmount;
    entry.rateNum     = o.rateNum;
    entry.pair        = o.pair;
    entry.makerPubKey = Common::podToHex(o.makerPubKey);
    entry.timestamp   = o.timestamp;
    entry.ttlBlocks   = o.ttlBlocks;
    entry.postedHeight = o.postedHeight;
    res.offers.push_back(std::move(entry));
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_swap_price(const COMMAND_RPC_GET_SWAP_PRICE::request& req, COMMAND_RPC_GET_SWAP_PRICE::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }

  // Per-pair TWAP + seed
  double twap = m_swapRelay->getTwap(req.pair);
  double seed = SwapOfferRelay::getSeedRate(req.pair);
  res.twap = std::to_string(twap);
  res.seedRate = std::to_string(seed);

  // Composite price with source breakdown
  CompositePrice cp = m_swapRelay->getCompositePrice(req.pair);
  res.compositeRate = std::to_string(cp.rate);
  res.sourceCount   = static_cast<uint32_t>(cp.sourceCount);

  for (const auto& src : cp.sources) {
    price_source_rpc_entry e;
    e.name      = src.name;
    e.pair      = src.pair;
    e.weight    = std::to_string(src.weight);
    e.rate      = std::to_string(src.rate);
    e.updatedAt = src.updatedAt;
    e.stale     = src.stale;
    res.sources.push_back(std::move(e));
  }

  // Cross-pair native XFG price range
  NativeXfgPriceRange range = m_swapRelay->getNativeXfgPrice();
  res.xfgUsdLow  = std::to_string(range.lowUsd);
  res.xfgUsdHigh = std::to_string(range.highUsd);
  res.xfgUsdMid  = std::to_string(range.midUsd);

  for (const auto& kv : range.pairImplied) {
    pair_implied_rpc_entry e;
    e.pair       = kv.first;
    e.impliedUsd = std::to_string(kv.second);
    res.pairImplied.push_back(std::move(e));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_swap_trades(const COMMAND_RPC_GET_SWAP_TRADES::request& req, COMMAND_RPC_GET_SWAP_TRADES::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }

  uint32_t limit = req.limit;
  if (limit == 0 || limit > 200) limit = 50;

  auto trades = m_swapRelay->getRecentTrades(req.pair, limit);
  res.trades.reserve(trades.size());
  for (const auto& t : trades) {
    swap_trade_rpc_entry entry;
    entry.pair        = t.pair;
    entry.xfgAmount   = t.xfgAmount;
    entry.ctrAmount   = t.ctrAmount;
    entry.rate        = std::to_string(t.rate);
    entry.blockHeight = t.blockHeight;
    entry.timestamp   = t.timestamp;
    res.trades.push_back(std::move(entry));
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_submit_swap_offer(const COMMAND_RPC_SUBMIT_SWAP_OFFER::request& req, COMMAND_RPC_SUBMIT_SWAP_OFFER::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }

  // Parse hex pubkey
  Crypto::PublicKey pubkey;
  if (!Common::podFromHex(req.makerPubKey, pubkey)) {
    res.status = "Invalid makerPubKey hex";
    return true;
  }

  // Parse hex signature
  Crypto::Signature sig;
  if (!Common::podFromHex(req.signature, sig)) {
    res.status = "Invalid signature hex";
    return true;
  }

  // Build offer message
  SwapOfferMsg offer;
  offer.offerId     = req.offerId;
  offer.isSell      = true;
  offer.xfgAmount   = req.xfgAmount;
  offer.rateNum     = req.rateNum;
  offer.pair        = req.pair;
  offer.makerPubKey = pubkey;
  offer.signature   = sig;
  // The canonical signature covers the timestamp — honor the client's
  // signed value; fall back to server time for legacy callers.
  offer.timestamp   = (req.timestamp != 0) ? req.timestamp
                                           : static_cast<uint64_t>(std::time(nullptr));
  offer.ttlBlocks   = req.ttlBlocks;
  offer.isSoftOrder = req.isSoftOrder;
  offer.allowedSlippagePct = 0;

  // Set postedHeight to current height
  uint32_t height = 0;
  Crypto::Hash topId;
  m_core.get_blockchain_top(height, topId);
  offer.postedHeight = height;

  if (!m_swapRelay->submitOffer(offer)) {
    res.status = "Offer rejected (invalid signature or duplicate)";
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_cancel_swap_offer(const COMMAND_RPC_CANCEL_SWAP_OFFER::request& req, COMMAND_RPC_CANCEL_SWAP_OFFER::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }

  Crypto::PublicKey pubkey;
  if (!Common::podFromHex(req.makerPubKey, pubkey)) {
    res.status = "Invalid makerPubKey hex";
    return true;
  }

  Crypto::Signature sig;
  if (!Common::podFromHex(req.signature, sig)) {
    res.status = "Invalid signature hex";
    return true;
  }

  m_swapRelay->cancelOffer(req.offerId, pubkey, sig, req.timestamp);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_request_swap(const COMMAND_RPC_REQUEST_SWAP::request& req, COMMAND_RPC_REQUEST_SWAP::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }
  if (req.offerId.empty()) {
    res.status = "offerId is required";
    return true;
  }
  // Taker identity: 64-char hex Ed25519 public key. The maker's SwapDaemon
  // binds this as expectedPeerSwapPubKey for the resulting AFK swap.
  if (req.takerPubKey.size() != 64) {
    res.status = "takerPubKey must be 64 hex chars (Ed25519 public key)";
    return true;
  }
  for (char c : req.takerPubKey) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      res.status = "takerPubKey must be hex";
      return true;
    }
  }
  // Reserve proof is mandatory — the maker verifies it against the chain
  // before locking funds. Empty proofs are rejected here (fail fast).
  if (req.proofOfFunds.empty()) {
    res.status = "proofOfFunds is required (chain reserve proof bound to offerId)";
    return true;
  }

  // Echo the offer's pair + amount so the taker can drive its local swap
  // daemon after the maker locks (informational only).
  for (int pair = 0; pair <= static_cast<int>(XfgSwap::SwapPair::ZANO); ++pair) {
    auto offers = m_swapRelay->getOffers(static_cast<uint8_t>(pair));
    for (const auto& offer : offers) {
      if (offer.offerId == req.offerId) {
        res.pair = pair;
        res.xfgAmount = offer.xfgAmount;
        break;
      }
    }
  }

  // Queue for the local maker's SwapDaemon tick AND gossip to all peers so
  // the request reaches the maker's node wherever it is. The maker verifies
  // the reserve proof on-chain and creates the AFK lock for this taker.
  m_swapRelay->submitSwapRequest(req.offerId, req.amount, req.takerPubKey, req.proofOfFunds);

  res.status = "pending";
  res.offerId = req.offerId;
  return true;
}

bool RpcServer::on_get_swap_requests(const COMMAND_RPC_GET_SWAP_REQUESTS::request& req, COMMAND_RPC_GET_SWAP_REQUESTS::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }
  if (req.takerPubKey.size() != 64) {
    res.status = "takerPubKey must be 64 hex chars";
    return true;
  }
  for (char c : req.takerPubKey) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      res.status = "takerPubKey must be hex";
      return true;
    }
  }

  auto results = m_swapRelay->getSwapRequestResults(req.takerPubKey);
  for (const auto& r : results) {
    swap_request_result_entry e;
    e.offerId = r.offerId;
    e.lockId = r.lockId;
    e.makerEndpoint = r.makerEndpoint;
    e.adaptorPoint = r.adaptorPoint;
    e.hashLock = r.hashLock;
    e.preSig = r.preSig;
    e.ctrAddress = r.ctrAddress;
    e.createdAt = static_cast<uint64_t>(r.createdAt);
    res.requests.push_back(std::move(e));
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// v2 Orderbook RPC handlers
// ═══════════════════════════════════════════════════════════════════════════════

bool RpcServer::on_get_order_book(const COMMAND_RPC_GET_ORDER_BOOK::request& req, COMMAND_RPC_GET_ORDER_BOOK::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }

  auto snap = m_swapRelay->getOrderBookSnapshot(req.pair, req.depth);
  res.bids.reserve(snap.bids.size());
  for (const auto& lvl : snap.bids) {
    COMMAND_RPC_GET_ORDER_BOOK::response::OrderBookLevelJson j;
    j.price      = lvl.price;
    j.amount     = lvl.amount;
    j.orderCount = lvl.orderCount;
    res.bids.push_back(std::move(j));
  }
  res.asks.reserve(snap.asks.size());
  for (const auto& lvl : snap.asks) {
    COMMAND_RPC_GET_ORDER_BOOK::response::OrderBookLevelJson j;
    j.price      = lvl.price;
    j.amount     = lvl.amount;
    j.orderCount = lvl.orderCount;
    res.asks.push_back(std::move(j));
  }
  res.spread = snap.spread;
  res.height = snap.height;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_place_order(const COMMAND_RPC_PLACE_ORDER::request& req, COMMAND_RPC_PLACE_ORDER::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }
  if (m_restricted_rpc) {
    res.status = "Failed, restricted handle";
    return true;
  }

  // DoS guard: bound the order-placement rate so a single client cannot fill
  // the orderbook with valid-but-useless orders (spam / griefing).
  static const uint32_t MAX_ORDER_SUBMITS_PER_SEC = 20;
  if (!rateLimit(m_lastOrderSubmitWindow, m_orderSubmitCount, MAX_ORDER_SUBMITS_PER_SEC)) {
    res.status = "Order rate limit exceeded";
    return true;
  }

  if (req.pair > 7 || req.side > 1) {
    res.status = "Invalid pair or side";
    return true;
  }
  if (req.amount == 0 || req.price == 0) {
    res.status = "Amount and price must be > 0";
    return true;
  }
  if (req.orderId.empty() || req.makerPubKey.empty() || req.signature.empty()) {
    res.status = "Signed order required (orderId, makerPubKey, signature, nonce)";
    return true;
  }

  CryptoNote::SwapOrder order;
  order.side = static_cast<CryptoNote::SwapOrder::Side>(req.side);
  order.pair = req.pair;
  order.price = req.price;
  order.amount = req.amount;
  order.ttlBlocks = req.ttlBlocks ? req.ttlBlocks : 8640;
  order.orderId = req.orderId;
  order.nonce = req.nonce;
  order.timestamp = req.timestamp;
  order.filled = 0;
  if (!Common::podFromHex(req.makerPubKey, order.makerPubKey)) {
    res.status = "Invalid makerPubKey";
    return true;
  }
  if (!Common::podFromHex(req.signature, order.signature)) {
    res.status = "Invalid signature";
    return true;
  }

  uint64_t filled = 0;
  bool ok = m_swapRelay->placeSignedOrder(order, &filled);
  if (!ok) {
    res.status = "Order rejected (bad signature, replay, or limits)";
    return true;
  }

  res.orderId   = order.orderId;
  res.filled    = filled;
  res.status    = CORE_RPC_STATUS_OK;
  res.statusMsg = "Order placed";
  return true;
}

bool RpcServer::on_cancel_order(const COMMAND_RPC_CANCEL_ORDER::request& req, COMMAND_RPC_CANCEL_ORDER::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }
  if (m_restricted_rpc) {
    res.status = "Failed, restricted handle";
    return true;
  }
  if (req.orderId.empty() || req.makerPubKey.empty() || req.signature.empty()) {
    res.status = "Signed cancel required (orderId, makerPubKey, signature)";
    return true;
  }

  Crypto::PublicKey pubkey;
  Crypto::Signature sig;
  if (!Common::podFromHex(req.makerPubKey, pubkey) || !Common::podFromHex(req.signature, sig)) {
    res.status = "Invalid makerPubKey or signature hex";
    return true;
  }

  bool ok = m_swapRelay->cancelOrderByClient(req.orderId, pubkey, sig, req.timestamp);
  res.status = ok ? CORE_RPC_STATUS_OK : "Cancel rejected (bad sig or not found)";
  return true;
}

bool RpcServer::on_get_open_orders(const COMMAND_RPC_GET_OPEN_ORDERS::request& req, COMMAND_RPC_GET_OPEN_ORDERS::response& res) {
  if (!m_swapRelay) {
    res.status = "Swap relay not running";
    return true;
  }

  // Return all orders for now (address filter not yet implemented)
  for (int pair = 0; pair < 8; ++pair) {
    auto snap = m_swapRelay->getOrderBookSnapshot(pair, 1000);
    for (const auto& lvl : snap.bids) {
      (void)lvl;
    }
    for (const auto& lvl : snap.asks) {
      (void)lvl;
    }
  }

  // TODO: implement per-address filtering using m_clientOrders
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_ethereal_flame(const COMMAND_RPC_GET_ETHERNAL_FLAME::request& req, COMMAND_RPC_GET_ETHERNAL_FLAME::response& res) {
  uint64_t current_height = m_core.get_current_blockchain_height();
  res.ethereal_xfg = m_core.getBurnedXfgAtHeight(current_height);
  res.formattedAmount = m_core.currency().formatAmount(res.ethereal_xfg) + " XFG";
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res) {
  // DoS guard: cap the number of tx hashes per request; each matching tx is
  // fully serialized to hex in the response.
  static const size_t MAX_TX_HASHES = 100;
  if (req.txs_hashes.size() > MAX_TX_HASHES) {
    res.status = "Failed";
    return true;
  }

  std::vector<Hash> vh;
  for (const auto& tx_hex_str : req.txs_hashes) {
    BinaryArray b;
    if (!fromHex(tx_hex_str, b))
    {
      res.status = "Failed to parse hex representation of transaction hash";
      return true;
    }
    if (b.size() != sizeof(Hash))
    {
      res.status = "Failed, size of data mismatch";
      return true;
    }
    vh.push_back(*reinterpret_cast<const Hash*>(b.data()));
  }
  std::list<Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(vh, txs, missed_txs);

  for (auto& tx : txs) {
    res.txs_as_hex.push_back(toHex(toBinaryArray(tx)));
  }

  for (const auto& miss_tx : missed_txs) {
    res.missed_tx.push_back(Common::podToHex(miss_tx));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res) {
  // DoS guard: bound the rate of raw-tx submissions per second. Transaction
  // validation and pool insertion are CPU-heavy; an unthrottled client can
  // flood the node.
  static const uint32_t MAX_TX_SUBMITS_PER_SEC = 20;
  if (!rateLimit(m_lastTxSubmitWindow, m_txSubmitCount, MAX_TX_SUBMITS_PER_SEC)) {
    logger(WARNING) << "on_send_raw_tx: rate limit exceeded, rejecting";
    res.status = "Failed";
    return true;
  }

  BinaryArray tx_blob;
  if (!fromHex(req.tx_as_hex, tx_blob))
  {
    logger(INFO) << "<< rpcserver.cpp << " << "[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex;
    res.status = "Failed";
    return true;
  }

  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  if (!m_core.handle_incoming_tx(tx_blob, tvc, false))
  {
    logger(INFO) << "<< rpcserver.cpp << " << "[on_send_raw_tx]: Failed to process tx";
    res.status = "Failed";
    return true;
  }

  if (tvc.m_verification_failed)
  {
    logger(INFO) << "<< rpcserver.cpp << " << "[on_send_raw_tx]: tx verification failed";
    res.status = "Failed";
    return true;
  }

  if (!tvc.m_should_be_relayed)
  {
    logger(INFO) << "<< rpcserver.cpp << " << "[on_send_raw_tx]: tx accepted, but not relayed";
    res.status = "Not relayed";
    return true;
  }

  /* check tx for node fee

  if (!m_fee_address.empty() && m_view_key != NULL_SECRET_KEY) {
    if (!remotenode_check_incoming_tx(tx_blob)) {
      logger(INFO) << "<< rpcserver.cpp << " << "Transaction not relayed due to lack of remote node fee";
      res.status = "Not relayed due to lack of node fee";
      return true;
    }
  }

  */

  NOTIFY_NEW_TRANSACTIONS::request r;
  r.txs.push_back(asString(tx_blob));
  m_core.get_protocol()->relay_transactions(r);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res) {
  if (m_restricted_rpc) {
        res.status = "Failed, restricted handle";
        return false;
  }
  AccountPublicAddress adr;
  if (!m_core.currency().parseAccountAddressString(req.miner_address, adr)) {
    res.status = "Failed, wrong address";
    return true;
  }

  if (!m_core.get_miner().start(adr, static_cast<size_t>(req.threads_count))) {
    res.status = "Failed, mining not started";
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

/*

bool RpcServer::remotenode_check_incoming_tx(const BinaryArray& tx_blob) {
	Crypto::Hash tx_hash = NULL_HASH;
	Crypto::Hash tx_prefixt_hash = NULL_HASH;
	Transaction tx;
	if (!parseAndValidateTransactionFromBinaryArray(tx_blob, tx, tx_hash, tx_prefixt_hash)) {
		logger(INFO) << "<< rpcserver.cpp << " << "Could not parse tx from blob";
		return false;
	}
	CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

	std::vector<uint32_t> out;
	uint64_t amount;

	if (!CryptoNote::findOutputsToAccount(transaction, m_fee_acc, m_view_key, out, amount)) {
		logger(INFO) << "<< rpcserver.cpp << " << "Could not find outputs to remote node fee address";
		return false;
	}

	if (amount != 0) {
		logger(INFO) << "<< rpcserver.cpp << " << "Node received relayed transaction fee: " << m_core.currency().formatAmount(amount) << " KRB";
		return true;
	}
	return false;
}

*/

bool RpcServer::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res) {
  if (m_restricted_rpc) {
        res.status = "Failed, restricted handle";
        return false;
  }
  if (!m_core.get_miner().stop()) {
    res.status = "Failed, mining not stopped";
    return true;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res) {
  if (m_restricted_rpc) {
        res.status = "Failed, restricted handle";
        return false;
  }
  if (m_core.currency().isTestnet()) {
    m_p2p.sendStopSignal();
    res.status = CORE_RPC_STATUS_OK;
  } else {
    res.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }
  return true;
}

bool RpcServer::on_get_payment_id(const COMMAND_RPC_GEN_PAYMENT_ID::request& req, COMMAND_RPC_GEN_PAYMENT_ID::response& res) {
  std::string pid;
  try {
    pid = Common::podToHex(Crypto::rand<Crypto::Hash>());
  } catch (const std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't generate Payment ID" };
  }
  res.payment_id = pid;
  return true;
}
//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------
bool RpcServer::f_on_blocks_list_json(const F_COMMAND_RPC_GET_BLOCKS_LIST::request& req, F_COMMAND_RPC_GET_BLOCKS_LIST::response& res) {
  if (m_core.get_current_blockchain_height() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.get_current_blockchain_height()) };
  }

  uint32_t print_blocks_count = 30;
  uint32_t last_height = req.height - print_blocks_count;
  if (req.height <= print_blocks_count)  {
    last_height = 0;
  }

  for (uint32_t i = req.height; i >= last_height; i--) {
    Hash block_hash = m_core.getBlockIdByHeight(static_cast<uint32_t>(i));
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }

    size_t tx_cumulative_block_size;
    m_core.getBlockSize(block_hash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);

    f_block_short_response block_short;
    block_short.cumul_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    block_short.timestamp = blk.timestamp;
    block_short.height = i;
    m_core.getBlockDifficulty(static_cast<uint32_t>(block_short.height), block_short.difficulty);
    block_short.hash = Common::podToHex(block_hash);
    block_short.tx_count = blk.transactionHashes.size() + 1;

    res.blocks.push_back(block_short);

    if (i == 0)
      break;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::f_on_block_json(const F_COMMAND_RPC_GET_BLOCK_DETAILS::request& req, F_COMMAND_RPC_GET_BLOCK_DETAILS::response& res) {
  Hash hash;

  if (!parse_hash256(req.hash, hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
  }

  Block blk;
  if (!m_core.getBlockByHash(hash, blk)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  block_header_response block_header; // create block_header_response object

  uint32_t block_height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;
  res.block.height = block_height;
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(block_height);
  bool is_orphaned = hash != tmp_hash; // true!=true -> false,  true!=false -> true , fase!=false --> false

  fill_block_header_response(blk, is_orphaned, res.block.height, hash, block_header); // fill up block_header object


  res.block.major_version = block_header.major_version;
  res.block.minor_version = block_header.minor_version;
  res.block.timestamp = block_header.timestamp;
  res.block.prev_hash = block_header.prev_hash;
  res.block.nonce = block_header.nonce;
  res.block.hash = Common::podToHex(hash);
  res.block.orphan_status = is_orphaned;
  res.block.depth = m_core.get_current_blockchain_height() - res.block.height - 1;
  res.block.orphan_status = block_header.orphan_status; // set orphan status from block_header object response
  res.block.difficulty = block_header.difficulty; // set difficulty from block_header object response
  res.block.reward = block_header.reward;
  //m_core.getBlockDifficulty(static_cast<uint32_t>(res.block.height), res.block.difficulty);

  std::vector<size_t> blocksSizes;
  if (!m_core.getBackwardBlocksSizes(res.block.height, blocksSizes, parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW)) {
    return false;
  }
  res.block.sizeMedian = Common::medianValue(blocksSizes);

  size_t blockSize = 0;
  if (!m_core.getBlockSize(hash, blockSize)) {
    return false;
  }
  res.block.transactionsCumulativeSize = blockSize;

  size_t blokBlobSize = getObjectBinarySize(blk);
  size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
  res.block.blockSize = blokBlobSize + res.block.transactionsCumulativeSize - minerTxBlobSize;

  uint64_t alreadyGeneratedCoins;
  if (!m_core.getAlreadyGeneratedCoins(hash, alreadyGeneratedCoins)) {
    return false;
  }
  res.block.alreadyGeneratedCoins = std::to_string(alreadyGeneratedCoins);

  if (!m_core.getGeneratedTransactionsNumber(res.block.height, res.block.alreadyGeneratedTransactions)) {
    return false;
  }

  uint64_t prevBlockGeneratedCoins = 0;
  if (res.block.height > 0) {
    if (!m_core.getAlreadyGeneratedCoins(blk.previousBlockHash, prevBlockGeneratedCoins)) {
      return false;
    }
  }
  uint64_t maxReward = 0;
  uint64_t currentReward = 0;
  int64_t emissionChange = 0;
  bool penalizeFee = blk.majorVersion >= 2;
  size_t blockGrantedFullRewardZone = m_core.currency().blockGrantedFullRewardZoneByBlockVersion(blk.majorVersion);
  res.block.effectiveSizeMedian = std::max(res.block.sizeMedian, blockGrantedFullRewardZone);

  // virtual bool getBlockReward(size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint32_t height,
                              // uint64_t& reward, int64_t& emissionChange) = 0;

  if (!m_core.getBlockReward(res.block.major_version, res.block.sizeMedian, 0, prevBlockGeneratedCoins, 0, res.block.height, maxReward, emissionChange)) {
    return false;
  }
  if (!m_core.getBlockReward(res.block.major_version, res.block.sizeMedian, res.block.transactionsCumulativeSize, prevBlockGeneratedCoins, 0, res.block.height, currentReward, emissionChange)) {
    return false;
  }

  // if (!m_core.getBlockReward(res.block.sizeMedian, 0, prevBlockGeneratedCoins, 0, penalizeFee, maxReward, emissionChange)) {
  //   return false;
  // }
  // if (!m_core.getBlockReward(res.block.sizeMedian, res.block.transactionsCumulativeSize, prevBlockGeneratedCoins, 0, penalizeFee, currentReward, emissionChange)) {
  //   return false;
  // }

  res.block.baseReward = maxReward;
  if (maxReward == 0 && currentReward == 0) {
    res.block.penalty = static_cast<double>(0);
  } else {
    if (maxReward < currentReward) {
      return false;
    }
    res.block.penalty = static_cast<double>(maxReward - currentReward) / static_cast<double>(maxReward);
  }

  // Base transaction adding
  f_transaction_short_response transaction_short;
  transaction_short.hash = Common::podToHex(getObjectHash(blk.baseTransaction));
  transaction_short.fee = 0;
  transaction_short.amount_out = get_outs_money_amount(blk.baseTransaction);
  transaction_short.size = getObjectBinarySize(blk.baseTransaction);
  res.block.transactions.push_back(transaction_short);


  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(blk.transactionHashes, txs, missed_txs);

  res.block.totalFeeAmount = 0;

  for (const Transaction& tx : txs) {
    f_transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(tx, amount_in);
    uint64_t amount_out = get_outs_money_amount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee =
			amount_in < amount_out + m_core.currency().minimumFee() //account for interest in output, it always has minimum fee
			? m_core.currency().minimumFee()
			: amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    res.block.transactions.push_back(transaction_short);

    res.block.totalFeeAmount += transaction_short.fee;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::f_on_transaction_json(const F_COMMAND_RPC_GET_TRANSACTION_DETAILS::request& req, F_COMMAND_RPC_GET_TRANSACTION_DETAILS::response& res) {
  Hash hash;

  if (!parse_hash256(req.hash, hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
  }

  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(hash);

  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs);

  if (1 == txs.size()) {
    res.tx = txs.front();
  } else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "transaction wasn't found. Hash = " + req.hash + '.' };
  }

  Crypto::Hash blockHash;
  uint32_t blockHeight;
  if (m_core.getBlockContainingTx(hash, blockHash, blockHeight)) {
    Block blk;
    if (m_core.getBlockByHash(blockHash, blk)) {
      size_t tx_cumulative_block_size;
      m_core.getBlockSize(blockHash, tx_cumulative_block_size);
      size_t blokBlobSize = getObjectBinarySize(blk);
      size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
      f_block_short_response block_short;

      block_short.cumul_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
      block_short.timestamp = blk.timestamp;
      block_short.height = blockHeight;
      block_short.hash = Common::podToHex(blockHash);
      block_short.cumul_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
      block_short.tx_count = blk.transactionHashes.size() + 1;
      res.block = block_short;
    }
  }

  uint64_t amount_in = 0;
  get_inputs_money_amount(res.tx, amount_in);
  uint64_t amount_out = get_outs_money_amount(res.tx);

  res.txDetails.hash = Common::podToHex(getObjectHash(res.tx));
  if (amount_in == 0)
    res.txDetails.fee = 0;
  else {
	res.txDetails.fee =
		                amount_in < amount_out + m_core.currency().minimumFee() //account for interest in output, it always has minimum fee
		                        ? m_core.currency().minimumFee()
		                        : amount_in - amount_out;
  }
  res.txDetails.amount_out = amount_out;
  res.txDetails.size = getObjectBinarySize(res.tx);

  uint64_t mixin;
  if (!f_getMixin(res.tx, mixin)) {
    return false;
  }
  res.txDetails.mixin = mixin;

  Crypto::Hash paymentId;
  if (CryptoNote::getPaymentIdFromTxExtra(res.tx.extra, paymentId)) {
    res.txDetails.paymentId = Common::podToHex(paymentId);
  } else {
    res.txDetails.paymentId = "";
  }

      res.txDetails.networkId = "93385046440755750514194170694064996624";  // Fuego network mainnet ID

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::f_getMixin(const Transaction& transaction, uint64_t& mixin) {
  mixin = 0;
  for (const TransactionInput& txin : transaction.inputs) {
    if (txin.type() != typeid(KeyInput)) {
      continue;
    }
    uint64_t currentMixin = boost::get<KeyInput>(txin).outputIndexes.size();
    if (currentMixin > mixin) {
      mixin = currentMixin;
    }
  }
  return true;
}

bool RpcServer::f_on_transactions_pool_json(const F_COMMAND_RPC_GET_POOL::request& req, F_COMMAND_RPC_GET_POOL::response& res) {
    auto pool = m_core.getPoolTransactions();
    for (const Transaction tx : pool) {
        f_transaction_short_response transaction_short;
        uint64_t amount_in = getInputAmount(tx);
        uint64_t amount_out = getOutputAmount(tx);

        transaction_short.hash = Common::podToHex(getObjectHash(tx));
        transaction_short.fee =
			                        amount_in < amount_out + m_core.currency().minimumFee() //account for interest in output, it always has minimum fee
			                        ? m_core.currency().minimumFee()
			                        : amount_in - amount_out;
        transaction_short.amount_out = amount_out;
        transaction_short.size = getObjectBinarySize(tx);
        res.transactions.push_back(transaction_short);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
}

bool RpcServer::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res) {
  res.count = m_core.get_current_blockchain_height();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t h = static_cast<uint32_t>(req[0]);
  Crypto::Hash blockId = m_core.getBlockIdByHeight(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.get_current_blockchain_height())
    };
  }

  res = Common::podToHex(blockId);
  return true;
}

namespace {
  uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
  {
    void* buf = start_buff;
    void* end = (char*)buf + buflen - patlen;
    while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
    {
      if (buf>end)
        return 0;
      if (memcmp(buf, pat, patlen) == 0)
        return (char*)buf - (char*)start_buff;
      buf = (char*)buf + 1;
    }
    return 0;
  }
}

bool RpcServer::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res) {
  if (req.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "To big reserved size, maximum 255" };
  }

  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();

  if (!req.wallet_address.size() || !m_core.currency().parseAccountAddressString(req.wallet_address, acc)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS, "Failed to parse wallet address" };
  }

  Block b = boost::value_initialized<Block>();
  CryptoNote::BinaryArray blob_reserve;
  blob_reserve.resize(req.reserve_size, 0);
  if (!m_core.get_block_template(b, acc, res.difficulty, res.height, blob_reserve)) {
    logger(ERROR) << "Failed to create block template";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
  }

  BinaryArray block_blob = toBinaryArray(b);
  PublicKey tx_pub_key = CryptoNote::getTransactionPublicKeyFromExtra(b.baseTransaction.extra);
  if (tx_pub_key == NULL_PUBLIC_KEY) {
    logger(ERROR) << "Failed to find tx pub key in coinbase extra";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra" };
  }

  if (0 < req.reserve_size) {
    res.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if (!res.reserved_offset) {
      logger(ERROR) << "Failed to find tx pub key in blockblob";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
    res.reserved_offset += sizeof(tx_pub_key) + 3; //3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if (res.reserved_offset + req.reserve_size > block_blob.size()) {
      logger(ERROR) << "Failed to calculate offset for reserved bytes";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
  } else {
    res.reserved_offset = 0;
  }

  res.blocktemplate_blob = toHex(block_blob);
  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& /*req*/, COMMAND_RPC_GET_CURRENCY_ID::response& res) {
  Hash currencyId = m_core.currency().genesisBlockHash();
  res.currency_id_blob = Common::podToHex(currencyId);
  return true;
}

bool RpcServer::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param" };
  }

  BinaryArray blockblob;
  if (!fromHex(req[0], blockblob)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob" };
  }

  block_verification_context bvc = boost::value_initialized<block_verification_context>();

  m_core.handle_incoming_block_blob(blockblob, bvc, true, true);

  if (!bvc.m_added_to_main_chain) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted" };
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}


namespace {
  uint64_t get_block_reward(const Block& blk) {
    uint64_t reward = 0;
    for (const TransactionOutput& out : blk.baseTransaction.outputs) {
      reward += out.amount;
    }
    return reward;
  }
}

bool RpcServer::on_alt_blocks_list_json(const COMMAND_RPC_GET_ALT_BLOCKS_LIST::request &req, COMMAND_RPC_GET_ALT_BLOCKS_LIST::response &res)
{
  std::list<Block> alt_blocks;

  if (m_core.get_alternative_blocks(alt_blocks) && !alt_blocks.empty())
  {
    for (const auto &b : alt_blocks)
    {
      Crypto::Hash block_hash = get_block_hash(b);
      uint32_t block_height = boost::get<BaseInput>(b.baseTransaction.inputs.front()).blockIndex;
      size_t tx_cumulative_block_size;
      m_core.getBlockSize(block_hash, tx_cumulative_block_size);
      size_t blokBlobSize = getObjectBinarySize(b);
      size_t minerTxBlobSize = getObjectBinarySize(b.baseTransaction);
      difficulty_type blockDiff;
      m_core.getBlockDifficulty(static_cast<uint32_t>(block_height), blockDiff);

      block_short_response block_short;
      block_short.timestamp = b.timestamp;
      block_short.height = block_height;
      block_short.hash = Common::podToHex(block_hash);
      block_short.cumulative_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
      block_short.transactions_count = b.transactionHashes.size() + 1;
      block_short.difficulty = blockDiff;

      res.alt_blocks.push_back(block_short);
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

void RpcServer::fill_block_header_response(const Block& blk, bool orphan_status, uint64_t height, const Hash& hash, block_header_response& responce) {
  responce.major_version = blk.majorVersion;
  responce.minor_version = blk.minorVersion;
  responce.timestamp = blk.timestamp;
  responce.prev_hash = Common::podToHex(blk.previousBlockHash);
  responce.nonce = blk.nonce;
  responce.orphan_status = orphan_status;
  responce.height = height;
  responce.deposits = m_core.depositAmountAtHeight(height);
  responce.depth = m_core.get_current_blockchain_height() - height - 1;
  responce.hash = Common::podToHex(hash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(height), responce.difficulty);
  responce.reward = get_block_reward(blk);
}

bool RpcServer::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res) {
  uint32_t last_block_height;
  Hash last_block_hash;

  m_core.get_blockchain_top(last_block_height, last_block_hash);

  Block last_block;
  if (!m_core.getBlockByHash(last_block_hash, last_block)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last block hash." };
  }

  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(last_block_height);
  bool is_orphaned = last_block_hash != tmp_hash;
  fill_block_header_response(last_block, is_orphaned, last_block_height, last_block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res) {
  Hash block_hash;

  if (!parse_hash256(req.hash, block_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
  }

  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint32_t block_height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(block_height);
  bool is_orphaned = block_hash != tmp_hash;

  fill_block_header_response(blk, is_orphaned, block_height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res) {
  if (m_core.get_current_blockchain_height() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.get_current_blockchain_height()) };
  }

  Hash block_hash = m_core.getBlockIdByHeight(static_cast<uint32_t>(req.height));
  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.' };
  }

  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(req.height);
  bool is_orphaned = block_hash != tmp_hash;
  fill_block_header_response(blk, false, req.height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}


bool RpcServer::on_prove_collateral(const COMMAND_RPC_PROVE_COLLATERAL::request& req, COMMAND_RPC_PROVE_COLLATERAL::response& res) {
  // Validate transaction hash format
  Crypto::Hash txHash;
  if (!Common::podFromHex(req.transactionHash, txHash)) {
    res.exists = false;
    res.amount = 0;
    res.hasCommitment = false;
    res.status = "error";
    res.errorMessage = "Invalid transaction hash format";
    return true;
  }

  // Get transaction from blockchain
  Transaction tx;
  if (!m_core.getTransaction(txHash, tx)) {
    res.exists = false;
    res.amount = 0;
    res.hasCommitment = false;
    res.status = "not_found";
    res.errorMessage = "Transaction not found";
    return true;
  }

  // Transaction exists
  res.exists = true;
  res.hasCommitment = false;
  res.commitmentType = 0;

  // Calculate total output amount
  res.amount = 0;
  for (const auto& output : tx.outputs) {
    res.amount += output.amount;
  }

  // Parse transaction extra to detect commitment types
  if (req.commitment) {
    std::vector<TransactionExtraField> extraFields;
    if (parseTransactionExtra(tx.extra, extraFields)) {
      for (const auto& field : extraFields) {
        // Check for HEAT commitment (0x08 = 136)
        if (field.type() == typeid(TransactionExtraHeatCommitment)) {
          res.hasCommitment = true;
          res.commitmentType = 0x08; // 136
          break;
        }
        // Check for YIELD commitment (0x07 = 7)
        else if (field.type() == typeid(TransactionExtraYieldCommitment)) {
          res.hasCommitment = true;
          res.commitmentType = 0x07; // 7
          break;
        }
        // Check for CD deposit commitment (0xCD = 205)
        else if (field.type() == typeid(TransactionExtraDepositSecret)) {
          res.hasCommitment = true;
          res.commitmentType = 0xCD; // 205
          break;
        }
      }
    }
  }

  res.status = "found";
  res.errorMessage = "";
  return true;
}



bool RpcServer::on_get_alias(const COMMAND_RPC_GET_ALIAS::request& req,
                              COMMAND_RPC_GET_ALIAS::response& res) {
  try {
    if (req.alias.empty()) {
      res.found = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    auto entry = m_core.getAliasByName(req.alias);
    if (entry.has_value()) {
      res.alias = entry->alias;
      res.address = entry->ownerAddress;
      res.address_hash = Common::podToHex(entry->addressHash);
      res.registered_block = entry->registeredBlock;
      res.alias_type = entry->aliasType;
      res.found = true;
    } else {
      res.found = false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.found = false;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}

bool RpcServer::on_get_alias_by_address(const COMMAND_RPC_GET_ALIAS_BY_ADDRESS::request& req,
                                          COMMAND_RPC_GET_ALIAS_BY_ADDRESS::response& res) {
  try {
    if (req.address.empty()) {
      res.found = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    auto entry = m_core.getAliasByAddress(req.address);
    if (entry.has_value()) {
      res.alias = entry->alias;
      res.address = entry->ownerAddress;
      res.registered_block = entry->registeredBlock;
      res.alias_type = entry->aliasType;
      res.found = true;
    } else {
      res.found = false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.found = false;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}

bool RpcServer::on_get_all_aliases(const COMMAND_RPC_GET_ALL_ALIASES::request& /*req*/,
                                    COMMAND_RPC_GET_ALL_ALIASES::response& res) {
  try {
    auto all = m_core.getAllAliases();

    for (const auto& entry : all) {
      COMMAND_RPC_GET_ALL_ALIASES::alias_entry ae;
      ae.alias = entry.alias;
      ae.address = entry.ownerAddress;
      ae.registered_block = entry.registeredBlock;
      ae.alias_type = entry.aliasType;
      res.aliases.push_back(ae);
    }

    res.total = static_cast<uint32_t>(res.aliases.size());
    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.total = 0;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}

// ============================================================
// Commitment Index RPC handlers (Fuego → EVM bridge)
// ============================================================

bool RpcServer::on_get_commitment(const COMMAND_RPC_GET_COMMITMENT::request& req,
                                   COMMAND_RPC_GET_COMMITMENT::response& res) {
  try {
    if (req.commitment_hash.empty() || req.commitment_hash.length() != 64) {
      res.found = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    Crypto::Hash commitHash;
    if (!Common::podFromHex(req.commitment_hash, commitHash)) {
      res.found = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    auto entry = m_core.getCommitmentByHash(commitHash);
    if (entry.has_value()) {
      res.found = true;
      res.commitment_hash = Common::podToHex(entry->commitment);
      res.tx_hash = Common::podToHex(entry->txHash);
      res.block_height = entry->blockHeight;
      res.amount = entry->amount;
      res.term = entry->term;
      res.type = static_cast<uint8_t>(entry->type);
      res.target_chain_id = entry->targetChainId;
      res.leaf_index = static_cast<uint32_t>(m_core.getCommitmentLeafIndex(commitHash));
      res.is_legacy = entry->isLegacyMigration;
    } else {
      res.found = false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.found = false;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}

bool RpcServer::on_get_commitment_stats(const COMMAND_RPC_GET_COMMITMENT_STATS::request& /*req*/,
                                         COMMAND_RPC_GET_COMMITMENT_STATS::response& res) {
  try {
    res.total_commitments = m_core.getCommitmentCount();
    res.heat_commitments = m_core.getHeatCommitmentCount();
    res.cold_commitments = m_core.getColdCommitmentCount();
    res.highest_block = static_cast<uint32_t>(m_core.getCommitmentHighestBlock());
    res.merkle_root = Common::podToHex(m_core.getCommitmentMerkleRoot());
    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.total_commitments = 0;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}

bool RpcServer::on_get_commitment_merkle_root(const COMMAND_RPC_GET_COMMITMENT_MERKLE_ROOT::request& /*req*/,
                                               COMMAND_RPC_GET_COMMITMENT_MERKLE_ROOT::response& res) {
  try {
    res.merkle_root = Common::podToHex(m_core.getCommitmentMerkleRoot());
    res.total_leaves = m_core.getCommitmentCount();
    res.highest_block = static_cast<uint32_t>(m_core.getCommitmentHighestBlock());
    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.merkle_root = "";
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}

bool RpcServer::on_get_commitment_merkle_proof(const COMMAND_RPC_GET_COMMITMENT_MERKLE_PROOF::request& req,
                                                COMMAND_RPC_GET_COMMITMENT_MERKLE_PROOF::response& res) {
  try {
    if (req.commitment_hash.empty() || req.commitment_hash.length() != 64) {
      res.found = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    Crypto::Hash commitHash;
    if (!Common::podFromHex(req.commitment_hash, commitHash)) {
      res.found = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    if (!m_core.hasCommitment(commitHash)) {
      res.found = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    // Get merkle proof path
    auto proofPath = m_core.getCommitmentMerkleProof(commitHash);

    res.found = true;
    res.merkle_root = Common::podToHex(m_core.getCommitmentMerkleRoot());
    res.leaf_hash = req.commitment_hash;
    res.leaf_index = static_cast<uint32_t>(m_core.getCommitmentLeafIndex(commitHash));

    // Convert proof path hashes to hex strings
    for (const auto& hash : proofPath) {
      res.proof_path.push_back(Common::podToHex(hash));
    }

    // Generate proof indices from leaf index
    // For a standard binary merkle tree: at each level, if leaf_index bit is 0 → sibling is right (1),
    // if bit is 1 → sibling is left (0)
    uint32_t idx = res.leaf_index;
    for (size_t i = 0; i < proofPath.size(); ++i) {
      res.proof_indices.push_back(idx & 1);  // 0 = left child, 1 = right child
      idx >>= 1;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.found = false;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}

bool RpcServer::on_check_commitment_exists(const COMMAND_RPC_CHECK_COMMITMENT_EXISTS::request& req,
                                            COMMAND_RPC_CHECK_COMMITMENT_EXISTS::response& res) {
  try {
    if (req.commitment_hash.empty() || req.commitment_hash.length() != 64) {
      res.exists = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    Crypto::Hash commitHash;
    if (!Common::podFromHex(req.commitment_hash, commitHash)) {
      res.exists = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    res.exists = m_core.hasCommitment(commitHash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.exists = false;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
}


//-----------------------------------------------
// Fee pool analytics + treasury RPC handlers
//-----------------------------------------------

bool RpcServer::on_get_fee_pool_info(const COMMAND_RPC_GET_FEE_POOL_INFO::request& req,
                                      COMMAND_RPC_GET_FEE_POOL_INFO::response& res) {
  const uint64_t epochDuration = m_core.currency().isTestnet()
    ? CryptoNote::parameters::TESTNET_EPOCH_DURATION_BLOCKS
    : CryptoNote::parameters::EPOCH_DURATION_BLOCKS;
  const uint64_t height = m_core.get_current_blockchain_height();
  res.fee_pool_balance = m_core.get_blockchain_storage().getFeePoolBalance();
  res.treasury_balance = m_core.get_blockchain_storage().getTreasuryBalance();
  res.bonus_vault_balance = m_core.get_blockchain_storage().getBonusVaultBalance();
  res.rollover_vault_balance = m_core.get_blockchain_storage().getTreasuryCounterXFG();
  res.current_epoch_swap_fees = m_core.get_blockchain_storage().getCurrentEpochSwapFees();
  res.total_cd_locked = m_core.get_blockchain_storage().getTotalCdLocked();
  res.current_epoch_number = (epochDuration > 0) ? (height / epochDuration) : 0;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_epoch_history(const COMMAND_RPC_GET_EPOCH_HISTORY::request& req,
                                      COMMAND_RPC_GET_EPOCH_HISTORY::response& res) {
  static constexpr uint32_t MAX_EPOCH_HISTORY = 100;

  const uint64_t totalEpochs = m_core.getCommitmentIndex().getEpochCount();
  res.total_epochs = totalEpochs;

  if (totalEpochs == 0) {
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  const uint32_t count = (req.count == 0) ? 10 : std::min(req.count, MAX_EPOCH_HISTORY);
  const uint64_t startEpoch = (totalEpochs > static_cast<uint64_t>(count))
    ? (totalEpochs - static_cast<uint64_t>(count))
    : 0;

  uint32_t collected = 0;
  uint64_t n = totalEpochs - 1;
  while (collected < count) {
    auto report = m_core.getCommitmentIndex().getEpochReport(n);
    if (report) {
      COMMAND_RPC_GET_EPOCH_HISTORY::epoch_summary summary;
      summary.epoch_number = report->epochNumber;
      summary.swap_fees_collected = report->swapFeesCollected;
      summary.total_cd_locked_at_start = report->totalCdLockedAtStart;
      summary.fee_rate_fixed_point = report->feeRateFixedPoint;
      summary.total_fees_distributed = report->totalFeesDistributed;
      res.epochs.push_back(summary);
      ++collected;
    }
    if (n == startEpoch) break;
    --n;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_estimate_cd_yield(const COMMAND_RPC_ESTIMATE_CD_YIELD::request& req,
                                      COMMAND_RPC_ESTIMATE_CD_YIELD::response& res) {
  const uint32_t currentHeight = (req.current_height > 0)
    ? req.current_height
    : static_cast<uint32_t>(m_core.get_current_blockchain_height());

  res.estimated_interest = m_core.currency().calculateCdInterest(
    req.amount, req.creation_height, currentHeight, m_core.getCommitmentIndex(),
    false, req.term, false);

  const uint64_t epochDuration = m_core.currency().isTestnet()
    ? CryptoNote::parameters::TESTNET_EPOCH_DURATION_BLOCKS
    : CryptoNote::parameters::EPOCH_DURATION_BLOCKS;
  res.effective_epochs = (epochDuration > 0 && currentHeight > req.creation_height)
    ? ((currentHeight - req.creation_height) / epochDuration)
    : 0;

  // Pool-aware cap: consensus only accepts claims backed by the fee pool AND
  // the CD_APY_POOL vault partition (see checkCommitmentSpendInput + F-001).
  res.fee_pool_balance = m_core.get_blockchain_storage().getFeePoolBalance();
  res.cd_apy_vault_balance = m_core.get_blockchain_storage().getCdApyVaultBalance();
  res.claimable_interest = std::min(res.estimated_interest,
      std::min(res.fee_pool_balance, res.cd_apy_vault_balance));
  res.pool_info_present = true;

  // v11+: split the estimate into pool-backed base and BV-backed bonus using
  // the same consensus formulas (no loyalty in the base; bonus from realized
  // BV inflows, capped by the vault). Pre-v11 chains keep the legacy
  // loyalty-inclusive estimate.
  {
    uint8_t chainVersion = m_core.currency().blockMajorVersionAtHeight(currentHeight);
    if (chainVersion >= BLOCK_MAJOR_VERSION_11) {
      const auto& ci = m_core.getCommitmentIndex();
      uint64_t base = m_core.currency().calculateCdInterest(
          req.amount, req.creation_height, currentHeight, ci,
          false, req.term, false);
      uint64_t bonus = m_core.currency().calculateCdBonus(
          req.amount, req.creation_height, currentHeight, ci, req.term);
      uint64_t bv = m_core.get_blockchain_storage().getBonusVaultBalance();
      uint64_t bvUtxo = m_core.get_blockchain_storage().getBonusVaultUtxoBalance();
      uint64_t bvBacking = std::min(bv, bvUtxo);
      res.base_interest = base;
      res.bonus_interest = bonus;
      res.bonus_vault_balance = bvBacking;
      res.claimable_bonus = std::min(bonus, bvBacking);
      uint64_t totalFormula = (base > UINT64_MAX - bonus) ? UINT64_MAX : (base + bonus);
      res.estimated_interest = totalFormula;
      res.claimable_interest = (base > UINT64_MAX - res.claimable_bonus)
          ? UINT64_MAX : (base + res.claimable_bonus);
    }
  }

  res.note = "Estimate only: the protocol distributes realized fee revenue "
             "(real yield — no interest is printed), so this is based on accrued "
             "epoch fee rates, not a promise; the amount actually claimable is "
             "capped by the CD yield pool (and Bonus Vault for the tier bonus) "
             "at claim time.";

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_treasury_info(const COMMAND_RPC_GET_TREASURY_INFO::request& req,
                                      COMMAND_RPC_GET_TREASURY_INFO::response& res) {
  res.treasury_balance = m_core.get_blockchain_storage().getTreasuryBalance();
  res.treasury_counter_xfg = m_core.get_blockchain_storage().getTreasuryCounterXFG();
  res.treasury_heat_reserve = m_core.get_blockchain_storage().getTreasuryHeatReserve();
  res.swf_burned_xfg_pending_heat = m_core.get_blockchain_storage().getSwfBurnedXfgPendingHeat();
  res.bonus_vault_balance = m_core.get_blockchain_storage().getBonusVaultBalance();
  res.fee_pool_balance = m_core.get_blockchain_storage().getFeePoolBalance();
  res.total_burned_xfg = m_core.get_blockchain_storage().getTotalBurnedXfg();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

// Phase 5: Wallet Auto-Rollover + Compound Interest

bool RpcServer::on_get_maturing_deposits(const COMMAND_RPC_GET_MATURING_DEPOSITS::request& req,
                                         COMMAND_RPC_GET_MATURING_DEPOSITS::response& res) {
  try {
    // Note: This is a daemon-side query — would need wallet integration in production
    // For now, we return status explaining that maturing deposits are queried at wallet level
    res.status = CORE_RPC_STATUS_OK;
    return true;
  } catch (const std::exception& e) {
    res.status = "Error: " + std::string(e.what());
    return false;
  }
}

bool RpcServer::on_rollover_deposit(const COMMAND_RPC_ROLLOVER_DEPOSIT::request& req,
                                    COMMAND_RPC_ROLLOVER_DEPOSIT::response& res) {
  try {
    // Note: This is a wallet-side operation — daemon cannot execute this directly
    // The wallet RPC must implement this endpoint
    res.tx_hash = "";
    res.new_amount = 0;
    res.claimed_interest = 0;
    res.status = "Error: Rollover must be called from wallet RPC, not daemon RPC";
    return false;
  } catch (const std::exception& e) {
    res.status = "Error: " + std::string(e.what());
    return false;
  }
}

bool RpcServer::on_get_block_range(const COMMAND_RPC_GET_BLOCK_RANGE::request& req, COMMAND_RPC_GET_BLOCK_RANGE::response& res) {
  uint64_t height = m_core.get_current_blockchain_height();
  if (height == 0) {
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  uint64_t end = std::min(req.end_height, height - 1);

  for (uint64_t h = req.start_height; h <= end; ++h) {
    Crypto::Hash bHash = m_core.getBlockIdByHeight(static_cast<uint32_t>(h));
    Block blk;
    if (!m_core.getBlockByHash(bHash, blk)) {
      continue;
    }

    COMMAND_RPC_GET_BLOCK_RANGE::block_entry entry;
    entry.major_version = blk.majorVersion;
    entry.minor_version = blk.minorVersion;
    entry.nonce = blk.nonce;
    entry.timestamp = blk.timestamp;
    entry.previous_block_hash = Common::podToHex(blk.previousBlockHash);

    // Include coinbase tx_extra
    entry.tx_extras.push_back(Common::toHex(blk.baseTransaction.extra.data(), blk.baseTransaction.extra.size()));

    // Include tx_extra for each transaction in the block
    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    m_core.getTransactions(blk.transactionHashes, txs, missed_txs);
    for (const Transaction& tx : txs) {
      entry.tx_extras.push_back(Common::toHex(tx.extra.data(), tx.extra.size()));
    }

    res.blocks.push_back(std::move(entry));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_commitment_leaves(const COMMAND_RPC_GET_COMMITMENT_LEAVES::request& /*req*/, COMMAND_RPC_GET_COMMITMENT_LEAVES::response& res) {
  auto leaves = m_core.getCommitmentLeaves();
  res.leaves.reserve(leaves.size());
  for (const auto& h : leaves) {
    res.leaves.push_back(Common::podToHex(h));
  }
  res.count = res.leaves.size();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_heat_metrics(const COMMAND_RPC_GET_HEAT_METRICS::request& req,
                                     COMMAND_RPC_GET_HEAT_METRICS::response& res) {
  auto metrics = m_core.getHeatMetrics();
  res.heat_supply = metrics.heatSupply;
  res.heat_on_deposit = metrics.heatOnDeposit;
  res.burned_xfg = metrics.burnedXfg;
  res.total_burned_xfg = metrics.totalBurnedXfg;
  res.redemption_price_num = metrics.redemptionPriceNum;
  res.redemption_price_denom = metrics.redemptionPriceDenom;
  res.treasury_balance = metrics.treasuryBalance;
  res.treasury_counter_xfg = metrics.treasuryCounterXFG;
  res.swf_burned_xfg_pending_heat = metrics.swfBurnedXfgPendingHeat;
  res.epoch_swap_fees = metrics.epochSwapFees;
  res.vault_heat_cd_fee_pool = metrics.vaultHeatCdFeePool;
  res.vault_heat_lp_reserve  = metrics.vaultHeatLpReserve;
  res.vault_heat_general     = metrics.vaultHeatGeneral;
  res.vault_heat_swf         = metrics.vaultHeatSwf;
  res.vault_xfg_cd_fee_pool  = metrics.vaultXfgCdFeePool;
  res.vault_xfg_lp_reserve   = metrics.vaultXfgLpReserve;
  res.vault_xfg_general      = metrics.vaultXfgGeneral;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_amm_quote(const COMMAND_RPC_AMM_QUOTE::request& req,
                              COMMAND_RPC_AMM_QUOTE::response& res) {
  auto quote = m_core.getAmmQuote(req.input_amount, req.direction);
  res.expected_output = quote.expectedOutput;
  res.price_impact_bps = quote.priceImpactBps;
  res.fee = quote.fee;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_amm_pool_info(const COMMAND_RPC_AMM_POOL_INFO::request& req,
                                  COMMAND_RPC_AMM_POOL_INFO::response& res) {
  auto info = m_core.getAmmPoolInfo();
  res.reserve_xfg = info.reserveXfg;
  res.reserve_heat = info.reserveHeat;
  res.total_lp_shares = info.totalLpShares;
  res.spot_price = info.spotPrice;
  res.epoch_swap_fees = info.epochSwapFees;
  res.hearth_twap = m_core.getHearthTwap();
  res.height = m_core.get_current_blockchain_height();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_fuego_price(const COMMAND_RPC_GET_FUEGO_PRICE::request& /*req*/,
                                   COMMAND_RPC_GET_FUEGO_PRICE::response& res) {
  try {
    auto info = m_core.getAmmPoolInfo();
    auto metrics = m_core.getHeatMetrics();

    res.reserve_xfg = info.reserveXfg;
    res.reserve_heat = info.reserveHeat;
    res.spot_price = info.spotPrice;
    res.redemption_price_num = metrics.redemptionPriceNum;
    res.redemption_price_denom = metrics.redemptionPriceDenom;

    // Human-readable ratio: HEAT per XFG = spot_price / COIN.
    const double ratio = (info.spotPrice > 0)
      ? static_cast<double>(info.spotPrice) / static_cast<double>(parameters::COIN) : 0.0;
    char buf[64];
    snprintf(buf, sizeof(buf), "%.8f", ratio);
    res.xfg_heat_ratio = buf;

    const double heatPegUsd = parameters::HEAT_PEG_USD;
    snprintf(buf, sizeof(buf), "%.4f", heatPegUsd);
    res.heat_peg_usd = buf;

    const double xfgSpotUsd = ratio * heatPegUsd;
    snprintf(buf, sizeof(buf), "%.4f", xfgSpotUsd);
    res.xfg_spot_usd = buf;

    res.status = CORE_RPC_STATUS_OK;
  } catch (...) {
    res.status = "Failed";
  }
  return true;
}

bool RpcServer::on_get_limit_orders(const COMMAND_RPC_GET_LIMIT_ORDERS::request& req,
                                    COMMAND_RPC_GET_LIMIT_ORDERS::response& res) {
  const auto& deposits = m_core.get_blockchain_storage().getLimitDeposits();
  uint32_t count = 0;
  uint32_t skipped = 0;
  for (const auto& kv : deposits) {
    bool is_withdrawn = kv.second.withdrawn || kv.second.expired;
    if (req.active_only && is_withdrawn) {
      continue;
    }
    if (req.offset > 0 && skipped < req.offset) {
      ++skipped;
      continue;
    }
    COMMAND_RPC_GET_LIMIT_ORDERS::LimitOrderInfo info;
    info.order_id = Common::podToHex(kv.first);
    info.address_hash = Common::podToHex(kv.second.addressHash);
    info.side = kv.second.side;
    info.amount = kv.second.amount;
    info.proceeds_xfg = kv.second.proceedsXfg;
    info.proceeds_heat = kv.second.proceedsHeat;
    info.target_price = kv.second.targetPrice;
    info.expiration = kv.second.expiration;
    info.withdrawn = is_withdrawn;
    res.orders.push_back(std::move(info));
    ++count;
    if (req.limit > 0 && count >= req.limit) {
      break;
    }
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_add_swap_fee(const COMMAND_RPC_ADD_SWAP_FEE::request& req,
                                 COMMAND_RPC_ADD_SWAP_FEE::response& res) {
  if (req.amount == 0 || req.amount > 100000000000000ULL) {
    res.status = "Invalid fee amount";
    return false;
  }
  m_core.addSwapFee(req.amount);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

}
