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

#include "EthRpcClient.h"
#include "ContractAbi.h"
#include "Crypto/Secp256k1Signer.h"
#include "Crypto/RlpEncoder.h"
#include "crypto/keccak.h"
#include "Common/WinCompat.h"

#ifndef _WIN32
#include <fcntl.h>
#include <sys/select.h>
#endif

#include <atomic>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <algorithm>

namespace XfgSwap {

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

static uint64_t hexToUint64(const std::string& hex) {
  std::string s = hex;
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    s = s.substr(2);
  }
  // Reject hex values longer than 16 hex chars (64 bits) to prevent overflow
  if (s.size() > 16) return UINT64_MAX;
  uint64_t result = 0;
  for (char c : s) {
    result <<= 4;
    if (c >= '0' && c <= '9')      result |= static_cast<uint64_t>(c - '0');
    else if (c >= 'a' && c <= 'f') result |= static_cast<uint64_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') result |= static_cast<uint64_t>(c - 'A' + 10);
  }
  return result;
}

static std::string uint64ToHex(uint64_t val) {
  if (val == 0) return "0x0";
  std::ostringstream oss;
  oss << "0x" << std::hex << val;
  return oss.str();
}

// ---------------------------------------------------------------------------
// Minimal JSON value extraction helpers (no external JSON library dependency)
// ---------------------------------------------------------------------------

// Extract a string value for a given key from a flat JSON object.
// Returns empty string if not found. Handles null values.
static std::string jsonGetString(const std::string& json, const std::string& key) {
  std::string needle = "\"" + key + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return "";

  // Skip past key and colon
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return "";
  ++pos;

  // Skip whitespace
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                json[pos] == '\n' || json[pos] == '\r')) {
    ++pos;
  }

  if (pos >= json.size()) return "";

  // Handle null
  if (json.compare(pos, 4, "null") == 0) return "";

  // Must be a quoted string
  if (json[pos] != '"') return "";
  ++pos;

  std::string result;
  while (pos < json.size() && json[pos] != '"') {
    if (json[pos] == '\\' && pos + 1 < json.size()) {
      ++pos; // skip escape
    }
    result += json[pos];
    ++pos;
  }
  return result;
}

// Check if a JSON object has an "error" field that is non-null
static bool jsonHasError(const std::string& json) {
  std::string needle = "\"error\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return false;

  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return false;
  ++pos;

  // Skip whitespace
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                json[pos] == '\n' || json[pos] == '\r')) {
    ++pos;
  }

  // null means no error
  if (pos + 4 <= json.size() && json.compare(pos, 4, "null") == 0) return false;
  return true;
}

// Extract "result" from top-level JSON-RPC response.
// For string results, strips quotes. For object results, returns the raw substring.
static std::string jsonGetResult(const std::string& json) {
  std::string needle = "\"result\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return "";

  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return "";
  ++pos;

  // Skip whitespace
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                json[pos] == '\n' || json[pos] == '\r')) {
    ++pos;
  }

  if (pos >= json.size()) return "";

  // null
  if (json.compare(pos, 4, "null") == 0) return "";

  // Quoted string
  if (json[pos] == '"') {
    ++pos;
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
      if (json[pos] == '\\' && pos + 1 < json.size()) {
        ++pos;
      }
      result += json[pos];
      ++pos;
    }
    return result;
  }

  // Object or array — find matching brace/bracket
  if (json[pos] == '{' || json[pos] == '[') {
    char open = json[pos];
    char close = (open == '{') ? '}' : ']';
    int depth = 1;
    size_t start = pos;
    ++pos;
    bool inStr = false;
    while (pos < json.size() && depth > 0) {
      if (json[pos] == '\\' && inStr) {
        ++pos; // skip escaped char
      } else if (json[pos] == '"') {
        inStr = !inStr;
      } else if (!inStr) {
        if (json[pos] == open)  ++depth;
        if (json[pos] == close) --depth;
      }
      ++pos;
    }
    return json.substr(start, pos - start);
  }

  // Number or boolean — read until delimiter
  {
    size_t start = pos;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' &&
           json[pos] != ']' && json[pos] != ' ' && json[pos] != '\n') {
      ++pos;
    }
    return json.substr(start, pos - start);
  }
}

// ---------------------------------------------------------------------------
// EthRpcClient
// ---------------------------------------------------------------------------

// ─── hex utilities ─────────────────────────────────────────────────────────

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
  std::string s = hex;
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
  if (s.size() % 2 != 0) s = "0" + s;
  std::vector<uint8_t> out(s.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    unsigned b;
    sscanf(s.c_str() + i * 2, "%02x", &b);
    out[i] = static_cast<uint8_t>(b);
  }
  return out;
}

static std::string bytesToHex(const uint8_t* data, size_t len, bool prefix = true) {
  std::string s = prefix ? "0x" : "";
  char buf[3];
  for (size_t i = 0; i < len; ++i) {
    snprintf(buf, 3, "%02x", data[i]);
    s += buf;
  }
  return s;
}

static std::string bytesToHex(const std::vector<uint8_t>& v, bool prefix = true) {
  return bytesToHex(v.data(), v.size(), prefix);
}

// ─── EthRpcClient constructors ──────────────────────────────────────────────

EthRpcClient::EthRpcClient(const std::string& host, uint16_t port)
  : m_host(host), m_port(port) {
  m_privKey.fill(0);
}

EthRpcClient::EthRpcClient(const std::string& host, uint16_t port,
                            const std::string& privKeyHex,
                            const std::string& signerAddress,
                            uint64_t chainId,
                            EthTxType txType)
  : m_host(host), m_port(port),
    m_signerAddress(signerAddress), m_chainId(chainId), m_hasSigner(true),
    m_txType(txType) {
  auto keyBytes = hexToBytes(privKeyHex);
  if (keyBytes.size() != 32) {
    throw std::invalid_argument("EthRpcClient: privKeyHex must be 32 bytes (64 hex chars)");
  }
  std::copy(keyBytes.begin(), keyBytes.end(), m_privKey.begin());
}

// ---------------------------------------------------------------------------
// HTTP POST with keep-alive (persistent socket)
// ---------------------------------------------------------------------------

bool EthRpcClient::connectSocket() {
  closeSocket();

  struct addrinfo hints{}, *res = nullptr;
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  std::string portStr = std::to_string(m_port);
  if (getaddrinfo(m_host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
    return false;
  }

  m_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (m_sock < 0) { freeaddrinfo(res); return false; }

#ifdef _WIN32
  DWORD tvSec = 10000;  // 10 seconds in milliseconds for SO_RCVTIMEO
  setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO,
    reinterpret_cast<const char*>(&tvSec), sizeof(tvSec));
  setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO,
    reinterpret_cast<const char*>(&tvSec), sizeof(tvSec));
#else
  struct timeval tv = {10, 0};
  setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

#ifdef _WIN32
  u_long nonblocking = 1;
  ioctlsocket(m_sock, FIONBIO, &nonblocking);
#else
  int flags = fcntl(m_sock, F_GETFL, 0);
  if (flags >= 0) fcntl(m_sock, F_SETFL, flags | O_NONBLOCK);
#endif

  int connRet = ::connect(m_sock, res->ai_addr, res->ai_addrlen);
#ifdef _WIN32
  if (connRet < 0 && WSAGetLastError() == WSAEWOULDBLOCK) {
#else
  if (connRet < 0 && errno == EINPROGRESS) {
#endif
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(m_sock, &fdset);
#ifdef _WIN32
    struct timeval selectTv = {10, 0};
    if (select(0, NULL, &fdset, NULL, &selectTv) <= 0) {
#else
    if (select(m_sock + 1, NULL, &fdset, NULL, &tv) <= 0) {
#endif
      closeSocket(); freeaddrinfo(res); return false;
    }
  } else if (connRet < 0) {
    closeSocket(); freeaddrinfo(res); return false;
  }

#ifdef _WIN32
  u_long blocking = 0;
  ioctlsocket(m_sock, FIONBIO, &blocking);
#else
  if (flags >= 0) fcntl(m_sock, F_SETFL, flags);
#endif
  freeaddrinfo(res);
  m_sockHost = m_host;
  m_sockPort = m_port;
  return true;
}

void EthRpcClient::closeSocket() {
  if (m_sock >= 0) { close(m_sock); m_sock = -1; }
}

void EthRpcClient::clear() {
  volatile uint8_t* p = m_privKey.data();
  for (size_t i = 0; i < m_privKey.size(); ++i) p[i] = 0;
  m_hasSigner = false;
}

static bool httpReadResponse(int sock, std::string& response) {
  char buf[4096];
  // Read until \r\n\r\n appears in accumulated data
  std::string accum;
  size_t hdrEnd = std::string::npos;
  while (hdrEnd == std::string::npos) {
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    accum.append(buf, static_cast<size_t>(n));
    hdrEnd = accum.find("\r\n\r\n");
  }
  // Parse Content-Length
  size_t clPos = accum.find("Content-Length:");
  if (clPos == std::string::npos) return false;
  clPos += 15;
  while (clPos < accum.size() && accum[clPos] == ' ') ++clPos;
  size_t contentLen = 0;
  while (clPos < accum.size() && accum[clPos] >= '0' && accum[clPos] <= '9')
    contentLen = contentLen * 10 + (accum[clPos++] - '0');
  // Body starts after \r\n\r\n
  response = accum.substr(hdrEnd + 4);
  // Read remaining body
  while (response.size() < contentLen) {
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    response.append(buf, static_cast<size_t>(n));
  }
  return true;
}

std::string EthRpcClient::httpPost(const std::string& path, const std::string& body) {
  // Connect or reconnect if host/port changed or socket broken
  if (m_sock < 0 || m_sockHost != m_host || m_sockPort != m_port) {
    if (!connectSocket()) return "";
  }

  // Build HTTP request with keep-alive
  std::ostringstream req;
  req << "POST " << path << " HTTP/1.1\r\n";
  req << "Host: " << m_host << ":" << m_port << "\r\n";
  req << "Content-Type: application/json\r\n";
  req << "Content-Length: " << body.size() << "\r\n";
  req << "Connection: keep-alive\r\n";
  req << "\r\n";
  req << body;

  std::string request = req.str();

  // Send, retry once on failure
  for (int attempt = 0; attempt < 2; ++attempt) {
    if (attempt > 0) {
      closeSocket();
      if (!connectSocket()) return "";
    }
    if (send(m_sock, request.data(), request.size(),
#ifndef _WIN32
             MSG_NOSIGNAL
#else
             0
#endif
             ) < 0)
      continue;

    std::string response;
    if (httpReadResponse(m_sock, response))
      return response;
  }

  closeSocket();
  return "";
}

// ---------------------------------------------------------------------------
// JSON-RPC wrapper
// ---------------------------------------------------------------------------

std::string EthRpcClient::jsonRpc(const std::string& method, const std::string& params) {
  static std::atomic<int> requestId{1};

  std::ostringstream body;
  body << "{\"jsonrpc\":\"2.0\",\"method\":\"" << method
       << "\",\"params\":" << params
       << ",\"id\":" << requestId++ << "}";

  return httpPost("/", body.str());
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool EthRpcClient::getBlockNumber(uint64_t& blockNum) {
  std::string resp = jsonRpc("eth_blockNumber", "[]");
  if (resp.empty() || jsonHasError(resp)) return false;

  std::string result = jsonGetResult(resp);
  if (result.empty()) return false;

  blockNum = hexToUint64(result);
  return true;
}

bool EthRpcClient::getBalance(const std::string& address, uint64_t& balanceWei) {
  std::string params = "[\"" + address + "\",\"latest\"]";
  std::string resp = jsonRpc("eth_getBalance", params);
  if (resp.empty() || jsonHasError(resp)) return false;

  std::string result = jsonGetResult(resp);
  if (result.empty()) return false;

  balanceWei = hexToUint64(result);
  return true;
}

bool EthRpcClient::getTransactionReceipt(const std::string& txHash, EthTxReceipt& receipt) {
  std::string params = "[\"" + txHash + "\"]";
  std::string resp = jsonRpc("eth_getTransactionReceipt", params);
  if (resp.empty() || jsonHasError(resp)) return false;

  std::string result = jsonGetResult(resp);
  if (result.empty()) return false;

  receipt.txHash          = jsonGetString(result, "transactionHash");
  receipt.contractAddress = jsonGetString(result, "contractAddress");
  receipt.gasUsed         = hexToUint64(jsonGetString(result, "gasUsed"));
  receipt.blockNumber     = hexToUint64(jsonGetString(result, "blockNumber"));

  std::string status = jsonGetString(result, "status");
  receipt.success = (status == "0x1" || status == "0x01");

  return true;
}

bool EthRpcClient::getNonce(const std::string& address, uint64_t& nonce) {
  std::string params = "[\"" + address + "\",\"pending\"]";
  std::string resp = jsonRpc("eth_getTransactionCount", params);
  if (resp.empty() || jsonHasError(resp)) return false;
  std::string result = jsonGetResult(resp);
  if (result.empty()) return false;
  nonce = hexToUint64(result);
  return true;
}

// ─── EIP-155 signing internals ──────────────────────────────────────────────

std::vector<uint8_t> EthRpcClient::buildLegacySignedTx(uint64_t nonce,
                                                        uint64_t gasPriceWei,
                                                        uint64_t gasLimit,
                                                        const std::vector<uint8_t>& to,
                                                        uint64_t valueWei,
                                                        const std::vector<uint8_t>& data) {
  if (!m_hasSigner) {
    throw std::runtime_error("EthRpcClient::buildLegacySignedTx: no signer configured");
  }

  using namespace CryptoNote::SwapDaemon::Crypto;

  // Step 1: RLP-encode the pre-sign payload: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
  RlpEncoder preSig;
  preSig.beginList();
  preSig.writeUint(nonce);
  preSig.writeUint(gasPriceWei);
  preSig.writeUint(gasLimit);
  preSig.writeBytes(to);            // empty = contract deploy
  preSig.writeUint(valueWei);
  preSig.writeBytes(data);
  preSig.writeUint(m_chainId);      // EIP-155: chain ID
  preSig.writeBytes({});            // r = 0
  preSig.writeBytes({});            // s = 0
  preSig.endList();
  auto preSigBytes = preSig.finalize();

  // Step 2: keccak256 of the pre-sign encoding
  std::array<uint8_t, 32> msgHash;
  keccak(preSigBytes.data(), static_cast<int>(preSigBytes.size()), msgHash.data(), 32);

  // Step 3: sign with secp256k1
  Secp256k1Signer signer;
  auto sig = signer.signRecoverable(msgHash, m_privKey);

  // Step 4: EIP-155 v = chainId * 2 + 35 + recid
  uint64_t v = m_chainId * 2 + 35 + sig.recid;

  // Step 5: RLP-encode the signed transaction: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
  RlpEncoder signedEnc;
  signedEnc.beginList();
  signedEnc.writeUint(nonce);
  signedEnc.writeUint(gasPriceWei);
  signedEnc.writeUint(gasLimit);
  signedEnc.writeBytes(to);
  signedEnc.writeUint(valueWei);
  signedEnc.writeBytes(data);
  signedEnc.writeUint(v);
  signedEnc.writeBytes(sig.r.data(), sig.r.size());
  signedEnc.writeBytes(sig.s.data(), sig.s.size());
  signedEnc.endList();
  return signedEnc.finalize();
}

// ─── EIP-1559 signing ─────────────────────────────────────────────────────

std::vector<uint8_t> EthRpcClient::buildEip1559SignedTx(uint64_t nonce,
                                                         uint64_t maxPriorityFeePerGas,
                                                         uint64_t maxFeePerGas,
                                                         uint64_t gasLimit,
                                                         const std::vector<uint8_t>& to,
                                                         uint64_t valueWei,
                                                         const std::vector<uint8_t>& data) {
  if (!m_hasSigner) {
    throw std::runtime_error("EthRpcClient::buildEip1559SignedTx: no signer configured");
  }

  using namespace CryptoNote::SwapDaemon::Crypto;

  // Pre-sign payload: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
  //                                 gasLimit, to, value, data, accessList])
  RlpEncoder preSig;
  preSig.beginList();
  preSig.writeUint(m_chainId);
  preSig.writeUint(nonce);
  preSig.writeUint(maxPriorityFeePerGas);
  preSig.writeUint(maxFeePerGas);
  preSig.writeUint(gasLimit);
  preSig.writeBytes(to);
  preSig.writeUint(valueWei);
  preSig.writeBytes(data);
  preSig.writeEmptyList();          // empty access list MUST be RLP list 0xc0, not empty string 0x80
  preSig.endList();
  auto preSigBytes = preSig.finalize();

  // Prepend 0x02 type prefix
  std::vector<uint8_t> sigInput = {0x02};
  sigInput.insert(sigInput.end(), preSigBytes.begin(), preSigBytes.end());

  // keccak256 of the signing payload
  std::array<uint8_t, 32> msgHash;
  keccak(sigInput.data(), static_cast<int>(sigInput.size()), msgHash.data(), 32);

  // sign with secp256k1
  Secp256k1Signer signer;
  auto sig = signer.signRecoverable(msgHash, m_privKey);

  // yParity for EIP-1559 is the recid (0 or 1).
  // Signed payload: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
  //                              gasLimit, to, value, data, accessList, yParity, r, s])
  RlpEncoder signedEnc;
  signedEnc.beginList();
  signedEnc.writeUint(m_chainId);
  signedEnc.writeUint(nonce);
  signedEnc.writeUint(maxPriorityFeePerGas);
  signedEnc.writeUint(maxFeePerGas);
  signedEnc.writeUint(gasLimit);
  signedEnc.writeBytes(to);
  signedEnc.writeUint(valueWei);
  signedEnc.writeBytes(data);
  signedEnc.writeEmptyList();       // accessList (must match pre-image)
  signedEnc.writeUint(sig.recid);   // yParity
  signedEnc.writeBytes(sig.r.data(), sig.r.size());
  signedEnc.writeBytes(sig.s.data(), sig.s.size());
  signedEnc.endList();
  auto signedRlp = signedEnc.finalize();

  // Prepend 0x02 type prefix
  std::vector<uint8_t> result = {0x02};
  result.insert(result.end(), signedRlp.begin(), signedRlp.end());
  return result;
}

// ─── Dynamic fee estimation (EIP-1559) ────────────────────────────────────

bool EthRpcClient::estimateFees(uint64_t& maxPriorityFeePerGas, uint64_t& maxFeePerGas) {
  // Query suggested tip from RPC
  std::string tipResp = jsonRpc("eth_maxPriorityFeePerGas", "[]");
  if (tipResp.empty() || jsonHasError(tipResp)) return false;
  std::string tipStr = jsonGetResult(tipResp);
  if (tipStr.empty()) return false;
  uint64_t suggestedTip = hexToUint64(tipStr);

  // Floor at 1 gwei
  const uint64_t minTip = 1000000000ULL; // 1 gwei
  maxPriorityFeePerGas = (suggestedTip > minTip) ? suggestedTip : minTip;

  // Query latest block to get base fee
  std::string blockResp = jsonRpc("eth_getBlockByNumber",
                                   "[\"latest\",false]");
  if (blockResp.empty() || jsonHasError(blockResp)) {
    return false;
  }
  std::string blockResult = jsonGetResult(blockResp);
  if (blockResult.empty()) return false;

  std::string baseFeeStr = jsonGetString(blockResult, "baseFeePerGas");
  if (baseFeeStr.empty()) return false;
  uint64_t baseFee = hexToUint64(baseFeeStr);

  // maxFeePerGas = 2 * baseFee + maxPriorityFeePerGas
  maxFeePerGas = baseFee * 2 + maxPriorityFeePerGas;
  return true;
}

bool EthRpcClient::queryGasPrice(uint64_t& gasPriceWei) {
  std::string resp = jsonRpc("eth_gasPrice", "[]");
  if (resp.empty() || jsonHasError(resp)) return false;
  std::string priceStr = jsonGetResult(resp);
  if (priceStr.empty()) return false;
  uint64_t rawPrice = hexToUint64(priceStr);
  if (rawPrice == 0) return false;
  constexpr uint64_t MAX_GAS_PRICE_WEI = 500000000000ULL; // 500 gwei cap
  if (rawPrice > MAX_GAS_PRICE_WEI) {
    rawPrice = MAX_GAS_PRICE_WEI;
  }
  gasPriceWei = rawPrice;
  return true;
}

bool EthRpcClient::estimateGas(const std::string& to, const std::string& data,
                                uint64_t valueWei, uint64_t& gasEstimate) {
  // Build eth_estimateGas call
  (void)valueWei; // value is 0 for most contract calls
  std::string params = "[{\"to\":\"" + to + "\",\"data\":\"" + data + "\"},\"latest\"]";
  std::string resp = jsonRpc("eth_estimateGas", params);
  if (resp.empty() || jsonHasError(resp)) return false;
  std::string result = jsonGetResult(resp);
  if (result.empty()) return false;
  gasEstimate = hexToUint64(result);
  // Add 20% buffer
  gasEstimate = gasEstimate + gasEstimate / 5;
  return true;
}

bool EthRpcClient::signAndSend(const std::vector<uint8_t>& to,
                                const std::vector<uint8_t>& data,
                                uint64_t valueWei,
                                uint64_t gasLimit,
                                std::string& txHash) {
  if (!m_hasSigner) {
    throw std::runtime_error("EthRpcClient::signAndSend: no signer configured — "
                             "construct with EthRpcClient(host, port, privKeyHex, address, chainId)");
  }

  // Fetch current nonce for the signer address.
  uint64_t nonce = 0;
  if (!getNonce(m_signerAddress, nonce)) {
    return false;
  }

  std::vector<uint8_t> rawTx;

  if (m_txType == EthTxType::Eip1559) {
    // Dynamic fee estimation for EIP-1559
    uint64_t maxPriorityFeePerGas = 0;
    uint64_t maxFeePerGas = 0;
    if (!estimateFees(maxPriorityFeePerGas, maxFeePerGas)) {
      return false;
    }
    rawTx = buildEip1559SignedTx(nonce, maxPriorityFeePerGas, maxFeePerGas,
                                  gasLimit, to, valueWei, data);
  } else {
    // Legacy: query eth_gasPrice, fall back to configured default
    uint64_t gasPriceWei = m_gasPriceFallback;
    queryGasPrice(gasPriceWei); // use dynamic if available, fallback otherwise
    rawTx = buildLegacySignedTx(nonce, gasPriceWei, gasLimit, to, valueWei, data);
  }

  std::string rawHex = bytesToHex(rawTx);
  return sendRawTransaction(rawHex, txHash);
}

bool EthRpcClient::deployContract(const std::string& /*fromAddress*/,
                                  const std::string& bytecode,
                                  uint64_t gasLimit,
                                  std::string& txHash) {
  auto bytecodeBytes = hexToBytes(bytecode);
  return signAndSend(/*to=*/{}, bytecodeBytes, /*valueWei=*/0, gasLimit, txHash);
}

bool EthRpcClient::sendTransaction(const std::string& /*from*/, const std::string& to,
                                   const std::string& data, uint64_t value,
                                   uint64_t gasLimit, std::string& txHash) {
  auto toBytes   = hexToBytes(to);
  auto dataBytes = hexToBytes(data);
  return signAndSend(toBytes, dataBytes, value, gasLimit, txHash);
}

bool EthRpcClient::callContract(const std::string& to, const std::string& data,
                                std::string& result) {
  std::ostringstream params;
  params << "[{\"to\":\"" << to
         << "\",\"data\":\"" << data
         << "\"},\"latest\"]";

  std::string resp = jsonRpc("eth_call", params.str());
  if (resp.empty() || jsonHasError(resp)) return false;

  result = jsonGetResult(resp);
  return !result.empty();
}

// ─── HTLC operations (HashedTimelock.sol registry) ──────────────────────────

static std::string normalizeAddr20(const std::string& addr) {
  std::string a = addr;
  if (a.size() >= 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')) a = a.substr(2);
  // lowercase for consistency
  for (char& c : a) if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
  return a;
}

std::string EthRpcClient::computeContractId(const std::string& sender,
                                            const std::string& recipient,
                                            uint64_t valueWei,
                                            const std::string& hashLockHex,
                                            uint64_t timeoutBlock) {
  // abi.encodePacked(address, address, uint256, bytes32, uint256)
  // addresses are 20 bytes (not left-padded), uint256/bytes32 are 32 bytes.
  auto sendBytes = hexToBytes(sender);
  auto recvBytes = hexToBytes(recipient);
  auto hashBytes = hexToBytes(hashLockHex);
  if (sendBytes.size() != 20 || recvBytes.size() != 20 || hashBytes.size() != 32)
    return {};

  std::vector<uint8_t> packed;
  packed.reserve(20 + 20 + 32 + 32 + 32);
  packed.insert(packed.end(), sendBytes.begin(), sendBytes.end());
  packed.insert(packed.end(), recvBytes.begin(), recvBytes.end());

  // valueWei as big-endian uint256 (32 bytes)
  {
    std::vector<uint8_t> valBuf(32, 0);
    for (int i = 0; i < 8; ++i)
      valBuf[31 - i] = static_cast<uint8_t>((valueWei >> (i * 8)) & 0xFF);
    packed.insert(packed.end(), valBuf.begin(), valBuf.end());
  }

  packed.insert(packed.end(), hashBytes.begin(), hashBytes.end());

  // timeout as big-endian uint256 (32 bytes)
  {
    std::vector<uint8_t> toBuf(32, 0);
    for (int i = 0; i < 8; ++i)
      toBuf[31 - i] = static_cast<uint8_t>((timeoutBlock >> (i * 8)) & 0xFF);
    packed.insert(packed.end(), toBuf.begin(), toBuf.end());
  }

  uint8_t digest[32];
  keccak(packed.data(), static_cast<int>(packed.size()), digest, 32);
  return bytesToHex(digest, 32, /*prefix=*/false);
}

bool EthRpcClient::lockHtlc(const std::string& fromAddress,
                            const std::string& recipientAddress,
                            const std::string& hashLockHex,
                            uint64_t timeoutBlock,
                            uint64_t valueWei,
                            std::string& contractIdHex) {
  if (m_htlcRegistry.empty()) {
    throw std::runtime_error("EthRpcClient::lockHtlc: HTLC registry address not set — "
                             "call setHtlcRegistry() with the deployed HashedTimelock address");
  }
  auto hashBytes = hexToBytes(hashLockHex);
  if (hashBytes.size() != 32) return false;

  Crypto::Hash hashLock;
  std::memcpy(&hashLock, hashBytes.data(), 32);
  std::string calldata = EthAbi::encodeLock(recipientAddress, hashLock, timeoutBlock);
  auto toBytes   = hexToBytes(m_htlcRegistry);
  auto dataBytes = hexToBytes(calldata.substr(2));

  std::string txHash;
  if (!signAndSend(toBytes, dataBytes, valueWei, /*gasLimit=*/200000, txHash))
    return false;

  // Wait for success receipt (lock does not create a new contract address)
  EthTxReceipt receipt;
  for (int i = 0; i < 60; ++i) {
    if (getTransactionReceipt(txHash, receipt) && receipt.success) break;
#ifdef _WIN32
    Sleep(1000);
#else
    usleep(1000000);
#endif
  }
  if (!receipt.success) return false;

  contractIdHex = computeContractId(fromAddress, recipientAddress, valueWei,
                                    hashLockHex, timeoutBlock);
  return !contractIdHex.empty();
}

bool EthRpcClient::deployHtlc(const std::string& fromAddress,
                               const std::string& recipientAddress,
                               const std::string& hashLockHex,
                               uint64_t timeoutBlock,
                               uint64_t valueWei,
                               std::string& contractAddressOrId) {
  // Prefer registry lock() path (matches HashedTimelock.sol).
  if (!m_htlcRegistry.empty()) {
    return lockHtlc(fromAddress, recipientAddress, hashLockHex,
                    timeoutBlock, valueWei, contractAddressOrId);
  }
  throw std::runtime_error(
      "EthRpcClient::deployHtlc: set HTLC registry via setHtlcRegistry() "
      "(HashedTimelock is a single registry, not a per-swap constructor deploy)");
}

bool EthRpcClient::verifyLock(const std::string& contractIdHex,
                               uint64_t expectedWei,
                               const std::string& expectedRecipient,
                               const std::string& expectedHashLockHex,
                               uint64_t minTimeoutBlock) {
  if (m_htlcRegistry.empty()) return false;

  std::string calldata = EthAbi::encodeGetContract(contractIdHex);
  std::string result;
  if (!callContract(m_htlcRegistry, calldata, result)) return false;

  EthAbi::ContractInfo info;
  if (!EthAbi::decodeGetContract(result, info)) return false;
  if (info.amount < expectedWei) return false;
  if (info.claimed || info.refunded) return false;
  // AUDIT 6.1: reject a lock whose on-chain timeout is too soon — otherwise the
  // counterparty can refund before we can safely claim after revealing t.
  if (minTimeoutBlock != 0 && info.timeoutBlock < minTimeoutBlock) return false;

  if (!expectedRecipient.empty()) {
    std::string er = normalizeAddr20(expectedRecipient);
    std::string ir = normalizeAddr20(info.recipient);
    if (er != ir) return false;
  }
  if (!expectedHashLockHex.empty()) {
    std::string eh = expectedHashLockHex;
    if (eh.size() >= 2 && eh[0] == '0' && (eh[1] == 'x' || eh[1] == 'X')) eh = eh.substr(2);
    std::string ih = bytesToHex(reinterpret_cast<const uint8_t*>(&info.hashLock), 32, false);
    if (eh != ih) return false;
  }
  return true;
}

std::string EthRpcClient::getClaimedPreimage(const std::string& contractIdHex) {
  if (m_htlcRegistry.empty() || contractIdHex.empty()) return {};
  std::string calldata = EthAbi::encodeGetContract(contractIdHex);
  std::string result;
  if (!callContract(m_htlcRegistry, calldata, result)) return {};
  EthAbi::ContractInfo info;
  if (!EthAbi::decodeGetContract(result, info)) return {};
  if (!info.claimed) return {};
  // Zero preimage means not set
  bool nonzero = false;
  for (int i = 0; i < 32; ++i) if (info.preimage.data[i]) { nonzero = true; break; }
  if (!nonzero) return {};
  return bytesToHex(reinterpret_cast<const uint8_t*>(&info.preimage), 32, /*prefix=*/false);
}

bool EthRpcClient::claimHtlc(const std::string& /*fromAddress*/,
                               const std::string& contractIdHex,
                               const std::string& preimageHex,
                               std::string& claimTxHash) {
  if (m_htlcRegistry.empty()) return false;
  Crypto::Hash preimage;
  auto preimageBytes = hexToBytes(preimageHex);
  if (preimageBytes.size() != 32) return false;
  std::copy(preimageBytes.begin(), preimageBytes.end(),
            reinterpret_cast<uint8_t*>(&preimage));

  std::string calldata = EthAbi::encodeClaim(contractIdHex, preimage);
  auto toBytes   = hexToBytes(m_htlcRegistry);
  auto dataBytes = hexToBytes(calldata.substr(2));
  return signAndSend(toBytes, dataBytes, /*valueWei=*/0, /*gasLimit=*/150000, claimTxHash);
}

bool EthRpcClient::claimPoint(const std::string& /*fromAddress*/,
                              const std::string& contractIdHex,
                              const std::string& secretHex32,
                              std::string& claimTxHash) {
  if (m_ptlcRegistry.empty()) return false;
  auto secretBytes = hexToBytes(secretHex32);
  if (secretBytes.size() != 32) return false;

  // PointTimelock.claim(bytes32 contractId, bytes32 secret) — same selector
  // shape as the HTLC path; secret is the canonical BIG-endian scalar t.
  uint8_t cidBuf[32] = {};
  auto cidBytes = hexToBytes(contractIdHex);
  if (cidBytes.size() >= 32)
    std::memcpy(cidBuf, cidBytes.data(), 32);
  else
    std::memcpy(cidBuf + (32 - cidBytes.size()), cidBytes.data(), cidBytes.size());

  std::string calldata = "0x" + EthAbi::functionSelector("claim(bytes32,bytes32)").substr(2)
    + bytesToHex(cidBuf, 32)
    + bytesToHex(secretBytes.data(), 32);

  auto toBytes   = hexToBytes(m_ptlcRegistry);
  auto dataBytes = hexToBytes(calldata.substr(2));
  return signAndSend(toBytes, dataBytes, /*valueWei=*/0, /*gasLimit=*/150000, claimTxHash);
}

bool EthRpcClient::refundHtlc(const std::string& /*fromAddress*/,
                                const std::string& contractIdHex,
                                std::string& refundTxHash) {
  if (m_htlcRegistry.empty()) return false;
  std::string calldata = EthAbi::encodeRefund(contractIdHex);
  auto toBytes   = hexToBytes(m_htlcRegistry);
  auto dataBytes = hexToBytes(calldata.substr(2));
  return signAndSend(toBytes, dataBytes, /*valueWei=*/0, /*gasLimit=*/80000, refundTxHash);
}

bool EthRpcClient::refundPoint(const std::string& fromAddress,
                                 const std::string& contractIdHex,
                                 std::string& refundTxHash) {
  // Same selector as the HTLC path: refund(bytes32) — verified identical in
  // PointTimelock.sol and HashedTimelock.sol. Only the target registry differs.
  if (m_ptlcRegistry.empty()) return false;
  std::string calldata = EthAbi::encodeRefund(contractIdHex);
  auto toBytes   = hexToBytes(m_ptlcRegistry);
  auto dataBytes = hexToBytes(calldata.substr(2));
  return signAndSend(toBytes, dataBytes, /*valueWei=*/0, /*gasLimit=*/80000, refundTxHash);
}

bool EthRpcClient::sendRawTransaction(const std::string& signedTxHex, std::string& txHash) {
  std::string params = "[\"" + signedTxHex + "\"]";
  std::string resp = jsonRpc("eth_sendRawTransaction", params);
  if (resp.empty() || jsonHasError(resp)) return false;

  txHash = jsonGetResult(resp);
  return !txHash.empty();
}

std::string EthRpcClient::computePointContractId(const std::string& sender,
                                                 const std::string& recipient,
                                                 uint64_t valueWei,
                                                 const std::string& pointAddress,
                                                 uint64_t timeoutBlock) {
  auto sendBytes  = hexToBytes(sender);
  auto recvBytes  = hexToBytes(recipient);
  auto pointBytes = hexToBytes(pointAddress);
  if (sendBytes.size() != 20 || recvBytes.size() != 20 || pointBytes.size() != 20)
    return {};

  std::vector<uint8_t> packed;
  packed.reserve(20 + 20 + 32 + 20 + 32);
  packed.insert(packed.end(), sendBytes.begin(), sendBytes.end());
  packed.insert(packed.end(), recvBytes.begin(), recvBytes.end());

  {
    std::vector<uint8_t> valBuf(32, 0);
    for (int i = 0; i < 8; ++i)
      valBuf[31 - i] = static_cast<uint8_t>((valueWei >> (i * 8)) & 0xFF);
    packed.insert(packed.end(), valBuf.begin(), valBuf.end());
  }

  packed.insert(packed.end(), pointBytes.begin(), pointBytes.end());

  {
    std::vector<uint8_t> toBuf(32, 0);
    for (int i = 0; i < 8; ++i)
      toBuf[31 - i] = static_cast<uint8_t>((timeoutBlock >> (i * 8)) & 0xFF);
    packed.insert(packed.end(), toBuf.begin(), toBuf.end());
  }

  uint8_t digest[32];
  keccak(packed.data(), static_cast<int>(packed.size()), digest, 32);
  return bytesToHex(digest, 32, /*prefix=*/false);
}

bool EthRpcClient::lockPoint(const std::string& fromAddress,
                             const std::string& recipientAddress,
                             const std::string& pointAddress,
                             uint64_t timeoutBlock,
                             uint64_t valueWei,
                             std::string& contractIdHex) {
  // m_ptlcRegistry is the dedicated pre-deployed PointTimelock registry
  // address (kept separate from the HashedTimelock registry so a chain can
  // run BRIDGE and pure-PTLC locks against different deployments).
  if (m_ptlcRegistry.empty()) {
    throw std::runtime_error("EthRpcClient::lockPoint: PointTimelock registry address not set "
                             "(configure setPtlcRegistry() with the deployed PointTimelock address)");
  }

  std::string calldata = EthAbi::encodeLockPoint(recipientAddress, pointAddress, timeoutBlock);
  auto toBytes   = hexToBytes(m_ptlcRegistry);
  auto dataBytes = hexToBytes(calldata.substr(2));

  std::string txHash;
  if (!signAndSend(toBytes, dataBytes, valueWei, /*gasLimit=*/200000, txHash))
    return false;

  EthTxReceipt receipt;
  for (int i = 0; i < 60; ++i) {
    if (getTransactionReceipt(txHash, receipt) && receipt.success) break;
#ifdef _WIN32
    Sleep(1000);
#else
    usleep(1000000);
#endif
  }
  if (!receipt.success) return false;

  contractIdHex = computePointContractId(fromAddress, recipientAddress, valueWei,
                                        pointAddress, timeoutBlock);
  return !contractIdHex.empty();
}

bool EthRpcClient::verifyPointLock(const std::string& contractIdHex,
                                   uint64_t expectedWei,
                                   const std::string& expectedRecipient,
                                   const std::string& expectedPointAddress,
                                   uint64_t minTimeoutBlock) {
  if (m_ptlcRegistry.empty()) return false;

  std::string calldata = EthAbi::encodeGetContract(contractIdHex);
  std::string result;
  if (!callContract(m_ptlcRegistry, calldata, result)) return false;

  EthAbi::PointContractInfo info;
  if (!EthAbi::decodeGetContractPoint(result, info)) return false;
  if (info.amount < expectedWei) return false;
  if (info.claimed || info.refunded) return false;
  // AUDIT 6.1: reject a lock whose on-chain timeout is too soon.
  if (minTimeoutBlock != 0 && info.timeoutBlock < minTimeoutBlock) return false;

  if (!expectedRecipient.empty()) {
    std::string er = normalizeAddr20(expectedRecipient);
    std::string ir = normalizeAddr20(info.recipient);
    if (er != ir) return false;
  }
  if (!expectedPointAddress.empty()) {
    std::string ep = normalizeAddr20(expectedPointAddress);
    std::string ip = normalizeAddr20(info.pointAddress);
    if (ep != ip) return false;
  }
  return true;
}

std::string EthRpcClient::getClaimedPointSecret(const std::string& contractIdHex) {
  if (m_ptlcRegistry.empty() || contractIdHex.empty()) return {};
  std::string calldata = EthAbi::encodeGetContract(contractIdHex);
  std::string result;
  if (!callContract(m_ptlcRegistry, calldata, result)) return {};
  EthAbi::PointContractInfo info;
  if (!EthAbi::decodeGetContractPoint(result, info)) return {};
  if (!info.claimed) return {};
  bool nonzero = false;
  for (int i = 0; i < 32; ++i) if (info.secret.data[i]) { nonzero = true; break; }
  if (!nonzero) return {};
  // Canonical big-endian scalar t as revealed on-chain (see ContractAbi endian rule).
  return bytesToHex(reinterpret_cast<const uint8_t*>(&info.secret), 32, /*prefix=*/false);
}

} // namespace XfgSwap
