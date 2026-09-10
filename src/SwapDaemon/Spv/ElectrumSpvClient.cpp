// Copyright (c) 2017-2026 Fuego Developers
//
// ElectrumSpvClient: ISpvClient implementation using the Electrum protocol
// for header synchronization.

#include "SwapDaemon/Spv/ElectrumSpvClient.h"
#include "SwapDaemon/Spv/SpvMerkle.h"

#include "SwapDaemon/BitcoinCash/HtlcScript.h"
#include "Common/JsonValue.h"

#include <algorithm>
#include <stdexcept>

namespace XfgSwap {

// =============================================================================
// Construction / Destruction
// =============================================================================

ElectrumSpvClient::ElectrumSpvClient(
    const std::vector<std::string>& servers,
    size_t minServers,
    uint64_t checkpointHeight,
    const std::string& checkpointHashDisplay)
    : m_serverAddrs(servers)
    , m_minServers(minServers) {
  if (checkpointHeight > 0) {
    m_store.anchor(checkpointHeight, checkpointHashDisplay);
  }
  // Limit memory: keep only last 2000 block headers
  m_store.setMaxHeightDelta(2000);
}

ElectrumSpvClient::~ElectrumSpvClient() = default;

// =============================================================================
// ISpvClient interface
// =============================================================================

std::string ElectrumSpvClient::protocolName() const {
  return "electrum";
}

bool ElectrumSpvClient::syncHeaders() {
  if (!connectToServers()) {
    return false;
  }

  // Verify connectivity with server.version on each connection
  for (auto& conn : m_conns) {
    std::string result = conn->call("server.version", R"(["FuegoSPV","1.4"])");
    if (result.empty()) {
      return false;
    }
  }

  // Subscribe for tip on first connected server
  std::string subResult = m_conns[0]->call("blockchain.headers.subscribe", "[]");
  if (subResult.empty()) {
    return false;
  }

  // Parse subscribe result: {"height":N,"hex":"<80-byte header hex>"}
  Common::JsonValue subJson;
  try {
    subJson = Common::JsonValue::fromString(subResult);
  } catch (const std::exception&) {
    return false;
  }

  if (!subJson.contains("height") || !subJson.contains("hex")) {
    return false;
  }

  uint64_t tipHeight = static_cast<uint64_t>(subJson("height").getInteger());
  std::string tipHex = subJson("hex").getString();

  // Verify tip header is parseable
  std::vector<uint8_t> tipRaw = BchHtlcScript::hexToBytes(tipHex);
  if (tipRaw.size() != 80) {
    return false;
  }
  SpvHeader::parse(tipRaw);

  // Determine start height for fetching
  uint64_t startHeight = 0;
  uint64_t storeTip;
  std::string storeTipHash;
  if (m_store.bestTip(storeTip, storeTipHash)) {
    if (storeTip >= tipHeight) {
      return true;  // Already synced
    }
    startHeight = storeTip + 1;
  }

  // Fetch headers in batches of 2000
  const uint32_t BATCH = 2000;
  uint64_t current = startHeight;

  while (current <= tipHeight) {
    uint32_t count = static_cast<uint32_t>(
        std::min<uint64_t>(BATCH, tipHeight - current + 1));

    std::string params = "[" + std::to_string(current) + ","
        + std::to_string(count) + "]";
    std::string result = m_conns[0]->call("blockchain.block.headers", params);

    if (result.empty()) {
      return false;
    }

    // Parse block.headers result: {"headers":"<hex>","max":"<hash>"}
    Common::JsonValue json;
    try {
      json = Common::JsonValue::fromString(result);
    } catch (const std::exception&) {
      return false;
    }

    if (!json.contains("headers")) {
      return false;
    }

    std::string headersHex = json("headers").getString();
    if (headersHex.empty()) {
      return false;
    }

    std::vector<uint8_t> rawBytes = BchHtlcScript::hexToBytes(headersHex);
    if (rawBytes.size() % 80 != 0 || rawBytes.empty()) {
      return false;
    }

    size_t numHeaders = rawBytes.size() / 80;
    for (size_t i = 0; i < numHeaders; ++i) {
      std::vector<uint8_t> headerBytes(
          rawBytes.begin() + i * 80,
          rawBytes.begin() + (i + 1) * 80);
      SpvHeader header = SpvHeader::parse(headerBytes);

      if (!m_store.addHeader(header)) {
        return false;
      }
    }

    // Eclipse mitigation: cross-check batch tip against majority when multi-server
    if (m_conns.size() > 1 && numHeaders > 0) {
      std::vector<uint8_t> lastBytes(rawBytes.begin() + (numHeaders - 1) * 80,
                                     rawBytes.begin() + numHeaders * 80);
      SpvHeader last = SpvHeader::parse(lastBytes);
      uint64_t batchTip = current + numHeaders - 1;
      // current will be incremented below, so batchTip is last height fetched
      if (!crossCheckHeader(batchTip, last.merkleRootDisplay())) {
        return false;
      }
    }

    current += numHeaders;

    if (numHeaders < count) {
      break;
    }
  }

  return true;
}

// =============================================================================
// Eclipse mitigation: multi-server cross-check
// =============================================================================

bool ElectrumSpvClient::crossCheckHeader(
    uint64_t blockHeight, const std::string& merkleRootDisplay) {
  if (m_conns.empty()) {
    return false;
  }
  if (m_conns.size() == 1) {
    return true;  // single-server mode, trust it
  }

  size_t agreeCount = 0;
  for (auto& conn : m_conns) {
    std::string params = "[" + std::to_string(blockHeight) + ",1]";
    std::string result = conn->call("blockchain.block.headers", params);
    if (result.empty()) {
      continue;
    }

    Common::JsonValue json;
    try {
      json = Common::JsonValue::fromString(result);
    } catch (const std::exception&) {
      continue;
    }

    if (!json.contains("headers")) {
      continue;
    }

    std::string hexStr = json("headers").getString();
    if (hexStr.empty()) {
      continue;
    }

    std::vector<uint8_t> rawBytes = BchHtlcScript::hexToBytes(hexStr);
    if (rawBytes.size() != 80) {
      continue;
    }

    SpvHeader header = SpvHeader::parse(rawBytes);
    std::string rootDisplay = header.merkleRootDisplay();

    if (rootDisplay == merkleRootDisplay) {
      agreeCount++;
    }
  }

  size_t required = (m_conns.size() / 2) + 1;  // strict majority
  return agreeCount >= required;
}

SpvTxInclusion ElectrumSpvClient::crossCheckTxVerify(
    const std::string& txid, const SpvTxInclusion& serverInclusion) {
  if (m_conns.size() <= 1) {
    return serverInclusion;
  }

  size_t agreeCount = 0;

  // Skip first connection (original server) — verify independently with others
  for (size_t i = 1; i < m_conns.size(); ++i) {
    auto& conn = m_conns[i];
    try {
      std::string params = "[\"" + txid + "\"]";
      std::string result = conn->call("blockchain.transaction.get_merkle", params);
      if (result.empty()) {
        continue;
      }

      Common::JsonValue json;
      try {
        json = Common::JsonValue::fromString(result);
      } catch (const std::exception&) {
        continue;
      }

      if (!json.contains("block_height") || !json.contains("merkle") || !json.contains("pos")) {
        continue;
      }

      uint64_t blockHeight = static_cast<uint64_t>(json("block_height").getInteger());
      uint32_t pos = static_cast<uint32_t>(json("pos").getInteger());

      std::vector<std::string> branch;
      const Common::JsonValue& merkleArr = json("merkle");
      for (size_t j = 0; j < merkleArr.size(); ++j) {
        branch.push_back(merkleArr[j].getString());
      }

      // Verify against our header store
      std::vector<uint8_t> rootLE;
      if (!m_store.merkleRootAt(blockHeight, rootLE)) {
        continue;
      }

      std::vector<uint8_t> rootBE(rootLE.rbegin(), rootLE.rend());
      std::string storedRootDisplay = BchHtlcScript::bytesToHex(rootBE);

      std::string computedRoot = SpvMerkle::computeRootHexDisplay(txid, branch, pos);

      if (computedRoot == storedRootDisplay) {
        agreeCount++;
      }
    } catch (const std::exception&) {
      continue;
    }
  }

  size_t required = (m_conns.size() / 2) + 1;
  // -1 because the original server already agrees
  if (agreeCount >= required - 1) {
    return serverInclusion;
  } else {
    return SpvTxInclusion();  // rejected — not enough servers agree
  }
}

bool ElectrumSpvClient::getTipHeight(uint64_t& height) {
  if (m_conns.empty()) {
    uint64_t h;
    std::string hash;
    if (!m_store.bestTip(h, hash)) {
      return false;
    }
    height = h;
    return true;
  }

  if (m_conns.size() == 1) {
    std::string result = m_conns[0]->call("blockchain.headers.subscribe", "[]");
    if (result.empty()) {
      uint64_t h;
      std::string hash;
      if (!m_store.bestTip(h, hash)) {
        return false;
      }
      height = h;
      return true;
    }
    Common::JsonValue json;
    try {
      json = Common::JsonValue::fromString(result);
    } catch (const std::exception&) {
      uint64_t h;
      std::string hash;
      if (!m_store.bestTip(h, hash)) {
        return false;
      }
      height = h;
      return true;
    }
    if (!json.contains("height")) {
      uint64_t h;
      std::string hash;
      if (!m_store.bestTip(h, hash)) {
        return false;
      }
      height = h;
      return true;
    }
    height = static_cast<uint64_t>(json("height").getInteger());
    return true;
  }

  // Multi-server: query all servers for their tip, use median to resist high-tip injection.
  std::vector<uint64_t> tips;
  for (auto& conn : m_conns) {
    std::string result = conn->call("blockchain.headers.subscribe", "[]");
    if (result.empty()) {
      continue;
    }
    Common::JsonValue json;
    try {
      json = Common::JsonValue::fromString(result);
    } catch (const std::exception&) {
      continue;
    }
    if (!json.contains("height")) {
      continue;
    }
    uint64_t h = static_cast<uint64_t>(json("height").getInteger());
    tips.push_back(h);
  }
  if (tips.empty()) {
    return false;
  }
  std::sort(tips.begin(), tips.end());
  uint64_t medianTip = tips[tips.size() / 2];
  if (medianTip == 0) {
    return false;
  }
  std::vector<uint8_t> rootLE;
  if (!m_store.merkleRootAt(medianTip, rootLE)) {
    return false;
  }
  std::vector<uint8_t> rootBE(rootLE.rbegin(), rootLE.rend());
  std::string rootDisplay = BchHtlcScript::bytesToHex(rootBE);
  if (!crossCheckHeader(medianTip, rootDisplay)) {
    return false;
  }
  height = medianTip;
  return true;
}

// =============================================================================
// Task 7: verifyTxInclusion
// =============================================================================

bool ElectrumSpvClient::verifyTxInclusion(
    const std::string& txid, SpvTxInclusion& out) {
  out = SpvTxInclusion();

  if (m_conns.empty()) {
    return false;
  }

  // 1. Call Electrum: blockchain.transaction.get_merkle(txid)
  std::string params = "[\"" + txid + "\"]";
  std::string result = m_conns[0]->call("blockchain.transaction.get_merkle", params);
  if (result.empty()) {
    return false;
  }

  Common::JsonValue json;
  try {
    json = Common::JsonValue::fromString(result);
  } catch (const std::exception&) {
    return false;
  }

  if (!json.contains("block_height") || !json.contains("merkle") || !json.contains("pos")) {
    return false;
  }

  uint64_t blockHeight = static_cast<uint64_t>(json("block_height").getInteger());
  uint32_t pos = static_cast<uint32_t>(json("pos").getInteger());

  std::vector<std::string> branch;
  const Common::JsonValue& merkleArr = json("merkle");
  for (size_t i = 0; i < merkleArr.size(); ++i) {
    branch.push_back(merkleArr[i].getString());
  }

  // 2. Get the merkle root from our header store at block_height
  std::vector<uint8_t> rootLE;
  if (!m_store.merkleRootAt(blockHeight, rootLE)) {
    // Height not in our store — cannot verify
    return false;
  }

  // Convert rootLE to display hex for comparison
  std::vector<uint8_t> rootBE(rootLE.rbegin(), rootLE.rend());
  std::string storedRootDisplay = BchHtlcScript::bytesToHex(rootBE);

  // 3. Compute Merkle root from txid + branch + pos
  std::string computedRoot = SpvMerkle::computeRootHexDisplay(txid, branch, pos);

  // 4. If computed root != stored root: proof is invalid
  if (computedRoot != storedRootDisplay) {
    out.included = false;
    out.merkleVerified = false;
    return true;
  }

  // 5. Roots match — tx is included
  out.included = true;
  out.blockHeight = blockHeight;
  out.depth = m_store.depthOf(blockHeight);
  out.merkleVerified = true;

  // 6. Cross-check with other servers (eclipse mitigation)
  out = crossCheckTxVerify(txid, out);
  return true;
}

// =============================================================================
// Task 8: getRawTx + findSpend
// =============================================================================

// Minimal raw Bitcoin transaction parser (non-witness parts only).

struct ParsedTxInput {
  std::vector<uint8_t> prevoutHash;  // 32 bytes
  uint32_t prevoutIndex = 0;
};

struct ParsedTxOutput {
  std::vector<uint8_t> scriptPubKey;
};

struct ParsedTx {
  bool valid = false;
  std::vector<ParsedTxInput> inputs;
  std::vector<ParsedTxOutput> outputs;
};

static bool readVarInt(const std::vector<uint8_t>& data, size_t& pos, uint64_t& result) {
  if (pos >= data.size()) return false;
  uint8_t first = data[pos++];
  if (first < 0xFD) {
    result = first;
    return true;
  }
  if (first == 0xFD) {
    if (pos + 2 > data.size()) return false;
    result = static_cast<uint64_t>(data[pos]) | (static_cast<uint64_t>(data[pos + 1]) << 8);
    pos += 2;
    return true;
  }
  if (first == 0xFE) {
    if (pos + 4 > data.size()) return false;
    result = static_cast<uint64_t>(data[pos])
        | (static_cast<uint64_t>(data[pos + 1]) << 8)
        | (static_cast<uint64_t>(data[pos + 2]) << 16)
        | (static_cast<uint64_t>(data[pos + 3]) << 24);
    pos += 4;
    return true;
  }
  // 0xFF — 8-byte varint
  if (pos + 8 > data.size()) return false;
  result = 0;
  for (int i = 0; i < 8; ++i) {
    result |= static_cast<uint64_t>(data[pos + i]) << (8 * i);
  }
  pos += 8;
  return true;
}

static bool readBytes(const std::vector<uint8_t>& data, size_t& pos, size_t count, std::vector<uint8_t>& out) {
  if (pos + count > data.size()) return false;
  out.assign(data.begin() + pos, data.begin() + pos + count);
  pos += count;
  return true;
}

static bool readU32LE(const std::vector<uint8_t>& data, size_t& pos, uint32_t& out) {
  if (pos + 4 > data.size()) return false;
  out = static_cast<uint32_t>(data[pos])
      | (static_cast<uint32_t>(data[pos + 1]) << 8)
      | (static_cast<uint32_t>(data[pos + 2]) << 16)
      | (static_cast<uint32_t>(data[pos + 3]) << 24);
  pos += 4;
  return true;
}

static ParsedTx parseRawTx(const std::vector<uint8_t>& raw) {
  ParsedTx tx;
  size_t pos = 0;

  // version (4 bytes LE)
  uint32_t version;
  if (!readU32LE(raw, pos, version)) return tx;

  // Check for SegWit marker: after version, if byte 0x00 then next is 0x01
  bool hasWitness = false;
  if (pos < raw.size() && raw[pos] == 0x00) {
    if (pos + 1 < raw.size() && raw[pos + 1] == 0x01) {
      hasWitness = true;
      pos += 2;  // skip marker + flag
    }
  }

  // input count
  uint64_t inputCount;
  if (!readVarInt(raw, pos, inputCount)) return tx;

  // parse inputs
  for (uint64_t i = 0; i < inputCount; ++i) {
    ParsedTxInput in;
    if (!readBytes(raw, pos, 32, in.prevoutHash)) return tx;
    if (!readU32LE(raw, pos, in.prevoutIndex)) return tx;

    // scriptSig
    uint64_t scriptSigLen;
    if (!readVarInt(raw, pos, scriptSigLen)) return tx;
    pos += scriptSigLen;
    if (pos > raw.size()) return tx;

    // sequence (4 bytes LE)
    pos += 4;
    if (pos > raw.size()) return tx;

    tx.inputs.push_back(std::move(in));
  }

  // output count
  uint64_t outputCount;
  if (!readVarInt(raw, pos, outputCount)) return tx;

  // parse outputs
  for (uint64_t i = 0; i < outputCount; ++i) {
    ParsedTxOutput out;
    pos += 8;  // value (8 bytes LE)
    if (pos > raw.size()) return tx;

    uint64_t scriptPubKeyLen;
    if (!readVarInt(raw, pos, scriptPubKeyLen)) return tx;
    if (!readBytes(raw, pos, scriptPubKeyLen, out.scriptPubKey)) return tx;

    tx.outputs.push_back(std::move(out));
  }

  // If witness, skip witness data (not needed for our purposes)
  // Witness: for each input, count + witness items
  if (hasWitness) {
    for (uint64_t i = 0; i < inputCount; ++i) {
      uint64_t itemCount;
      if (!readVarInt(raw, pos, itemCount)) return tx;
      for (uint64_t j = 0; j < itemCount; ++j) {
        uint64_t itemLen;
        if (!readVarInt(raw, pos, itemLen)) return tx;
        pos += itemLen;
        if (pos > raw.size()) return tx;
      }
    }
  }

  // locktime (4 bytes LE) — already consumed if we get here
  // pos += 4; // not needed since we're done parsing

  tx.valid = true;
  return tx;
}

// Compute Electrum scripthash: reverse(sha256(scriptPubKey))
static std::string computeElectrumScripthash(const std::vector<uint8_t>& scriptPubKey) {
  std::vector<uint8_t> hash = BchHtlcScript::sha256(scriptPubKey);
  std::reverse(hash.begin(), hash.end());
  return BchHtlcScript::bytesToHex(hash);
}

bool ElectrumSpvClient::getRawTx(
    const std::string& txid, std::vector<uint8_t>& rawTx) {
  rawTx.clear();

  if (m_conns.empty()) {
    return false;
  }

  // Validate txid is hex-only to prevent JSON injection
  static const char hexChars[] = "0123456789abcdefABCDEF";
  if (txid.size() != 64 || txid.find_first_not_of(hexChars) != std::string::npos) {
    return false;
  }

  std::string params = "[\"" + txid + "\"]";
  std::string result = m_conns[0]->call("blockchain.transaction.get", params);
  if (result.empty()) {
    return false;
  }

  // Result is a JSON string containing the raw hex
  Common::JsonValue json;
  try {
    json = Common::JsonValue::fromString(result);
  } catch (const std::exception&) {
    return false;
  }

  if (!json.isString()) {
    return false;
  }

  std::string hexStr = json.getString();
  if (hexStr.empty()) {
    return false;
  }

  rawTx = BchHtlcScript::hexToBytes(hexStr);
  return !rawTx.empty();
}

bool ElectrumSpvClient::findSpend(
    const std::string& txid, uint32_t vout, SpvSpend& out) {
  out = SpvSpend();

  if (m_conns.empty()) {
    return false;
  }

  // 1. Get the funding transaction
  std::vector<uint8_t> fundingRaw;
  if (!getRawTx(txid, fundingRaw)) {
    return false;
  }

  // 2. Parse the funding tx to extract the output's scriptPubKey
  ParsedTx fundingTx = parseRawTx(fundingRaw);
  if (!fundingTx.valid) {
    return false;
  }
  if (vout >= fundingTx.outputs.size()) {
    // Output index doesn't exist — successfully determined no spend
    return true;
  }

  const std::vector<uint8_t>& scriptPubKey = fundingTx.outputs[vout].scriptPubKey;

  // 3. Compute the Electrum scripthash
  std::string scripthash = computeElectrumScripthash(scriptPubKey);

  // 4. Get the history for this scripthash
  std::string historyParams = "[\"" + scripthash + "\"]";
  std::string historyResult = m_conns[0]->call("blockchain.scripthash.get_history", historyParams);
  if (historyResult.empty()) {
    return false;
  }

  Common::JsonValue historyJson;
  try {
    historyJson = Common::JsonValue::fromString(historyResult);
  } catch (const std::exception&) {
    return false;
  }

  // history is an array of {"tx_hash":"...","height":N}
  if (!historyJson.isArray()) {
    return false;
  }

  // 5. For each candidate txid in the history, check inputs
  // Pre-compute funding txid in internal LE bytes for outpoint comparison
  std::vector<uint8_t> fundingTxidBE = BchHtlcScript::hexToBytes(txid);
  if (fundingTxidBE.size() != 32) {
    return false;
  }
  std::vector<uint8_t> fundingTxidLE(fundingTxidBE.rbegin(), fundingTxidBE.rend());

  for (size_t i = 0; i < historyJson.size(); ++i) {
    const Common::JsonValue& entry = historyJson[i];
    if (!entry.contains("tx_hash") || !entry("tx_hash").isString()) {
      continue;
    }

    std::string candidateTxid = entry("tx_hash").getString();

    // Skip the funding tx itself
    if (candidateTxid == txid) {
      continue;
    }

    // Get the candidate spending tx
    std::vector<uint8_t> candidateRaw;
    if (!getRawTx(candidateTxid, candidateRaw)) {
      continue;
    }

    ParsedTx candidateTx = parseRawTx(candidateRaw);
    if (!candidateTx.valid) {
      continue;
    }

    // 6. Check if any input spends txid:vout
    for (const auto& input : candidateTx.inputs) {
      if (input.prevoutHash.size() != 32) continue;
      if (input.prevoutHash == fundingTxidLE && input.prevoutIndex == vout) {
        // Found the spend!
        out.spent = true;
        out.spendingTxid = candidateTxid;
        out.rawSpendingTx = candidateRaw;

        // 7. Verify inclusion
        verifyTxInclusion(candidateTxid, out.inclusion);
        return true;
      }
    }
  }

  return true;
}

bool ElectrumSpvClient::broadcastTx(const std::vector<uint8_t>& rawTx, std::string& txid) {
  if (m_conns.empty()) {
    return false;
  }

  // Convert raw tx to hex string
  std::string hexTx = BchHtlcScript::bytesToHex(rawTx);
  if (hexTx.empty()) {
    return false;
  }

  std::string params = "[\"" + hexTx + "\"]";
  std::string result = m_conns[0]->call("blockchain.transaction.broadcast", params);
  if (result.empty()) {
    return false;
  }

  // Parse result as JSON string
  Common::JsonValue json;
  try {
    json = Common::JsonValue::fromString(result);
  } catch (const std::exception&) {
    return false;
  }

  if (!json.isString()) {
    return false;
  }

  txid = json.getString();
  return txid.size() == 64;
}

// =============================================================================
// Private helpers
// =============================================================================

bool ElectrumSpvClient::connectToServers() {
  // Disconnect any existing connections
  m_conns.clear();

  size_t connected = 0;
  for (const auto& addr : m_serverAddrs) {
    // Parse "host:port"
    auto colon = addr.rfind(':');
    if (colon == std::string::npos) {
      continue;
    }

    std::string host = addr.substr(0, colon);
    uint16_t port = 0;
    try {
      port = static_cast<uint16_t>(std::stoi(addr.substr(colon + 1)));
    } catch (const std::exception&) {
      continue;
    }

    auto conn = std::make_unique<ElectrumConnection>();
    conn->setConnectTimeout(5);
    conn->setReadTimeout(30);
    if (conn->connect(host, port)) {
      m_conns.push_back(std::move(conn));
      ++connected;
    }
  }

  return connected >= m_minServers;
}

} // namespace XfgSwap
