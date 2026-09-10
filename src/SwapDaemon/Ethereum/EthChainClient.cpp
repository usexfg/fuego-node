#include "EthChainClient.h"
#include "ContractAbi.h"
#include "Common/StringTools.h"
#include "crypto/keccak.h"
#include "crypto/secp_adaptor.h"
#include "../Crypto/Secp256k1Signer.h"
#include "../SwapHashLock.h"
#include "../SwapTimelock.h"   // AUDIT 6.1: msPerBlock() for the timeout floor
#include <algorithm>
#include <stdexcept>
#include <cctype>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace XfgSwap {

namespace {
bool isZeroSecret(const Crypto::SecretKey& s) {
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&s);
  for (size_t i = 0; i < sizeof(Crypto::SecretKey); ++i) {
    if (p[i]) return false;
  }
  return true;
}

// True when the swap negotiated a PURE point lock on this chain (not the
// PTLC_HTLC_BRIDGE hybrid): lockType == PTLC and Bob published T_secp.
bool ptlcNegotiated(const SwapParams& params) {
  return params.lockType == SwapLockType::PTLC && !params.secpPubHex.empty();
}
} // namespace

// Canonical endian rule (see PointTimelock.sol claim() and ContractAbi):
// Solidity uint256 / libsecp256k1 read scalars BIG-endian; CryptoNote stores
// scalars LITTLE-endian. secp-domain secret bytes = byte-reversed CryptoNote
// scalar bytes. Cross-curve scalar reuse is sound: t < l_ed25519 < n_secp.
std::string EthChainClient::secretBeHex(const Crypto::SecretKey& t) {
  const auto* le = reinterpret_cast<const uint8_t*>(&t);
  std::string hex;
  hex.reserve(64);
  static const char* kDigits = "0123456789abcdef";
  for (int i = 31; i >= 0; --i) {   // reverse => canonical big-endian
    hex.push_back(kDigits[le[i] >> 4]);
    hex.push_back(kDigits[le[i] & 0x0F]);
  }
  return hex;
}

// Inverse of secretBeHex: on-chain revealed BE scalar -> CryptoNote LE
// scalar bytes, ready for XFG adaptor-sig completion.
std::string EthChainClient::secretLeHexFromBe(const std::string& beHex64) {
  if (beHex64.size() != 64) return {};
  std::string out;
  out.reserve(64);
  for (int byte = 31; byte >= 0; --byte) {
    out.push_back(beHex64[2 * byte]);
    out.push_back(beHex64[2 * byte + 1]);
  }
  return out;
}

EthChainClient::EthChainClient(std::unique_ptr<EthRpcClient> rpc, const std::string& address,
                               const std::string& chainName)
  : m_rpc(std::move(rpc)), m_address(address), m_chainName(chainName) {}

void EthChainClient::setPtlcRegistry(const std::string& registryAddress) {
  m_ptlcRegistry = registryAddress;
  if (m_rpc) m_rpc->setPtlcRegistry(registryAddress);
}

bool EthChainClient::supportsPurePtlc() const {
  return !m_ptlcRegistry.empty();
}

ChainClientResult EthChainClient::lock(const SwapParams& params) {
  try {
    // ── Pure PTLC routing (PointTimelock registry model) ────────────────────
    // lockType == PTLC + published T_secp + registry configured => fund the
    // point lock. Fail-closed: when pure PTLC was negotiated but the registry
    // is missing we must NOT silently fall back to an HTLC deploy — the
    // counterparty verified a point lock and the adaptor equation binds to it.
    if (ptlcNegotiated(params)) {
      if (m_ptlcRegistry.empty())
        return ChainClientResult::fail(m_chainName +
            " pure PTLC negotiated but PointTimelock registry not configured");
      Crypto::SecpPubKey secpPub;
      if (!Crypto::hexToSecpPubKey(params.secpPubHex, secpPub))
        return ChainClientResult::fail(m_chainName + " lock: malformed secpPubHex");
      std::string pointAddress =
          EthAbi::derivePointAddressFromSecpBytes(secpPub.data.data(), secpPub.data.size());
      if (pointAddress.empty())
        return ChainClientResult::fail(m_chainName + " lock: point-address derivation failed");
      std::string contractId;
      if (!m_rpc->lockPoint(m_address, params.ctrAddress, pointAddress,
                            params.ctrTimeoutBlock, params.ctrAmount, contractId))
        return ChainClientResult::fail(m_chainName + " lockPoint failed");
      return ChainClientResult::ok(contractId);
    }

    // Hashlock MUST be keccak256(adaptorSecret) / params.hashLock from Bob.
    // Alice-locks model: Alice has hashLock (H(t)) but not t; Bob has t for claim.
    std::string hashHex;
    if (!isZeroSecret(params.adaptorSecret)) {
      hashHex = ethHashLockHex(params.adaptorSecret);
    } else {
      // Use Bob's published H(t)
      bool nonzero = false;
      for (size_t i = 0; i < sizeof(params.hashLock); ++i)
        if (reinterpret_cast<const uint8_t*>(&params.hashLock)[i]) { nonzero = true; break; }
      if (!nonzero)
        return ChainClientResult::fail(m_chainName + " lock: no adaptor secret or hashLock");
      hashHex = Common::podToHex(params.hashLock);
    }

    std::string contractAddress;
    bool ok = m_rpc->deployHtlc(
        m_address,
        params.ctrAddress,
        hashHex,
        params.ctrTimeoutBlock,
        params.ctrAmount,
        contractAddress);
    if (!ok) return ChainClientResult::fail(m_chainName + " deployHtlc failed");
    return ChainClientResult::ok(contractAddress);
  } catch (const std::runtime_error& e) {
    auto r = ChainClientResult::fail(m_chainName + " lock error: " + e.what());
    r.fatal = true;
    return r;
  }
}

ChainClientResult EthChainClient::verifyLock(const SwapParams& params) {
  // ctrLockTxId holds the registry contractId (not a tx hash).

  // AUDIT 6.1: the counterparty's on-chain timeout must leave us enough runway
  // to observe the lock, wait our required confirmations, and get our claim
  // mined before they can refund (otherwise: they refund, we've already
  // revealed t / locked our side, we lose). Require the lock to outlast the
  // current tip by (confirmations + a ~1h time-based floor in this chain's
  // blocks). If the tip is unavailable we pass 0 and skip the check —
  // behaviour is then exactly as before this fix, never stricter-by-accident.
  uint64_t minTimeoutBlock = 0;
  {
    uint64_t ethTip = 0;
    if (m_rpc->getBlockNumber(ethTip)) {
      const uint64_t msPer = msPerBlock(params.pair);
      uint64_t runwayBlocks = (msPer > 0) ? (3600ULL * 1000ULL) / msPer : 300;
      runwayBlocks = std::max<uint64_t>(runwayBlocks, 30);
      const uint64_t conf =
          params.requiredConfirmations ? params.requiredConfirmations : 6;
      minTimeoutBlock = ethTip + conf + runwayBlocks;
    }
  }

  // Pure PTLC: verify amount + recipient + pointAddress + not claimed/refunded
  // against the PointTimelock registry. Fail-closed on missing registry.
  if (ptlcNegotiated(params)) {
    if (m_ptlcRegistry.empty())
      return ChainClientResult::fail(m_chainName +
          " pure PTLC negotiated but PointTimelock registry not configured");
    Crypto::SecpPubKey secpPub;
    if (!Crypto::hexToSecpPubKey(params.secpPubHex, secpPub))
      return ChainClientResult::fail(m_chainName + " verifyLock: malformed secpPubHex");
    std::string expectedPointAddress =
        EthAbi::derivePointAddressFromSecpBytes(secpPub.data.data(), secpPub.data.size());
    bool ok = m_rpc->verifyPointLock(params.ctrLockTxId, params.ctrAmount,
                                     params.ctrAddress, expectedPointAddress,
                                     minTimeoutBlock);
    if (!ok) return ChainClientResult::fail(m_chainName +
        " lock not verified (amount/recipient/point/timeout)");
    return ChainClientResult::ok(params.ctrLockTxId);
  }

  // Verify amount + recipient + hashlock + not claimed/refunded via getContract.
  // Prefer H(t) from adaptorSecret; Alice has only published hashLock — use that.
  std::string expectedHash;
  if (!isZeroSecret(params.adaptorSecret)) {
    expectedHash = ethHashLockHex(params.adaptorSecret);
  } else {
    bool nonzero = false;
    for (size_t i = 0; i < sizeof(params.hashLock); ++i)
      if (reinterpret_cast<const uint8_t*>(&params.hashLock)[i]) { nonzero = true; break; }
    if (nonzero)
      expectedHash = Common::podToHex(params.hashLock);
  }
  if (expectedHash.empty())
    return ChainClientResult::fail(m_chainName + " verifyLock: no hashLock or adaptorSecret");
  bool ok = m_rpc->verifyLock(params.ctrLockTxId, params.ctrAmount,
                              params.ctrAddress, expectedHash, minTimeoutBlock);
  if (!ok) return ChainClientResult::fail(m_chainName +
      " lock not verified (amount/recipient/hashlock/timeout)");
  return ChainClientResult::ok(params.ctrLockTxId);
}

ChainClientResult EthChainClient::claim(const SwapParams& params) {
  try {
    std::string claimTxHash;
    // Pure PTLC: reveal the canonical BIG-endian scalar t via
    // claim(contractId, secret) on the PointTimelock registry.
    if (ptlcNegotiated(params)) {
      if (m_ptlcRegistry.empty())
        return ChainClientResult::fail(m_chainName +
            " pure PTLC negotiated but PointTimelock registry not configured");
      bool ok = m_rpc->claimPoint(
          m_address,
          params.ctrLockTxId,
          secretBeHex(params.adaptorSecret),
          claimTxHash);
      if (!ok) return ChainClientResult::fail(m_chainName + " claimPoint failed");
      return ChainClientResult::ok(claimTxHash);
    }

    bool ok = m_rpc->claimHtlc(
        m_address,
        params.ctrLockTxId,
        Common::podToHex(params.adaptorSecret),
        claimTxHash);
    if (!ok) return ChainClientResult::fail(m_chainName + " claimHtlc failed");
    return ChainClientResult::ok(claimTxHash);
  } catch (const std::runtime_error& e) {
    auto r = ChainClientResult::fail(m_chainName + " claim error: " + e.what());
    r.fatal = true;
    return r;
  }
}

ChainClientResult EthChainClient::refund(const SwapParams& params) {
  try {
    std::string refundTxHash;
    // Pure PTLC: refund(contractId) on the PointTimelock registry. Selector is
    // identical to the HTLC path (refund(bytes32) — verified in both .sol
    // files), so we route to the shared encoding with m_ptlcRegistry as target.
    if (ptlcNegotiated(params)) {
      if (m_ptlcRegistry.empty())
        return ChainClientResult::fail(m_chainName +
            " pure PTLC negotiated but PointTimelock registry not configured");
      bool ok = m_rpc->refundPoint(
          m_address,
          params.ctrLockTxId,
          refundTxHash);
      if (!ok) return ChainClientResult::fail(m_chainName + " refundPoint failed");
      return ChainClientResult::ok(refundTxHash);
    }

    bool ok = m_rpc->refundHtlc(
        m_address,
        params.ctrLockTxId,
        refundTxHash);
    if (!ok) return ChainClientResult::fail(m_chainName + " refundHtlc failed");
    return ChainClientResult::ok(refundTxHash);
  } catch (const std::runtime_error& e) {
    auto r = ChainClientResult::fail(m_chainName + " refund error: " + e.what());
    r.fatal = true;
    return r;
  }
}

ChainClientResult EthChainClient::verifyReserveProof(const std::string& expectedMessage,
    uint64_t minAmount, const std::string& proof) {
  size_t c1 = proof.find(':');
  size_t c2 = proof.find(':', c1 + 1);
  if (c1 == std::string::npos || c2 == std::string::npos)
    return ChainClientResult::fail(m_chainName + " reserve proof: invalid format (expected address:signature:message)");

  std::string address   = proof.substr(0, c1);
  std::string sigHex    = proof.substr(c1 + 1, c2 - c1 - 1);
  std::string message   = proof.substr(c2 + 1);

  // Parse 65-byte recoverable signature: r(32) + s(32) + v(1)
  if (sigHex.size() != 130)
    return ChainClientResult::fail(m_chainName + " reserve proof: signature must be 65 bytes hex (130 chars)");

  auto hexNibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };

  std::array<uint8_t, 32> rBytes;
  std::array<uint8_t, 32> sBytes;
  for (int i = 0; i < 32; ++i) {
    rBytes[i] = static_cast<uint8_t>((hexNibble(sigHex[2*i]) << 4) | hexNibble(sigHex[2*i + 1]));
    sBytes[i] = static_cast<uint8_t>((hexNibble(sigHex[64 + 2*i]) << 4) | hexNibble(sigHex[64 + 2*i + 1]));
  }
  uint8_t v = static_cast<uint8_t>((hexNibble(sigHex[128]) << 4) | hexNibble(sigHex[129]));

  CryptoNote::SwapDaemon::Crypto::RecoverableSignature sig;
  sig.r = rBytes;
  sig.s = sBytes;
  sig.recid = (v >= 27) ? static_cast<uint8_t>(v - 27) : v;

  // Compute EIP-191 personal_sign digest: keccak256("\x19Ethereum Signed Message:\n" + len + message)
  std::string prefix = "\x19" "Ethereum Signed Message:\n" + std::to_string(message.size());
  std::vector<uint8_t> eip191(prefix.size() + message.size());
  std::memcpy(eip191.data(), prefix.data(), prefix.size());
  std::memcpy(eip191.data() + prefix.size(), message.data(), message.size());

  std::array<uint8_t, 32> msgHash;
  keccak(eip191.data(), static_cast<int>(eip191.size()), msgHash.data(), 32);

  CryptoNote::SwapDaemon::Crypto::Secp256k1Signer signer;
  std::vector<uint8_t> pubkey;
  try {
    pubkey = signer.recoverPublicKey(msgHash, sig);
  } catch (const std::runtime_error&) {
    return ChainClientResult::fail(m_chainName + " reserve proof: ecrecover failed");
  }

  // Derive ETH address: last 20 bytes of keccak256(pubkey[1..64])
  uint8_t addrHash[32];
  keccak(pubkey.data() + 1, 64, addrHash, 32);

  std::ostringstream derived;
  derived << "0x";
  for (int i = 12; i < 32; ++i) {
    derived << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(addrHash[i]);
  }

  // Case-insensitive compare
  std::string derivedAddr = derived.str();
  if (address.size() != derivedAddr.size())
    return ChainClientResult::fail(m_chainName + " reserve proof: invalid signature (address mismatch)");
  for (size_t i = 0; i < address.size(); ++i) {
    if (std::tolower(address[i]) != std::tolower(derivedAddr[i]))
      return ChainClientResult::fail(m_chainName + " reserve proof: invalid signature (address mismatch)");
  }

  if (!expectedMessage.empty() && message != expectedMessage)
    return ChainClientResult::fail(m_chainName + " reserve proof: message not bound to this offer");

  uint64_t balanceWei = 0;
  if (!m_rpc->getBalance(address, balanceWei))
    return ChainClientResult::fail(m_chainName + " reserve proof: balance check RPC failed");
  if (balanceWei < minAmount)
    return ChainClientResult::fail(m_chainName + " reserve proof: insufficient balance (" +
                                   std::to_string(balanceWei) + " < " + std::to_string(minAmount) + ")");

  return ChainClientResult::ok(address);
}

bool EthChainClient::getCurrentHeight(uint64_t& height) {
  return m_rpc->getBlockNumber(height);
}

std::string EthChainClient::tryExtractClaimedSecret(const SwapParams& params) {
  // Pure PTLC: ctrLockTxId is the PointTimelock contractId; after claim the
  // canonical BIG-endian scalar t is stored on-chain. Reverse it back to the
  // CryptoNote LITTLE-endian scalar our XFG adaptor consumes.
  if (ptlcNegotiated(params)) {
    if (m_ptlcRegistry.empty()) return {};
    return secretLeHexFromBe(m_rpc->getClaimedPointSecret(params.ctrLockTxId));
  }
  // BRIDGE/HTLC: after claim, preimage is stored on-chain.
  return m_rpc->getClaimedPreimage(params.ctrLockTxId);
}

} // namespace XfgSwap
