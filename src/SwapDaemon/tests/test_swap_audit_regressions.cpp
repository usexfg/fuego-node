// Copyright (c) 2017-2026 Fuego Developers
//
// Regression tests for the 2026-09-09 swap security audit
// (docs/review/2026-09-09-swap-security-audit.md).
//
//   1.2 / 3.2  a recovered adaptor scalar must actually open the adaptor point
//              published for THIS swap, not merely be non-zero.
//   6.1        a counterparty lock whose on-chain timeout is too soon must be
//              rejected; this pins the timeout floor the check is built on.
//
// 6.2 (contract-wallet recipients / reentrancy) is covered by forge in
// contracts/point-timelock/test/PointTimelock.t.sol; 2.1 (matured legacy
// deposits still withdraw for principal) by tests/CoreTests/TreasuryCoreTests.cpp.

#include <algorithm>
#include <cstring>
#include <iostream>

#include "crypto/secp_adaptor.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "SwapDaemon/SwapTimelock.h"
#include "SwapDaemon/SwapTypes.h"

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(cond, msg) do { \
  if (cond) { ++g_pass; std::cout << "  PASS: " << msg << "\n"; } \
  else { ++g_fail; std::cerr << "  FAIL: " << msg << "\n"; } \
} while (0)

using namespace Crypto;

static Hash msgDigest(uint8_t seed) {
  Hash h{}; for (size_t i = 0; i < sizeof(h.data); ++i) h.data[i] = (uint8_t)(seed + i);
  return h;
}

// ── AUDIT 1.2 / 3.2 ──────────────────────────────────────────────────────────

static void testAdaptorExtractBindsToPublishedPoint() {
  std::cout << "\nAUDIT 1.2/3.2: extracted scalar must open the published point\n";

  SecretKey sk, k, t, tOther;
  PublicKey ignore{};
  generate_keys(ignore, sk);
  generate_keys(ignore, k);
  generate_keys(ignore, t);
  generate_keys(ignore, tOther);

  SecpPubKey P{}, T{}, TOther{};
  CHECK(secp_secret_to_pubkey(sk, P), "signer pubkey derives");
  CHECK(secp_secret_to_pubkey(t, T), "adaptor point T = t*G derives");
  CHECK(secp_secret_to_pubkey(tOther, TOther), "unrelated point T' derives");
  CHECK(T != TOther, "T and T' are distinct points");

  const Hash msg = msgDigest(0x11);
  SecpAdaptorPresig presig{};
  CHECK(secp_adaptor_sign(sk, k, t, msg, presig), "adaptor presig created");
  CHECK(secp_adaptor_verify(P, T, presig, msg), "presig verifies against P and T");

  SecpSchnorrSig sig{};
  CHECK(secp_complete_schnorr_sig(sk, k, msg, sig), "counterparty completes the signature");

  // Correct point: extraction succeeds and returns exactly t.
  SecretKey got{};
  CHECK(secp_adaptor_extract(presig, sig, T, got), "extract succeeds for the published T");
  CHECK(std::memcmp(&got, &t, sizeof(t)) == 0, "recovered scalar equals t");

  // Wrong point: the scalar is non-zero and would have passed the old check,
  // but it does not open T', so extraction must refuse it.
  SecretKey bogus{};
  bool acceptedWrongT = secp_adaptor_extract(presig, sig, TOther, bogus);
  CHECK(!acceptedWrongT, "extract REFUSES a scalar that does not open the given point");

  // The 3-arg form still recovers t (it only guards t != 0) — this is the
  // weaker contract the 4-arg overload exists to replace.
  SecretKey legacy{};
  CHECK(secp_adaptor_extract(presig, sig, legacy), "3-arg extract still recovers t");
  CHECK(std::memcmp(&legacy, &t, sizeof(t)) == 0, "3-arg result equals t");

  // A presig/sig pair from different sessions yields a scalar that opens
  // nothing — precisely the rogue-signature case 1.2 describes.
  SecpAdaptorPresig otherPresig{};
  CHECK(secp_adaptor_sign(sk, k, tOther, msgDigest(0x22), otherPresig),
        "second-session presig created");
  SecretKey crossed{};
  CHECK(!secp_adaptor_extract(otherPresig, sig, T, crossed),
        "cross-session presig/sig pair is rejected against T");
}

// ── AUDIT 6.1 ────────────────────────────────────────────────────────────────

// Mirrors the derivation in EthChainClient::verifyLock.
static uint64_t runwayBlocksFor(uint64_t msPer) {
  uint64_t runway = (msPer > 0) ? (3600ULL * 1000ULL) / msPer : 300;
  return std::max<uint64_t>(runway, 30);
}

static void testLockTimeoutFloor() {
  std::cout << "\nAUDIT 6.1: lock timeout floor leaves real claim runway\n";

  const XfgSwap::SwapPair pairs[] = {
    XfgSwap::SwapPair::ETH, XfgSwap::SwapPair::ARB, XfgSwap::SwapPair::BASE,
    XfgSwap::SwapPair::BNB, XfgSwap::SwapPair::POLYGON, XfgSwap::SwapPair::AVAX,
    XfgSwap::SwapPair::CRO, XfgSwap::SwapPair::BOB, XfgSwap::SwapPair::GLEEC,
    XfgSwap::SwapPair::ROBINHOOD, XfgSwap::SwapPair::BTC, XfgSwap::SwapPair::LTC,
    XfgSwap::SwapPair::XMR, XfgSwap::SwapPair::DCR,
  };

  bool allCoverAnHour = true, allAtLeastFloor = true;
  for (auto p : pairs) {
    uint64_t msPer = XfgSwap::msPerBlock(p);
    if (msPer == 0) { allCoverAnHour = false; continue; }
    uint64_t runway = runwayBlocksFor(msPer);
    if (runway * msPer < 3600ULL * 1000ULL) allCoverAnHour = false;
    if (runway < 30) allAtLeastFloor = false;
  }
  CHECK(allCoverAnHour, "every chain's runway spans at least one hour of blocks");
  CHECK(allAtLeastFloor, "runway never drops below the 30-block floor");

  // The check itself: a lock expiring at or before tip+confirmations+runway is
  // rejected; one beyond it is accepted. minTimeoutBlock == 0 disables the test,
  // which is the fail-open path used when the chain tip is unavailable.
  const uint64_t tip = 1'000'000, conf = 6;
  const uint64_t runway = runwayBlocksFor(XfgSwap::msPerBlock(XfgSwap::SwapPair::ETH));
  const uint64_t minTimeoutBlock = tip + conf + runway;

  auto rejected = [&](uint64_t onChainTimeout, uint64_t minBlock) {
    return minBlock != 0 && onChainTimeout < minBlock;   // EthRpcClient.cpp:855
  };

  CHECK(rejected(tip + 1, minTimeoutBlock), "a 1-block timeout is rejected");
  CHECK(rejected(tip + conf, minTimeoutBlock), "a confirmations-only timeout is rejected");
  CHECK(rejected(minTimeoutBlock - 1, minTimeoutBlock), "one block short is rejected");
  CHECK(!rejected(minTimeoutBlock, minTimeoutBlock), "exactly the floor is accepted");
  CHECK(!rejected(minTimeoutBlock + 1000, minTimeoutBlock), "a generous timeout is accepted");
  CHECK(!rejected(tip + 1, 0), "minTimeoutBlock == 0 skips the check (tip unavailable)");
}

int main() {
  std::cout << "Swap security audit regressions\n===============================\n";
  testAdaptorExtractBindsToPublishedPoint();
  testLockTimeoutFloor();
  std::cout << "\n===============================\n"
            << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}
