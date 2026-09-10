// Copyright (c) 2017-2026 Fuego Developers
//
// Pre-sig round wiring test: ESCROW_FUNDED message codec, Musig2 state
// persistence (nonce reuse class protections), and session determinism.
//
// Stages:
//   1. ESCROW_FUNDED message serialize/deserialize roundtrip + signature
//   2. SwapStateMachine v4 roundtrip: musig2 nonce, partial sigs and progress
//      flags survive serialize → deserialize → decrypt
//   3. Nonce non-resurrection: after adaptor_partial_sign consumes (zeroes)
//      the secret nonce, the roundtrip record must NOT restore it, and
//      partialSigGenerated must survive
//   4. Presig session message determinism: both parties derive the same
//      session hash from the escrow tx hash (via presigSessionHash)
//   5. Zero-nonce guard: adaptor_partial_sign refuses a zeroed secret nonce
//   6. Failed nonce decrypt clears pre-sig progress (fail closed, no re-sign)

#include <cstring>
#include <iostream>

#include "SwapDaemon/AdaptorSwap.h"
#include "SwapDaemon/SwapDatabase.h"
#include "SwapDaemon/SwapPeerProtocol.h"
#include "SwapDaemon/SwapStateMachine.h"
#include "SwapDaemon/SwapTypes.h"
#include "crypto/crypto.h"

#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

using namespace XfgSwap;

static int g_pass = 0, g_fail = 0;
#define CHECK(c, m) do { if (c) { ++g_pass; std::cout << "  PASS: " << m << "\n"; } \
  else { ++g_fail; std::cerr << "  FAIL: " << m << "\n"; } } while (0)

static bool bytesEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  return std::memcmp(a, b, n) == 0;
}

static bool isZeroBytes(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; ++i) if (p[i]) return false;
  return true;
}

static bool testEscrowFundedCodec() {
  Crypto::SecretKey sk;
  Crypto::PublicKey pk;
  Crypto::generate_keys(pk, sk);

  PeerMessage msg;
  msg.type = PeerMessageType::ESCROW_FUNDED;
  msg.swapId = "escrow-funded-codec-1";
  for (size_t i = 0; i < 32; ++i) msg.escrowFunded.escrowTxHash.data[i] = static_cast<uint8_t>(i * 7 + 1);
  signPeerMessage(msg, pk, sk);

  std::string json = serializePeerMessage(msg);
  PeerMessage decoded;
  if (!deserializePeerMessage(json, decoded)) return false;
  if (decoded.type != PeerMessageType::ESCROW_FUNDED) return false;
  if (decoded.swapId != msg.swapId) return false;
  if (!bytesEqual(decoded.escrowFunded.escrowTxHash.data,
                  msg.escrowFunded.escrowTxHash.data, 32)) return false;
  return verifyPeerMessage(decoded, pk);
}

static bool testStateRoundtrip() {
  SwapParams p{};
  p.swapId = "persist-1";
  p.role = SwapRole::BOB;
  p.pair = SwapPair::ETH;
  adaptor_generate_keys(p);
  adaptor_nonce_generate(p);
  p.musig2.nonceSent = true;
  // Simulate a peer nonce and partial sig
  Crypto::Musig2SecNonce junkSec;
  Crypto::musig2_nonce_gen(junkSec, p.musig2.peerPubNonce);
  for (size_t i = 0; i < 32; ++i) {
    p.musig2.peerPartialSig.s.data[i] = static_cast<uint8_t>(i + 3);
    p.musig2.ourPartialSig.s.data[i] = static_cast<uint8_t>(i + 9);
  }
  p.musig2.partialSigGenerated = true;
  p.musig2.partialSigSent = true;
  p.escrowFundedSent = true;
  for (size_t i = 0; i < 32; ++i) p.escrowTxHash.data[i] = static_cast<uint8_t>(i + 1);

  SwapStateMachine sm(p);
  sm.setEncryptionKey("presig-roundtrip-enc-key");
  std::string json = sm.serialize();
  if (json.empty()) return false;

  SwapStateMachine loaded = SwapStateMachine::deserialize(json);
  loaded.setEncryptionKey("presig-roundtrip-enc-key");
  loaded.decryptStoredSecret();
  const SwapParams& lp = loaded.params();

  if (!bytesEqual(reinterpret_cast<const uint8_t*>(&lp.musig2.ourPubNonce),
                  reinterpret_cast<const uint8_t*>(&p.musig2.ourPubNonce),
                  sizeof(Crypto::Musig2PubNonce))) return false;
  if (!bytesEqual(reinterpret_cast<const uint8_t*>(&lp.musig2.peerPubNonce),
                  reinterpret_cast<const uint8_t*>(&p.musig2.peerPubNonce),
                  sizeof(Crypto::Musig2PubNonce))) return false;
  if (!bytesEqual(reinterpret_cast<const uint8_t*>(&lp.musig2.ourSecNonce),
                  reinterpret_cast<const uint8_t*>(&p.musig2.ourSecNonce),
                  sizeof(Crypto::Musig2SecNonce))) return false;
  if (!bytesEqual(lp.musig2.ourPartialSig.s.data, p.musig2.ourPartialSig.s.data, 32)) return false;
  if (!bytesEqual(lp.musig2.peerPartialSig.s.data, p.musig2.peerPartialSig.s.data, 32)) return false;
  if (!lp.musig2.nonceGenerated || !lp.musig2.nonceSent) return false;
  if (!lp.musig2.partialSigGenerated || !lp.musig2.partialSigSent) return false;
  if (!lp.escrowFundedSent) return false;
  return true;
}

static bool testNonceNonResurrection() {
  // After partial_sign the secret nonce is consumed (zeroed). A serialize →
  // deserialize roundtrip must NOT resurrect it, and the progress flag must
  // prevent any re-sign attempt after a crash/restart.
  SwapParams p{};
  p.swapId = "persist-2";
  p.role = SwapRole::BOB;
  p.pair = SwapPair::ETH;
  adaptor_generate_keys(p);
  Crypto::SecretKey peerSk;
  Crypto::PublicKey peerPk;
  Crypto::generate_keys(peerPk, peerSk);
  p.peerSwapPubKey = peerPk;
  adaptor_key_aggregate(p);

  adaptor_nonce_generate(p);
  Crypto::Musig2SecNonce junkSec;
  Crypto::musig2_nonce_gen(junkSec, p.musig2.peerPubNonce);
  for (size_t i = 0; i < 32; ++i) p.escrowTxHash.data[i] = 0xEE;

  if (!adaptor_session_init(p, p.escrowTxHash, true)) return false;
  if (!adaptor_partial_sign(p)) return false;
  if (!isZeroBytes(reinterpret_cast<const uint8_t*>(&p.musig2.ourSecNonce),
                   sizeof(Crypto::Musig2SecNonce))) return false;  // consumed in memory
  p.musig2.partialSigGenerated = true;

  SwapStateMachine sm(p);
  sm.setEncryptionKey("presig-nonres-enc-key");
  std::string json = sm.serialize();
  if (json.empty()) return false;

  SwapStateMachine loaded = SwapStateMachine::deserialize(json);
  loaded.setEncryptionKey("presig-nonres-enc-key");
  loaded.decryptStoredSecret();
  const SwapParams& lp = loaded.params();

  // Nonce stays zeroed after reload (never resurrected for re-signing).
  if (!isZeroBytes(reinterpret_cast<const uint8_t*>(&lp.musig2.ourSecNonce),
                   sizeof(Crypto::Musig2SecNonce))) return false;
  if (!lp.musig2.partialSigGenerated) return false;
  // Our partial sig survives (needed to complete/verify the aggregate).
  if (!bytesEqual(lp.musig2.ourPartialSig.s.data, p.musig2.ourPartialSig.s.data, 32)) return false;
  return true;
}

static bool testSessionDeterminism() {
  // Both parties must derive the identical session for the same escrow tx
  // hash. Simulate: two params instances with the same escrowTxHash, ordered
  // keys/nonces, and adaptor point must produce equal challenges.
  SwapParams alice{};
  SwapParams bob{};
  alice.role = SwapRole::ALICE;
  bob.role = SwapRole::BOB;
  alice.pair = bob.pair = SwapPair::ETH;
  // AUDIT 1.8: the DLEQ proof is bound to the swap id; both sides share it.
  alice.swapId = bob.swapId = "presig-session-converge-1";
  adaptor_generate_keys(alice);
  adaptor_generate_keys(bob);
  alice.peerSwapPubKey = bob.ourSwapPubKey;
  bob.peerSwapPubKey = alice.ourSwapPubKey;
  if (!adaptor_key_aggregate(alice) || !adaptor_key_aggregate(bob)) return false;
  if (!adaptor_generate_adaptor(bob, bob.escrowPubKey)) return false;
  alice.adaptorPoint = bob.adaptorPoint;
  alice.adaptorDleqQ = bob.adaptorDleqQ;
  alice.adaptorDleqProof = bob.adaptorDleqProof;

  adaptor_nonce_generate(alice);
  adaptor_nonce_generate(bob);
  alice.musig2.peerPubNonce = bob.musig2.ourPubNonce;
  bob.musig2.peerPubNonce = alice.musig2.ourPubNonce;

  Crypto::Hash escrowHash{};
  for (size_t i = 0; i < 32; ++i) escrowHash.data[i] = static_cast<uint8_t>(i * 3 + 11);
  alice.escrowTxHash = bob.escrowTxHash = escrowHash;

  // Production path: both parties derive the session message the same way.
  Crypto::Hash aliceMsg = presigSessionHash(alice.escrowTxHash);
  Crypto::Hash bobMsg = presigSessionHash(bob.escrowTxHash);
  if (!bytesEqual(aliceMsg.data, bobMsg.data, 32)) return false;
  if (!adaptor_session_init(alice, aliceMsg, true)) return false;
  if (!adaptor_session_init(bob, bobMsg, true)) return false;
  if (!bytesEqual(alice.musig2.session.challenge.data,
                  bob.musig2.session.challenge.data, 32)) return false;

  adaptor_partial_sign(alice);
  adaptor_partial_sign(bob);
  alice.musig2.peerPartialSig = bob.musig2.ourPartialSig;
  bob.musig2.peerPartialSig = alice.musig2.ourPartialSig;
  if (!adaptor_partial_verify(alice)) return false;
  if (!adaptor_partial_verify(bob)) return false;
  return true;
}

static bool testZeroNonceGuard() {
  SwapParams p{};
  p.role = SwapRole::BOB;
  p.pair = SwapPair::ETH;
  adaptor_generate_keys(p);
  Crypto::SecretKey peerSk;
  Crypto::PublicKey peerPk;
  Crypto::generate_keys(peerPk, peerSk);
  p.peerSwapPubKey = peerPk;
  adaptor_key_aggregate(p);

  // Nonce deliberately left all-zero; session init will fail on the zero
  // nonce aggregate, so emulate the dangerous path: a session that exists
  // but with a zeroed secret nonce. AdaptorSwap must refuse to sign.
  Crypto::Musig2PubNonce peerPub;
  Crypto::Musig2SecNonce junk;
  Crypto::musig2_nonce_gen(junk, peerPub);
  p.musig2.peerPubNonce = peerPub;
  // Zero OUR pub nonce too, then build a session from arbitrary valid
  // nonces to isolate the sign guard.
  Crypto::musig2_nonce_gen(p.musig2.ourSecNonce, p.musig2.ourPubNonce);
  Crypto::Hash msg{};
  std::memset(msg.data, 0x5A, 32);
  if (!adaptor_session_init(p, msg, true)) return false;
  if (!adaptor_partial_sign(p)) return false;  // first sign consumes nonce
  p.musig2.partialSigGenerated = true;

  // Fresh session over a DIFFERENT message with the SAME (now zeroed) nonce
  // must be refused, not signed.
  Crypto::Hash msg2{};
  std::memset(msg2.data, 0x6B, 32);
  Musig2State saved = p.musig2;
  if (!adaptor_session_init(p, msg2, true)) return false;
  if (adaptor_partial_sign(p)) return false;  // must refuse: nonce is zero
  p.musig2 = saved;
  return true;
}

static bool testDecryptFailureClearsProgress() {
  // A v4 record carrying an encrypted nonce, loaded with the WRONG key,
  // must fail closed: nonce stays zeroed and all pre-sig progress flags are
  // cleared so the daemon never signs with a zero nonce.
  SwapParams p{};
  p.swapId = "persist-3";
  p.role = SwapRole::BOB;
  p.pair = SwapPair::ETH;
  adaptor_generate_keys(p);
  adaptor_nonce_generate(p);
  p.musig2.nonceSent = true;
  p.musig2.partialSigGenerated = true;
  p.musig2.partialSigSent = true;

  SwapStateMachine sm(p);
  sm.setEncryptionKey("correct-enc-key");
  std::string json = sm.serialize();
  if (json.empty()) return false;

  SwapStateMachine loaded = SwapStateMachine::deserialize(json);
  loaded.setEncryptionKey("WRONG-enc-key");
  loaded.decryptStoredSecret();
  const SwapParams& lp = loaded.params();

  if (!isZeroBytes(reinterpret_cast<const uint8_t*>(&lp.musig2.ourSecNonce),
                   sizeof(Crypto::Musig2SecNonce))) return false;
  if (lp.musig2.nonceGenerated || lp.musig2.nonceSent) return false;
  if (lp.musig2.partialSigGenerated || lp.musig2.partialSigSent) return false;
  if (lp.musig2.peerPartialSigVerified) return false;
  return true;
}

static bool testAfkClaimCodec() {
  Crypto::SecretKey sk;
  Crypto::PublicKey pk;
  Crypto::generate_keys(pk, sk);

  PeerMessage msg;
  msg.type = PeerMessageType::AFK_CLAIM;
  msg.swapId = "afk-claim-codec-1";
  msg.afkClaim.ctrLockTxId = "0xdeadbeef0123456789abcdef";
  msg.afkClaim.payoutAddress = "fireVHx9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123";
  msg.afkClaim.finalSigHex = std::string(128, 'a');
  signPeerMessage(msg, pk, sk);

  std::string json = serializePeerMessage(msg);
  PeerMessage decoded;
  if (!deserializePeerMessage(json, decoded)) return false;
  if (decoded.type != PeerMessageType::AFK_CLAIM) return false;
  if (decoded.afkClaim.ctrLockTxId != msg.afkClaim.ctrLockTxId) return false;
  if (decoded.afkClaim.payoutAddress != msg.afkClaim.payoutAddress) return false;
  if (decoded.afkClaim.finalSigHex != msg.afkClaim.finalSigHex) return false;
  if (!verifyPeerMessage(decoded, pk)) return false;

  // Digest must distinguish fields (length-prefixed): swapping field contents
  // must produce a different digest.
  PeerMessage swapped = msg;
  swapped.afkClaim.ctrLockTxId = msg.afkClaim.payoutAddress.substr(0, 20);
  Crypto::Hash h1 = peerMessageDigest(msg);
  Crypto::Hash h2 = peerMessageDigest(swapped);
  if (bytesEqual(h1.data, h2.data, 32)) return false;

  PeerMessage ack;
  ack.type = PeerMessageType::AFK_CLAIM_ACK;
  ack.swapId = "afk-claim-codec-1";
  signPeerMessage(ack, pk, sk);
  PeerMessage ackDecoded;
  if (!deserializePeerMessage(serializePeerMessage(ack), ackDecoded)) return false;
  return verifyPeerMessage(ackDecoded, pk);
}

static bool testAfkStateTransitions() {
  SwapParams p{};
  p.swapId = "afk-sm";
  p.role = SwapRole::BOB;
  p.pair = SwapPair::ETH;
  p.xfgTimeoutHeight = 1000;
  SwapStateMachine sm(p);
  sm.setEncryptionKey("afk-sm-enc");
  if (!sm.transition(SwapState::AFK_OFFER_LOCKED)) return false;
  if (!sm.transition(SwapState::AFK_OFFER_ACCEPTED)) return false;
  if (!sm.transition(SwapState::AFK_CLAIMED)) return false;
  if (!sm.isTerminal()) return false;

  // Roundtrip with AFK claim fields populated.
  p.afkClaimReceived = true;
  p.afkClaimCtrLockTxId = "0xabcd";
  p.afkClaimPayoutAddress = "fireVHx000";
  p.afkClaimFinalSigHex = std::string(128, 'b');
  SwapStateMachine sm2(p);
  sm2.setEncryptionKey("afk-sm-enc");
  std::string json = sm2.serialize();
  if (json.empty()) return false;
  SwapStateMachine loaded = SwapStateMachine::deserialize(json);
  const SwapParams& lp = loaded.params();
  if (!lp.afkClaimReceived) return false;
  if (lp.afkClaimCtrLockTxId != p.afkClaimCtrLockTxId) return false;
  if (lp.afkClaimPayoutAddress != p.afkClaimPayoutAddress) return false;
  if (lp.afkClaimFinalSigHex != p.afkClaimFinalSigHex) return false;
  return true;
}

static bool testVersionConflictDetection() {
  // Optimistic concurrency: a stale in-memory record must NOT clobber a
  // newer on-disk record (the P2P/tick lost-update race).
  std::string tmpDir = "/tmp/fuego_swapdb_test_" + std::to_string(static_cast<long>(::getpid()));
  {
    SwapDatabase db(tmpDir);
    SwapParams p{};
    p.swapId = "version-conflict-1";
    p.role = SwapRole::BOB;
    p.pair = SwapPair::ETH;
    p.xfgAmount = 10000000;
    p.ctrAmount = 5000000;
    SwapStateMachine sm(p);
    sm.transition(SwapState::ADAPTOR_KEYS_EXCHANGED);
    // First save: no file yet → succeeds, version becomes 1.
    if (!db.saveSwap(sm)) return false;
    if (sm.recordVersion() != 1) return false;

    // Two concurrent readers, both at version 1.
    SwapStateMachine a, b;
    if (!db.loadSwap("version-conflict-1", a)) return false;
    if (!db.loadSwap("version-conflict-1", b)) return false;

    // a saves first (wins) → version 2.
    a.transition(SwapState::ADAPTOR_ESCROW_FUNDED);
    if (!db.saveSwap(a)) return false;

    // b's stale write must be rejected.
    b.transition(SwapState::ADAPTOR_ESCROW_FUNDED);
    if (db.saveSwap(b)) return false;

    // Reload: a's state + version 2 survived.
    SwapStateMachine c;
    if (!db.loadSwap("version-conflict-1", c)) return false;
    if (c.recordVersion() != 2) return false;
    if (c.currentState() != SwapState::ADAPTOR_ESCROW_FUNDED) return false;

    // A fresh load saves fine → version 3.
    c.transition(SwapState::ADAPTOR_PRESIGS_READY);
    if (!db.saveSwap(c)) return false;
    SwapStateMachine d;
    if (!db.loadSwap("version-conflict-1", d)) return false;
    if (d.recordVersion() != 3) return false;
  }
  // Best-effort cleanup
  std::remove((tmpDir + "/swaps/version-conflict-1.json").c_str());
  std::remove((tmpDir + "/swaps").c_str());
  std::remove((tmpDir + "/archive").c_str());
  std::remove(tmpDir.c_str());
  return true;
}

int main() {
  std::cout << "=== Pre-sig round wiring test ===\n";
  CHECK(testEscrowFundedCodec(), "ESCROW_FUNDED message codec + signature");
  CHECK(testStateRoundtrip(), "Musig2 state persists across v4 roundtrip");
  CHECK(testNonceNonResurrection(), "consumed nonce never resurrected after reload");
  CHECK(testSessionDeterminism(), "both parties converge on one session");
  CHECK(testZeroNonceGuard(), "zero-nonce partial sign refused (key-leak guard)");
  CHECK(testDecryptFailureClearsProgress(), "failed nonce decrypt clears progress (fail closed)");
  CHECK(testAfkClaimCodec(), "AFK_CLAIM + AFK_CLAIM_ACK codec + signature");
  CHECK(testAfkStateTransitions(), "AFK states reach AFK_CLAIMED + persist");
  CHECK(testVersionConflictDetection(), "stale record save rejected (lost-update guard)");

  std::cout << "\nResults: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}
