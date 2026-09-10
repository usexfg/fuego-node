// Copyright (c) 2017-2026 Fuego Developers
//
// v11+ swap escrow consensus primitives (offline):
//   [1] the deterministic claim tx is byte-identical on both sides, and the
//       completed MuSig2 adaptor aggregate verifies under the STANDARD
//       check_signature over that prefix (claim path).
//   [2] maker refund signature verifies under check_signature.
//   [3] deterministic escrow key images are stable per (tx, index, mode).
//   [4] escrow output/input binary serialization roundtrip.

#include <cstring>
#include <iostream>
#include "SwapDaemon/AdaptorSwap.h"
#include "SwapDaemon/SwapTxBuilder.h"
#include "SwapDaemon/SwapTypes.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Serialization/BinarySerializationTools.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

using namespace XfgSwap;

static int g_pass = 0, g_fail = 0;
#define CHECK(c, m) do { if (c) { ++g_pass; std::cout << "  PASS: " << m << "\n"; } \
  else { ++g_fail; std::cerr << "  FAIL: " << m << "\n"; } } while (0)

// Keys, escrow aggregation, adaptor point, and nonce exchange — everything
// up to (but not including) the musig2 session.
static bool setupKeys(SwapParams& alice, SwapParams& bob) {
  alice = SwapParams{};
  bob = SwapParams{};
  alice.role = SwapRole::ALICE;
  bob.role = SwapRole::BOB;
  alice.xfgAmount = 100000000;
  bob.xfgAmount = 100000000;

  adaptor_generate_keys(alice);
  adaptor_generate_keys(bob);
  alice.peerSwapPubKey = bob.ourSwapPubKey;
  bob.peerSwapPubKey = alice.ourSwapPubKey;

  // AUDIT 1.8: both sides must share the swap id — the DLEQ proof is bound to it.
  alice.swapId = bob.swapId = "escrow-claim-1";

  if (!adaptor_key_aggregate(alice)) return false;
  if (!adaptor_key_aggregate(bob)) return false;
  if (std::memcmp(&alice.escrowPubKey, &bob.escrowPubKey, 32) != 0) return false;

  if (!adaptor_generate_adaptor(bob, bob.escrowPubKey)) return false;
  alice.adaptorPoint = bob.adaptorPoint;
  alice.adaptorDleqQ = bob.adaptorDleqQ;
  alice.adaptorDleqProof = bob.adaptorDleqProof;
  if (!adaptor_verify_adaptor(alice, alice.escrowPubKey, alice.adaptorDleqQ)) return false;

  adaptor_nonce_generate(alice);
  adaptor_nonce_generate(bob);
  alice.musig2.peerPubNonce = bob.musig2.ourPubNonce;
  bob.musig2.peerPubNonce = alice.musig2.ourPubNonce;
  return true;
}

static void runSession(SwapParams& alice, SwapParams& bob, const Crypto::Hash& msg) {
  adaptor_session_init(alice, msg, true);
  adaptor_session_init(bob, msg, true);
  adaptor_partial_sign(alice);
  adaptor_partial_sign(bob);
  alice.musig2.peerPartialSig = bob.musig2.ourPartialSig;
  bob.musig2.peerPartialSig = alice.musig2.ourPartialSig;
}

static Crypto::PublicKey testTreasuryKey() {
  Crypto::SecretKey seed;
  std::memset(&seed, 0x42, sizeof(seed));
  Crypto::PublicKey pub;
  Crypto::SecretKey sec;
  Crypto::generate_keys_from_seed(pub, sec, seed);
  return pub;
}

static bool test_claim_signature_verification() {
  std::cout << "[1] Deterministic claim tx + MuSig2 aggregate under check_signature\n";
  SwapParams alice, bob;
  if (!setupKeys(alice, bob)) {
    std::cerr << "  FAIL: setup\n";
    return false;
  }

  std::memset(alice.escrowTxHash.data, 0xAB, sizeof(alice.escrowTxHash.data));
  std::memset(bob.escrowTxHash.data, 0xAB, sizeof(bob.escrowTxHash.data));

  const Crypto::PublicKey treasury = testTreasuryKey();
  const uint64_t protocolFee =
      2 * (alice.xfgAmount * CryptoNote::parameters::SWAP_FEE_RATE_BPS) /
          CryptoNote::parameters::SWAP_FEE_RATE_DIVISOR;

  // Destinations are symmetric: both sides derive Alice's key.
  CryptoNote::Transaction txA, txB;
  Crypto::Hash prefixA, prefixB;
  const Crypto::PublicKey destAlice = alice.ourSwapPubKey;
  const Crypto::PublicKey destBob = bob.peerSwapPubKey;
  CHECK(std::memcmp(&destAlice, &destBob, 32) == 0, "destination keys agree");
  CHECK(SwapTxBuilder::buildDeterministicClaimTx(alice, destAlice, protocolFee, treasury, txA, prefixA) &&
        SwapTxBuilder::buildDeterministicClaimTx(bob, destBob, protocolFee, treasury, txB, prefixB),
        "deterministic claim tx builds");
  CHECK(std::memcmp(&prefixA, &prefixB, sizeof(prefixA)) == 0, "identical claim prefixes");
  CHECK(CryptoNote::storeToBinary(static_cast<const CryptoNote::TransactionPrefix&>(txA)) ==
        CryptoNote::storeToBinary(static_cast<const CryptoNote::TransactionPrefix&>(txB)),
        "byte-identical claim transaction prefixes");

  runSession(alice, bob, prefixA);

  Crypto::Signature claimSig = adaptor_aggregate(bob, true);
  {
    Crypto::Signature zeroSig{};
    if (std::memcmp(&claimSig, &zeroSig, sizeof(claimSig)) == 0) {
      std::cerr << "  FAIL: aggregate empty\n";
      return false;
    }
  }

  CHECK(Crypto::check_signature(prefixA, alice.escrowPubKey, claimSig),
        "claim sig verifies under standard check_signature");

  Crypto::Signature bad = claimSig;
  bad.data[0] ^= 0x01;
  CHECK(!Crypto::check_signature(prefixA, alice.escrowPubKey, bad),
        "tampered claim sig rejected");
  CHECK(!Crypto::check_signature(prefixA, alice.ourSwapPubKey, claimSig),
        "claim sig rejected under wrong key");

  // Unadapted aggregate must fail (adaptor atomicity: t is required).
  Crypto::Signature unadapted = adaptor_aggregate(alice, false);
  CHECK(!Crypto::check_signature(prefixA, alice.escrowPubKey, unadapted),
        "unadapted aggregate rejected (no t)");
  return true;
}

static bool test_refund_signature() {
  std::cout << "[2] Maker refund signature under standard check_signature\n";
  SwapParams alice, bob;
  if (!setupKeys(alice, bob)) {
    std::cerr << "  FAIL: setup\n";
    return false;
  }

  std::memset(bob.escrowTxHash.data, 0xCD, sizeof(bob.escrowTxHash.data));
  CryptoNote::Transaction tx;
  Crypto::Hash prefix;
  // Reuse the deterministic builder with mode flipped manually: build a
  // refund tx via the daemon would need SwapDaemon; here we verify the
  // signature primitive only.
  {
    tx.version = CryptoNote::TRANSACTION_VERSION_2;
    tx.unlockTime = 0;
    CryptoNote::TransactionInputSwapEscrow in;
    in.amount = bob.xfgAmount;
    in.escrowTxId = bob.escrowTxHash;
    in.escrowOutputIndex = 0;
    in.mode = 1;
    in.keyImage = SwapTxBuilder::swapEscrowKeyImage(bob.escrowTxHash, 0, 1);
    tx.inputs.push_back(in);
    CryptoNote::KeyOutput ko;
    ko.key = bob.ourSwapPubKey;
    CryptoNote::TransactionOutput o;
    o.amount = bob.xfgAmount - 100000;
    o.target = ko;
    tx.outputs.push_back(o);
    CryptoNote::getObjectHash(
        static_cast<CryptoNote::TransactionPrefix&>(tx), prefix);
  }

  Crypto::Signature refundSig;
  Crypto::generate_signature(prefix, bob.ourSwapPubKey, bob.ourSwapSecKey, refundSig);
  CHECK(Crypto::check_signature(prefix, bob.ourSwapPubKey, refundSig),
        "refund sig verifies");
  CHECK(!Crypto::check_signature(prefix, alice.ourSwapPubKey, refundSig),
        "refund sig rejected under wrong key");
  return true;
}

static bool test_escrow_key_image_determinism() {
  std::cout << "[3] Deterministic escrow key images\n";
  Crypto::Hash txid;
  std::memset(txid.data, 0xAB, sizeof(txid.data));
  Crypto::KeyImage ki1 = SwapTxBuilder::swapEscrowKeyImage(txid, 0, 0);
  Crypto::KeyImage ki2 = SwapTxBuilder::swapEscrowKeyImage(txid, 0, 0);
  Crypto::KeyImage kiR = SwapTxBuilder::swapEscrowKeyImage(txid, 0, 1);
  Crypto::KeyImage ki3 = SwapTxBuilder::swapEscrowKeyImage(txid, 1, 0);
  CHECK(std::memcmp(&ki1, &ki2, sizeof(ki1)) == 0, "same inputs → same KI");
  CHECK(std::memcmp(&ki1, &kiR, sizeof(ki1)) != 0, "claim and refund KIs differ");
  CHECK(std::memcmp(&ki1, &ki3, sizeof(ki1)) != 0, "different output index → different KI");
  return true;
}

static bool test_serialization_roundtrip() {
  std::cout << "[4] Escrow output/input binary roundtrip\n";
  CryptoNote::Transaction tx;
  tx.version = 2;
  tx.unlockTime = 0;

  CryptoNote::TransactionOutputSwapEscrow out;
  {
    Crypto::SecretKey s1, s2, s3;
    Crypto::generate_keys(out.claimKey, s1);
    Crypto::generate_keys(out.refundKey, s2);
    Crypto::generate_keys(out.adaptorPoint, s3);
  }
  out.refundTimeout = 1234567;
  CryptoNote::TransactionOutput o;
  o.amount = 100000000;
  o.target = out;
  tx.outputs.push_back(o);

  CryptoNote::TransactionInputSwapEscrow in;
  in.amount = 100000000;
  std::memset(in.escrowTxId.data, 0x5C, sizeof(in.escrowTxId.data));
  in.escrowOutputIndex = 0;
  in.mode = 0;
  in.keyImage = SwapTxBuilder::swapEscrowKeyImage(in.escrowTxId, 0, 0);
  tx.inputs.push_back(in);
  Crypto::Signature sig;
  std::memset(&sig, 0, sizeof(sig));
  tx.signatures.push_back({sig});

  CryptoNote::BinaryArray blob = CryptoNote::storeToBinary(tx);
  CryptoNote::Transaction tx2;
  CHECK(CryptoNote::fromBinaryArray(tx2, blob), "deserialize tx with escrow in/out");
  CHECK(tx2.outputs.size() == 1 && tx2.outputs[0].target.type() == typeid(CryptoNote::TransactionOutputSwapEscrow),
        "output variant preserved");
  const auto& out2 = boost::get<CryptoNote::TransactionOutputSwapEscrow>(tx2.outputs[0].target);
  CHECK(std::memcmp(&out2.claimKey, &out.claimKey, sizeof(out.claimKey)) == 0 &&
        std::memcmp(&out2.refundKey, &out.refundKey, sizeof(out.refundKey)) == 0 &&
        std::memcmp(&out2.adaptorPoint, &out.adaptorPoint, sizeof(out.adaptorPoint)) == 0 &&
        out2.refundTimeout == out.refundTimeout,
        "escrow output fields preserved");
  CHECK(tx2.inputs.size() == 1 && tx2.inputs[0].type() == typeid(CryptoNote::TransactionInputSwapEscrow),
        "input variant preserved");
  const auto& in2 = boost::get<CryptoNote::TransactionInputSwapEscrow>(tx2.inputs[0]);
  CHECK(in2.amount == in.amount && in2.mode == in.mode &&
        in2.escrowOutputIndex == in.escrowOutputIndex &&
        std::memcmp(&in2.escrowTxId, &in.escrowTxId, sizeof(in.escrowTxId)) == 0 &&
        std::memcmp(&in2.keyImage, &in.keyImage, sizeof(in.keyImage)) == 0,
        "escrow input fields preserved");
  return true;
}

int main() {
  std::cout << "=== v11 swap escrow consensus primitives ===\n";
  test_claim_signature_verification();
  test_refund_signature();
  test_escrow_key_image_determinism();
  test_serialization_roundtrip();
  std::cout << "\nResults: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}
