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

// Roundtrip test for adaptor_aggregate ↔ adaptor_extract_secret.
//
// Verifies the core assumption that musig2_aggregate stores the raw
// s0 + s1 scalar sum (no challenge tweak, no key-agg coefficient fold-in),
// so that extract_secret can recover t = (s_agg - s0) - s1.
//
// Scenario: Alice and Bob run a full Musig2 2-of-2 session with an
// adaptor point. Bob adapts his partial sig by adding his adaptor
// secret t. Alice, knowing both raw partial sigs and the on-chain
// aggregate signature, extracts t.

#include <iostream>
#include <cstring>
#include "SwapDaemon/AdaptorSwap.h"
#include "SwapDaemon/SwapTypes.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

using namespace XfgSwap;

// Set up matching Alice/Bob SwapParams pairs with shared escrow key,
// shared nonces, and an adaptor point owned by Bob.
static bool setupPair(SwapParams& alice, SwapParams& bob) {
  alice = SwapParams{};
  bob   = SwapParams{};
  alice.role = SwapRole::ALICE;
  bob.role   = SwapRole::BOB;

  // Step 1: both generate their own keypair
  adaptor_generate_keys(alice);
  adaptor_generate_keys(bob);

  // Each side sees the other's pubkey
  alice.peerSwapPubKey = bob.ourSwapPubKey;
  bob.peerSwapPubKey   = alice.ourSwapPubKey;

  // Step 2: both aggregate to the same escrow key
  // AUDIT 1.8: both sides must share the swap id — the DLEQ proof is bound to it.
  alice.swapId = bob.swapId = "adaptor-roundtrip-1";

  if (!adaptor_key_aggregate(alice)) return false;
  if (!adaptor_key_aggregate(bob))   return false;
  if (std::memcmp(&alice.escrowPubKey, &bob.escrowPubKey, 32) != 0) {
    std::cerr << "    FAIL: escrow keys diverged\n";
    return false;
  }

  // Step 3: Bob generates adaptor secret t, point T = t*G
  if (!adaptor_generate_adaptor(bob, bob.escrowPubKey)) return false;
  // Alice sees T (in the wire protocol this comes with a DLEQ proof + Q)
  alice.adaptorPoint     = bob.adaptorPoint;
  alice.adaptorDleqQ     = bob.adaptorDleqQ;
  alice.adaptorDleqProof = bob.adaptorDleqProof;
  if (!adaptor_verify_adaptor(alice, alice.escrowPubKey, alice.adaptorDleqQ)) {
    std::cerr << "    FAIL: Alice rejected Bob's DLEQ proof\n";
    return false;
  }

  // Step 4: both generate per-session nonces
  adaptor_nonce_generate(alice);
  adaptor_nonce_generate(bob);
  alice.musig2.peerPubNonce = bob.musig2.ourPubNonce;
  bob.musig2.peerPubNonce   = alice.musig2.ourPubNonce;

  // Step 5: both init the session for the SAME message with adaptor
  Crypto::Hash msg;
  std::memset(msg.data, 0x5A, sizeof(msg.data));
  if (!adaptor_session_init(alice, msg, true)) return false;
  if (!adaptor_session_init(bob,   msg, true)) return false;

  // Step 6: both create their partial sigs
  adaptor_partial_sign(alice);
  adaptor_partial_sign(bob);

  // Each side receives the counterparty's raw (unadapted) partial
  alice.musig2.peerPartialSig = bob.musig2.ourPartialSig;
  bob.musig2.peerPartialSig   = alice.musig2.ourPartialSig;
  return true;
}

static bool test_roundtrip() {
  std::cout << "[1] adaptor_aggregate → adaptor_extract_secret roundtrip\n";

  SwapParams alice, bob;
  if (!setupPair(alice, bob)) return false;

  // Step 7 (Bob): verify Alice's partial
  if (!adaptor_partial_verify(bob)) {
    std::cout << "    FAIL: Bob can't verify Alice's partial\n";
    return false;
  }
  if (!adaptor_partial_verify(alice)) {
    std::cout << "    FAIL: Alice can't verify Bob's partial\n";
    return false;
  }

  // Step 8 (Bob): adapt his partial sig by adding t, then aggregate.
  // Save the original adaptor secret BEFORE aggregating (aggregate zeroes it).
  Crypto::SecretKey originalT;
  std::memcpy(&originalT, &bob.adaptorSecret, sizeof(originalT));

  // This is the signature that would be broadcast on-chain.
  Crypto::Signature onChainSig = adaptor_aggregate(bob, /*adapted=*/true);

  // Step 9 (Alice): sees the on-chain sig, extracts t from it.
  // Alice has her own partial and Bob's unadapted partial (peerPartialSig).
  // Her adaptorSecret field is initially zero.
  std::memset(&alice.adaptorSecret, 0, sizeof(alice.adaptorSecret));
  if (!adaptor_extract_secret(alice, onChainSig)) {
    std::cout << "    FAIL: extraction returned false\n";
    return false;
  }

  // The extracted secret must equal Bob's original t.
  if (std::memcmp(&alice.adaptorSecret, &originalT, 32) != 0) {
    std::cout << "    FAIL: extracted secret != original t\n";
    return false;
  }
  std::cout << "    PASS: t recovered bit-for-bit\n";
  return true;
}

static bool test_unadapted_sig_extraction_yields_zero() {
  std::cout << "[2] Aggregating without adaptation yields extractable t = 0\n";

  SwapParams alice, bob;
  if (!setupPair(alice, bob)) return false;

  // Aggregate WITHOUT adapting (e.g. cooperative refund path).
  Crypto::Signature refundSig = adaptor_aggregate(bob, /*adapted=*/false);

  std::memset(&alice.adaptorSecret, 0, sizeof(alice.adaptorSecret));
  bool ok = adaptor_extract_secret(alice, refundSig);
  // Extraction should return false because t = 0 in the unadapted case.
  if (ok) {
    std::cout << "    FAIL: extraction returned true for unadapted sig\n";
    return false;
  }
  // And the extracted scalar should be zero.
  uint8_t zero[32] = {};
  if (std::memcmp(&alice.adaptorSecret, zero, 32) != 0) {
    std::cout << "    FAIL: expected zero scalar, got non-zero\n";
    return false;
  }
  std::cout << "    PASS: unadapted aggregate yields zero scalar (not extractable)\n";
  return true;
}

static bool test_multiple_sessions_distinct_secrets() {
  std::cout << "[3] Two independent sessions extract distinct secrets\n";

  SwapParams a1, b1, a2, b2;
  if (!setupPair(a1, b1)) return false;
  if (!setupPair(a2, b2)) return false;

  // Secrets should be independent across sessions
  if (std::memcmp(&b1.adaptorSecret, &b2.adaptorSecret, 32) == 0) {
    std::cout << "    FAIL: two sessions produced identical t\n";
    return false;
  }

  // Save originals BEFORE aggregate (which zeroes them)
  Crypto::SecretKey t1_orig, t2_orig;
  std::memcpy(&t1_orig, &b1.adaptorSecret, 32);
  std::memcpy(&t2_orig, &b2.adaptorSecret, 32);

  Crypto::Signature sig1 = adaptor_aggregate(b1, true);
  Crypto::Signature sig2 = adaptor_aggregate(b2, true);

  std::memset(&a1.adaptorSecret, 0, 32);
  std::memset(&a2.adaptorSecret, 0, 32);

  if (!adaptor_extract_secret(a1, sig1)) {
    std::cout << "    FAIL: extract session 1\n"; return false;
  }
  if (!adaptor_extract_secret(a2, sig2)) {
    std::cout << "    FAIL: extract session 2\n"; return false;
  }

  if (std::memcmp(&a1.adaptorSecret, &t1_orig, 32) != 0 ||
      std::memcmp(&a2.adaptorSecret, &t2_orig, 32) != 0) {
    std::cout << "    FAIL: extracted secrets don't match originals\n";
    return false;
  }
  std::cout << "    PASS: both sessions' secrets recovered independently\n";
  return true;
}

int main() {
  std::cout << "=== AdaptorSwap aggregate/extract roundtrip ===\n\n";
  int pass = 0, total = 3;
  if (test_roundtrip())                           ++pass;
  if (test_unadapted_sig_extraction_yields_zero()) ++pass;
  if (test_multiple_sessions_distinct_secrets())  ++pass;

  std::cout << "\n=== " << pass << "/" << total << " tests passed ===\n";
  return (pass == total) ? 0 : 1;
}
