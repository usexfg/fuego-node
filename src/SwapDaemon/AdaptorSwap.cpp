// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2020-2026 Elderfire Privacy Group
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

#include "AdaptorSwap.h"
#include "BitcoinCash/HtlcScript.h"
#include "Sia/SiaHtlcScript.h"
#include "crypto/secp_adaptor.h"
#include <cstring>
#include <vector>

extern "C" {
#include "crypto/crypto-ops.h"
#include "crypto/keccak.h"
}

namespace XfgSwap {

Crypto::Hash presigSessionHash(const Crypto::Hash& escrowTxHash) {
  std::vector<uint8_t> buf;
  const char domainSep[] = "fuego-swap-presig-v1";
  buf.insert(buf.end(), domainSep, domainSep + sizeof(domainSep) - 1);
  buf.insert(buf.end(), escrowTxHash.data, escrowTxHash.data + sizeof(escrowTxHash.data));
  Crypto::Hash out;
  Crypto::cn_fast_hash(buf.data(), buf.size(), out);
  return out;
}

// ─── helpers ─────────────────────────────────────────────────────────

// Signer index: Alice = 0, Bob = 1.
static unsigned int signerIndex(SwapRole role) {
  return role == SwapRole::ALICE ? 0 : 1;
}

// Ordered keys for Musig2: Alice is pub0, Bob is pub1.
static void orderedKeys(const SwapParams& p,
                        Crypto::PublicKey& pub0,
                        Crypto::PublicKey& pub1) {
  if (p.role == SwapRole::ALICE) {
    pub0 = p.ourSwapPubKey;
    pub1 = p.peerSwapPubKey;
  } else {
    pub0 = p.peerSwapPubKey;
    pub1 = p.ourSwapPubKey;
  }
}

// ─── implementation ──────────────────────────────────────────────────

void adaptor_generate_keys(SwapParams& params) {
  Crypto::generate_keys(params.ourSwapPubKey, params.ourSwapSecKey);
}

bool adaptor_key_aggregate(SwapParams& params) {
  Crypto::PublicKey pub0, pub1;
  orderedKeys(params, pub0, pub1);

  if (!Crypto::musig2_key_agg(pub0, pub1, params.musig2.keyAgg)) {
    return false;
  }
  params.escrowPubKey = params.musig2.keyAgg.agg_pubkey;
  return true;
}

bool adaptor_generate_adaptor(SwapParams& params,
                              const Crypto::PublicKey& dleq_base_point) {
  // Generate adaptor secret t, point T = t*G
  Crypto::generate_keys(params.adaptorPoint, params.adaptorSecret);

  // Cross-curve binding: publish T_secp = t·G_secp (byte-reversed scalar).
  // Fail closed — a swap without a verifiable cross-curve point must not
  // proceed (same policy as the DLEQ failure below).
  Crypto::SecpPubKey secpPub;
  if (!Crypto::secp_point_from_ed_secret(params.adaptorSecret, secpPub)) {
    return false;
  }
  params.secpPubHex = Crypto::secpPubKeyToHex(secpPub);

  // HTLC hashlock H(t) so Alice can lock without learning t (Alice-locks model).
  // Match the counterparty program's hash: SHA-256 for UTXO, keccak for EVM/SOL.
  // Hashlock MUST match the counterparty HTLC program (not T = t*G).
  // SHA-256: Bitcoin-family UTXO scripts (OP_SHA256) + TON cell-hash.
  // Keccak-256: EVM HashedTimelock + Solana xfg_htlc (GLEEC included — EVM).
  // Sia is the third family: Blake2b-256(preimage).
  if (params.pair == SwapPair::SIA) {
    auto md = SiaHtlcScript::blake2b256(
        reinterpret_cast<const uint8_t*>(&params.adaptorSecret), 32);
    std::memcpy(&params.hashLock, md.data(), 32);
  } else if (isLegacyUtxoPair(params.pair)) {
    std::vector<uint8_t> in(reinterpret_cast<const uint8_t*>(&params.adaptorSecret),
                            reinterpret_cast<const uint8_t*>(&params.adaptorSecret) + 32);
    auto md = BchHtlcScript::sha256(in);
    std::memcpy(&params.hashLock, md.data(), 32);
  } else {
    keccak(reinterpret_cast<const uint8_t*>(&params.adaptorSecret), 32,
           reinterpret_cast<uint8_t*>(&params.hashLock), 32);
  }

  // Compute Q = t * base_point (for DLEQ proof)
  ge_p3 P_p3;
  if (ge_frombytes_vartime(&P_p3,
      reinterpret_cast<const unsigned char*>(&dleq_base_point)) != 0) {
    return false;
  }
  ge_p2 Q_p2;
  ge_scalarmult(&Q_p2,
      reinterpret_cast<const unsigned char*>(&params.adaptorSecret),
      &P_p3);

  // The caller passes Q (params.adaptorDleqQ) alongside T and proof to the peer.
  ge_tobytes(reinterpret_cast<unsigned char*>(&params.adaptorDleqQ), &Q_p2);

  return Crypto::generate_dleq_proof(
      dleq_base_point,
      params.adaptorPoint,  // A = t*G
      params.adaptorDleqQ,  // B = t*P
      params.adaptorSecret,
      params.adaptorDleqProof);
}

bool adaptor_verify_adaptor(const SwapParams& params,
                            const Crypto::PublicKey& dleq_base_point,
                            const Crypto::PublicKey& dleq_peer_Q) {
  return Crypto::check_dleq_proof(
      dleq_base_point,
      params.adaptorPoint,
      dleq_peer_Q,
      params.adaptorDleqProof);
}

void adaptor_nonce_generate(SwapParams& params) {
  Crypto::musig2_nonce_gen(params.musig2.ourSecNonce,
                           params.musig2.ourPubNonce);
  params.musig2.nonceGenerated = true;
}

bool adaptor_session_init(SwapParams& params,
                          const Crypto::Hash& tx_prefix_hash,
                          bool use_adaptor) {
  // Aggregate nonces: order matches key ordering (Alice=0, Bob=1)
  Crypto::Musig2PubNonce nonce0, nonce1;
  if (params.role == SwapRole::ALICE) {
    nonce0 = params.musig2.ourPubNonce;
    nonce1 = params.musig2.peerPubNonce;
  } else {
    nonce0 = params.musig2.peerPubNonce;
    nonce1 = params.musig2.ourPubNonce;
  }

  if (!Crypto::musig2_nonce_agg(nonce0, nonce1, params.musig2.aggNonce)) {
    return false;
  }

  const Crypto::PublicKey* adaptor_ptr =
      use_adaptor ? &params.adaptorPoint : nullptr;

  if (!Crypto::musig2_session_init(
      tx_prefix_hash,
      params.musig2.keyAgg,
      params.musig2.aggNonce,
      adaptor_ptr,
      params.musig2.session)) {
    return false;
  }

  params.musig2.sessionInitialized = true;
  return true;
}

bool adaptor_partial_sign(SwapParams& params) {
  // Zero-nonce guard: signing with an all-zero secret nonce produces
  // s = -c * a_i * x_i, from which anyone who knows the challenge and the
  // key-agg coefficients can solve for our private key. This can only
  // happen if the persisted nonce was lost (e.g. encryption key unavailable
  // after restart) — fail closed instead of signing.
  {
    const uint8_t* n = reinterpret_cast<const uint8_t*>(&params.musig2.ourSecNonce);
    bool allZero = true;
    for (size_t i = 0; i < sizeof(Crypto::Musig2SecNonce); ++i) {
      if (n[i]) { allZero = false; break; }
    }
    if (allZero) return false;
  }
  if (params.musig2.session.nonceSigned) {
    // Nonce has already been consumed for this session. Signing again would
    // reuse the same nonce, which leaks the private key in MuSig2.
    return false;
  }
  return Crypto::musig2_partial_sign(
      params.musig2.session,
      params.musig2.keyAgg,
      params.musig2.ourSecNonce,   // zeroed after use
      params.ourSwapSecKey,
      signerIndex(params.role),
      params.musig2.ourPartialSig);
}

bool adaptor_partial_verify(const SwapParams& params) {
  // Verify peer's partial sig
  Crypto::PublicKey peerPub = params.peerSwapPubKey;
  unsigned int peerIdx = (params.role == SwapRole::ALICE) ? 1 : 0;

  return Crypto::musig2_partial_verify(
      params.musig2.session,
      params.musig2.keyAgg,
      params.musig2.peerPubNonce,
      peerPub,
      peerIdx,
      params.musig2.peerPartialSig);
}

Crypto::Signature adaptor_aggregate(SwapParams& params, bool adapted) {
  // Adaptation requires the adaptor secret t. Bob always holds it; Alice
  // holds it only after extracting it from Bob's counterparty claim. A zero
  // t would produce a malformed aggregate, so reject in that case.
  if (adapted) {
    const uint8_t* t = reinterpret_cast<const uint8_t*>(&params.adaptorSecret);
    bool zero = true;
    for (size_t i = 0; i < sizeof(params.adaptorSecret); ++i) if (t[i]) { zero = false; break; }
    if (zero) {
      Crypto::Signature empty{};
      return empty;
    }
  }

  Crypto::Musig2PartialSig sig0, sig1;

  if (params.role == SwapRole::ALICE) {
    sig0 = params.musig2.ourPartialSig;
    sig1 = params.musig2.peerPartialSig;
  } else {
    sig0 = params.musig2.peerPartialSig;
    sig1 = params.musig2.ourPartialSig;
  }

  // If adapted, add adaptor secret t to Bob's partial sig.
  // Bob's slot is sig1 (signer index 1) in the canonical ordering.
  if (adapted) {
    sc_add(reinterpret_cast<unsigned char*>(&sig1.s),
           reinterpret_cast<const unsigned char*>(&sig1.s),
           reinterpret_cast<const unsigned char*>(&params.adaptorSecret));

    // Zero the adaptor secret immediately after use to prevent it lingering
    // in memory. volatile cast prevents the compiler from eliding the wipe.
    volatile unsigned char* secret_ptr =
        reinterpret_cast<volatile unsigned char*>(&params.adaptorSecret);
    for (size_t i = 0; i < sizeof(params.adaptorSecret); ++i) {
      secret_ptr[i] = 0;
    }
  }

  Crypto::Signature final_sig;
  Crypto::musig2_aggregate(params.musig2.session, sig0, sig1, final_sig);
  return final_sig;
}

bool adaptor_extract_secret(SwapParams& params,
                            const Crypto::Signature& on_chain_sig) {
  Crypto::EllipticCurveScalar s0, s1;

  if (params.role == SwapRole::ALICE) {
    s0 = params.musig2.ourPartialSig.s;
    s1 = params.musig2.peerPartialSig.s;
  } else {
    s0 = params.musig2.peerPartialSig.s;
    s1 = params.musig2.ourPartialSig.s;
  }

  Crypto::EllipticCurveScalar s1_adapted;
  sc_sub(reinterpret_cast<unsigned char*>(&s1_adapted),
         on_chain_sig.data + 32,
         reinterpret_cast<const unsigned char*>(&s0));

  sc_sub(reinterpret_cast<unsigned char*>(&params.adaptorSecret),
         reinterpret_cast<const unsigned char*>(&s1_adapted),
         reinterpret_cast<const unsigned char*>(&s1));

  // AUDIT 1.2 / 3.2: the recovered scalar is only usable if it actually opens
  // the adaptor point T published for THIS swap. A malformed or rogue on-chain
  // signature (protocol deviation, reorg, wrong tx) otherwise yields a wrong t;
  // adaptor_aggregate() would fold it into our claim, which then fails
  // consensus and strands our funds until the timeout refund. Verify t*G == T
  // (and t != 0) before returning success; wipe on mismatch.
  if (sc_isnonzero(
        reinterpret_cast<const unsigned char*>(&params.adaptorSecret)) == 0) {
    return false;
  }
  {
    Crypto::PublicKey derivedT;
    if (!Crypto::secret_key_to_public_key(params.adaptorSecret, derivedT) ||
        std::memcmp(&derivedT, &params.adaptorPoint,
                    sizeof(Crypto::PublicKey)) != 0) {
      volatile unsigned char* p =
          reinterpret_cast<volatile unsigned char*>(&params.adaptorSecret);
      for (size_t i = 0; i < sizeof(params.adaptorSecret); ++i) p[i] = 0;
      return false;
    }
  }
  return true;
}

} // namespace XfgSwap
