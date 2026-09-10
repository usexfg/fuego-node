// Copyright (c) 2017-2026 Fuego Developers
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include "crypto/hash.h"

namespace Crypto {

// ── secp256k1 Schnorr adaptor (BIP340) for BTC/LTC Taproot PTLC ──
// Implements s' = k + e*sk + t  (mod n), verify s'*G == R + e*P + T
// Challenge e = TaggedHash("Fuego/adaptor_challenge", R||P||msg) as in fuego-swapd-adaptor/lib.rs:105
// msg is 32-byte digest (e.g., presigSessionHash).

struct SecpPubKey {
  std::array<uint8_t, 33> data{}; // compressed 02/03 || x
  bool operator==(const SecpPubKey& o) const { return data == o.data; }
  bool operator!=(const SecpPubKey& o) const { return data != o.data; }
};

struct SecpAdaptorPresig {
  SecpPubKey R{};                 // nonce point
  std::array<uint8_t, 32> s_prime{}; // scalar s'
};

struct SecpSchnorrSig {
  std::array<uint8_t, 64> data{}; // BIP340 [R_x 32 || s 32]
};

// Tagged hash challenge scalar (32 bytes, reduced mod n if >= n)
std::array<uint8_t, 32> secp_adaptor_challenge(const SecpPubKey& R, const SecpPubKey& P, const Hash& msg);

// Derive P = sk*G (compressed). Returns false if sk == 0 or >= n.
bool secp_secret_to_pubkey(const SecretKey& sec, SecpPubKey& pub);

// Derive the secp256k1 point for the CROSS-CURVE binding from a CryptoNote
// (little-endian) scalar: reverses bytes to the canonical BE secp scalar,
// then P = scalar*G. Returns false if scalar==0 or >= n.
bool secp_point_from_ed_secret(const SecretKey& edSecret, SecpPubKey& out);

// Generate nonce k and R = k*G.
bool secp_generate_nonce(const SecretKey& k, SecpPubKey& R);

// Create adaptor presig s' = k + e*sk + t.
bool secp_adaptor_sign(const SecretKey& sk, const SecretKey& k, const SecretKey& t, const Hash& msg, SecpAdaptorPresig& out);

// Verify s'*G == R + e*P + T. T is adaptor point t*G.
bool secp_adaptor_verify(const SecpPubKey& P, const SecpPubKey& T, const SecpAdaptorPresig& presig, const Hash& msg);

// Extract t = s' - s (scalar mod n). sig is complete Schnorr sig [R_x||s] with same R as presig.
// 3-arg form guards only t != 0 (AUDIT 1.2/3.2). Prefer the 4-arg overload when
// the adaptor point T is known — it also verifies t*G == T.
bool secp_adaptor_extract(const SecpAdaptorPresig& presig, const SecpSchnorrSig& sig, SecretKey& t_out);
bool secp_adaptor_extract(const SecpAdaptorPresig& presig, const SecpSchnorrSig& sig,
                          const SecpPubKey& expectedT, SecretKey& t_out);

// Scalar helpers (mod n)
std::array<uint8_t, 32> secp_scalar_add(const std::array<uint8_t,32>& a, const std::array<uint8_t,32>& b);
std::array<uint8_t, 32> secp_scalar_neg(const std::array<uint8_t,32>& a);
bool secp_scalar_is_zero(const std::array<uint8_t,32>& a);
std::string secpPubKeyToHex(const SecpPubKey& k);
bool hexToSecpPubKey(const std::string& hex, SecpPubKey& k);

// Complete Schnorr sig s = k + e*sk with same R (for extraction test)
bool secp_complete_schnorr_sig(const SecretKey& sk, const SecretKey& k, const Hash& msg, SecpSchnorrSig& out);

} // namespace Crypto
