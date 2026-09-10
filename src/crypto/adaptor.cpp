// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2020-2026 Elderfire Privacy Group
//
// L. Fournier,2019.
// A. Aumayr 2021.
// D.J. Bernstein et al
//
// This file is part of Fuego.
//
// Fuego is free & open source software distributed in the hope
// it will be useful, but WITHOUT ANY WARRANTY; without even an
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. You may redistribute it and/or modify it under the terms
// of the GNU General Public License v3 or later versions as published
// by the Free Software Foundation. Fuego includes elements written
// by third parties. See file labeled LICENSE for more details.
// You should have received a copy of the GNU General Public License
// along with Fuego. If not, see <https://www.gnu.org/licenses/>.


#include "adaptor.h"
#include "crypto.h"

extern "C" {
#include "crypto-ops.h"
#include "random.h"
}

namespace {

bool point_is_valid(const unsigned char bytes[32]) {
  int nonzero = 0;
  for (int i = 0; i < 32; ++i) nonzero |= bytes[i];
  if (!nonzero) return false;
  ge_p3 p3;
  if (ge_frombytes_vartime(&p3, bytes) != 0) return false;
  ge_p2 p2;
  ge_p3_to_p2(&p2, &p3);
  ge_p1p1 p1p1;
  ge_mul8(&p1p1, &p2);
  ge_p2 p2r;
  ge_p1p1_to_p2(&p2r, &p1p1);
  unsigned char out[32];
  ge_tobytes(out, &p2r);
  // Reject small-order points: P is small-order exactly when 8*P is the
  // neutral element. The neutral element encodes as {0x01, 0, ..., 0} — NOT
  // all-zero. Comparing against all-zero made this check inert, because no
  // valid point ever encodes to 32 zero bytes, so every decodable point was
  // accepted (identity and the 8-torsion points included).
  static const unsigned char kNeutral[32] = {
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  int diff = 0;
  for (int i = 0; i < 32; ++i) diff |= (out[i] ^ kNeutral[i]);
  return diff != 0;
}

} // namespace

#include <mutex>
#include <cstring>

namespace Crypto {

// Mirror of s_comm from crypto.cpp — the hash buffer for Schnorr challenges.
// c = Hs(prefix_hash || pub || nonce_point)
struct adaptor_s_comm {
  Hash h;
  EllipticCurvePoint key;
  EllipticCurvePoint comm;
};

// Thread-safe random scalar generation (same as crypto.cpp:random_scalar).
static inline void adaptor_random_scalar(EllipticCurveScalar &res) {
  unsigned char tmp[64];
  generate_random_bytes(64, tmp);
  sc_reduce(tmp);
  memcpy(&res, tmp, 32);
}

bool generate_adaptor_signature(
    const Hash &prefix_hash,
    const PublicKey &pub,
    const SecretKey &sec,
    const PublicKey &adaptor_point,
    AdaptorSignature &pre_sig)
{
  std::lock_guard<std::mutex> lock(random_lock);

  // Decode adaptor point T
  ge_p3 T_p3;
  if (ge_frombytes_vartime(&T_p3,
      reinterpret_cast<const unsigned char*>(&adaptor_point)) != 0) {
    return false;
  }
  if (!point_is_valid(reinterpret_cast<const unsigned char*>(&adaptor_point))) {
    return false;
  }

  // Random nonce k
  EllipticCurveScalar k;
  adaptor_random_scalar(k);

  // R = k*G
  ge_p3 R_p3;
  ge_scalarmult_base(&R_p3, reinterpret_cast<const unsigned char*>(&k));

  // R' = R + T (adapted nonce)
  ge_cached T_cached;
  ge_p3_to_cached(&T_cached, &T_p3);
  ge_p1p1 Rp_p1p1;
  ge_add(&Rp_p1p1, &R_p3, &T_cached);
  ge_p3 Rp_p3;
  ge_p1p1_to_p3(&Rp_p3, &Rp_p1p1);

  // Build hash buffer: c = Hs(prefix_hash || pub || R')
  adaptor_s_comm buf;
  buf.h = prefix_hash;
  buf.key = reinterpret_cast<const EllipticCurvePoint&>(pub);
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&buf.comm), &Rp_p3);

  // c = hash_to_scalar(buf)
  EllipticCurveScalar c;
  hash_to_scalar(&buf, sizeof(adaptor_s_comm), c);

  // r_hat = k - c*sec  (standard Schnorr response with ORIGINAL nonce k)
  EllipticCurveScalar r_hat;
  sc_mulsub(reinterpret_cast<unsigned char*>(&r_hat),
            reinterpret_cast<const unsigned char*>(&c),
            reinterpret_cast<const unsigned char*>(&sec),
            reinterpret_cast<const unsigned char*>(&k));

  // Store: pre_sig = (c, r_hat)
  memcpy(pre_sig.data, &c, 32);
  memcpy(pre_sig.data + 32, &r_hat, 32);
  return true;
}

bool check_adaptor_signature(
    const Hash &prefix_hash,
    const PublicKey &pub,
    const PublicKey &adaptor_point,
    const AdaptorSignature &pre_sig)
{
  // Decode adaptor point T — reject identity and small-order points
  ge_p3 T_p3;
  if (ge_frombytes_vartime(&T_p3,
      reinterpret_cast<const unsigned char*>(&adaptor_point)) != 0) {
    return false;
  }
  if (!point_is_valid(reinterpret_cast<const unsigned char*>(&adaptor_point))) {
    return false;
  }

  // Decode public key P
  ge_p3 P_p3;
  if (ge_frombytes_vartime(&P_p3,
      reinterpret_cast<const unsigned char*>(&pub)) != 0) {
    return false;
  }

  // Extract c, r_hat
  const unsigned char *c_bytes = pre_sig.data;
  const unsigned char *r_hat_bytes = pre_sig.data + 32;

  if (sc_check(c_bytes) != 0 || sc_check(r_hat_bytes) != 0) {
    return false;
  }

  // R = r_hat*G + c*P  (this recovers the original nonce point k*G)
  ge_p2 R_p2;
  ge_double_scalarmult_base_vartime(&R_p2, c_bytes, &P_p3, r_hat_bytes);

  // Serialize R then deserialize to p3 for point addition
  unsigned char R_bytes[32];
  ge_tobytes(R_bytes, &R_p2);
  ge_p3 R_p3;
  if (ge_frombytes_vartime(&R_p3, R_bytes) != 0) {
    return false;
  }

  // R' = R + T
  ge_cached T_cached;
  ge_p3_to_cached(&T_cached, &T_p3);
  ge_p1p1 Rp_p1p1;
  ge_add(&Rp_p1p1, &R_p3, &T_cached);
  ge_p3 Rp_p3;
  ge_p1p1_to_p3(&Rp_p3, &Rp_p1p1);

  // Recompute challenge: c' = Hs(prefix_hash || pub || R')
  adaptor_s_comm buf;
  buf.h = prefix_hash;
  buf.key = reinterpret_cast<const EllipticCurvePoint&>(pub);
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&buf.comm), &Rp_p3);

  EllipticCurveScalar c_prime;
  hash_to_scalar(&buf, sizeof(adaptor_s_comm), c_prime);

  // Verify c == c'
  EllipticCurveScalar diff;
  sc_sub(reinterpret_cast<unsigned char*>(&diff),
         reinterpret_cast<const unsigned char*>(&c_prime),
         c_bytes);
  return sc_isnonzero(reinterpret_cast<const unsigned char*>(&diff)) == 0;
}

void adapt_signature(
    const AdaptorSignature &pre_sig,
    const EllipticCurveScalar &adaptor_secret,
    Signature &sig)
{
  // Challenge stays the same
  memcpy(sig.data, pre_sig.data, 32);

  // r = r_hat + t
  // Adapted response: (k - c*x) + t = (k + t) - c*x
  // This makes sig verify against R' = (k+t)*G = R + T
  sc_add(sig.data + 32,
         pre_sig.data + 32,
         reinterpret_cast<const unsigned char*>(&adaptor_secret));
}

bool extract_adaptor_secret(
    const AdaptorSignature &pre_sig,
    const Signature &sig,
    EllipticCurveScalar &adaptor_secret)
{
  // Challenges must match — both from the same adaptor session
  if (memcmp(pre_sig.data, sig.data, 32) != 0) {
    return false;
  }

  // t = r - r_hat = (r_hat + t) - r_hat
  sc_sub(reinterpret_cast<unsigned char*>(&adaptor_secret),
          sig.data + 32,
          pre_sig.data + 32);

  // Secret must be nonzero (zero would mean T was the identity)
  return sc_isnonzero(
      reinterpret_cast<const unsigned char*>(&adaptor_secret)) != 0;
}

bool generate_afk_lock_data(
    const Hash &prefix_hash,
    const PublicKey &pub,
    const SecretKey &sec,
    AFKLockData &out)
{
  // 1. Generate secret s
  adaptor_random_scalar(out.secret);
  
  // 2. Compute adaptor point S = s*G
  ge_p3 S_p3;
  ge_scalarmult_base(&S_p3, reinterpret_cast<const unsigned char*>(&out.secret));
  ge_p3_tobytes(reinterpret_cast<unsigned char*>(&out.adaptor_point), &S_p3);
  
  // 3. Generate twisted pre-signature
  return generate_adaptor_signature(prefix_hash, pub, sec, out.adaptor_point, out.pre_sig);
}

void complete_afk_signature(
    const AdaptorSignature &pre_sig,
    const EllipticCurveScalar &adaptor_secret,
    Signature &sig)
{
  adapt_signature(pre_sig, adaptor_secret, sig);
}

bool extract_afk_secret(
    const AdaptorSignature &pre_sig,
    const Signature &sig,
    EllipticCurveScalar &adaptor_secret)
{
  return extract_adaptor_secret(pre_sig, sig, adaptor_secret);
}

} // namespace Crypto

