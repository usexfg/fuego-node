// Copyright (c) 2017-2026 Fuego Developers

#include "Ed25519Verify.h"

extern "C" {
#include "crypto/crypto-ops.h"
}

#include <openssl/sha.h>
#include <cstring>
#include <algorithm>

namespace XfgSwap {

bool Ed25519Verify::verify(const uint8_t pubkey[32],
                           const std::string& message,
                           const uint8_t signature[64]) {
  const uint8_t* R_bytes = signature;
  const uint8_t* S_bytes = signature + 32;

  ge_p3 R;
  if (ge_frombytes_vartime(&R, R_bytes) != 0) return false;

  ge_p3 A;
  if (ge_frombytes_vartime(&A, pubkey) != 0) return false;

  // Reject small-subgroup (low-order) public keys: multiply A by the cofactor
  // (8 = 3 doublings). If the result is the identity point, A has order
  // dividing 8 and a signature would verify for any message — reject outright.
  {
    ge_p2 tmp2;
    ge_p1p1 tmp11;
    ge_p3_to_p2(&tmp2, &A);
    ge_p2_dbl(&tmp11, &tmp2);   // 2A
    ge_p1p1_to_p2(&tmp2, &tmp11);
    ge_p2_dbl(&tmp11, &tmp2);   // 4A
    ge_p1p1_to_p2(&tmp2, &tmp11);
    ge_p2_dbl(&tmp11, &tmp2);   // 8A
    ge_p1p1_to_p2(&tmp2, &tmp11);
    uint8_t cofactor_point[32];
    ge_tobytes(cofactor_point, &tmp2);
    static const uint8_t identity[32] = {};
    if (std::memcmp(cofactor_point, identity, 32) == 0) return false;
  }

  if (sc_isnonzero(S_bytes) == 0) return false;

  std::vector<uint8_t> hash_input(64 + message.size());
  std::memcpy(hash_input.data(),          R_bytes, 32);
  std::memcpy(hash_input.data() + 32,     pubkey,  32);
  std::memcpy(hash_input.data() + 64,     message.data(), message.size());

  uint8_t hash_output[SHA512_DIGEST_LENGTH];
  SHA512(hash_input.data(), hash_input.size(), hash_output);

  unsigned char k_scalar[64];
  std::memcpy(k_scalar, hash_output, 64);
  sc_reduce(k_scalar);

  // Verify: [S]B == R + [k]A  ⇔  R == [S]B + [-k]A
  unsigned char k_neg[32];
  unsigned char zero[32] = {};
  sc_sub(k_neg, zero, k_scalar);

  ge_p2 computed;
  ge_double_scalarmult_base_vartime(&computed, k_neg, &A, S_bytes);

  uint8_t computed_bytes[32];
  ge_tobytes(computed_bytes, &computed);

  return std::memcmp(computed_bytes, R_bytes, 32) == 0;
}

} // namespace XfgSwap
