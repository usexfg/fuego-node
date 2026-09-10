// Copyright (c) 2017-2026 Fuego Developers
#include "secp_adaptor.h"
#include "Common/StringTools.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <cstring>
#include <algorithm>
#include <vector>

namespace Crypto {

static const char* SECP_ORDER_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

static BIGNUM* get_order(BN_CTX* ctx) {
  BIGNUM* n = BN_new();
  BN_hex2bn(&n, SECP_ORDER_HEX);
  (void)ctx;
  return n;
}

static EC_GROUP* secp_group() {
  static EC_GROUP* g = nullptr;
  if (!g) {
    g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
  }
  return g;
}

static std::array<uint8_t,32> bn_to_bytes(const BIGNUM* bn) {
  std::array<uint8_t,32> out{}; out.fill(0);
  int len = BN_num_bytes(bn);
  std::vector<uint8_t> tmp(len);
  BN_bn2bin(bn, tmp.data());
  if (len <= 32)
    std::memcpy(out.data() + 32 - len, tmp.data(), len);
  else
    std::memcpy(out.data(), tmp.data() + len - 32, 32);
  return out;
}

static BIGNUM* bytes_to_bn(const std::array<uint8_t,32>& b) {
  return BN_bin2bn(b.data(), 32, nullptr);
}

std::array<uint8_t,32> secp_scalar_add(const std::array<uint8_t,32>& a, const std::array<uint8_t,32>& b) {
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM *ba = bytes_to_bn(a), *bb = bytes_to_bn(b), *n = get_order(ctx), *res = BN_new();
  BN_mod_add(res, ba, bb, n, ctx);
  auto out = bn_to_bytes(res);
  BN_free(ba); BN_free(bb); BN_free(n); BN_free(res); BN_CTX_free(ctx);
  return out;
}

std::array<uint8_t,32> secp_scalar_neg(const std::array<uint8_t,32>& a) {
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM *ba = bytes_to_bn(a), *n = get_order(ctx), *res = BN_new();
  if (BN_is_zero(ba)) BN_zero(res); else BN_sub(res, n, ba);
  auto out = bn_to_bytes(res);
  BN_free(ba); BN_free(n); BN_free(res); BN_CTX_free(ctx);
  return out;
}

bool secp_scalar_is_zero(const std::array<uint8_t,32>& a) {
  for (auto b: a) if (b) return false;
  return true;
}

std::array<uint8_t,32> secp_adaptor_challenge(const SecpPubKey& R, const SecpPubKey& P, const Hash& msg) {
  unsigned char tag[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>("Fuego/adaptor_challenge"), 23, tag);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(ctx, tag, 32);
  EVP_DigestUpdate(ctx, tag, 32);
  EVP_DigestUpdate(ctx, R.data.data(), 33);
  EVP_DigestUpdate(ctx, P.data.data(), 33);
  EVP_DigestUpdate(ctx, msg.data, 32);
  unsigned char out[SHA256_DIGEST_LENGTH];
  unsigned int outlen = 0;
  EVP_DigestFinal_ex(ctx, out, &outlen);
  EVP_MD_CTX_free(ctx);
  std::array<uint8_t,32> e{}; std::memcpy(e.data(), out, 32);
  return e;
}

bool secp_secret_to_pubkey(const SecretKey& sec, SecpPubKey& pub) {
  EC_GROUP* grp = secp_group();
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* priv = BN_bin2bn(reinterpret_cast<const unsigned char*>(&sec), 32, nullptr);
  BIGNUM* n = get_order(ctx);
  if (BN_is_zero(priv) || BN_cmp(priv, n) >= 0) { BN_free(priv); BN_free(n); BN_CTX_free(ctx); return false; }
  EC_POINT* pt = EC_POINT_new(grp);
  if (!EC_POINT_mul(grp, pt, priv, nullptr, nullptr, ctx)) { EC_POINT_free(pt); BN_free(priv); BN_free(n); BN_CTX_free(ctx); return false; }
  size_t len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_COMPRESSED, pub.data.data(), 33, ctx);
  EC_POINT_free(pt); BN_free(priv); BN_free(n); BN_CTX_free(ctx);
  return len == 33;
}

bool secp_generate_nonce(const SecretKey& k, SecpPubKey& R) {
  return secp_secret_to_pubkey(k, R);
}

bool secp_point_from_ed_secret(const SecretKey& edSecret, SecpPubKey& out) {
  // CryptoNote scalars are stored LITTLE-endian; the canonical secp256k1
  // scalar domain is BIG-endian. Byte-reverse into a local copy before
  // BN_bin2bn (which interprets big-endian) — see AGENTS.md cross-curve rule:
  // "secp-domain scalar = byte-reversed CryptoNote scalar".
  std::array<uint8_t,32> be{};
  std::memcpy(be.data(), &edSecret, 32);
  std::reverse(be.begin(), be.end());
  EC_GROUP* grp = secp_group();
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* priv = BN_bin2bn(be.data(), 32, nullptr);
  BIGNUM* n = get_order(ctx);
  if (BN_is_zero(priv) || BN_cmp(priv, n) >= 0) { BN_free(priv); BN_free(n); BN_CTX_free(ctx); return false; }
  EC_POINT* pt = EC_POINT_new(grp);
  if (!EC_POINT_mul(grp, pt, priv, nullptr, nullptr, ctx)) { EC_POINT_free(pt); BN_free(priv); BN_free(n); BN_CTX_free(ctx); return false; }
  size_t len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_COMPRESSED, out.data.data(), 33, ctx);
  EC_POINT_free(pt); BN_free(priv); BN_free(n); BN_CTX_free(ctx);
  return len == 33;
}

static bool ec_point_from_pubkey(const SecpPubKey& pk, EC_GROUP* grp, EC_POINT* pt, BN_CTX* ctx) {
  return EC_POINT_oct2point(grp, pt, pk.data.data(), 33, ctx) == 1;
}

static bool ec_point_to_pubkey(EC_GROUP* grp, EC_POINT* pt, SecpPubKey& out, BN_CTX* ctx) {
  size_t l = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_COMPRESSED, out.data.data(), 33, ctx);
  return l == 33;
}

bool secp_adaptor_sign(const SecretKey& sk, const SecretKey& k, const SecretKey& t, const Hash& msg, SecpAdaptorPresig& out) {
  EC_GROUP* grp = secp_group();
  BN_CTX* ctx = BN_CTX_new();
  SecpPubKey P, R;
  if (!secp_secret_to_pubkey(sk, P) || !secp_secret_to_pubkey(k, R)) { BN_CTX_free(ctx); return false; }
  auto e_bytes = secp_adaptor_challenge(R, P, msg);
  BIGNUM *sk_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(&sk), 32, nullptr);
  BIGNUM *k_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(&k), 32, nullptr);
  BIGNUM *t_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(&t), 32, nullptr);
  BIGNUM *e_bn = BN_bin2bn(e_bytes.data(), 32, nullptr);
  BIGNUM *n = get_order(ctx), *e_sk = BN_new(), *tmp = BN_new(), *s_prime = BN_new();
  if (BN_is_zero(sk_bn) || BN_is_zero(k_bn) || BN_cmp(sk_bn,n)>=0 || BN_cmp(k_bn,n)>=0 || BN_cmp(t_bn,n)>=0) { BN_free(sk_bn); BN_free(k_bn); BN_free(t_bn); BN_free(e_bn); BN_free(n); BN_free(e_sk); BN_free(tmp); BN_free(s_prime); BN_CTX_free(ctx); return false; }
  BN_mod_mul(e_sk, e_bn, sk_bn, n, ctx);
  BN_mod_add(tmp, e_sk, t_bn, n, ctx);
  BN_mod_add(s_prime, k_bn, tmp, n, ctx);
  out.R = R;
  auto sp = bn_to_bytes(s_prime);
  out.s_prime = sp;
  BN_free(sk_bn); BN_free(k_bn); BN_free(t_bn); BN_free(e_bn); BN_free(n); BN_free(e_sk); BN_free(tmp); BN_free(s_prime);
  BN_CTX_free(ctx);
  return true;
}

bool secp_adaptor_verify(const SecpPubKey& P, const SecpPubKey& T, const SecpAdaptorPresig& presig, const Hash& msg) {
  EC_GROUP* grp = secp_group();
  BN_CTX* ctx = BN_CTX_new();
  auto e_bytes = secp_adaptor_challenge(presig.R, P, msg);
  BIGNUM* e = BN_bin2bn(e_bytes.data(), 32, nullptr);
  BIGNUM* s_prime = BN_bin2bn(presig.s_prime.data(), 32, nullptr);
  BIGNUM* n = get_order(ctx);
  if (BN_cmp(s_prime,n)>=0) { BN_free(e); BN_free(s_prime); BN_free(n); BN_CTX_free(ctx); return false; }
  // LHS: s'*G
  EC_POINT *lhs = EC_POINT_new(grp), *R_pt = EC_POINT_new(grp), *P_pt = EC_POINT_new(grp), *T_pt = EC_POINT_new(grp), *eP = EC_POINT_new(grp), *rhs = EC_POINT_new(grp), *tmp = EC_POINT_new(grp);
  bool ok = false;
  do {
    if (!EC_POINT_mul(grp, lhs, s_prime, nullptr, nullptr, ctx)) break;
    if (!ec_point_from_pubkey(presig.R, grp, R_pt, ctx)) break;
    if (!ec_point_from_pubkey(P, grp, P_pt, ctx)) break;
    if (!ec_point_from_pubkey(T, grp, T_pt, ctx)) break;
    if (!EC_POINT_mul(grp, eP, nullptr, P_pt, e, ctx)) break;
    if (!EC_POINT_add(grp, tmp, R_pt, eP, ctx)) break;
    if (!EC_POINT_add(grp, rhs, tmp, T_pt, ctx)) break;
    if (EC_POINT_cmp(grp, lhs, rhs, ctx) != 0) break;
    ok = true;
  } while (false);
  EC_POINT_free(lhs); EC_POINT_free(R_pt); EC_POINT_free(P_pt); EC_POINT_free(T_pt); EC_POINT_free(eP); EC_POINT_free(rhs); EC_POINT_free(tmp);
  BN_free(e); BN_free(s_prime); BN_free(n); BN_CTX_free(ctx);
  return ok;
}

bool secp_adaptor_extract(const SecpAdaptorPresig& presig, const SecpSchnorrSig& sig, SecretKey& t_out) {
  // t = s' - s  mod n, where sig.s = s (from [R_x||s]), presig.s_prime = s'
  std::array<uint8_t,32> s{}; std::memcpy(s.data(), sig.data.data()+32, 32);
  std::array<uint8_t,32> s_prime = presig.s_prime;
  std::array<uint8_t,32> neg_s = secp_scalar_neg(s);
  auto t = secp_scalar_add(s_prime, neg_s);
  // AUDIT 1.2 / 3.2: a zero result means the "adaptor" was the identity — the
  // presig was already a full signature and nothing was locked. Reject.
  // NOTE: callers that hold the adaptor point T MUST prefer the 4-arg overload
  // below, which additionally checks t*G == T. The 3-arg form only guards t!=0.
  if (secp_scalar_is_zero(t)) return false;
  std::memcpy(&t_out, t.data(), 32);
  return true;
}

bool secp_adaptor_extract(const SecpAdaptorPresig& presig, const SecpSchnorrSig& sig,
                          const SecpPubKey& expectedT, SecretKey& t_out) {
  SecretKey t{};
  if (!secp_adaptor_extract(presig, sig, t)) return false;
  // AUDIT 1.2 / 3.2: the recovered scalar must open the adaptor point that was
  // committed for this swap. Without this a rogue completed signature yields a
  // wrong t and the counter-chain claim fails, stranding funds to timeout.
  SecpPubKey derived{};
  if (!secp_secret_to_pubkey(t, derived) || derived != expectedT) {
    std::memset(&t, 0, sizeof(t));
    return false;
  }
  t_out = t;
  return true;
}

bool secp_complete_schnorr_sig(const SecretKey& sk, const SecretKey& k, const Hash& msg, SecpSchnorrSig& out) {
  EC_GROUP* grp = secp_group();
  BN_CTX* ctx = BN_CTX_new();
  SecpPubKey P, R;
  if (!secp_secret_to_pubkey(sk, P) || !secp_secret_to_pubkey(k, R)) { BN_CTX_free(ctx); return false; }
  // Need x-only R_x for sig: compressed R's x. Extract x from R point.
  EC_POINT* rPt = EC_POINT_new(grp);
  if (!ec_point_from_pubkey(R, grp, rPt, ctx)) { EC_POINT_free(rPt); BN_CTX_free(ctx); return false; }
  BIGNUM* x = BN_new(), *y = BN_new();
  if (!EC_POINT_get_affine_coordinates(grp, rPt, x, y, ctx)) { BN_free(x); BN_free(y); EC_POINT_free(rPt); BN_CTX_free(ctx); return false; }
  auto e_bytes = secp_adaptor_challenge(R, P, msg);
  BIGNUM *e = BN_bin2bn(e_bytes.data(),32,nullptr), *sk_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(&sk),32,nullptr), *k_bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(&k),32,nullptr), *n=get_order(ctx), *e_sk=BN_new(), *s=BN_new();
  BN_mod_mul(e_sk, e, sk_bn, n, ctx);
  BN_mod_add(s, k_bn, e_sk, n, ctx);
  auto s_bytes = bn_to_bytes(s);
  auto x_bytes = bn_to_bytes(x); // x already 32 bytes via bn_to_bytes pad
  // Use x coordinate directly (32 bytes)
  std::memcpy(out.data.data(), x_bytes.data(), 32);
  std::memcpy(out.data.data()+32, s_bytes.data(), 32);
  BN_free(x); BN_free(y); BN_free(e); BN_free(sk_bn); BN_free(k_bn); BN_free(n); BN_free(e_sk); BN_free(s);
  EC_POINT_free(rPt); BN_CTX_free(ctx);
  return true;
}

std::string secpPubKeyToHex(const SecpPubKey& k) {
  return Common::toHex(k.data.data(), 33);
}
bool hexToSecpPubKey(const std::string& hex, SecpPubKey& k) {
  if (hex.size()!=66) return false;
  return Common::podFromHex(hex, k);
}

} // namespace Crypto
