// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2020-2026 Elderfire Privacy Group
//
//  D. Chaum and T.P. Pedersen, 1992
//  D.J. Bernstein et al.
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
//
// Discrete Log Equality (DLEQ) proofs.
//
// Proves knowledge of a scalar x such that A = x*G AND B = x*P
// simultaneously, without revealing x. Standard Chaum-Pedersen
// proof applied to Ed25519.
//
// Used in swaps to prove that adaptor point T = t*G is
// well-formed and prover actually knows the discrete log t.
//
// AUDIT 1.8: every proof is bound to a caller-supplied 32-byte context, which
// MUST be unique per swap (e.g. a hash of the swap id). Without it a proof over
// (P, A, B) verifies in ANY session reusing those points, so one captured proof
// can be replayed into an unrelated swap. The context is hashed into the
// challenge, so a proof made for one context cannot verify under another.
//
// NOTE: this changes the challenge preimage. Proofs from builds before this
// change do not verify here, and vice versa — there is no wire-format
// negotiation in the swap protocol, so both peers must run the same build.

#pragma once

#include <cstdint>
#include "../../include/CryptoTypes.h"

extern "C" {
#include "crypto-ops.h"
}

namespace Crypto {

// DLEQ proof: 64 bytes (challenge + response).
// Proves: "I know x such that A = x*G and B = x*P"
struct DLEQProof {
  EllipticCurveScalar challenge;  // e = Hs(domain || G || P || A || B || R1 || R2)
  EllipticCurveScalar response;   // s = k - e*x
};

// Generate a DLEQ proof.
//
// Proves knowledge of secret x such that:
//   point_G = x * G  (base point G is the Ed25519 generator)
//   point_P = x * base_point
//
// All points must be valid compressed Ed25519 points.
// Returns false if any point fails to decode.
bool generate_dleq_proof(
    const PublicKey &base_point,   // P (second generator)
    const PublicKey &point_G,      // A = x*G
    const PublicKey &point_P,      // B = x*P
    const SecretKey &secret,       // x
    const Hash &context,           // per-swap transcript binding (AUDIT 1.8)
    DLEQProof &proof);

// Verify a DLEQ proof.
//
// Checks that there exists some x (unknown to verifier) such that
// point_G = x*G and point_P = x*base_point.
bool check_dleq_proof(
    const PublicKey &base_point,   // P
    const PublicKey &point_G,      // A = x*G
    const PublicKey &point_P,      // B = x*P
    const Hash &context,           // must equal the prover's context
    const DLEQProof &proof);

} // namespace Crypto
