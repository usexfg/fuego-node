// Copyright (c) 2017-2026 Fuego Developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See file labeled LICENSE for more details.

#include "VaultKeys.h"
#include "CryptoNoteConfig.h"
#include "crypto/crypto.h"
#include "crypto/keccak.h"
#include "crypto/hash.h"
#include <cstring>

namespace CryptoNote {

VaultKeypair deriveVaultKeys(const Crypto::Hash& genesisHash) {
    VaultKeypair keys;
    memset(&keys, 0, sizeof(keys));

    uint8_t seedInput[32 + sizeof(parameters::VAULT_KEY_SEED) - 1];
    memcpy(seedInput, genesisHash.data, 32);
    memcpy(seedInput + 32, parameters::VAULT_KEY_SEED, sizeof(parameters::VAULT_KEY_SEED) - 1);
    size_t seedLen = 32 + sizeof(parameters::VAULT_KEY_SEED) - 1;

    Crypto::Hash spendSeed;
    keccak(seedInput, static_cast<int>(seedLen), spendSeed.data, 32);

    Crypto::hash_to_scalar(spendSeed.data, sizeof(spendSeed.data),
                           reinterpret_cast<Crypto::EllipticCurveScalar&>(keys.spendKey));

    Crypto::secret_key_to_public_key(keys.spendKey, keys.spendPub);

    Crypto::Hash viewSeed;
    keccak(keys.spendKey.data, 32, viewSeed.data, 32);

    Crypto::hash_to_scalar(viewSeed.data, sizeof(viewSeed.data),
                           reinterpret_cast<Crypto::EllipticCurveScalar&>(keys.viewKey));

    Crypto::secret_key_to_public_key(keys.viewKey, keys.viewPub);

    return keys;
}

bool isVaultViewKey(const Crypto::PublicKey& key, const Crypto::PublicKey& vaultViewPub) {
    // Use volatile XOR reduction to prevent compiler from short-circuiting to
    // variable-time memcmp behavior on secret-adjacent key material.
    const uint8_t* a = key.data;
    const uint8_t* b = vaultViewPub.data;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < sizeof(key.data); ++i) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace CryptoNote
