// Copyright (c) 2017-2026 Fuego Developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See file labeled LICENSE for more details.

#pragma once

#include <cstdint>
#include <CryptoNote.h>
#include "VaultTypes.h"

namespace CryptoNote {

class VaultUtxoSet;

class VaultPolicy {
public:
    static VaultPartition classifySpend(
        const Transaction& tx,
        const VaultUtxoSet& utxoSet);

    static bool isPermitted(
        const Transaction& tx,
        VaultPartition source,
        const VaultUtxoSet& utxoSet);
};

} // namespace CryptoNote
