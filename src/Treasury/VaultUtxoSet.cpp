// Copyright (c) 2017-2026 Fuego Developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See file labeled LICENSE for more details.

#include "VaultUtxoSet.h"
#include "Serialization/ISerializer.h"
#include "crypto/crypto.h"
#include <algorithm>

namespace CryptoNote {

const char* vaultPartitionName(VaultPartition p) {
    switch (p) {
        case VaultPartition::CD_APY_POOL:     return "CD_APY_POOL";
        case VaultPartition::LP_RESERVE:      return "LP_RESERVE";
        case VaultPartition::GENERAL_RESERVE: return "GENERAL_RESERVE";
        case VaultPartition::SWF:             return "SWF";
        case VaultPartition::BONUS_VAULT:     return "BONUS_VAULT";
        default: return "UNKNOWN";
    }
}

const char* VaultUtxoSet::partitionName(VaultPartition p) {
    return vaultPartitionName(p);
}

void VaultUtxoSet::addUtxo(uint64_t globalIndex,
                            uint64_t amount,
                            AssetType asset,
                            VaultPartition partition,
                            const Crypto::Hash& txHash,
                            const Crypto::PublicKey& outputKey) {
    VaultOutput vo;
    vo.globalOutputIndex = globalIndex;
    vo.amount = amount;
    vo.asset = asset;
    vo.partition = partition;
    vo.txHash = txHash;
    vo.outputKey = outputKey;
    vo.spent = false;
    m_utxos[globalIndex] = vo;

    // CRIT-01 fix: compute and register key image when spend key is available
    if (m_spendKeySet) {
        Crypto::KeyImage ki;
        Crypto::generate_key_image(outputKey, m_spendKey, ki);
        registerKeyImage(ki, globalIndex);
    }
}

void VaultUtxoSet::markSpent(uint64_t globalIndex) {
    auto it = m_utxos.find(globalIndex);
    if (it != m_utxos.end() && !it->second.spent) {
        it->second.spent = true;
        m_spentCount++;
    }
}

uint64_t VaultUtxoSet::partitionBalance(VaultPartition partition, AssetType asset) const {
    uint64_t balance = 0;
    for (const auto& [idx, vo] : m_utxos) {
        if (!vo.spent && vo.partition == partition && vo.asset == asset) {
            balance += vo.amount;
        }
    }
    return balance;
}

VaultBalance VaultUtxoSet::allBalances() const {
    VaultBalance b;
    for (const auto& [idx, vo] : m_utxos) {
        if (vo.spent) continue;
        if (vo.asset == AssetType::XFG) {
            switch (vo.partition) {
                case VaultPartition::CD_APY_POOL:     b.xfgCdFeePool += vo.amount; break;
                case VaultPartition::LP_RESERVE:      b.xfgLpReserve += vo.amount; break;
                case VaultPartition::GENERAL_RESERVE: b.xfgGeneral += vo.amount; break;
                case VaultPartition::BONUS_VAULT:     b.xfgBonusVault += vo.amount; break;
                default: break;
            }
        } else if (vo.asset == AssetType::HEAT) {
            switch (vo.partition) {
                case VaultPartition::CD_APY_POOL:     b.heatCdFeePool += vo.amount; break;
                case VaultPartition::LP_RESERVE:      b.heatLpReserve += vo.amount; break;
                case VaultPartition::GENERAL_RESERVE: b.heatGeneral += vo.amount; break;
                case VaultPartition::SWF:             b.heatSwf += vo.amount; break;
                case VaultPartition::BONUS_VAULT:     b.heatBonusVault += vo.amount; break;
                default: break;
            }
        }
    }
    return b;
}

bool VaultUtxoSet::isVaultOutput(uint64_t globalIndex) const {
    auto it = m_utxos.find(globalIndex);
    return it != m_utxos.end() && !it->second.spent;
}

VaultPartition VaultUtxoSet::getPartition(uint64_t globalIndex) const {
    auto it = m_utxos.find(globalIndex);
    if (it != m_utxos.end()) {
        return it->second.partition;
    }
    return VaultPartition::GENERAL_RESERVE;
}

const VaultOutput* VaultUtxoSet::getOutput(uint64_t globalIndex) const {
    auto it = m_utxos.find(globalIndex);
    if (it != m_utxos.end()) {
        return &it->second;
    }
    return nullptr;
}

bool VaultUtxoSet::isVaultKeyImage(const Crypto::KeyImage& ki) const {
    return m_keyImages.find(ki) != m_keyImages.end();
}

uint64_t VaultUtxoSet::getOutputIndexForKeyImage(const Crypto::KeyImage& ki) const {
    auto it = m_keyImages.find(ki);
    return (it != m_keyImages.end()) ? it->second : 0;
}

void VaultUtxoSet::registerKeyImage(const Crypto::KeyImage& ki, uint64_t globalIndex) {
    m_keyImages[ki] = globalIndex;
}

void VaultUtxoSet::setSpendKey(const Crypto::SecretKey& spendKey) {
    m_spendKey = spendKey;
    m_spendKeySet = true;
}

void VaultUtxoSet::rebuildKeyImageIndex() {
    if (!m_spendKeySet) return;
    m_keyImages.clear();
    for (const auto& [idx, vo] : m_utxos) {
        Crypto::KeyImage ki;
        Crypto::generate_key_image(vo.outputKey, m_spendKey, ki);
        m_keyImages[ki] = idx;
    }
}

std::vector<VaultOutput> VaultUtxoSet::selectUtxos(
    VaultPartition partition,
    AssetType asset,
    uint64_t neededAmount) const {
    std::vector<VaultOutput> candidates;
    for (const auto& [idx, vo] : m_utxos) {
        if (!vo.spent && vo.partition == partition && vo.asset == asset) {
            candidates.push_back(vo);
        }
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const VaultOutput& a, const VaultOutput& b) {
                  return a.amount < b.amount;
              });

    std::vector<VaultOutput> selected;
    uint64_t collected = 0;
    for (const auto& vo : candidates) {
        selected.push_back(vo);
        collected += vo.amount;
        if (collected >= neededAmount) break;
    }
    return selected;
}

VaultUtxoSet::SpendResult VaultUtxoSet::spendUtxos(
    VaultPartition partition, AssetType asset, uint64_t neededAmount) {
    SpendResult result;
    auto candidates = selectUtxos(partition, asset, neededAmount);
    for (const auto& vo : candidates) {
        markSpent(vo.globalOutputIndex);
        result.amountSpent += vo.amount;
        result.spentIndices.push_back(vo.globalOutputIndex);
    }
    // W-3: no surplus destruction. If the final selected UTXO overshoots,
    // report the surplus so the caller can mint a change UTXO back to the
    // same partition (keeping the partition balance equal to actual claims).
    if (result.amountSpent > neededAmount && !candidates.empty()) {
        result.changeAmount = result.amountSpent - neededAmount;
        result.changeSourceIndex = candidates.back().globalOutputIndex;
    }
    return result;
}

void VaultUtxoSet::unSpendUtxos(const std::vector<uint64_t>& indices) {
    for (uint64_t idx : indices) {
        auto it = m_utxos.find(idx);
        if (it != m_utxos.end() && it->second.spent) {
            it->second.spent = false;
            if (m_spentCount > 0) m_spentCount--;
        }
    }
}

void VaultUtxoSet::serialize(ISerializer& s) {
    bool isInput = (s.type() == ISerializer::INPUT);

    if (isInput) {
        m_utxos.clear();
        m_keyImages.clear();
        m_spentCount = 0;
    }

    uint64_t count = isInput ? 0 : m_utxos.size();
    s(count, "vault_utxo_count");

    if (isInput) {
        for (uint64_t i = 0; i < count; ++i) {
            VaultOutput vo;
            s(vo.globalOutputIndex, "vo_idx");
            s(vo.amount, "vo_amount");
            uint8_t assetRaw = static_cast<uint8_t>(vo.asset);
            s(assetRaw, "vo_asset");
            if (assetRaw > static_cast<uint8_t>(AssetType::HEAT)) {
                return;
            }
            vo.asset = static_cast<AssetType>(assetRaw);
            uint8_t partRaw = static_cast<uint8_t>(vo.partition);
            s(partRaw, "vo_partition");
            if (partRaw > static_cast<uint8_t>(VaultPartition::BONUS_VAULT)) {
                return;
            }
            vo.partition = static_cast<VaultPartition>(partRaw);
            s.binary(vo.txHash.data, sizeof(vo.txHash.data), "vo_txhash");
            s.binary(vo.outputKey.data, sizeof(vo.outputKey.data), "vo_outkey");
            s(vo.spent, "vo_spent");

            m_utxos[vo.globalOutputIndex] = vo;
            if (vo.spent) m_spentCount++;
        }
    } else {
        std::vector<VaultOutput> outputs;
        for (const auto& [idx, vo] : m_utxos) {
            outputs.push_back(vo);
        }
        std::sort(outputs.begin(), outputs.end(),
                  [](const VaultOutput& a, const VaultOutput& b) {
                      return a.globalOutputIndex < b.globalOutputIndex;
                  });
        for (size_t i = 0; i < outputs.size(); ++i) {
            VaultOutput& vo = outputs[i];
            s(vo.globalOutputIndex, "vo_idx");
            s(vo.amount, "vo_amount");
            uint8_t assetRaw = static_cast<uint8_t>(vo.asset);
            s(assetRaw, "vo_asset");
            uint8_t partRaw = static_cast<uint8_t>(vo.partition);
            s(partRaw, "vo_partition");
            s.binary(vo.txHash.data, sizeof(vo.txHash.data), "vo_txhash");
            s.binary(vo.outputKey.data, sizeof(vo.outputKey.data), "vo_outkey");
            s(vo.spent, "vo_spent");
        }
    }

    s(m_spentCount, "vault_spent_count");

    // CRIT-01 fix: rebuild key image index after deserialization
    if (isInput) {
        rebuildKeyImageIndex();
    }
}

void VaultUtxoSet::clear() {
    m_utxos.clear();
    m_keyImages.clear();
    m_spentCount = 0;
}

void VaultUtxoSet::removeAboveIndex(uint64_t minIndex) {
    std::vector<uint64_t> toRemove;
    for (const auto& [idx, vo] : m_utxos) {
        if (idx >= minIndex) toRemove.push_back(idx);
    }
    for (uint64_t idx : toRemove) {
        auto it = m_utxos.find(idx);
        if (it != m_utxos.end()) {
            if (it->second.spent) m_spentCount--;
            // Remove associated key image
            if (m_spendKeySet) {
                Crypto::KeyImage ki;
                Crypto::generate_key_image(it->second.outputKey, m_spendKey, ki);
                m_keyImages.erase(ki);
            }
            m_utxos.erase(it);
        }
    }
}

} // namespace CryptoNote
