// Copyright (c) 2017-2026, Fuego Developers
// Copyright (c) 2017-2025 Elderfire Privacy Council
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2014-2016 The XDN developers
// Copyright (c) 2012-2018 The CryptoNote developers
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

#include "BankingIndex.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <limits>

//#include "CryptoNoteSerialization.h"
#include "../Serialization/SerializationOverloads.h"

namespace CryptoNote {

BankingIndex::BankingIndex() : blockCount(0), m_ethereal_xfg(0), m_total_burned_xfg(0), m_permanently_burned_xfg(0) {
}

BankingIndex::BankingIndex(DepositHeight expectedHeight) : blockCount(0), m_ethereal_xfg(0), m_total_burned_xfg(0), m_permanently_burned_xfg(0) {
  index.reserve(expectedHeight + 1);
}

void BankingIndex::reserve(DepositHeight expectedHeight) {
  index.reserve(expectedHeight + 1);
}

auto BankingIndex::fullDepositAmount() const -> DepositAmount {
  return index.empty() ? 0 : index.back().amount;
}

auto BankingIndex::fullInterestAmount() const -> DepositInterest {
  return index.empty() ? 0 : index.back().interest;
}

static inline bool sumWillOverflow(int64_t x, int64_t y) {
  if (y > 0 && x > std::numeric_limits<int64_t>::max() - y) {
    return true;
  }

  if (y < 0 && x < std::numeric_limits<int64_t>::min() - y) {
    return true;
  }

  return false;
}

static inline bool sumWillOverflow(uint64_t x, uint64_t y) {
  if (x > std::numeric_limits<uint64_t>::max() - y) {
    return true;
  }

  return false;
}

void BankingIndex::pushBlock(DepositAmount amount, DepositInterest interest) {
  DepositAmount lastAmount;
  DepositInterest lastInterest;
  if (index.empty()) {
    lastAmount = 0;
    lastInterest = 0;
  } else {
    lastAmount = index.back().amount;
    lastInterest = index.back().interest;
  }

  assert(!sumWillOverflow(amount, lastAmount));
  assert(!sumWillOverflow(interest, lastInterest));
  assert(amount + lastAmount >= 0);
  if (amount != 0) {
    index.push_back({blockCount, amount + lastAmount, interest + lastInterest});
  }

  ++blockCount;
}

void BankingIndex::popBlock() {
  assert(blockCount > 0);

  --blockCount;

  uint64_t burnedInBlock = 0;
  if (!m_burnedXfgEntries.empty() && m_burnedXfgEntries.back().height == blockCount) {
    uint64_t currentTotal = m_ethereal_xfg;
    uint64_t previousTotal = (m_burnedXfgEntries.size() > 1) ?
      (m_burnedXfgEntries.end() - 2)->cumulative_burned : 0;
    burnedInBlock = currentTotal - previousTotal;

    m_burnedXfgEntries.pop_back();
    m_ethereal_xfg -= burnedInBlock;
  }

  if (!m_totalBurnedEntries.empty() && m_totalBurnedEntries.back().height == blockCount) {
    uint64_t currentTotal = m_total_burned_xfg;
    uint64_t previousTotal = (m_totalBurnedEntries.size() > 1) ?
      (m_totalBurnedEntries.end() - 2)->cumulative_burned : 0;
    uint64_t totalInBlock = currentTotal - previousTotal;

    m_totalBurnedEntries.pop_back();
    m_total_burned_xfg -= totalInBlock;
  }

  if (!m_permanentBurnedEntries.empty() && m_permanentBurnedEntries.back().height == blockCount) {
    uint64_t currentTotal = m_permanently_burned_xfg;
    uint64_t previousTotal = (m_permanentBurnedEntries.size() > 1) ?
      (m_permanentBurnedEntries.end() - 2)->cumulative_burned : 0;
    uint64_t permInBlock = currentTotal - previousTotal;

    m_permanentBurnedEntries.pop_back();
    m_permanently_burned_xfg -= permInBlock;
  }

  if (!index.empty() && index.back().height == blockCount) {
    index.pop_back();
  }
}

auto BankingIndex::size() const -> DepositHeight {
  return blockCount;
}

auto BankingIndex::upperBound(DepositHeight height) const -> IndexType::const_iterator {
  return std::upper_bound(
      index.cbegin(), index.cend(), height,
      [] (DepositHeight height, const BankingIndexEntry& left) { return height < left.height; });
}

size_t BankingIndex::popBlocks(DepositHeight from) {
  if (from >= blockCount) {
    return 0;
  }

  IndexType::iterator it = index.begin();
  std::advance(it, std::distance(index.cbegin(), upperBound(from)));
  if (it != index.begin()) {
    --it;
    if (it->height != from) {
      ++it;
    }
  }

  index.erase(it, index.end());

  // Also pop burned XFG entries from this height
  auto burnedIt = m_burnedXfgEntries.begin();
  while (burnedIt != m_burnedXfgEntries.end() && burnedIt->height < from) {
    ++burnedIt;
  }
  if (!m_burnedXfgEntries.empty() && burnedIt != m_burnedXfgEntries.begin()) {
    m_ethereal_xfg = (burnedIt - 1)->cumulative_burned;
  } else if (burnedIt == m_burnedXfgEntries.begin()) {
    m_ethereal_xfg = 0;
  }
  m_burnedXfgEntries.erase(burnedIt, m_burnedXfgEntries.end());

  // Pop the overall burn tally from this height too.
  auto totalIt = m_totalBurnedEntries.begin();
  while (totalIt != m_totalBurnedEntries.end() && totalIt->height < from) {
    ++totalIt;
  }
  if (!m_totalBurnedEntries.empty() && totalIt != m_totalBurnedEntries.begin()) {
    m_total_burned_xfg = (totalIt - 1)->cumulative_burned;
  } else if (totalIt == m_totalBurnedEntries.begin()) {
    m_total_burned_xfg = 0;
  }
  m_totalBurnedEntries.erase(totalIt, m_totalBurnedEntries.end());

  auto permIt = m_permanentBurnedEntries.begin();
  while (permIt != m_permanentBurnedEntries.end() && permIt->height < from) {
    ++permIt;
  }
  if (!m_permanentBurnedEntries.empty() && permIt != m_permanentBurnedEntries.begin()) {
    m_permanently_burned_xfg = (permIt - 1)->cumulative_burned;
  } else if (permIt == m_permanentBurnedEntries.begin()) {
    m_permanently_burned_xfg = 0;
  }
  m_permanentBurnedEntries.erase(permIt, m_permanentBurnedEntries.end());

  auto diff = blockCount - from;
  blockCount -= diff;
  return diff;
}

auto BankingIndex::depositAmountAtHeight(DepositHeight height) const -> DepositAmount {
  if (blockCount == 0) {
    return 0;
  } else {
    auto it = upperBound(height);
    return it == index.cbegin() ? 0 : (--it)->amount;
  }
}

auto BankingIndex::depositInterestAtHeight(DepositHeight height) const -> DepositInterest {
  if (blockCount == 0) {
    return 0;
  } else {
    auto it = upperBound(height);
    return it == index.cbegin() ? 0 : (--it)->interest;
  }
}

// burned XFG tracking methods
BankingIndex::BurnedAmount BankingIndex::getBurnedXfgAmount() const {
  return m_ethereal_xfg;
}

BankingIndex::BurnedAmount BankingIndex::getBurnedXfgAtHeight(DepositHeight height) const {
  if (m_burnedXfgEntries.empty()) {
    return 0;
  }

  auto it = std::upper_bound(
    m_burnedXfgEntries.cbegin(), m_burnedXfgEntries.cend(), height,
    [] (DepositHeight height, const BurnedXfgEntry& entry) { return height < entry.height; });

  return it == m_burnedXfgEntries.cbegin() ? 0 : (--it)->cumulative_burned;
}

BankingIndex::BurnedAmount BankingIndex::getTotalBurnedXfg() const {
  return m_total_burned_xfg;
}

BankingIndex::BurnedAmount BankingIndex::getTotalBurnedXfgAtHeight(DepositHeight height) const {
  if (m_totalBurnedEntries.empty()) return 0;
  auto it = std::upper_bound(
    m_totalBurnedEntries.cbegin(), m_totalBurnedEntries.cend(), height,
    [] (DepositHeight height, const BurnedXfgEntry& entry) { return height < entry.height; });
  return it == m_totalBurnedEntries.cbegin() ? 0 : (--it)->cumulative_burned;
}

void BankingIndex::addTotalBurn(BurnedAmount amount, DepositHeight height) {
  if (amount == 0) return;
  const uint64_t MAX_BURNED = std::numeric_limits<uint64_t>::max();
  if (amount > MAX_BURNED - m_total_burned_xfg) {
    fprintf(stderr, "[BankingIndex] addTotalBurn: overflow rejected (total=%llu amount=%llu)\n",
            (unsigned long long)m_total_burned_xfg, (unsigned long long)amount);
    return;
  }
  m_total_burned_xfg += amount;

  if (!m_totalBurnedEntries.empty() && m_totalBurnedEntries.back().height == height) {
    if (amount > MAX_BURNED - m_totalBurnedEntries.back().amount) {
      fprintf(stderr, "[BankingIndex] addTotalBurn: entry amount overflow rejected at height %u\n", height);
      return;
    }
    m_totalBurnedEntries.back().amount += amount;
    m_totalBurnedEntries.back().cumulative_burned = m_total_burned_xfg;
  } else {
    m_totalBurnedEntries.push_back({ height, amount, m_total_burned_xfg });
  }
}

BankingIndex::BurnedAmount BankingIndex::getPermanentlyBurnedXfg() const {
  return m_permanently_burned_xfg;
}

BankingIndex::BurnedAmount BankingIndex::getPermanentlyBurnedXfgAtHeight(DepositHeight height) const {
  if (m_permanentBurnedEntries.empty()) return 0;
  auto it = std::upper_bound(
    m_permanentBurnedEntries.cbegin(), m_permanentBurnedEntries.cend(), height,
    [] (DepositHeight height, const BurnedXfgEntry& entry) { return height < entry.height; });
  return it == m_permanentBurnedEntries.cbegin() ? 0 : (--it)->cumulative_burned;
}

void BankingIndex::addPermanentBurn(BurnedAmount amount, DepositHeight height) {
  if (amount == 0) return;
  const uint64_t MAX_BURNED = std::numeric_limits<uint64_t>::max();
  if (amount > MAX_BURNED - m_permanently_burned_xfg) {
    fprintf(stderr, "[BankingIndex] addPermanentBurn: overflow rejected (perm=%llu amount=%llu)\n",
            (unsigned long long)m_permanently_burned_xfg, (unsigned long long)amount);
    return;
  }
  m_permanently_burned_xfg += amount;

  if (!m_permanentBurnedEntries.empty() && m_permanentBurnedEntries.back().height == height) {
    if (amount > MAX_BURNED - m_permanentBurnedEntries.back().amount) {
      fprintf(stderr, "[BankingIndex] addPermanentBurn: entry amount overflow rejected at height %u\n", height);
      return;
    }
    m_permanentBurnedEntries.back().amount += amount;
    m_permanentBurnedEntries.back().cumulative_burned = m_permanently_burned_xfg;
  } else {
    m_permanentBurnedEntries.push_back({ height, amount, m_permanently_burned_xfg });
  }
}

void BankingIndex::addForeverDeposit(BurnedAmount amount, DepositHeight height) {
  if (amount == 0) return;

  // Add to regular deposit tracking (existing functionality)
  // Note: This would typically be called from the wallet when creating a FOREVER deposit
  // pushBlock(static_cast<DepositAmount>(amount), 0);

  // Add to burned XFG tracking (new functionality)
  const uint64_t MAX_BURNED = std::numeric_limits<uint64_t>::max();
  if (amount > MAX_BURNED - m_ethereal_xfg) {
    fprintf(stderr, "[BankingIndex] addForeverDeposit: overflow rejected (ethereal=%llu amount=%llu)\n",
            (unsigned long long)m_ethereal_xfg, (unsigned long long)amount);
    return;
  }

  m_ethereal_xfg += amount;

  if (!m_burnedXfgEntries.empty() && m_burnedXfgEntries.back().height == height) {
    if (amount > MAX_BURNED - m_burnedXfgEntries.back().amount) {
      fprintf(stderr, "[BankingIndex] addForeverDeposit: entry amount overflow rejected at height %u\n", height);
      return;
    }
    m_burnedXfgEntries.back().amount += amount;
    m_burnedXfgEntries.back().cumulative_burned = m_ethereal_xfg;
  } else {
    // Create new entry
    m_burnedXfgEntries.push_back({
      height,
      amount,
      m_ethereal_xfg
    });
  }
}



BankingIndex::DepositStats BankingIndex::getStats() const {
  DepositStats stats;
  stats.totalDeposits = static_cast<uint64_t>(fullDepositAmount());
  stats.ethereal_xfg = m_ethereal_xfg;
  stats.regularDeposits = stats.totalDeposits > stats.ethereal_xfg ?
    stats.totalDeposits - stats.ethereal_xfg : 0;
  return stats;
}

void BankingIndex::serialize(ISerializer& s) {
  s(blockCount, "blockCount");
  s(m_ethereal_xfg, "ethernalXFG");

  if (s.type() == ISerializer::INPUT) {
    readSequence<BankingIndexEntry>(std::back_inserter(index), "index", s);
    readSequence<BurnedXfgEntry>(std::back_inserter(m_burnedXfgEntries), "burnedXfgEntries", s);
    // Migration-safe trailing fields: absent in pre-tally databases, defaults
    // (0 / empty) stand and the burn rescan fills them on load.
    try {
      s(m_total_burned_xfg, "totalBurnedXFG");
      readSequence<BurnedXfgEntry>(std::back_inserter(m_totalBurnedEntries), "totalBurnedEntries", s);
    } catch (const std::exception& e) {
      fprintf(stderr, "[BankingIndex] totalBurned deserialization failed: %s — rescan required\n", e.what());
      m_total_burned_xfg = 0;
      m_totalBurnedEntries.clear();
      m_rescanRequired = true;
    } catch (...) {
      fprintf(stderr, "[BankingIndex] totalBurned deserialization failed (unknown) — rescan required\n");
      m_total_burned_xfg = 0;
      m_totalBurnedEntries.clear();
      m_rescanRequired = true;
    }
    try {
      s(m_permanently_burned_xfg, "permanentlyBurnedXFG");
      readSequence<BurnedXfgEntry>(std::back_inserter(m_permanentBurnedEntries), "permanentBurnedEntries", s);
    } catch (const std::exception& e) {
      fprintf(stderr, "[BankingIndex] permanentBurned deserialization failed: %s — rescan required\n", e.what());
      m_permanently_burned_xfg = 0;
      m_permanentBurnedEntries.clear();
      m_rescanRequired = true;
    } catch (...) {
      fprintf(stderr, "[BankingIndex] permanentBurned deserialization failed (unknown) — rescan required\n");
      m_permanently_burned_xfg = 0;
      m_permanentBurnedEntries.clear();
      m_rescanRequired = true;
    }
  } else {
    writeSequence<BankingIndexEntry>(index.begin(), index.end(), "index", s);
    writeSequence<BurnedXfgEntry>(m_burnedXfgEntries.begin(), m_burnedXfgEntries.end(), "burnedXfgEntries", s);
    s(m_total_burned_xfg, "totalBurnedXFG");
    writeSequence<BurnedXfgEntry>(m_totalBurnedEntries.begin(), m_totalBurnedEntries.end(), "totalBurnedEntries", s);
    s(m_permanently_burned_xfg, "permanentlyBurnedXFG");
    writeSequence<BurnedXfgEntry>(m_permanentBurnedEntries.begin(), m_permanentBurnedEntries.end(), "permanentBurnedEntries", s);
  }
}

void BankingIndex::BankingIndexEntry::serialize(ISerializer& s) {
  s(height, "height");
  s(amount, "amount");
  s(interest, "interest");
}

void BankingIndex::BurnedXfgEntry::serialize(ISerializer& s) {
  s(height, "height");
  s(amount, "amount");
  s(cumulative_burned, "cumulative_burned");
}

}
