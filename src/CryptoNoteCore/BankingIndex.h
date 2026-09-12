// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2017-2025 Elderfire Privacy Council
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2014-2017 The XDN developers
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

#pragma once

#include <vector>
#include <cstddef>
#include <cstdint>

namespace CryptoNote {
class ISerializer;

class BankingIndex {
public:
  using DepositAmount = int64_t;
  using DepositInterest = uint64_t;
  using DepositHeight = uint32_t;
  using BurnedAmount = uint64_t;

  BankingIndex();
  explicit BankingIndex(DepositHeight expectedHeight);
  void pushBlock(DepositAmount amount, DepositInterest interest);
  void popBlock();
  void reserve(DepositHeight expectedHeight);
  size_t popBlocks(DepositHeight from);
  DepositAmount depositAmountAtHeight(DepositHeight height) const;
  DepositAmount fullDepositAmount() const;
  DepositInterest depositInterestAtHeight(DepositHeight height) const;
  DepositInterest fullInterestAmount() const;
  DepositHeight size() const;
  void serialize(ISerializer& s);

  // integrated burned XFG tracking
  // m_ethereal_xfg: Eternal Flame bucket — the 50% routing share of burns.
  BurnedAmount getBurnedXfgAmount() const;
  BurnedAmount getBurnedXfgAtHeight(DepositHeight height) const;
  void addForeverDeposit(BurnedAmount amount, DepositHeight height);

   // Overall burn tally: EVERY XFG atom destroyed (mint burns, fee conversions),
  // any route, all-time. Additive only; reversed by popBlock via height entries.
  BurnedAmount getTotalBurnedXfg() const;
  BurnedAmount getTotalBurnedXfgAtHeight(DepositHeight height) const;
  void addTotalBurn(BurnedAmount amount, DepositHeight height);

  // Permanent burn: SWF XFG permanently retired from total supply when
  // converted to HEAT (SWF->HEAT on demand). Removed from circulating
  // immediately at burn, but removed from total supply only at conversion.
  // Not used in baseReward — baseReward uses ethereal only.
  BurnedAmount getPermanentlyBurnedXfg() const;
  BurnedAmount getPermanentlyBurnedXfgAtHeight(DepositHeight height) const;
  void addPermanentBurn(BurnedAmount amount, DepositHeight height);

  // Combined statistics
  struct DepositStats {
    uint64_t totalDeposits;
    uint64_t ethereal_xfg;
    uint64_t regularDeposits;  // totalDeposits - ethereal_xfg
  };

  DepositStats getStats() const;

  // True when burn tallies were zeroed during deserialization due to a
  // missing or corrupt tally section. The node must complete a burn rescan
  // before accepting new blocks; check with needsRescan().
  bool needsRescan() const { return m_rescanRequired; }
  void clearRescanFlag() { m_rescanRequired = false; }

private:
  struct BankingIndexEntry {
    DepositHeight height;
    DepositAmount amount;
    DepositInterest interest;

    void serialize(ISerializer& s);
  };

  // Integrated burned XFG tracking
  struct BurnedXfgEntry {
    DepositHeight height;
    BurnedAmount amount;
    BurnedAmount cumulative_burned;

    void serialize(ISerializer& s);
  };

  using IndexType = std::vector<BankingIndexEntry>;
  IndexType::const_iterator upperBound(DepositHeight height) const;
  IndexType index;
  DepositHeight blockCount;

  // Integrated burned XFG tracking
  std::vector<BurnedXfgEntry> m_burnedXfgEntries;
  BurnedAmount m_ethereal_xfg;
  std::vector<BurnedXfgEntry> m_totalBurnedEntries;
  BurnedAmount m_total_burned_xfg;
  std::vector<BurnedXfgEntry> m_permanentBurnedEntries;
  BurnedAmount m_permanently_burned_xfg;
  bool m_rescanRequired = false;
};
}
