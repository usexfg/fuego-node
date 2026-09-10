// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2018-2019 Conceal Network & Conceal Devs
// Copyright (c) 2016-2019 The Karbowanec developers
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

#include "Currency.h"
#include "Common/Int128.h"
#include <cctype>
#include <numeric>
#include <boost/algorithm/string/trim.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/lexical_cast.hpp>
#include "../Common/Base58.h"
#include "../Common/int-util.h"
#include "../Common/StringTools.h"
#include "../CryptoNoteConfig.h"
#include "Account.h"
#include "CryptoNoteBasicImpl.h"
#include "CryptoNoteFormatUtils.h"
#include "CryptoNoteTools.h"
#include "TransactionExtra.h"
#include "UpgradeDetector.h"
#include "CommitmentIndex.h"
#include "../crypto/hash.h"
#include "../crypto/keccak.h"
#include <algorithm>


#undef ERROR

using namespace Logging;
using namespace Common;

namespace CryptoNote
{

  const std::vector<uint64_t> Currency::PRETTY_AMOUNTS = {
      1, 2, 3, 4, 5, 6, 7, 8, 9,
      10, 20, 30, 40, 50, 60, 70, 80, 90,
      100, 200, 300, 400, 500, 600, 700, 800, 900,
      1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000,
      10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000,
      100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000,
      1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000, 9000000,
      10000000, 20000000, 30000000, 40000000, 50000000, 60000000, 70000000, 80000000, 90000000,
      100000000, 200000000, 300000000, 400000000, 500000000, 600000000, 700000000, 800000000, 900000000,
      1000000000, 2000000000, 3000000000, 4000000000, 5000000000, 6000000000, 7000000000, 8000000000, 9000000000,
      10000000000, 20000000000, 30000000000, 40000000000, 50000000000, 60000000000, 70000000000, 80000000000, 90000000000,
      100000000000, 200000000000, 300000000000, 400000000000, 500000000000, 600000000000, 700000000000, 800000000000, 900000000000,
      1000000000000, 2000000000000, 3000000000000, 4000000000000, 5000000000000, 6000000000000, 7000000000000, 8000000000000, 9000000000000,
      10000000000000, 20000000000000, 30000000000000, 40000000000000, 50000000000000, 60000000000000, 70000000000000, 80000000000000, 90000000000000,
      100000000000000, 200000000000000, 300000000000000, 400000000000000, 500000000000000, 600000000000000, 700000000000000, 800000000000000, 900000000000000,
      1000000000000000, 2000000000000000, 3000000000000000, 4000000000000000, 5000000000000000, 6000000000000000, 7000000000000000, 8000000000000000, 9000000000000000,
      10000000000000000, 20000000000000000, 30000000000000000, 40000000000000000, 50000000000000000, 60000000000000000, 70000000000000000, 80000000000000000, 90000000000000000,
      100000000000000000, 200000000000000000, 300000000000000000, 400000000000000000, 500000000000000000, 600000000000000000, 700000000000000000, 800000000000000000, 900000000000000000,
      1000000000000000000, 2000000000000000000, 3000000000000000000, 4000000000000000000, 5000000000000000000, 6000000000000000000, 7000000000000000000, 8000000000000000000, 9000000000000000000,
      10000000000000000000ull};

     bool Currency::init() {
    if (!generateGenesisBlock())
    {
      logger(ERROR, BRIGHT_RED) << "Failed to generate genesis block";
      return false;
    }

    if (!get_block_hash(m_genesisBlock, m_genesisBlockHash))
    {
      logger(ERROR, BRIGHT_RED) << "Failed to get genesis block hash";
      return false;
    }

		if (isTestnet()) {
			m_upgradeHeightV2 = 2;
			m_upgradeHeightV3 = 3;
			m_upgradeHeightV4 = 4;
			m_upgradeHeightV5 = 5;
			m_upgradeHeightV6 = 6;
			m_upgradeHeightV7 = 17;
			m_upgradeHeightV8 = 18;
		m_upgradeHeightV9 = 19;
		m_upgradeHeightV10 = 25;
		m_upgradeHeightV11 = 30;
		m_upgradeHeightV12 = 180;
		m_bootstrapBlocks = TESTNET_BOOTSTRAP_BLOCKS;
		m_difficultyTarget = 10;  // 10-second target for testnet (fast mining)

      m_blocksFileName = "testnet_" + m_blocksFileName;
      m_blocksCacheFileName = "testnet_" + m_blocksCacheFileName;
      m_blockIndexesFileName = "testnet_" + m_blockIndexesFileName;
      m_txPoolFileName = "testnet_" + m_txPoolFileName;
      m_blockchinIndicesFileName = "testnet_" + m_blockchinIndicesFileName;
    }

    return true;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::generateGenesisBlock()
  {
    m_genesisBlock = boost::value_initialized<Block>();

    // Hard code coinbase tx in genesis block, because "tru" generating tx use random, but genesis should be always the same
    std::string genesisCoinbaseTxHex = m_testnet ? GENESIS_COINBASE_TX_HEX_TESTNET : GENESIS_COINBASE_TX_HEX;
    BinaryArray minerTxBlob;

    bool r =
        fromHex(genesisCoinbaseTxHex, minerTxBlob) &&
        fromBinaryArray(m_genesisBlock.baseTransaction, minerTxBlob);

    if (!r)
    {
      logger(ERROR, BRIGHT_RED) << "failed to parse coinbase tx from hard coded blob";
      return false;
    }

    m_genesisBlock.majorVersion = BLOCK_MAJOR_VERSION_1;
    m_genesisBlock.minorVersion = BLOCK_MINOR_VERSION_0;
    m_genesisBlock.timestamp = 0;
    m_genesisBlock.nonce = 70;
    if (m_testnet)
    {
      m_genesisBlock.nonce = 80;
    }

    //miner::find_nonce_for_given_block(bl, 1, 0);
    return true;
  }

	size_t Currency::blockGrantedFullRewardZoneByBlockVersion(uint8_t blockMajorVersion) const {
		if (blockMajorVersion >= BLOCK_MAJOR_VERSION_3) {
			return m_blockGrantedFullRewardZone;
		}
		else if (blockMajorVersion == BLOCK_MAJOR_VERSION_2) {
			return CryptoNote::parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
		}
		else {
			return CryptoNote::parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
		}
	}

	uint32_t Currency::upgradeHeight(uint8_t majorVersion) const {
		if (majorVersion == BLOCK_MAJOR_VERSION_2) {
			return m_upgradeHeightV2;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_3) {
			return m_upgradeHeightV3;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_4) {
			return m_upgradeHeightV4;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_5) {
			return m_upgradeHeightV5;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_6) {
			return m_upgradeHeightV6;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_7) {
			return m_upgradeHeightV7;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_8) {
			return m_upgradeHeightV8;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_9) {
			return m_upgradeHeightV9;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_10) {
			return m_upgradeHeightV10;
		}  // upgradekit
		else if (majorVersion == BLOCK_MAJOR_VERSION_11) {
			return m_upgradeHeightV11;
		}  // HearthAMM+HEAT
		else if (majorVersion == BLOCK_MAJOR_VERSION_12) {
			return m_upgradeHeightV12;
		}  // CDs + unified outputs
		else {
			return static_cast<uint32_t>(-1);
		}
	}

	uint8_t Currency::blockMajorVersionAtHeight(uint32_t height) const {
		// Check from highest version to lowest
		if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_12)) {
			return BLOCK_MAJOR_VERSION_12;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_11)) {
			return BLOCK_MAJOR_VERSION_11;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_10)) {
			return BLOCK_MAJOR_VERSION_10;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_9)) {
			return BLOCK_MAJOR_VERSION_9;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_8)) {
			return BLOCK_MAJOR_VERSION_8;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_7)) {
			return BLOCK_MAJOR_VERSION_7;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_6)) {
			return BLOCK_MAJOR_VERSION_6;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_5)) {
			return BLOCK_MAJOR_VERSION_5;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_4)) {
			return BLOCK_MAJOR_VERSION_4;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_3)) {
			return BLOCK_MAJOR_VERSION_3;
		}
		else if (height >= upgradeHeight(BLOCK_MAJOR_VERSION_2)) {
			return BLOCK_MAJOR_VERSION_2;
		}
		else {
			return BLOCK_MAJOR_VERSION_1;
		}
	}

	uint64_t Currency::minimumFee(uint8_t blockMajorVersion) const {
		if (blockMajorVersion >= BLOCK_MAJOR_VERSION_10) {
			return parameters::MINIMUM_FEE_8KH;  // 0.0008 XFG for BMV10 and above
		} else if (blockMajorVersion >= BLOCK_MAJOR_VERSION_8) {
			return parameters::MINIMUM_FEE_V2;   // 0.008 XFG for BMV8 and above
		} else if (blockMajorVersion <= BLOCK_MAJOR_VERSION_7) {
			return parameters::MINIMUM_FEE_V1;   // 0.08 XFG for BMV7 and below
		} else {
			return m_minimumFee;  // Use the default minimum fee for edge cases
		}
	}

void Currency::syncEternalFlame(uint64_t authoritativeTotal) {
  m_ethereal_xfg = std::min(authoritativeTotal, m_moneySupply);
}
double Currency::getBurnPercentage() const {
  if (m_moneySupply == 0) {
    return 0.0;
  }
  return static_cast<double>(m_ethereal_xfg) / static_cast<double>(m_moneySupply) * 100.0;
}

	bool Currency::getBlockReward(uint8_t blockMajorVersion, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins,
		uint64_t fee, uint32_t height, uint64_t& reward, int64_t& emissionChange, uint64_t burnedCoinsOverride) const {
		unsigned int selectedEmissionSpeedFactor = emissionSpeedFactor(blockMajorVersion);

    assert(selectedEmissionSpeedFactor > 0 && selectedEmissionSpeedFactor <= 8 * sizeof(uint64_t));

    // Only use burn-adjusted reward formula for v10+ blocks (when burns were introduced)
    // burnedCoinsOverride: when != UINT64_MAX, use deterministic height-indexed value
    //                      instead of live mutable getEternalFlame()
    uint64_t baseReward;
    uint64_t eternalFlame = (burnedCoinsOverride != UINT64_MAX) ? burnedCoinsOverride : getEternalFlame();
    if (blockMajorVersion >= BLOCK_MAJOR_VERSION_10 && eternalFlame > 0) {
        // Osavvirsak = coins in circulation (minted minus burned)
        // This makes burned coins available for re-emission
        uint64_t Osavvirsak = (alreadyGeneratedCoins > eternalFlame) ?
                              (alreadyGeneratedCoins - eternalFlame) : 0;
        assert(Osavvirsak <= m_moneySupply);
        baseReward = (m_moneySupply - Osavvirsak) >> selectedEmissionSpeedFactor;
    } else {
        assert(alreadyGeneratedCoins <= m_moneySupply);
        baseReward = (m_moneySupply - alreadyGeneratedCoins) >> selectedEmissionSpeedFactor;
    }

    size_t blockGrantedFullRewardZone = blockGrantedFullRewardZoneByBlockVersion(blockMajorVersion);
    medianSize = std::max(medianSize, blockGrantedFullRewardZone);

    if (currentBlockSize > UINT64_C(2) * medianSize) {
      logger(DEBUGGING) << "Block cumulative size is too big: " << currentBlockSize << ", expected less than " << 2 * medianSize;
      return false;
    }

		uint64_t penalizedBaseReward = getPenalizedAmount(baseReward, medianSize, currentBlockSize, blockMajorVersion);
		uint64_t penalizedFee = blockMajorVersion >= BLOCK_MAJOR_VERSION_2 ? getPenalizedAmount(fee, medianSize, currentBlockSize, blockMajorVersion) : fee;
		if (cryptonoteCoinVersion() == 1) {
			penalizedFee = getPenalizedAmount(fee, medianSize, currentBlockSize, blockMajorVersion);
		}

    emissionChange = penalizedBaseReward - (fee - penalizedFee);
    reward = penalizedBaseReward + penalizedFee;

    return true;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  uint64_t Currency::calculateInterest(uint64_t amount, uint32_t term, uint32_t height) const
  {
    uint64_t a = static_cast<uint64_t>(term) * m_depositMaxTotalRate - m_depositMinTotalRateFactor;
    uint64_t bHi;
    uint64_t bLo = mul128(amount, a, &bHi);
    uint64_t cHi;
    uint64_t cLo;
    uint64_t offchaininterest = 0;
    assert(std::numeric_limits<uint32_t>::max() / 100 > m_depositMaxTerm);
    div128_32(bHi, bLo, static_cast<uint32_t>(100 * m_depositMaxTerm), &cHi, &cLo);
    assert(cHi == 0);

    // early deposit multiplier
    uint64_t interestHi;
    uint64_t interestLo;
    if (height <= CryptoNote::parameters::END_MULTIPLIER_BLOCK)
    {
      interestLo = mul128(cLo, CryptoNote::parameters::MULTIPLIER_FACTOR, &interestHi);
      assert(interestHi == 0);
    }
    else
    {
      interestHi = cHi;
      interestLo = cLo;
    }
    return offchaininterest;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  uint64_t Currency::loyaltyTierWeightPct(uint32_t term) const {
    const uint64_t epochDuration = m_testnet
        ? parameters::TESTNET_EPOCH_DURATION_BLOCKS
        : parameters::EPOCH_DURATION_BLOCKS;
    const uint32_t maxTerm = m_testnet
        ? parameters::TESTNET_DEPOSIT_MAX_TERM
        : parameters::DEPOSIT_MAX_TERM;
    if (term == maxTerm) {
      return parameters::LOYALTY_BONUS_72_EPOCHS_PCT;  // 72 epochs: 2.5×
    } else if (term == 36 * epochDuration) {
      return parameters::LOYALTY_BONUS_36_EPOCHS_PCT;  // 36 epochs: 2.0×
    } else if (term == 18 * epochDuration) {
      return parameters::LOYALTY_BONUS_18_EPOCHS_PCT;  // 18 epochs: 1.5×
    } else if (term == 6 * epochDuration) {
      return parameters::LOYALTY_BONUS_6_EPOCHS_PCT;   // 6 epochs: 1.25×
    }
    return 100;  // rolling / no tier bonus
  }

  uint64_t Currency::calculateCdBonus(uint64_t amount, uint32_t creationHeight,
                                       uint32_t currentHeight,
                                       const CommitmentIndex& commitmentIndex,
                                       uint32_t term) const {
    if (currentHeight <= creationHeight) return 0;

    uint64_t epochDuration = m_testnet
        ? parameters::TESTNET_EPOCH_DURATION_BLOCKS
        : parameters::EPOCH_DURATION_BLOCKS;
    uint64_t startEpoch = creationHeight / epochDuration;
    uint64_t endEpoch = currentHeight / epochDuration;
    if (term > 0) {
      uint64_t expiryEpoch = (creationHeight + term) / epochDuration;
      if (expiryEpoch < endEpoch) endEpoch = expiryEpoch;
    }
    uint64_t epochCount = commitmentIndex.getEpochCount();

    uint64_t weight = loyaltyTierWeightPct(term);
    uint64_t bonus = 0;
    for (uint64_t e = startEpoch; e <= endEpoch && e < epochCount; ++e) {
      BonusEpochRateEntry entry = commitmentIndex.getBonusEpochRateEntry(e);
      if (entry.bonusHeat == 0 || entry.weightedBase == 0) continue;
      // share = bonusHeat × (principal × weight/100) / weightedBase, where
      // weightedBase = Σ (principal_j × weight_j/100) over the rolling window —
      // realized BV inflow distributed pro-rata by tier weight (no overpromise).
      uint64_t share = static_cast<uint64_t>(
          (((uint128_t)amount * weight) / 100 * entry.bonusHeat) / entry.weightedBase);
      if (bonus > UINT64_MAX - share) return UINT64_MAX;
      bonus += share;
    }
    return bonus;
  }

/* ---------------------------------------------------------------------------------------------------- */

  uint64_t Currency::calculateCdInterest(uint64_t amount, uint32_t creationHeight,
                                          uint32_t currentHeight,
                                          const CommitmentIndex& commitmentIndex,
                                          bool isLegacyBond, uint32_t term,
                                          bool autoRolled) const {
    if (currentHeight <= creationHeight) return 0;

    uint64_t epochDuration = m_testnet
        ? parameters::TESTNET_EPOCH_DURATION_BLOCKS
        : parameters::EPOCH_DURATION_BLOCKS;
    uint64_t startEpoch = creationHeight / epochDuration;
    uint64_t endEpoch = currentHeight / epochDuration;
    uint64_t epochCount = commitmentIndex.getEpochCount();

    // Auto-roll boundary: compound point (only for auto-rolled CDs)
    uint64_t rolloverEpoch = autoRolled
        ? (creationHeight + term) / epochDuration
        : endEpoch;

    uint64_t baseInterest = 0;
    uint64_t currentBase = amount;

    for (uint64_t e = startEpoch; e <= endEpoch && e < epochCount; ++e) {
      uint64_t epochRate = isLegacyBond
          ? commitmentIndex.getLegacyEpochFeeRate(e)
          : commitmentIndex.getEpochFeeRate(e);
      uint64_t epochInterest = (uint64_t)(((uint128_t)currentBase * epochRate)
                                          / parameters::FEE_POOL_RATE_PRECISION);
      baseInterest += epochInterest;

      // Compound for next epoch (only up to rollover for auto-rolled CDs)
      if (e < rolloverEpoch) {
        currentBase += epochInterest;
      }
    }

return baseInterest;
  }

/* ---------------------------------------------------------------------------------------------------- */

  uint64_t Currency::calculateTotalTransactionInterest(const Transaction &tx, uint32_t height) const
  {
    uint64_t interest = 0;
    for (const TransactionInput &input : tx.inputs)
    {
      if (input.type() == typeid(MultisignatureInput))
      {
        const MultisignatureInput &multisignatureInput = boost::get<MultisignatureInput>(input);
        if (multisignatureInput.term != 0)
        {
          interest += calculateInterest(multisignatureInput.amount, multisignatureInput.term, height);
        }
      }
    }

    return interest;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  uint64_t Currency::getTransactionInputAmount(const TransactionInput &in, uint32_t height) const
  {
    if (in.type() == typeid(KeyInput))
    {
      return boost::get<KeyInput>(in).amount;
    }
    else if (in.type() == typeid(MultisignatureInput))
    {
      const MultisignatureInput &multisignatureInput = boost::get<MultisignatureInput>(in);
      if (multisignatureInput.term == 0)
      {
        return multisignatureInput.amount;
      }
      else
      {
        uint64_t interest = calculateInterest(multisignatureInput.amount, multisignatureInput.term, height);
        if (std::numeric_limits<uint64_t>::max() - multisignatureInput.amount < interest) {
          logger(ERROR, BRIGHT_RED) << "MultisignatureInput amount + interest overflow";
          return 0; // Or throw, but 0 makes validation fail
        }
        return multisignatureInput.amount + interest;
      }
    }
      else if (in.type() == typeid(TransactionInputCommitmentSpend))
    {
      const auto& spend = boost::get<TransactionInputCommitmentSpend>(in);
      if (std::numeric_limits<uint64_t>::max() - spend.amount < spend.claimedInterest) {
        logger(ERROR, BRIGHT_RED) << "CommitmentSpend amount + interest overflow";
        return 0;
      }
      return spend.amount + spend.claimedInterest;
    }
    else if (in.type() == typeid(TransactionInputCommitmentTransfer))
    {
      return boost::get<TransactionInputCommitmentTransfer>(in).amount;
    }
    else if (in.type() == typeid(BaseInput))
    {
      return 0;
    }
    else
    {
      assert(false);
      return 0;
    }
  }

  /* ---------------------------------------------------------------------------------------------------- */

  uint64_t Currency::getTransactionAllInputsAmount(const Transaction &tx, uint32_t height) const
  {
    uint64_t amount = 0;
    for (const auto &in : tx.inputs)
    {
      amount += getTransactionInputAmount(in, height);
    }

    return amount;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::sumCommitmentClaimedInterest(const Transaction &tx, uint64_t &total) const
  {
    total = 0;
    for (const auto &in : tx.inputs)
    {
      if (in.type() == typeid(TransactionInputCommitmentSpend))
      {
        uint64_t ci = boost::get<TransactionInputCommitmentSpend>(in).claimedInterest;
        if (ci > std::numeric_limits<uint64_t>::max() - total)
        {
          return false; // aggregate overflow
        }
        total += ci;
      }
    }
    return true;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  AssetType Currency::classifyOutputAsset(const TransactionOutputTarget& target, uint32_t term) {
    if (target.type() == typeid(KeyOutput)) {
      return AssetType::XFG;
    }
    if (target.type() == typeid(MultisignatureOutput)) {
      return AssetType::XFG;
    }
    if (target.type() == typeid(TransactionOutputCommitment)) {
      if (term == parameters::HEAT_TERM)
        return AssetType::HEAT;
      if (term == parameters::DEPOSIT_TERM_LP)
        return AssetType::LP;
      if (term == parameters::DEPOSIT_TERM_POOL_XFG)
        return AssetType::XFG;
      if (term == parameters::DEPOSIT_TERM_POOL_HEAT)
        return AssetType::HEAT;
      if (term == parameters::DEPOSIT_TERM_SWAP_RECEIVE_XFG)
        return AssetType::XFG;
      return AssetType::XFG;  // CD deposits
    }
    if (target.type() == typeid(TransactionOutputUnified)) {
      auto& unified = boost::get<TransactionOutputUnified>(target);
      if (unified.term == parameters::HEAT_TERM)
        return AssetType::HEAT;
      if (unified.term == parameters::DEPOSIT_TERM_LP)
        return AssetType::LP;
      if (unified.term == parameters::DEPOSIT_TERM_POOL_XFG)
        return AssetType::XFG;
      if (unified.term == parameters::DEPOSIT_TERM_POOL_HEAT)
        return AssetType::HEAT;
      if (unified.term == parameters::DEPOSIT_TERM_SWAP_RECEIVE_XFG)
        return AssetType::XFG;
      return AssetType::XFG;  // term=0 regular or finite CD
    }
    return AssetType::XFG;
  }

  AssetBalance Currency::getTransactionOutputAssetAmounts(const Transaction& tx) const {
    AssetBalance bal;
    for (const auto& out : tx.outputs) {
      AssetType asset = AssetType::XFG;
      uint32_t term = 0;
      if (out.target.type() == typeid(TransactionOutputCommitment)) {
        const auto& co = boost::get<TransactionOutputCommitment>(out.target);
        term = co.term;
      }
      asset = classifyOutputAsset(out.target, term);
      switch (asset) {
        case AssetType::HEAT: bal.heat += out.amount; break;
        case AssetType::LP:   bal.lp   += out.amount; break;
        default:              bal.xfg  += out.amount; break;
      }
    }
    return bal;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::getTransactionFee(const Transaction &tx, uint64_t &fee, uint32_t height) const
  {
    uint64_t amount_in = 0;
    uint64_t amount_out = 0;

    //if (tx.inputs.size() == 0)// || tx.outputs.size() == 0) //0 outputs needed in TestGenerator::constructBlock
    //	  return false;

    for (const auto &in : tx.inputs)
    {
      amount_in += getTransactionInputAmount(in, height);
    }

    for (const auto &o : tx.outputs)
    {
      amount_out += o.amount;
    }

    if (amount_out > amount_in)
    {
      // interest shows up in the output of the W/D transactions and W/Ds always have min fee
      // Use versioned minimum fee based on block height
      uint8_t blockVersion = blockMajorVersionAtHeight(height);
      uint64_t versionedMinFee = minimumFee(blockVersion);
      if (tx.inputs.size() > 0 && tx.outputs.size() > 0 && amount_out > amount_in + versionedMinFee)
      {
        fee = versionedMinFee;
        logger(INFO) << "TRIGGERED: Currency.cpp getTransactionFee with versioned fee: " << versionedMinFee;
      }
      else
      {
        return false;
      }
    }
    else
    {
      fee = amount_in - amount_out;
    }

    return true;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  uint64_t Currency::getTransactionFee(const Transaction &tx, uint32_t height) const
  {
    uint64_t r = 0;
    if (!getTransactionFee(tx, r, height))
    {
      r = 0;
    }

    return r;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  size_t Currency::maxBlockCumulativeSize(uint64_t height) const
  {
    assert(height <= std::numeric_limits<uint64_t>::max() / m_maxBlockSizeGrowthSpeedNumerator);
    size_t maxSize = static_cast<size_t>(m_maxBlockSizeInitial +
                                         (height * m_maxBlockSizeGrowthSpeedNumerator) / m_maxBlockSizeGrowthSpeedDenominator);

    assert(maxSize >= m_maxBlockSizeInitial);
    return maxSize;
  }

	bool Currency::constructMinerTx(uint8_t blockMajorVersion, uint32_t height, size_t medianSize, uint64_t alreadyGeneratedCoins, size_t currentBlockSize,
		uint64_t fee, const AccountPublicAddress& minerAddress, Transaction& tx, const BinaryArray& extraNonce/* = BinaryArray()*/, size_t maxOuts/* = 1*/, uint64_t burnedCoinsOverride/* = UINT64_MAX*/,
		uint64_t bankingFeesInBlock/* = 0*/) const {

		tx.inputs.clear();
		tx.outputs.clear();
		tx.extra.clear();

    KeyPair txkey = generateKeyPair();
    addTransactionPublicKeyToExtra(tx.extra, txkey.publicKey);
    if (!extraNonce.empty())
    {
      if (!addExtraNonceToTransactionExtra(tx.extra, extraNonce))
      {
        return false;
      }
    }

    BaseInput in;
    in.blockIndex = height;

    uint64_t blockReward;
    int64_t emissionChange;
    if (!getBlockReward(blockMajorVersion, medianSize, currentBlockSize, alreadyGeneratedCoins, fee, height, blockReward, emissionChange, burnedCoinsOverride))
    {
      logger(INFO) << "Block is too big";
      return false;
    }

    uint64_t minerReward = blockReward;

    // Decompose miner reward into outputs
    std::vector<uint64_t> outAmounts;
    if (blockMajorVersion >= BLOCK_MAJOR_VERSION_11) {
      // V11+: Uniform denomination decomposition for coinbase privacy.
      // Produces multiple outputs at standard power-of-10 tiers so all coinbase
      // outputs are indistinguishable across blocks regardless of reward amount.
      decompose_amount_uniform(minerReward, m_defaultDustThreshold, outAmounts);
    } else {
      decompose_amount_into_digits(
          minerReward, m_defaultDustThreshold,
          [&outAmounts](uint64_t a_chunk) { outAmounts.push_back(a_chunk); },
          [&outAmounts](uint64_t a_dust) { outAmounts.push_back(a_dust); });
    }

    if (!(1 <= maxOuts))
    {
      logger(ERROR, BRIGHT_RED) << "max_out must be non-zero";
      return false;
    }

    while (maxOuts < outAmounts.size())
    {
      outAmounts[outAmounts.size() - 2] += outAmounts.back();
      outAmounts.resize(outAmounts.size() - 1);
    }

    uint64_t summaryAmounts = 0;
    size_t outputIndex = 0;
    for (size_t no = 0; no < outAmounts.size(); no++)
    {
      Crypto::KeyDerivation derivation = boost::value_initialized<Crypto::KeyDerivation>();
      Crypto::PublicKey outEphemeralPubKey = boost::value_initialized<Crypto::PublicKey>();

      bool r = Crypto::generate_key_derivation(minerAddress.viewPublicKey, txkey.secretKey, derivation);

      if (!(r))
      {
        logger(ERROR, BRIGHT_RED)
            << "while creating outs: failed to generate_key_derivation("
            << minerAddress.viewPublicKey << ", <secret_key>)";

        return false;
      }

      r = Crypto::derive_public_key(derivation, outputIndex, minerAddress.spendPublicKey, outEphemeralPubKey);

      if (!(r))
      {
        logger(ERROR, BRIGHT_RED)
            << "while creating outs: failed to derive_public_key("
            << derivation << ", " << outputIndex << ", "
            << minerAddress.spendPublicKey << ")";

        return false;
      }

      KeyOutput tk;
      tk.key = outEphemeralPubKey;

      TransactionOutput out;
      summaryAmounts += out.amount = outAmounts[no];
      out.target = tk;
      tx.outputs.push_back(out);
      outputIndex++;
    }

    // Validate: miner outputs sum to the miner reward.
    if (summaryAmounts != minerReward)
    {
      logger(ERROR, BRIGHT_RED) << "Failed to construct miner tx, summaryAmounts = " << summaryAmounts
        << " not equal expected = " << minerReward;
      return false;
    }

    tx.version = TRANSACTION_VERSION_1;
    // lock
    tx.unlockTime = height + m_minedMoneyUnlockWindow;
    tx.inputs.push_back(in);
    return true;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::isFusionTransaction(const std::vector<uint64_t> &inputsAmounts, const std::vector<uint64_t> &outputsAmounts, size_t size) const
  {
    if (size > fusionTxMaxSize())
    {
      return false;
    }

    if (inputsAmounts.size() < fusionTxMinInputCount())
    {
      return false;
    }

    if (inputsAmounts.size() < outputsAmounts.size() * fusionTxMinInOutCountRatio())
    {
      return false;
    }

    uint64_t inputAmount = 0;
    for (auto amount : inputsAmounts)
    {
      if (amount < defaultDustThreshold())
      {
        return false;
      }

      inputAmount += amount;
    }

    std::vector<uint64_t> expectedOutputsAmounts;
    expectedOutputsAmounts.reserve(outputsAmounts.size());
    decomposeAmount(inputAmount, defaultDustThreshold(), expectedOutputsAmounts);
    std::sort(expectedOutputsAmounts.begin(), expectedOutputsAmounts.end());

    return expectedOutputsAmounts == outputsAmounts;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::isFusionTransaction(const Transaction &transaction, size_t size) const
  {
    assert(getObjectBinarySize(transaction) == size);

    std::vector<uint64_t> outputsAmounts;
    outputsAmounts.reserve(transaction.outputs.size());
    for (const TransactionOutput &output : transaction.outputs)
    {
      outputsAmounts.push_back(output.amount);
    }

    return isFusionTransaction(getInputsAmounts(transaction), outputsAmounts, size);
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::isFusionTransaction(const Transaction &transaction) const
  {
    return isFusionTransaction(transaction, getObjectBinarySize(transaction));
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::isAmountApplicableInFusionTransactionInput(uint64_t amount, uint64_t threshold, uint32_t height) const
  {
    uint8_t ignore;
    return isAmountApplicableInFusionTransactionInput(amount, threshold, ignore, height);
  }

  bool Currency::isAmountApplicableInFusionTransactionInput(uint64_t amount, uint64_t threshold, uint8_t &amountPowerOfTen, uint32_t height) const
  {
    if (amount >= threshold)
    {
      return false;
    }

    if (height < CryptoNote::parameters::UPGRADE_HEIGHT_V4 && amount < defaultDustThreshold())
    {
      return false;
    } /* why upgrade condition ?? */

    auto it = std::lower_bound(PRETTY_AMOUNTS.begin(), PRETTY_AMOUNTS.end(), amount);
    if (it == PRETTY_AMOUNTS.end() || amount != *it)
    {
      return false;
    }

    amountPowerOfTen = static_cast<uint8_t>(std::distance(PRETTY_AMOUNTS.begin(), it) / 9);
    return true;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  std::string Currency::accountAddressAsString(const AccountBase &account) const
  {
    return getAccountAddressAsStr(m_publicAddressBase58Prefix, account.getAccountKeys().address);
  }

  /* ---------------------------------------------------------------------------------------------------- */

  std::string Currency::accountAddressAsString(const AccountPublicAddress &accountPublicAddress) const
  {
    return getAccountAddressAsStr(m_publicAddressBase58Prefix, accountPublicAddress);
  }

  std::string Currency::subAddressAsString(const AccountPublicAddress &subAddressPublicAddress) const
  {
    return getAccountAddressAsStr(m_subAddressBase58Prefix, subAddressPublicAddress);
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::parseAccountAddressString(const std::string &str, AccountPublicAddress &addr) const
  {
    uint64_t prefix;
    if (!CryptoNote::parseAccountAddressString(prefix, addr, str))
    {
      return false;
    }

    if (prefix != m_publicAddressBase58Prefix && prefix != m_subAddressBase58Prefix)
    {
      logger(DEBUGGING) << "Wrong address prefix: " << prefix
                        << ", expected " << m_publicAddressBase58Prefix
                        << " or " << m_subAddressBase58Prefix;
      return false;
    }

    return true;
  }

  bool Currency::isSubAddressStr(const std::string& str) const
  {
    return CryptoNote::isSubAddressStr(str, m_subAddressBase58Prefix);
  }

  /* ---------------------------------------------------------------------------------------------------- */

  std::string Currency::formatAmount(uint64_t amount) const
  {
    std::string s = std::to_string(amount);
    if (s.size() < m_numberOfDecimalPlaces + 1)
    {
      s.insert(0, m_numberOfDecimalPlaces + 1 - s.size(), '0');
    }

    s.insert(s.size() - m_numberOfDecimalPlaces, ".");
    return s;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  std::string Currency::formatAmount(int64_t amount) const
  {
    std::string s = formatAmount(static_cast<uint64_t>(std::abs(amount)));

    if (amount < 0)
    {
      s.insert(0, "-");
    }

    return s;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  std::string Currency::toEuroDisplay(uint64_t usdCents) const
  {
    // EUR/CPI display mode removed — HEAT is now hard-pegged at $1.58 USD.
    // All display is in USD cents.
    return formatAmount(usdCents);
  }

  /* ---------------------------------------------------------------------------------------------------- */

  bool Currency::parseAmount(const std::string &str, uint64_t &amount) const
  {
    std::string strAmount = str;
    boost::algorithm::trim(strAmount);

    size_t pointIndex = strAmount.find_first_of('.');
    size_t fractionSize;

    if (std::string::npos != pointIndex)
    {
      fractionSize = strAmount.size() - pointIndex - 1;
      while (m_numberOfDecimalPlaces < fractionSize && '0' == strAmount.back())
      {
        strAmount.erase(strAmount.size() - 1, 1);
        --fractionSize;
      }

      if (m_numberOfDecimalPlaces < fractionSize)
      {
        return false;
      }

      strAmount.erase(pointIndex, 1);
    }
    else
    {
      fractionSize = 0;
    }

    if (strAmount.empty())
    {
      return false;
    }

    if (!std::all_of(strAmount.begin(), strAmount.end(), ::isdigit))
    {
      return false;
    }

    if (fractionSize < m_numberOfDecimalPlaces)
    {
      strAmount.append(m_numberOfDecimalPlaces - fractionSize, '0');
    }

    return Common::fromString(strAmount, amount);
  }

	difficulty_type Currency::nextDifficulty(uint32_t height, uint8_t blockMajorVersion, std::vector<uint64_t> timestamps,
		// upgradekit
	    std::vector<difficulty_type> cumulativeDifficulties) const {
			if (blockMajorVersion >= BLOCK_MAJOR_VERSION_10) {
			return nextDifficultyV6(height, blockMajorVersion, timestamps, cumulativeDifficulties);
		}
		else if (blockMajorVersion >= BLOCK_MAJOR_VERSION_7) {
			return nextDifficultyV5(height, blockMajorVersion, timestamps, cumulativeDifficulties);
		}
		else if (blockMajorVersion >= BLOCK_MAJOR_VERSION_4) {
			return nextDifficultyV4(height, blockMajorVersion, timestamps, cumulativeDifficulties);
		}
		else if (blockMajorVersion >= BLOCK_MAJOR_VERSION_3) {
			return nextDifficultyV3(timestamps, cumulativeDifficulties);
		}
		else if (blockMajorVersion == BLOCK_MAJOR_VERSION_2) {
			return nextDifficultyV2(timestamps, cumulativeDifficulties);
		}
		else {
			return nextDifficultyV1(timestamps, cumulativeDifficulties);
		}
	}


	difficulty_type Currency::nextDifficultyV1(std::vector<uint64_t> timestamps,
				std::vector<difficulty_type> cumulativeDifficulties) const {
		assert(m_difficultyWindow >= 2);

    if (timestamps.size() > m_difficultyWindow)
    {
      timestamps.resize(m_difficultyWindow);
      cumulativeDifficulties.resize(m_difficultyWindow);
    }

    size_t length = timestamps.size();
    assert(length == cumulativeDifficulties.size());
    assert(length <= m_difficultyWindow);
    if (length <= 1)
    {
      return 1;
    }

    sort(timestamps.begin(), timestamps.end());

    size_t cutBegin, cutEnd;
    assert(2 * m_difficultyCut <= m_difficultyWindow - 2);
    if (length <= m_difficultyWindow - 2 * m_difficultyCut)
    {
      cutBegin = 0;
      cutEnd = length;
    }
    else
    {
      cutBegin = (length - (m_difficultyWindow - 2 * m_difficultyCut) + 1) / 2;
      cutEnd = cutBegin + (m_difficultyWindow - 2 * m_difficultyCut);
    }

    assert(/*cut_begin >= 0 &&*/ cutBegin + 2 <= cutEnd && cutEnd <= length);
    uint64_t timeSpan = timestamps[cutEnd - 1] - timestamps[cutBegin];
    if (timeSpan == 0)
    {
      timeSpan = 1;
    }

    difficulty_type totalWork = cumulativeDifficulties[cutEnd - 1] - cumulativeDifficulties[cutBegin];
    assert(totalWork > 0);

    uint64_t low, high;
    low = mul128(totalWork, m_difficultyTarget_DRGL, &high);
    if (high != 0 || low + timeSpan - 1 < low)
    {
      return 0;
    }

    return (low + timeSpan - 1) / timeSpan;
  }

	difficulty_type Currency::nextDifficultyV2(std::vector<uint64_t> timestamps,
		std::vector<difficulty_type> cumulativeDifficulties) const {

		// Difficulty calculation v. 2
		// based on Zawy difficulty algorithm v1.0
		// next Diff = Avg past N Diff * TargetInterval / Avg past N solve times
		// as described at https://github.com/monero-project/research-lab/issues/3
		// Window time span and total difficulty is taken instead of average as suggested by Nuclear_chaos

		size_t m_difficultyWindow_2 = CryptoNote::parameters::DIFFICULTY_WINDOW_V2;
		assert(m_difficultyWindow_2 >= 2);

		if (timestamps.size() > m_difficultyWindow_2) {
			timestamps.resize(m_difficultyWindow_2);
			cumulativeDifficulties.resize(m_difficultyWindow_2);
		}

		size_t length = timestamps.size();
		assert(length == cumulativeDifficulties.size());
		assert(length <= m_difficultyWindow_2);
		if (length <= 1) {
			return 1;
		}

		sort(timestamps.begin(), timestamps.end());

		uint64_t timeSpan = timestamps.back() - timestamps.front();
		if (timeSpan == 0) {
			timeSpan = 1;
		}

		difficulty_type totalWork = cumulativeDifficulties.back() - cumulativeDifficulties.front();
		assert(totalWork > 0);

		// uint64_t nextDiffZ = totalWork * m_difficultyTarget / timeSpan;

		uint64_t low, high;
		low = mul128(totalWork, m_difficultyTarget_DRGL, &high);
		// blockchain error "Difficulty overhead" if this function returns zero
		if (high != 0) {
			return 0;
		}

		uint64_t nextDiffZ = low / timeSpan;

		// minimum limit
 		if (!isTestnet() && nextDiffZ < 10000) {
 			nextDiffZ = 10000;
 		}

		return nextDiffZ;
	}

	difficulty_type Currency::nextDifficultyV3(std::vector<uint64_t> timestamps,
		std::vector<difficulty_type> cumulativeDifficulties) const {

		// LWMA difficulty algorithm
		// Copyright (c) 2017-2018 Zawy
		// MIT license http://www.opensource.org/licenses/mit-license.php.
		// This is an improved version of Tom Harding's (Deger8) "WT-144"
		// Karbowanec, Masari, Bitcoin Gold, and Bitcoin Cash have contributed.
		// See https://github.com/zawy12/difficulty-algorithms/issues/1 for other algos.
		// Do not use "if solvetime < 0 then solvetime = 1" which allows a catastrophic exploit.
		// T= target_solvetime;
		// N = int(45 * (600 / T) ^ 0.3));

		const int64_t T = static_cast<int64_t>(m_difficultyTarget_DRGL);
		size_t N = CryptoNote::parameters::DIFFICULTY_WINDOW_V3;

		// return a difficulty of 1 for first 3 blocks if it's the start of the chain
		if (timestamps.size() < 4) {
			return 1;
		}
		// otherwise, use a smaller N if the start of the chain is less than N+1
		else if (timestamps.size() < N + 1) {
			N = timestamps.size() - 1;
		}
		else if (timestamps.size() > N + 1) {
			timestamps.resize(N + 1);
			cumulativeDifficulties.resize(N + 1);
		}

		// To get an average solvetime to within +/- ~0.1%, use an adjustment factor.
		const double adjust = 0.998;
		// The divisor k normalizes LWMA.
		const double k = N * (N + 1) / 2;

		double LWMA(0), sum_inverse_D(0), harmonic_mean_D(0), nextDifficulty(0);
		int64_t solveTime(0);
		uint64_t difficulty(0), next_difficulty(0);

		// Loop through N most recent blocks.
		for (size_t i = 1; i <= N; i++) {
			solveTime = static_cast<int64_t>(timestamps[i]) - static_cast<int64_t>(timestamps[i - 1]);
			solveTime = std::min<int64_t>((T * 7), std::max<int64_t>(solveTime, (-6 * T)));
			difficulty = cumulativeDifficulties[i] - cumulativeDifficulties[i - 1];
			LWMA += (int64_t)(solveTime * i) / k;
			sum_inverse_D += 1 / static_cast<double>(difficulty);
		}

		// Keep LWMA sane in case something unforeseen occurs.
		if (static_cast<int64_t>(boost::math::round(LWMA)) < T / 20)
			LWMA = static_cast<double>(T) / 20;

		harmonic_mean_D = N / sum_inverse_D * adjust;
		nextDifficulty = harmonic_mean_D * T / LWMA;
		next_difficulty = static_cast<uint64_t>(nextDifficulty);

		// minimum limit
 		if (!isTestnet() && next_difficulty < 10000) {
 			next_difficulty = 10000;
 		}

		return next_difficulty;
	}



	difficulty_type Currency::nextDifficultyV4(uint32_t height, uint8_t blockMajorVersion,
		std::vector<std::uint64_t> timestamps, std::vector<difficulty_type> cumulativeDifficulties) const {

			// LWMA-1 difficulty algorithm
			// Copyright (c) 2017-2018 Zawy, MIT License
			// https://github.com/zawy12/difficulty-algorithms/issues/3
			// See commented version for explanations & required config file changes. Fix FTL and MTP!

			   const uint64_t T = isTestnet() ? CryptoNote::parameters::DIFFICULTY_TARGET_TESTNET : CryptoNote::parameters::DIFFICULTY_TARGET_DRGL;
			   uint64_t N = CryptoNote::parameters::DIFFICULTY_WINDOW_V3; // N=60, 90, and 120 for T=600, 120, 60.
			   uint64_t  L(0), next_D, i, this_timestamp(0), previous_timestamp(0), avg_D;
			   uint32_t Dracarys = CryptoNote::parameters::UPGRADE_HEIGHT_V4;
	   		   uint64_t difficulty_plate = isTestnet() ? 1 : 10000;


			   assert(timestamps.size() == cumulativeDifficulties.size() && timestamps.size() <= static_cast<uint64_t>(N + 1));

			   // If it's a new coin, do startup code. Do not remove in case other coins copy your code.
			   // uint64_t difficulty_guess = 10000;
			   // if (timestamps.size() <= 12 ) {   return difficulty_guess;   }
			   // if ( timestamps.size()  < N +1 ) { N = timestamps.size()-1;  }
			   // If hashrate/difficulty ratio after a fork is < 1/3 prior ratio, hardcode D for N+1 blocks after fork.
			   // This will also cover up a very common type of backwards-incompatible fork.
			   // difficulty_guess = 10000; //  Dev may change.  Guess lower than anything expected.

	  		   if ( height <= Dracarys + 1 + N ) { return difficulty_plate;  }

			   previous_timestamp = timestamps[0];
			   for ( i = 1; i <= N; i++) {
			      // Safely prevent out-of-sequence timestamps
			      if ( timestamps[i]  > previous_timestamp ) {   this_timestamp = timestamps[i];  }
			      else {  this_timestamp = previous_timestamp;   }
			      L +=  i*std::min(6*T , this_timestamp - previous_timestamp);
			      previous_timestamp = this_timestamp;
			   }
			   if (L < N*N*T/20 ) { L =  N*N*T/20; }
			   avg_D = ( cumulativeDifficulties[N] - cumulativeDifficulties[0] )/ N;

			   // Prevent round off error for small D and overflow for large D.
			   if (avg_D > 2000000*N*N*T) {
			       next_D = (avg_D/(200*L))*(N*(N+1)*T*97);
			   }
			   else {    next_D = (avg_D*N*(N+1)*T*97)/(200*L);    }

			   // Optional. Make all insignificant digits zero for easy reading.
			   i = 1000000000;
			   while (i > 1) {
			     if ( next_D > i*100 ) { next_D = ((next_D+i/2)/i)*i; break; }
			     else { i /= 10; }
			   }
			   // Make least 2 digits = size of hash rate change last 11 blocks if it's statistically significant.
			   // D=2540035 => hash rate 3.5x higher than D expected. Blocks coming 3.5x too fast.
			   if ( next_D > 10000 ) {
			     uint64_t est_HR = (10*(11*T+(timestamps[N]-timestamps[N-11])/2))/(timestamps[N]-timestamps[N-11]+1);
			     if (  est_HR > 5 && est_HR < 22 )  {  est_HR=0;   }
			     est_HR = std::min(static_cast<uint64_t>(99), est_HR);
			     next_D = ((next_D+50)/100)*100 + est_HR;
			   }
	         	   // mini-lim
	   		   if (!isTestnet() && next_D < 10000) {
	  		   	next_D = 10000;

			   }

			   return  next_D;
	}

		difficulty_type Currency::nextDifficultyV5(uint32_t height, uint8_t blockMajorVersion,
		std::vector<std::uint64_t> timestamps, std::vector<difficulty_type> cumulativeDifficulties) const {

			// LWMA-1 difficulty algorithm
			// Copyright (c) 2017-2018 Zawy, MIT License
			// https://github.com/zawy12/difficulty-algorithms/issues/3
			// See commented version for explanations & required config file changes. Fix FTL and MTP!

			   const uint64_t T = isTestnet() ? CryptoNote::parameters::DIFFICULTY_TARGET_TESTNET : CryptoNote::parameters::DIFFICULTY_TARGET;
			   uint64_t N = CryptoNote::parameters::DIFFICULTY_WINDOW_V4; // N=60, 90, and 120 for T=600, 120, 60.
			   uint64_t  L(0), next_D, i, this_timestamp(0), previous_timestamp(0), avg_D;
			   uint32_t FanG = CryptoNote::parameters::UPGRADE_HEIGHT_V7;
	   		   uint64_t difficulty_plate = isTestnet() ? 1 : 100000;


			   assert(timestamps.size() == cumulativeDifficulties.size());

			   // If it's a new coin, do startup code. Do not remove in case other coins copy your code.
			   // uint64_t difficulty_guess = 10000;
			   // if (timestamps.size() <= 12 ) {   return difficulty_guess;   }
			   // if ( timestamps.size()  < N +1 ) { N = timestamps.size()-1;  }
			   // If hashrate/difficulty ratio after a fork is < 1/3 prior ratio, hardcode D for N+1 blocks after fork.
			   // This will also cover up a very common type of backwards-incompatible fork.
			   // difficulty_guess = 10000; //  Dev may change.  Guess lower than anything expected.

	  		   if ( height <= FanG + 1 + N ) { return difficulty_plate;  }

			   previous_timestamp = timestamps[0];
			   for ( i = 1; i <= N; i++) {
 			      // Safely prevent out-of-sequence timestamps
 			      if ( timestamps[i]  > previous_timestamp ) {   this_timestamp = timestamps[i];  }
 			      else {  this_timestamp = previous_timestamp;   }
 			      L +=  i*std::min(6*T , this_timestamp - previous_timestamp);
 			      previous_timestamp = this_timestamp;
			   }
			   if (L < N*N*T/20 ) { L =  N*N*T/20; }

			   // Fix array bounds issue - prevent accessing beyond array bounds
			   if (cumulativeDifficulties.size() > N) {
			       avg_D = ( cumulativeDifficulties[N] - cumulativeDifficulties[0] )/ N;
			   } else if (cumulativeDifficulties.size() > 0) {
			       // Fallback to last available difficulty if not enough data
			       avg_D = cumulativeDifficulties.back();
			   } else {
			       avg_D = 10000; // Minimum difficulty fallback
			   }

			   // Prevent round off error for small D and overflow for large D.
			   if (avg_D > 2000000*N*N*T) {
			       next_D = (avg_D/(200*L))*(N*(N+1)*T*97);
			   }
			   else {    next_D = (avg_D*N*(N+1)*T*97)/(200*L);    }

			   // DEBUG: Log difficulty calculation details
			   logger(DEBUGGING) << "LWMA V5 Calculation - Height: " << height
			                     << ", N: " << N << ", T: " << T
			                     << ", L: " << L << ", avg_D: " << avg_D
			                     << ", next_D: " << next_D;



			   // Add overflow protection for extreme hash rate changes
			   // If solve times are extremely fast, limit difficulty adjustment
			   if (L < N * T / 100) { // If average solve time is < 1% of target
			       // Cap the difficulty increase to prevent overflow
			       uint64_t maxDifficulty = avg_D * 1000; // Maximum 1000x increase
			       if (next_D > maxDifficulty) {
			           next_D = maxDifficulty;
			       }
			   }

			   // Optional. Make all insignificant digits zero for easy reading.
			   i = 1000000000;
			   while (i > 1) {
			     if ( next_D > i*100 ) { next_D = ((next_D+i/2)/i)*i; break; }
			     else { i /= 10; }
			   }
			   // Make least 2 digits = size of hash rate change last 11 blocks if it's statistically significant.
			   // D=2540035 => hash rate 3.5x higher than D expected. Blocks coming 3.5x too fast.
			   if ( next_D > 10000 ) {
			     uint64_t est_HR = (10*(11*T+(timestamps[N]-timestamps[N-11])/2))/(timestamps[N]-timestamps[N-11]+1);
			     if (  est_HR > 5 && est_HR < 22 )  {  est_HR=0;   }
			     est_HR = std::min(static_cast<uint64_t>(99), est_HR);
			     next_D = ((next_D+50)/100)*100 + est_HR;
			   }
	         	   // mini-lim
	   		   if (!isTestnet() && next_D < 10000) {
	  		   	next_D = 10000;

			   }

			   return  next_D;
	}


	// Helper: Calculate LWMA-1 difficulty for a specific window size
	// Returns the calculated difficulty using Zawy's LWMA-1 formula
	static uint64_t calculateLWMA(
		const std::vector<uint64_t>& timestamps,
		const std::vector<difficulty_type>& cumulativeDifficulties,
		uint64_t N,            // window size
		uint64_t T,            // target time
		uint64_t minDifficulty,
		uint64_t minSolveTime = 0) {  // lower clamp: 0 = disabled; use T/8 for testnet

		if (timestamps.size() < 2) return minDifficulty;

		uint64_t effectiveN = std::min(N, static_cast<uint64_t>(timestamps.size() - 1));
		if (effectiveN < 2) return minDifficulty;

		// LWMA-1: L = sum(i * solveTime[i]) for i = 1 to N
		uint64_t L = 0;
		uint64_t previous_timestamp = timestamps[0];

		for (uint64_t i = 1; i <= effectiveN; i++) {
			uint64_t this_timestamp = timestamps[i];

			// Prevent out-of-sequence timestamps
			if (this_timestamp <= previous_timestamp) {
				this_timestamp = previous_timestamp + 1;
			}

			uint64_t solveTime = this_timestamp - previous_timestamp;

			// Clamp solve time: upper bound 6*T (original LWMA-1), lower bound minSolveTime.
			// The lower clamp (T/8 on testnet) prevents burst-mined 1-6s blocks from
			// spiking the short window and creating unnecessary difficulty oscillation.
			if (solveTime > 6 * T) solveTime = 6 * T;
			if (minSolveTime > 0 && solveTime < minSolveTime) solveTime = minSolveTime;

			L += i * solveTime;
			previous_timestamp = this_timestamp;
		}

		// Prevent L from being too small
		uint64_t minL = effectiveN * effectiveN * T / 20;
		if (L < minL) L = minL;

		// Calculate average difficulty
		uint64_t avgD = minDifficulty;
		if (cumulativeDifficulties.size() > effectiveN && effectiveN > 0) {
			avgD = (cumulativeDifficulties[effectiveN] - cumulativeDifficulties[0]) / effectiveN;
		}
		if (avgD < minDifficulty) avgD = minDifficulty;

		// LWMA-1 formula: next_D = avg_D * N * (N+1) * T * 0.99 / (2 * L)
		uint64_t next_D;
		if (avgD > 2000000 * effectiveN * effectiveN * T) {
			next_D = (avgD / (200 * L)) * (effectiveN * (effectiveN + 1) * T * 99);
		} else {
			next_D = (avgD * effectiveN * (effectiveN + 1) * T * 99) / (200 * L);
		}

		return std::max(minDifficulty, next_D);
	}

	difficulty_type Currency::nextDifficultyV6(uint32_t height, uint8_t blockMajorVersion,
		std::vector<std::uint64_t> timestamps, std::vector<difficulty_type> cumulativeDifficulties) const {

		// LWMA-1 for v10+ — same proven Zawy algorithm as v5, with N=39.
		// Copyright (c) 2017-2018 Zawy, MIT License
		// https://github.com/zawy12/difficulty-algorithms/issues/3

		const uint64_t T = isTestnet() ? CryptoNote::parameters::DIFFICULTY_TARGET_TESTNET : CryptoNote::parameters::DIFFICULTY_TARGET;
		const uint64_t N = 39;
		const uint64_t minDifficulty = isTestnet() ? 1 : 1000000;

		if (timestamps.size() != cumulativeDifficulties.size() || timestamps.size() <= N) {
			return minDifficulty;
		}

		uint64_t L(0), next_D, i, this_timestamp(0), previous_timestamp(0), avg_D;

		previous_timestamp = timestamps[0];
		for (i = 1; i <= N; i++) {
			// Safely prevent out-of-sequence timestamps
			if (timestamps[i] > previous_timestamp) { this_timestamp = timestamps[i]; }
			else { this_timestamp = previous_timestamp; }
			// Symmetric solve time clamp: T/3 floor, 6*T ceiling.
			// T/3 prevents fast blocks from biasing LWMA downward (Poisson fast-block bias).
			uint64_t solveTime = this_timestamp - previous_timestamp;
			solveTime = std::max(T / 3, std::min(6 * T, solveTime));
			L += i * solveTime;
			previous_timestamp = this_timestamp;
		}
		if (L < N * N * T / 20) { L = N * N * T / 20; }

		avg_D = (cumulativeDifficulties[N] - cumulativeDifficulties[0]) / N;
		if (avg_D < minDifficulty) { avg_D = minDifficulty; }

		// Zawy LWMA-1 formula: next_D = avg_D * N * (N+1) * T * 97 / (200 * L)
		// The 97/200 factor adjusts for the LWMA weighting bias.
		if (avg_D > 2000000 * N * N * T) {
			next_D = (avg_D / (200 * L)) * (N * (N + 1) * T * 97);
		} else {
			next_D = (avg_D * N * (N + 1) * T * 97) / (200 * L);
		}

		// Overflow protection for extreme hash rate changes
		if (L < N * T / 100) {
			uint64_t maxDifficulty = avg_D * 1000;
			if (next_D > maxDifficulty) { next_D = maxDifficulty; }
		}

		// Round to clean numbers for readability
		i = 1000000000;
		while (i > 1) {
			if (next_D > i * 100) { next_D = ((next_D + i / 2) / i) * i; break; }
			else { i /= 10; }
		}

		return std::max(minDifficulty, next_D);
	}


	bool Currency::checkProofOfWorkV1(Crypto::cn_context& context, const Block& block, difficulty_type currentDiffic,
		Crypto::Hash& proofOfWork) const {
		if (BLOCK_MAJOR_VERSION_1 != block.majorVersion) {
			return false;
		}

		if (!get_block_longhash(context, block, proofOfWork)) {
			return false;
		}

		return check_hash(proofOfWork, currentDiffic);
	}

	bool Currency::checkProofOfWorkV2(Crypto::cn_context& context, const Block& block, difficulty_type currentDiffic,
		Crypto::Hash& proofOfWork) const {
		if (block.majorVersion < BLOCK_MAJOR_VERSION_2) {
			return false;
		}

		if (!get_block_longhash(context, block, proofOfWork)) {
			return false;
		}

		if (!check_hash(proofOfWork, currentDiffic)) {
			return false;
		}

		TransactionExtraMergeMiningTag mmTag;
		if (!getMergeMiningTagFromExtra(block.parentBlock.baseTransaction.extra, mmTag)) {
			logger(ERROR) << "merge mining tag wasn't found in extra of the parent block miner transaction";
			return false;
		}

		if (8 * sizeof(m_genesisBlockHash) < block.parentBlock.blockchainBranch.size()) {
			return false;
		}

		Crypto::Hash auxBlockHeaderHash;
		if (!get_aux_block_header_hash(block, auxBlockHeaderHash)) {
			return false;
		}

		Crypto::Hash auxBlocksMerkleRoot;
		Crypto::tree_hash_from_branch(block.parentBlock.blockchainBranch.data(), block.parentBlock.blockchainBranch.size(),
			auxBlockHeaderHash, &m_genesisBlockHash, auxBlocksMerkleRoot);

		if (auxBlocksMerkleRoot != mmTag.merkleRoot) {
			logger(ERROR, BRIGHT_YELLOW) << "Aux block hash wasn't found in merkle tree";
			return false;
		}

		return true;
	}

	bool Currency::checkProofOfWork(Crypto::cn_context& context, const Block& block, difficulty_type currentDiffic, Crypto::Hash& proofOfWork) const {
		switch (block.majorVersion) {
		case BLOCK_MAJOR_VERSION_1:
			return checkProofOfWorkV1(context, block, currentDiffic, proofOfWork);

		case BLOCK_MAJOR_VERSION_2:
		case BLOCK_MAJOR_VERSION_3:
		case BLOCK_MAJOR_VERSION_4:
		case BLOCK_MAJOR_VERSION_5:
		case BLOCK_MAJOR_VERSION_6:
		case BLOCK_MAJOR_VERSION_7:
		case BLOCK_MAJOR_VERSION_8:
		case BLOCK_MAJOR_VERSION_9:
		case BLOCK_MAJOR_VERSION_10:  // upgradekit
		case BLOCK_MAJOR_VERSION_11:  // HearthAMM + HEAT
		case BLOCK_MAJOR_VERSION_12:  // CDs + unified outputs

			return checkProofOfWorkV2(context, block, currentDiffic, proofOfWork);
		}

		logger(ERROR, BRIGHT_RED) << "Unknown block major version: " << block.majorVersion << "." << block.minorVersion;
		return false;
	}
    size_t Currency::getApproximateMaximumInputCount(size_t transactionSize, size_t outputCount, size_t mixinCount) const {
    const size_t KEY_IMAGE_SIZE = sizeof(Crypto::KeyImage);
    const size_t OUTPUT_KEY_SIZE = sizeof(decltype(KeyOutput::key));
    const size_t AMOUNT_SIZE = sizeof(uint64_t) + 2;                   // varint
    const size_t GLOBAL_INDEXES_VECTOR_SIZE_SIZE = sizeof(uint8_t);    // varint
    const size_t GLOBAL_INDEXES_INITIAL_VALUE_SIZE = sizeof(uint32_t); // varint
    const size_t GLOBAL_INDEXES_DIFFERENCE_SIZE = sizeof(uint32_t);    // varint
    const size_t SIGNATURE_SIZE = sizeof(Crypto::Signature);
    const size_t EXTRA_TAG_SIZE = sizeof(uint8_t);
    const size_t INPUT_TAG_SIZE = sizeof(uint8_t);
    const size_t OUTPUT_TAG_SIZE = sizeof(uint8_t);
    const size_t PUBLIC_KEY_SIZE = sizeof(Crypto::PublicKey);
    const size_t TRANSACTION_VERSION_SIZE = sizeof(uint8_t);
    const size_t TRANSACTION_UNLOCK_TIME_SIZE = sizeof(uint64_t);

    const size_t outputsSize = outputCount * (OUTPUT_TAG_SIZE + OUTPUT_KEY_SIZE + AMOUNT_SIZE);
    const size_t headerSize = TRANSACTION_VERSION_SIZE + TRANSACTION_UNLOCK_TIME_SIZE + EXTRA_TAG_SIZE + PUBLIC_KEY_SIZE;
    const size_t inputSize = INPUT_TAG_SIZE + AMOUNT_SIZE + KEY_IMAGE_SIZE + SIGNATURE_SIZE + GLOBAL_INDEXES_VECTOR_SIZE_SIZE +
                             GLOBAL_INDEXES_INITIAL_VALUE_SIZE + mixinCount * (GLOBAL_INDEXES_DIFFERENCE_SIZE + SIGNATURE_SIZE);

    return (transactionSize - headerSize - outputsSize) / inputSize;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  CurrencyBuilder::CurrencyBuilder(Logging::ILogger &log) : m_currency(log)
  {
    maxBlockNumber(parameters::CRYPTONOTE_MAX_BLOCK_NUMBER);
    maxBlockBlobSize(parameters::CRYPTONOTE_MAX_BLOCK_BLOB_SIZE);
    maxTxSize(parameters::CRYPTONOTE_MAX_TX_SIZE);
    publicAddressBase58Prefix(parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
    subAddressBase58Prefix(parameters::CRYPTONOTE_SUBADDRESS_BASE58_PREFIX);
    minedMoneyUnlockWindow(parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);

    timestampCheckWindow(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);
    timestampCheckWindow_v1(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1);
    blockFutureTimeLimit(parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT);
    blockFutureTimeLimit_v1(parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V1);
    blockFutureTimeLimit_v2(parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2);

		moneySupply(parameters::MONEY_SUPPLY);
		emissionSpeedFactor(parameters::EMISSION_SPEED_FACTOR);
		emissionSpeedFactor_FANGO(parameters::EMISSION_SPEED_FACTOR_FANGO);
                emissionSpeedFactor_FUEGO(parameters::EMISSION_SPEED_FACTOR_FUEGO);


		cryptonoteCoinVersion(parameters::CRYPTONOTE_COIN_VERSION);

		rewardBlocksWindow(parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW);
		blockGrantedFullRewardZone(parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE);
		minerTxBlobReservedSize(parameters::CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE);

		minMixin(parameters::MIN_TX_MIXIN_SIZE);
		maxMixin(parameters::MAX_TX_MIXIN_SIZE);

    numberOfDecimalPlaces(parameters::CRYPTONOTE_DISPLAY_DECIMAL_POINT);

    minimumFee(parameters::MINIMUM_FEE); // Use the configured default
    minimumFeeV1(parameters::MINIMUM_FEE_V1);
    minimumFeeV2(parameters::MINIMUM_FEE_V2);
    defaultDustThreshold(parameters::DEFAULT_DUST_THRESHOLD);

    difficultyTarget(parameters::DIFFICULTY_TARGET);
    difficultyTarget_DRGL(parameters::DIFFICULTY_TARGET_DRGL);
    difficultyWindow(parameters::DIFFICULTY_WINDOW);
    difficultyLag(parameters::DIFFICULTY_LAG);
    difficultyCut(parameters::DIFFICULTY_CUT);

    depositMinAmount(parameters::DEPOSIT_MIN_AMOUNT);
    // CD term in blocks = epochs * epoch_duration
    depositMinTerm(parameters::CD_MIN_EPOCHS * parameters::EPOCH_DURATION_BLOCKS);
    depositMaxTerm(parameters::CD_MAX_EPOCHS * parameters::EPOCH_DURATION_BLOCKS);

    // Override deposit terms for testnet (shorter epochs for testing)
    if (m_currency.m_testnet) {
      depositMinTerm(parameters::TESTNET_CD_MIN_EPOCHS * parameters::TESTNET_EPOCH_DURATION_BLOCKS);
      depositMaxTerm(parameters::TESTNET_CD_MAX_EPOCHS * parameters::TESTNET_EPOCH_DURATION_BLOCKS);
      // Fresh testnet chains have few outputs; allow mixIn=0 until the ring pool grows.
      // (minMixin(blockMajorVersion) already returns 0 on testnet for V10+.)
      minMixin(0);
    }

    // Burn deposit configuration
    burnDepositMinAmount(parameters::BURN_DEPOSIT_MIN_AMOUNT);

    depositTermForever(parameters::HEAT_TERM);

    // HEAT conversion rate (1 XFG = 5 HEAT at launch ratio)
    heatConversionRate(10000000);

    // Dynamic money supply initialization
    baseMoneySupply(parameters::MONEY_SUPPLY);


    // Fuego network ID - using hash of the full network ID for uint64_t compatibility
    std::string networkIdStr;
    if (m_currency.m_testnet) {
      // Testnet network ID based on P2P network ID "TEST FUEGO NET  "
      fuegoNetworkIdString("740838354326331649518908687400750781456");
      networkIdStr = "740838354326331649518908687400750781456";
    } else {
      // Mainnet network ID
      fuegoNetworkIdString("93385046440755750514194170694064996624");
      networkIdStr = "93385046440755750514194170694064996624";
    }
    Crypto::Hash networkIdHash;
    keccak(reinterpret_cast<const uint8_t*>(networkIdStr.data()), networkIdStr.size(), networkIdHash.data, sizeof(networkIdHash.data));
    // Use first 8 bytes of hash as uint64_t
    uint64_t networkIdUint64 = *reinterpret_cast<uint64_t*>(networkIdHash.data);
    fuegoNetworkId(networkIdUint64);

    maxBlockSizeInitial(parameters::MAX_BLOCK_SIZE_INITIAL);
    maxBlockSizeGrowthSpeedNumerator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR);
    maxBlockSizeGrowthSpeedDenominator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR);

    lockedTxAllowedDeltaSeconds(parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS);
    lockedTxAllowedDeltaSeconds_v2(parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2);
    lockedTxAllowedDeltaBlocks(parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS);

    mempoolTxLiveTime(parameters::CRYPTONOTE_MEMPOOL_TX_LIVETIME);
    mempoolTxFromAltBlockLiveTime(parameters::CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME);
    numberOfPeriodsToForgetTxDeletedFromPool(parameters::CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL);

    upgradeHeightV2(parameters::UPGRADE_HEIGHT_V2);
    upgradeHeightV3(parameters::UPGRADE_HEIGHT_V3);
    upgradeHeightV4(parameters::UPGRADE_HEIGHT_V4);
    upgradeHeightV5(parameters::UPGRADE_HEIGHT_V5);
    upgradeHeightV6(parameters::UPGRADE_HEIGHT_V6);
    upgradeHeightV7(parameters::UPGRADE_HEIGHT_V7);
    upgradeHeightV8(parameters::UPGRADE_HEIGHT_V8);
    upgradeHeightV9(parameters::UPGRADE_HEIGHT_V9);
    upgradeHeightV10(parameters::UPGRADE_HEIGHT_V10); // upgradekit
    upgradeHeightV11(parameters::UPGRADE_HEIGHT_V11); // HearthAMM+HEAT
    upgradeHeightV12(parameters::UPGRADE_HEIGHT_V12); // CDs + unified outputs

    bootstrapBlocks(BOOTSTRAP_BLOCKS);

    upgradeVotingThreshold(parameters::UPGRADE_VOTING_THRESHOLD);
    upgradeVotingWindow(parameters::UPGRADE_VOTING_WINDOW);
    upgradeWindow(parameters::UPGRADE_WINDOW);

    transactionMaxSize(parameters::CRYPTONOTE_MAX_TX_SIZE_LIMIT);
    fusionTxMaxSize(parameters::FUSION_TX_MAX_SIZE);
    fusionTxMinInputCount(parameters::FUSION_TX_MIN_INPUT_COUNT);
    fusionTxMinInOutCountRatio(parameters::FUSION_TX_MIN_IN_OUT_COUNT_RATIO);

    blocksFileName(parameters::CRYPTONOTE_BLOCKS_FILENAME);
    blocksCacheFileName(parameters::CRYPTONOTE_BLOCKSCACHE_FILENAME);
    blockIndexesFileName(parameters::CRYPTONOTE_BLOCKINDEXES_FILENAME);
    txPoolFileName(parameters::CRYPTONOTE_POOLDATA_FILENAME);
    blockchinIndicesFileName(parameters::CRYPTONOTE_BLOCKCHAIN_INDICES_FILENAME);

    testnet(false);
  }

	Transaction CurrencyBuilder::generateGenesisTransaction() {
		CryptoNote::Transaction tx;
		CryptoNote::AccountPublicAddress ac = boost::value_initialized<CryptoNote::AccountPublicAddress>();
		BinaryArray extraNonce;
		if (m_currency.m_testnet) {
			uint32_t nonce = m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_10);
			extraNonce.resize(4);
			memcpy(extraNonce.data(), &nonce, 4);
		}
		m_currency.constructMinerTx(1, 0, 0, 0, 0, 0, ac, tx, extraNonce);
		return tx;
	}
	CurrencyBuilder& CurrencyBuilder::emissionSpeedFactor(unsigned int val) {
		if (val <= 0 || val > 8 * sizeof(uint64_t)) {
			throw std::invalid_argument("val at emissionSpeedFactor()");
		}

		m_currency.m_emissionSpeedFactor = val;
		return *this;
	}
        CurrencyBuilder& CurrencyBuilder::emissionSpeedFactor_FANGO(unsigned int val) {
		if (val <= 0 || val > 8 * sizeof(uint64_t)) {
			throw std::invalid_argument("val at emissionSpeedFactor_FANGO()");
		}

		m_currency.m_emissionSpeedFactor_FANGO = val;
		return *this;
	}
        CurrencyBuilder& CurrencyBuilder::emissionSpeedFactor_FUEGO(unsigned int val) {
                if (val <= 0 || val > 8 * sizeof(uint64_t)) {
                        throw std::invalid_argument("val at emissionSpeedFactor_FUEGO()");
                }

                m_currency.m_emissionSpeedFactor_FUEGO = val;
                return *this;
        }

	CurrencyBuilder& CurrencyBuilder::numberOfDecimalPlaces(size_t val) {
		m_currency.m_numberOfDecimalPlaces = val;
		m_currency.m_coin = 1;
		for (size_t i = 0; i < m_currency.m_numberOfDecimalPlaces; ++i) {
			m_currency.m_coin *= 10;
		}

    return *this;
  }

  CurrencyBuilder &CurrencyBuilder::difficultyWindow(size_t val)
  {
    if (val < 2)
    {
      throw std::invalid_argument("val at difficultyWindow()");
    }

    m_currency.m_difficultyWindow = val;
    return *this;
  }

  /* ---------------------------------------------------------------------------------------------------- */

  CurrencyBuilder &CurrencyBuilder::upgradeVotingThreshold(unsigned int val)
  {
    if (val <= 0 || val > 100)
    {
      throw std::invalid_argument("val at upgradeVotingThreshold()");
    }

    m_currency.m_upgradeVotingThreshold = val;
    return *this;
  }

	CurrencyBuilder& CurrencyBuilder::upgradeWindow(size_t val) {
		if (val <= 0) {
			throw std::invalid_argument("val at upgradeWindow()");
		}

		m_currency.m_upgradeWindow = static_cast<uint32_t>(val);
		return *this;
	}

	/* ---------------------------------------------------------------------------------------------------- */
	/* Burn Deposit Methods */
	/* ---------------------------------------------------------------------------------------------------- */

	bool Currency::isValidBurnDepositAmount(uint64_t amount) const {
               // Valid burn amounts: 0.8 XFG (8,000,000) or 800 XFG (8,000,000,000)
		return (amount == m_burnDepositMinAmount ||
				amount == m_burnDepositStandardAmount ||
				amount == m_burnDepositLargeAmount);
	}

	bool Currency::isValidBurnDepositTerm(uint32_t term) const {
		// Valid burn terms: HEAT_TERM (4294967295) or DIGM_TERM (0x44494D47)
		return (term == m_depositTermForever || term == parameters::DIGM_TERM);
	}

	bool Currency::isBurnDeposit(uint32_t term) const {
		// Check if this is a burn
		return isValidBurnDepositTerm(term);
	}

	bool Currency::validateNetworkId(uint64_t networkId) const {
		// Validate against hashed Fuego network ID
		return (networkId == m_fuegoNetworkId);
	}

	bool Currency::validateNetworkIdString(const std::string& networkId) const {
		// Validate against full Fuego network ID string
		return (networkId == m_fuegoNetworkIdString);
	}

	Crypto::Hash Currency::calculateBurnNullifier(const Crypto::SecretKey& secret) const {
		// Calculate nullifier using Keccak256: hash(secret + "nullifier")
		std::vector<uint8_t> data;
		data.insert(data.end(), secret.data, secret.data + sizeof(secret.data));
		data.insert(data.end(), (uint8_t*)"nullifier", (uint8_t*)"nullifier" + 9);

		Crypto::Hash nullifier;
		keccak(data.data(), data.size(), nullifier.data, sizeof(nullifier.data));
		return nullifier;
	}

	Crypto::Hash Currency::calculateBurnCommitment(const Crypto::SecretKey& secret, uint64_t amount) const {
		// Calculate commitment using Keccak256: hash(secret + "commitment")
		std::vector<uint8_t> data;
		data.insert(data.end(), secret.data, secret.data + sizeof(secret.data));
		data.insert(data.end(), (uint8_t*)"commitment", (uint8_t*)"commitment" + 10);

		Crypto::Hash commitment;
		keccak(data.data(), data.size(), commitment.data, sizeof(commitment.data));
		return commitment;
	}

	Crypto::Hash Currency::calculateBurnRecipientHash(const std::string& recipientAddress) const {
		// Calculate recipient hash using Keccak256
		Crypto::Hash recipientHash;
		keccak(reinterpret_cast<const uint8_t*>(recipientAddress.data()), recipientAddress.size(), recipientHash.data, sizeof(recipientHash.data));
		return recipientHash;
	}

	bool Currency::validateBurnProofData(const std::string& secret, uint64_t amount, const std::string& commitment, const std::string& nullifier) const {
		// Validate secret format (hex encoded)
		if (secret.empty() || secret.length() != 64) {
			return false;
		}

		// Validate amount
		if (!isValidBurnDepositAmount(amount)) {
			return false;
		}

		// Validate commitment and nullifier format (hex encoded)
		if (commitment.empty() || commitment.length() != 64) {
			return false;
		}

		if (nullifier.empty() || nullifier.length() != 64) {
			return false;
		}


		return true;
	}

} // namespace CryptoNote
