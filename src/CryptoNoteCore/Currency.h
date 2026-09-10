// Copyright (c) 2017-2026 Fuego Developers
// Copyright (c) 2016-2019 The Karbowanec developers
// Copyright (c) 2012-2018 The CryptoNote developers
// Copyright (c) 2018-2019 Conceal Network Developers
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

#include <cstdint>
#include <string>
#include <vector>
#include <boost/utility.hpp>
#include "../CryptoNoteConfig.h"
#include "../crypto/hash.h"
#include "../Logging/LoggerRef.h"
#include "CryptoNoteBasic.h"
#include "Difficulty.h"
#include "AssetType.h"

namespace CryptoNote {

class CommitmentIndex;  // forward decl for fee-pool interest

class AccountBase;

class Currency {
public:
  static const std::vector<uint64_t> PRETTY_AMOUNTS;

  uint64_t maxBlockHeight() const { return m_maxBlockHeight; }
  size_t maxBlockBlobSize() const { return m_maxBlockBlobSize; }
  size_t maxTxSize() const { return m_maxTxSize; }
  uint64_t publicAddressBase58Prefix() const { return m_publicAddressBase58Prefix; }
  uint64_t subAddressBase58Prefix() const { return m_subAddressBase58Prefix; }
  bool isSubAddressStr(const std::string& str) const;
  size_t minedMoneyUnlockWindow() const { return m_minedMoneyUnlockWindow; }

  size_t timestampCheckWindow() const { return m_timestampCheckWindow; }
  size_t timestampCheckWindow(uint8_t blockMajorVersion) const {
     if (blockMajorVersion >= BLOCK_MAJOR_VERSION_5) {
        return timestampCheckWindow_v1();
       }
     else {
      return timestampCheckWindow();
       }
     }
  size_t timestampCheckWindow_v1() const { return m_timestampCheckWindow_v1; }
  uint64_t blockFutureTimeLimit() const { return m_blockFutureTimeLimit; }
  uint64_t blockFutureTimeLimit(uint8_t blockMajorVersion) const {
    if (blockMajorVersion >= BLOCK_MAJOR_VERSION_7) {
      return blockFutureTimeLimit_v2();
      }
    else if (blockMajorVersion >= BLOCK_MAJOR_VERSION_5) {
      return blockFutureTimeLimit_v1();
      }
    else {
      return blockFutureTimeLimit();
      }
    }
  uint64_t blockFutureTimeLimit_v1() const { return m_blockFutureTimeLimit_v1; }
  uint64_t blockFutureTimeLimit_v2() const { return m_blockFutureTimeLimit_v2; }

  unsigned int emissionSpeedFactor() const { return m_emissionSpeedFactor; }
  unsigned int emissionSpeedFactor_FANGO() const { return m_emissionSpeedFactor_FANGO; }
  unsigned int emissionSpeedFactor_FUEGO() const { return m_emissionSpeedFactor_FUEGO; }

  unsigned int emissionSpeedFactor(uint8_t blockMajorVersion) const {
    if (blockMajorVersion >= BLOCK_MAJOR_VERSION_9) {
      return emissionSpeedFactor_FUEGO();
      }
    else if (blockMajorVersion == BLOCK_MAJOR_VERSION_8) {
    return emissionSpeedFactor_FANGO();
    }
   else {
      return emissionSpeedFactor();
    }
  }
  uint64_t moneySupply() const { return m_moneySupply; }
  size_t cryptonoteCoinVersion() const { return m_cryptonoteCoinVersion; }

  size_t rewardBlocksWindow() const { return m_rewardBlocksWindow; }


  size_t blockGrantedFullRewardZone() const { return m_blockGrantedFullRewardZone; }
  size_t blockGrantedFullRewardZoneByBlockVersion(uint8_t blockMajorVersion) const;
  size_t blockGrantedFullRewardZoneByHeightVersion(uint8_t blockMajorVersion, uint32_t height) const;
  size_t blockGrantedFullRewardZoneAtHeight(uint32_t height) const;
  size_t minerTxBlobReservedSize() const { return m_minerTxBlobReservedSize; }
  size_t minMixin() const { return m_minMixin; }
  size_t minMixin(uint8_t blockMajorVersion) const {
    if (blockMajorVersion >= BLOCK_MAJOR_VERSION_10) {
      // Testnet allows mixin=0 so fresh chains can bootstrap before the decoy pool fills up
      return m_testnet ? 0 : parameters::MIN_TX_MIXIN_SIZE_V10;
    } else if (blockMajorVersion >= BLOCK_MAJOR_VERSION_7) {
      return parameters::MIN_TX_MIXIN_SIZE_V2;  // Legacy mixin: 2 for BMV7-BMV9
    } else {
      return m_minMixin;
    }
  }

  // Dynamic ring size calculation — use DynamicRingSizeCalculator::calculateOptimalRingSize
  // (in src/CryptoNoteCore/DynamicRingSize.cpp) which targets {32, 16, 8} ring sizes.

  size_t maxMixin() const { return m_maxMixin; }
  size_t numberOfDecimalPlaces() const { return m_numberOfDecimalPlaces; }
  uint64_t coin() const { return m_coin; }

  uint64_t minimumFee() const { return minimumFee(BLOCK_MAJOR_VERSION_10); } // Default to latest version (0.00008 XFG)
  uint64_t minimumFee(uint8_t blockMajorVersion) const;
  uint64_t minimumFeeV1() const { return m_minimumFeeV1; }
  uint64_t minimumFeeV2() const { return m_minimumFeeV2; }
  uint64_t minimumFeeBanking() const { return m_minimumFeeBanking; }

  // Dynamic minimum fee based on block size
  uint64_t dynamicMinimumFee(size_t currentBlockSize, size_t medianBlockSize, uint8_t blockMajorVersion) const;

  // Calculate banking fee: 0.1% (dynamic rate)
  uint64_t calculateBankingFee(uint64_t depositAmount) const;

  uint64_t defaultDustThreshold() const { return m_defaultDustThreshold; }
  uint64_t difficultyTarget_DRGL() const { return m_difficultyTarget_DRGL; }
  uint64_t difficultyTarget() const { return m_difficultyTarget; }
  uint64_t difficultyTarget(uint8_t blockMajorVersion) const {
    if (blockMajorVersion <= BLOCK_MAJOR_VERSION_6) {
      return difficultyTarget_DRGL();
    }
    else {
      return difficultyTarget();
    }
  }
  size_t difficultyWindow() const { return m_difficultyWindow; }
  size_t difficultyLag() const { return m_difficultyLag; }
  size_t difficultyCut() const { return m_difficultyCut; }
  size_t difficultyBlocksCountByBlockVersion(uint8_t blockMajorVersion) const
    {
      if (blockMajorVersion >= BLOCK_MAJOR_VERSION_10)
      {
        // v10+: LWMA-1 with N=36. Provide N+1=37 timestamps.
        return 40;
      }
      else if (blockMajorVersion >= BLOCK_MAJOR_VERSION_3)
      {
        return difficultyBlocksCount3() + 1;
      }
      else if (blockMajorVersion == BLOCK_MAJOR_VERSION_2)
      {
        return difficultyBlocksCount2();
      }
      else
      {
        return difficultyBlocksCount();
      }
    }
  size_t difficultyBlocksCount() const { return m_difficultyWindow + m_difficultyLag; }
  size_t difficultyBlocksCount2() const { return CryptoNote::parameters::DIFFICULTY_WINDOW_V2; }
  size_t difficultyBlocksCount3() const { return CryptoNote::parameters::DIFFICULTY_WINDOW_V3; }
  size_t difficultyBlocksCount4() const { return CryptoNote::parameters::DIFFICULTY_WINDOW_V4; }

    uint64_t depositMinAmount() const { return m_depositMinAmount; }
    uint32_t depositMinTerm() const { return m_depositMinTerm; }
    uint32_t depositMaxTerm() const { return m_depositMaxTerm; }

  uint32_t bootstrapBlocks() const { return m_bootstrapBlocks; }

  size_t maxBlockSizeInitial() const { return m_maxBlockSizeInitial; }
  uint64_t maxBlockSizeGrowthSpeedNumerator() const { return m_maxBlockSizeGrowthSpeedNumerator; }
  uint64_t maxBlockSizeGrowthSpeedDenominator() const { return m_maxBlockSizeGrowthSpeedDenominator; }

  uint64_t lockedTxAllowedDeltaSeconds() const { return m_lockedTxAllowedDeltaSeconds; }
  uint64_t lockedTxAllowedDeltaSeconds(uint8_t blockMajorVersion) const {
    if (blockMajorVersion >= BLOCK_MAJOR_VERSION_7) {
      return lockedTxAllowedDeltaSeconds_v2();
    }
    else {
      return lockedTxAllowedDeltaSeconds();
    }
  }
  uint64_t lockedTxAllowedDeltaSeconds_v2() const { return m_lockedTxAllowedDeltaSeconds_v2; }

  size_t lockedTxAllowedDeltaBlocks() const { return m_lockedTxAllowedDeltaBlocks; }

  uint64_t mempoolTxLiveTime() const { return m_mempoolTxLiveTime; }
  uint64_t mempoolTxFromAltBlockLiveTime() const { return m_mempoolTxFromAltBlockLiveTime; }
  uint64_t numberOfPeriodsToForgetTxDeletedFromPool() const { return m_numberOfPeriodsToForgetTxDeletedFromPool; }

  uint32_t upgradeHeight(uint8_t majorVersion) const;
  uint8_t blockMajorVersionAtHeight(uint32_t height) const;
  unsigned int upgradeVotingThreshold() const { return m_upgradeVotingThreshold; }
  uint32_t upgradeVotingWindow() const { return m_upgradeVotingWindow; }
  uint32_t upgradeWindow() const { return m_upgradeWindow; }
  uint32_t minNumberVotingBlocks() const { return (m_upgradeVotingWindow * m_upgradeVotingThreshold + 99) / 100; }
  uint32_t maxUpgradeDistance() const { return 7 * m_upgradeWindow; }
  uint32_t calculateUpgradeHeight(uint32_t voteCompleteHeight) const { return voteCompleteHeight + m_upgradeWindow; }

    size_t transactionMaxSize() const { return m_transactionMaxSize; }
    size_t fusionTxMaxSize() const { return m_fusionTxMaxSize; }
    size_t fusionTxMinInputCount() const { return m_fusionTxMinInputCount; }
    size_t fusionTxMinInOutCountRatio() const { return m_fusionTxMinInOutCountRatio; }

  const std::string &blocksFileName() const { return m_blocksFileName; }
  const std::string &blocksCacheFileName() const { return m_blocksCacheFileName; }
  const std::string &blockIndexesFileName() const { return m_blockIndexesFileName; }
  const std::string &txPoolFileName() const { return m_txPoolFileName; }
  const std::string &blockchinIndicesFileName() const { return m_blockchinIndicesFileName; }

  bool isTestnet() const { return m_testnet; }

  const Block& genesisBlock() const { return m_genesisBlock; }
  const Crypto::Hash& genesisBlockHash() const { return m_genesisBlockHash; }

  bool getBlockReward(uint8_t blockMajorVersion, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint32_t height,
                        uint64_t &reward, int64_t &emissionChange, uint64_t burnedCoinsOverride = UINT64_MAX) const;
    // Interest functions
    uint64_t calculateInterest(uint64_t amount, uint32_t term, uint32_t height) const;
    // Fee-pool interest: accrued from swap fees over epochs a CD was locked
    // isLegacyBond=true uses legacy bond fee rate track (50% CD share for bug-era deposits)
    // term=0 skips loyalty bonus check (conservative cap); pass actual term for payout
    // autoRolled=true compounds interest at the auto-roll boundary (doubled earning period)
    // v11+: returns BASE interest only; loyalty bonus is paid from Bonus Vault via calculateCdBonus().
    uint64_t calculateCdInterest(uint64_t amount, uint32_t creationHeight,
                                  uint32_t currentHeight,
                                  const CommitmentIndex& commitmentIndex,
                                  bool isLegacyBond = false, uint32_t term = 0,
                                  bool autoRolled = false) const;
    // v11+: BV-backed loyalty bonus. Σ over locked epochs of
    // bonusHeat_e × amount × tierWeight(term) / weightedBase_e — realized BV
    // inflows only, so total payouts can never exceed the vault (no
    // overpromising). Returns 0 pre-V11 (no bonus epoch rates recorded).
    uint64_t calculateCdBonus(uint64_t amount, uint32_t creationHeight,
                               uint32_t currentHeight,
                               const CommitmentIndex& commitmentIndex,
                               uint32_t term) const;
    // Tier weight in percent for a CD term: 250/200/150/125 for the 72/36/18/6
    // epoch tiers, 100 otherwise. Mirrors the loyalty multiplier mapping.
    uint64_t loyaltyTierWeightPct(uint32_t term) const;
    uint64_t calculateTotalTransactionInterest(const Transaction &tx, uint32_t height) const;
    uint64_t getTransactionInputAmount(const TransactionInput &in, uint32_t height) const;
    uint64_t getTransactionAllInputsAmount(const Transaction &tx, uint32_t height) const;
    // Sums claimedInterest across all TransactionInputCommitmentSpend inputs of a tx.
    // Returns false on uint64 overflow. Used by the block-validation aggregate
    // fee-pool cap that backs CD interest (see Blockchain.cpp, F-001 fix).
    bool sumCommitmentClaimedInterest(const Transaction &tx, uint64_t &total) const;
    bool getTransactionFee(const Transaction &tx, uint64_t &fee, uint32_t height) const;
    uint64_t getTransactionFee(const Transaction &tx, uint32_t height) const;

    static AssetType classifyOutputAsset(const TransactionOutputTarget& target, uint32_t term);
    AssetBalance getTransactionOutputAssetAmounts(const Transaction& tx) const;
  size_t maxBlockCumulativeSize(uint64_t height) const;

  bool constructMinerTx(uint8_t blockMajorVersion, uint32_t height, size_t medianSize, uint64_t alreadyGeneratedCoins, size_t currentBlockSize,
                          uint64_t fee, const AccountPublicAddress &minerAddress, Transaction &tx,
                          const BinaryArray &extraNonce = BinaryArray(), size_t maxOuts = 1, uint64_t burnedCoinsOverride = UINT64_MAX,
                          uint64_t bankingFeesInBlock = 0) const;

  bool isFusionTransaction(const Transaction &transaction) const;
  bool isFusionTransaction(const Transaction &transaction, size_t size) const;
  bool isFusionTransaction(const std::vector<uint64_t> &inputsAmounts, const std::vector<uint64_t> &outputsAmounts, size_t size) const;
  bool isAmountApplicableInFusionTransactionInput(uint64_t amount, uint64_t threshold, uint32_t height) const;
  bool isAmountApplicableInFusionTransactionInput(uint64_t amount, uint64_t threshold, uint8_t &amountPowerOfTen, uint32_t height) const;

  // Burn deposit validation methods
  bool isValidBurnDepositAmount(uint64_t amount) const;
  bool isValidBurnDepositTerm(uint32_t term) const;
  bool isBurnDeposit(uint32_t term) const;
  uint64_t getBurnDepositMinAmount() const { return m_burnDepositMinAmount; }
  uint64_t getBurnDepositStandardAmount() const { return m_burnDepositStandardAmount; }
  uint64_t getBurnDepositLargeAmount() const { return m_burnDepositLargeAmount; }
  uint32_t getDepositTermForever() const { return m_depositTermForever; }
  uint32_t getDepositTermBurn() const { return m_depositTermForever; }  // Alias for compatibility

  // HEAT token conversion methods
  uint64_t getHeatConversionRate() const { return m_heatConversionRate; }

  // Money supply methods
  uint64_t getBaseMoneySupply() const { return m_baseMoneySupply; }
  // Sync EternalFlame from authoritative source (BankingIndex).
  // This is the ONLY way m_ethereal_xfg should be updated.
  void syncEternalFlame(uint64_t authoritativeTotal);
  uint64_t getEternalFlame() const { return m_ethereal_xfg; }
  double getBurnPercentage() const;

  // Network validation
  uint64_t getFuegoNetworkId() const { return m_fuegoNetworkId; }
  const std::string& getFuegoNetworkIdString() const { return m_fuegoNetworkIdString; }
  bool validateNetworkId(uint64_t networkId) const;
  bool validateNetworkIdString(const std::string& networkId) const;

  // Burn proof data methods
  Crypto::Hash calculateBurnNullifier(const Crypto::SecretKey& secret) const;
  Crypto::Hash calculateBurnCommitment(const Crypto::SecretKey& secret, uint64_t amount) const;
  Crypto::Hash calculateBurnRecipientHash(const std::string& recipientAddress) const;
  bool validateBurnProofData(const std::string& secret, uint64_t amount, const std::string& commitment, const std::string& nullifier) const;

  std::string accountAddressAsString(const AccountBase &account) const;
  std::string accountAddressAsString(const AccountPublicAddress &accountPublicAddress) const;
  std::string subAddressAsString(const AccountPublicAddress &subAddressPublicAddress) const;
  bool parseAccountAddressString(const std::string &str, AccountPublicAddress &addr) const;

  std::string formatAmount(uint64_t amount) const;
  std::string formatAmount(int64_t amount) const;
  bool parseAmount(const std::string &str, uint64_t &amount) const;

  // EUR display — all public-facing USD values shown in EUR
  // GENIUS Act / Clarity Act compliance: HEAT is not pegged to USD,
  // it targets constant purchasing power via CPI-adjusted band.
  //   usdCents: USD value in cents (e.g. 150 = $1.50)
  //   returns: EUR string (e.g. "€1.38")
  std::string toEuroDisplay(uint64_t usdCents) const;

  difficulty_type nextDifficulty(uint32_t height, uint8_t blockMajorVersion, std::vector<uint64_t> timestamps, std::vector<difficulty_type> Difficulties) const;
  difficulty_type nextDifficultyV1(std::vector<uint64_t> timestamps, std::vector<difficulty_type> Difficulties) const;
  difficulty_type nextDifficultyV2(std::vector<uint64_t> timestamps, std::vector<difficulty_type> Difficulties) const;
  difficulty_type nextDifficultyV3(std::vector<uint64_t> timestamps, std::vector<difficulty_type> Difficulties) const;
  difficulty_type nextDifficultyV4(uint32_t height, uint8_t blockMajorVersion, std::vector<uint64_t> timestamps, std::vector<difficulty_type> Difficulties) const;
  difficulty_type nextDifficultyV5(uint32_t height, uint8_t blockMajorVersion, std::vector<uint64_t> timestamps, std::vector<difficulty_type> Difficulties) const;
  difficulty_type nextDifficultyV6(uint32_t height, uint8_t blockMajorVersion, std::vector<uint64_t> timestamps, std::vector<difficulty_type> Difficulties) const;

  bool checkProofOfWorkV1(Crypto::cn_context& context, const Block& block, difficulty_type currentDiffic, Crypto::Hash& proofOfWork) const;
  bool checkProofOfWorkV2(Crypto::cn_context& context, const Block& block, difficulty_type currentDiffic, Crypto::Hash& proofOfWork) const;
  bool checkProofOfWork(Crypto::cn_context& context, const Block& block, difficulty_type currentDiffic, Crypto::Hash& proofOfWork) const;
  size_t getApproximateMaximumInputCount(size_t transactionSize, size_t outputCount, size_t mixinCount) const;

private:
  Currency(Logging::ILogger& log) : logger(log, "currency") {
  }

  bool init();

  bool generateGenesisBlock();

  // getPenalizedAmount is a standalone function defined in CryptoNoteBasicImpl.h/CryptoNoteBasicImpl.cpp

private:
  uint64_t m_maxBlockHeight;
  size_t m_maxBlockBlobSize;
  size_t m_maxTxSize;
  uint64_t m_publicAddressBase58Prefix;
  uint64_t m_subAddressBase58Prefix;
  size_t m_minedMoneyUnlockWindow;

  size_t m_timestampCheckWindow;
  size_t m_timestampCheckWindow_v1;
  uint64_t m_blockFutureTimeLimit;
  uint64_t m_blockFutureTimeLimit_v1;
  uint64_t m_blockFutureTimeLimit_v2;

  uint64_t m_moneySupply;
  unsigned int m_emissionSpeedFactor;
  unsigned int m_emissionSpeedFactor_FANGO;
  unsigned int m_emissionSpeedFactor_FUEGO;

  size_t m_cryptonoteCoinVersion;

  size_t m_rewardBlocksWindow;
  size_t m_blockGrantedFullRewardZone;
  size_t m_minerTxBlobReservedSize;
  size_t m_numberOfDecimalPlaces;
  uint64_t m_coin;
  size_t m_minMixin;
  size_t m_maxMixin;
  uint64_t m_minimumFee;
  uint64_t m_minimumFeeV1;
  uint64_t m_minimumFeeV2;
  uint64_t m_minimumFeeBanking;
  uint64_t m_defaultDustThreshold;

  uint64_t m_difficultyTarget;
  uint64_t m_difficultyTarget_DRGL;
  size_t m_difficultyWindow;
  size_t m_difficultyLag;
  size_t m_difficultyCut;

  uint64_t m_depositMinAmount;
  uint32_t m_depositMinTerm;
  uint32_t m_depositMaxTerm;
    uint64_t m_depositMinTotalRateFactor;
    uint64_t m_depositMaxTotalRate;

  // Burn deposit configuration
  uint64_t m_burnDepositMinAmount;
  uint64_t m_burnDepositStandardAmount;
  uint64_t m_burnDepositLargeAmount;
  uint32_t m_depositTermForever;

  // HEAT token conversion
  uint64_t m_heatConversionRate;

  // Money supply
  uint64_t m_baseMoneySupply;
  uint64_t m_ethereal_xfg;

  // Network validation - using hash of network ID
  uint64_t m_fuegoNetworkId;
  std::string m_fuegoNetworkIdString;  // network ID as string

  size_t m_maxBlockSizeInitial;
  uint64_t m_maxBlockSizeGrowthSpeedNumerator;
  uint64_t m_maxBlockSizeGrowthSpeedDenominator;

  uint64_t m_lockedTxAllowedDeltaSeconds;
  uint64_t m_lockedTxAllowedDeltaSeconds_v2;
  size_t m_lockedTxAllowedDeltaBlocks;

  uint64_t m_mempoolTxLiveTime;
  uint64_t m_mempoolTxFromAltBlockLiveTime;
  uint64_t m_numberOfPeriodsToForgetTxDeletedFromPool;

  uint32_t m_upgradeHeightV2;
  uint32_t m_upgradeHeightV3;
  uint32_t m_upgradeHeightV4;
  uint32_t m_upgradeHeightV5;
  uint32_t m_upgradeHeightV6;
  uint32_t m_upgradeHeightV7;
  uint32_t m_upgradeHeightV8;
  uint32_t m_upgradeHeightV9;
   uint32_t m_upgradeHeightV10; // upgradekit
    uint32_t m_upgradeHeightV11; // HearthAMM + HEAT
    uint32_t m_upgradeHeightV12; // HEAT CDs + unified outputs

  uint32_t m_bootstrapBlocks;

  unsigned int m_upgradeVotingThreshold;
  uint32_t m_upgradeVotingWindow;
  uint32_t m_upgradeWindow;

  size_t m_transactionMaxSize;
  size_t m_fusionTxMaxSize;
  size_t m_fusionTxMinInputCount;
  size_t m_fusionTxMinInOutCountRatio;

  std::string m_blocksFileName;
  std::string m_blocksCacheFileName;
  std::string m_blockIndexesFileName;
  std::string m_txPoolFileName;
  std::string m_blockchinIndicesFileName;

  bool m_testnet;

  Block m_genesisBlock;
  Crypto::Hash m_genesisBlockHash;

  Logging::LoggerRef logger;

  friend class CurrencyBuilder;
};

class CurrencyBuilder : boost::noncopyable {
public:
  CurrencyBuilder(Logging::ILogger& log);

  Currency currency() {
    if (!m_currency.init()) {
      throw std::runtime_error("Failed to initialize currency object");
    }
    return m_currency;
  }

  Transaction generateGenesisTransaction();
  CurrencyBuilder& maxBlockNumber(uint64_t val) { m_currency.m_maxBlockHeight = val; return *this; }
  CurrencyBuilder& maxBlockBlobSize(size_t val) { m_currency.m_maxBlockBlobSize = val; return *this; }
  CurrencyBuilder& maxTxSize(size_t val) { m_currency.m_maxTxSize = val; return *this; }
  CurrencyBuilder& publicAddressBase58Prefix(uint64_t val) { m_currency.m_publicAddressBase58Prefix = val; return *this; }
  CurrencyBuilder& subAddressBase58Prefix(uint64_t val) { m_currency.m_subAddressBase58Prefix = val; return *this; }
  CurrencyBuilder& minedMoneyUnlockWindow(size_t val) { m_currency.m_minedMoneyUnlockWindow = val; return *this; }

  CurrencyBuilder& timestampCheckWindow(size_t val) { m_currency.m_timestampCheckWindow = val; return *this; }
  CurrencyBuilder& timestampCheckWindow_v1(size_t val) { m_currency.m_timestampCheckWindow_v1 = val; return *this; }

  CurrencyBuilder& blockFutureTimeLimit(uint64_t val) { m_currency.m_blockFutureTimeLimit = val; return *this; }
  CurrencyBuilder& blockFutureTimeLimit_v1(uint64_t val) { m_currency.m_blockFutureTimeLimit_v1 = val; return *this; }
  CurrencyBuilder& blockFutureTimeLimit_v2(uint64_t val) { m_currency.m_blockFutureTimeLimit_v2 = val; return *this; }

  CurrencyBuilder& moneySupply(uint64_t val) { m_currency.m_moneySupply = val; return *this; }
  CurrencyBuilder& emissionSpeedFactor(unsigned int val);
  CurrencyBuilder& emissionSpeedFactor_FANGO(unsigned int val);
  CurrencyBuilder& emissionSpeedFactor_FUEGO(unsigned int val);
  CurrencyBuilder& cryptonoteCoinVersion(size_t val) { m_currency.m_cryptonoteCoinVersion = val; return *this; }

  CurrencyBuilder& rewardBlocksWindow(size_t val) { m_currency.m_rewardBlocksWindow = val; return *this; }
  CurrencyBuilder& blockGrantedFullRewardZone(size_t val) { m_currency.m_blockGrantedFullRewardZone = val; return *this; }
  CurrencyBuilder& minerTxBlobReservedSize(size_t val) { m_currency.m_minerTxBlobReservedSize = val; return *this; }

  CurrencyBuilder& minMixin(size_t val) { m_currency.m_minMixin = val; return *this; }
  CurrencyBuilder& maxMixin(size_t val) { m_currency.m_maxMixin = val; return *this; }

  CurrencyBuilder& numberOfDecimalPlaces(size_t val);

  CurrencyBuilder& minimumFee(uint64_t val) { m_currency.m_minimumFee = val; return *this; }
  CurrencyBuilder& minimumFeeV1(uint64_t val) { m_currency.m_minimumFeeV1 = val; return *this; }
  CurrencyBuilder& minimumFeeV2(uint64_t val) { m_currency.m_minimumFeeV2 = val; return *this; }
  CurrencyBuilder& minimumFeeBanking(uint64_t val) { m_currency.m_minimumFeeBanking = val; return *this; }
  CurrencyBuilder& defaultDustThreshold(uint64_t val) { m_currency.m_defaultDustThreshold = val; return *this; }
  CurrencyBuilder& difficultyTarget(uint64_t val) { m_currency.m_difficultyTarget = val; return *this; }

  CurrencyBuilder& difficultyTarget_DRGL(uint64_t val) { m_currency.m_difficultyTarget_DRGL = val; return *this; }
  CurrencyBuilder& difficultyWindow(size_t val);
  CurrencyBuilder& difficultyLag(size_t val) { m_currency.m_difficultyLag = val; return *this; }
  CurrencyBuilder& difficultyCut(size_t val) { m_currency.m_difficultyCut = val; return *this; }

  CurrencyBuilder& maxBlockSizeInitial(size_t val) { m_currency.m_maxBlockSizeInitial = val; return *this; }
  CurrencyBuilder& maxBlockSizeGrowthSpeedNumerator(uint64_t val) { m_currency.m_maxBlockSizeGrowthSpeedNumerator = val; return *this; }
  CurrencyBuilder& maxBlockSizeGrowthSpeedDenominator(uint64_t val) { m_currency.m_maxBlockSizeGrowthSpeedDenominator = val; return *this; }
    CurrencyBuilder &depositMinTotalRateFactor(uint64_t val)
    {
      m_currency.m_depositMinTotalRateFactor = val;
      return *this;
    }
    CurrencyBuilder &depositMaxTotalRate(uint64_t val)
    {
      m_currency.m_depositMaxTotalRate = val;
      return *this;
    }

  CurrencyBuilder& lockedTxAllowedDeltaSeconds(uint64_t val) { m_currency.m_lockedTxAllowedDeltaSeconds = val; return *this; }
  CurrencyBuilder& lockedTxAllowedDeltaSeconds_v2(uint64_t val) { m_currency.m_lockedTxAllowedDeltaSeconds_v2 = val; return *this; }
  CurrencyBuilder& lockedTxAllowedDeltaBlocks(size_t val) { m_currency.m_lockedTxAllowedDeltaBlocks = val; return *this; }

  CurrencyBuilder& depositMinAmount(uint64_t val) { m_currency.m_depositMinAmount = val; return *this; }
  CurrencyBuilder& depositMinTerm(uint32_t val)   { m_currency.m_depositMinTerm = val; return *this;  }
  CurrencyBuilder& depositMaxTerm(uint32_t val)   { m_currency.m_depositMaxTerm = val; return *this; }

  // Burn deposit configuration builders
  CurrencyBuilder& burnDepositMinAmount(uint64_t val) { m_currency.m_burnDepositMinAmount = val; return *this; }
  CurrencyBuilder& burnDepositStandardAmount(uint64_t val) { m_currency.m_burnDepositStandardAmount = val; return *this; }
  CurrencyBuilder& burnDepositLargeAmount(uint64_t val) { m_currency.m_burnDepositLargeAmount = val; return *this; }
  CurrencyBuilder& depositTermForever(uint32_t val) { m_currency.m_depositTermForever = val; return *this; }

  // HEAT conversion builder
  CurrencyBuilder& heatConversionRate(uint64_t val) { m_currency.m_heatConversionRate = val; return *this; }

  // Money supply builders
  CurrencyBuilder& baseMoneySupply(uint64_t val) { m_currency.m_baseMoneySupply = val; return *this; }
  CurrencyBuilder& etherealXfg(uint64_t val) { m_currency.m_ethereal_xfg = val; return *this; }

  // Network validation builder
  CurrencyBuilder& fuegoNetworkId(uint64_t val) { m_currency.m_fuegoNetworkId = val; return *this; }
  CurrencyBuilder& fuegoNetworkIdString(const std::string& val) { m_currency.m_fuegoNetworkIdString = val; return *this; }

  CurrencyBuilder& mempoolTxLiveTime(uint64_t val) { m_currency.m_mempoolTxLiveTime = val; return *this; }
  CurrencyBuilder& mempoolTxFromAltBlockLiveTime(uint64_t val) { m_currency.m_mempoolTxFromAltBlockLiveTime = val; return *this; }
  CurrencyBuilder& numberOfPeriodsToForgetTxDeletedFromPool(uint64_t val) { m_currency.m_numberOfPeriodsToForgetTxDeletedFromPool = val; return *this; }
  CurrencyBuilder& transactionMaxSize(size_t val) { m_currency.m_transactionMaxSize = val; return *this;  }
  CurrencyBuilder& fusionTxMaxSize(size_t val) { m_currency.m_fusionTxMaxSize = val; return *this; }
  CurrencyBuilder& fusionTxMinInputCount(size_t val) { m_currency.m_fusionTxMinInputCount = val; return *this; }
  CurrencyBuilder& fusionTxMinInOutCountRatio(size_t val) { m_currency.m_fusionTxMinInOutCountRatio = val; return *this; }
  CurrencyBuilder& upgradeHeightV2(uint64_t val) { m_currency.m_upgradeHeightV2 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV3(uint64_t val) { m_currency.m_upgradeHeightV3 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV4(uint64_t val) { m_currency.m_upgradeHeightV4 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV5(uint64_t val) { m_currency.m_upgradeHeightV5 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV6(uint64_t val) { m_currency.m_upgradeHeightV6 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV7(uint64_t val) { m_currency.m_upgradeHeightV7 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV8(uint64_t val) { m_currency.m_upgradeHeightV8 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV9(uint64_t val) { m_currency.m_upgradeHeightV9 = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeHeightV10(uint64_t val) { m_currency.m_upgradeHeightV10 = static_cast<uint32_t>(val); return *this; }//upgradekit
    CurrencyBuilder& upgradeHeightV11(uint64_t val) { m_currency.m_upgradeHeightV11 = static_cast<uint32_t>(val); return *this; }//HearthAMM+HEAT
    CurrencyBuilder& upgradeHeightV12(uint64_t val) { m_currency.m_upgradeHeightV12 = static_cast<uint32_t>(val); return *this; }//CDs+unified outputs
    CurrencyBuilder& bootstrapBlocks(uint64_t val) { m_currency.m_bootstrapBlocks = static_cast<uint32_t>(val); return *this; }


  CurrencyBuilder& upgradeVotingThreshold(unsigned int val);
  CurrencyBuilder& upgradeVotingWindow(size_t val) { m_currency.m_upgradeVotingWindow = static_cast<uint32_t>(val); return *this; }
  CurrencyBuilder& upgradeWindow(size_t val);
  CurrencyBuilder& blocksFileName(const std::string& val) { m_currency.m_blocksFileName = val; return *this; }
  CurrencyBuilder& blocksCacheFileName(const std::string& val) { m_currency.m_blocksCacheFileName = val; return *this; }
  CurrencyBuilder& blockIndexesFileName(const std::string& val) { m_currency.m_blockIndexesFileName = val; return *this; }
  CurrencyBuilder& txPoolFileName(const std::string& val) { m_currency.m_txPoolFileName = val; return *this; }
  CurrencyBuilder& blockchinIndicesFileName(const std::string& val) { m_currency.m_blockchinIndicesFileName = val; return *this; }

  CurrencyBuilder& testnet(bool val) {
    m_currency.m_testnet = val;

    // Set testnet-specific address prefix when testnet mode is enabled
    if (val) {
      publicAddressBase58Prefix(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_TESTNET);
      subAddressBase58Prefix(CRYPTONOTE_SUBADDRESS_BASE58_PREFIX_TESTNET);
      // Set testnet-specific deposit terms
      depositMinTerm(parameters::TESTNET_CD_MIN_EPOCHS * parameters::TESTNET_EPOCH_DURATION_BLOCKS);
      depositMaxTerm(parameters::TESTNET_CD_MAX_EPOCHS * parameters::TESTNET_EPOCH_DURATION_BLOCKS);
      // Set testnet-specific mined money unlock window
      minedMoneyUnlockWindow(parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_TESTNET);
    } else {
      // Set mainnet deposit terms when switching from testnet to mainnet
      depositMinTerm(parameters::CD_MIN_EPOCHS * parameters::EPOCH_DURATION_BLOCKS);
      depositMaxTerm(parameters::CD_MAX_EPOCHS * parameters::EPOCH_DURATION_BLOCKS);
      // Set mainnet mined money unlock window
      minedMoneyUnlockWindow(parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
    }

    return *this;
  }

  private:
    Currency m_currency;
  };

} // namespace CryptoNote
