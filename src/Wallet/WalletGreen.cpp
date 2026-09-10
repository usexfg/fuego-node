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

#include "WalletGreen.h"

#include <algorithm>
#include <array>
#include <ctime>
#include <cassert>
#include <numeric>
#include <random>
#include <set>
#include <tuple>
#include <utility>
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#include <System/EventLock.h>
#include <System/RemoteContext.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "ITransaction.h"

#include "Common/ScopeExit.h"
#include "Common/ShuffleGenerator.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Common/StringTools.h"
#include "Common/Int128.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionApi.h"
#include <CryptoNoteCore/TransactionExtra.h>
#include "CryptoNoteCore/DepositCommitment.h"
#include "CryptoNoteCore/CommitmentIndex.h"
#include "INode.h"
#include "crypto/crypto.h"
#include "crypto/keccak.h"
#include "Transfers/TransfersContainer.h"
#include "WalletSerializationV1.h"
#include "WalletSerializationV2.h"
#include "WalletErrors.h"
#include "WalletUtils.h"
#include "DynamicRingSize.h"

using namespace Common;
using namespace Crypto;
using namespace CryptoNote;
using namespace Logging;

namespace
{
  // Dynamax for commitment/HEAT rings: probe at maxMixin, settle on largest of
  // {32,16,8} achievable from available same-amount outs (including the real).
  // When the HEAT decoy pool is empty at launch, allow ring size 1 (real only)
  // so txs can still clear — pool grows as mints/deposits land.
  size_t pickDynamaxCommitmentRingSize(size_t availableSameAmount, size_t maxRing, size_t minRingMainnet) {
    if (availableSameAmount == 0) {
      return 1; // should not happen (at least the real exists when building)
    }
    std::vector<CryptoNote::OutputInfo> infos;
    infos.emplace_back(0, availableSameAmount);
    // minRing=0 allows bootstrap below 8 when pool is thin (HEAT launch)
    size_t opt = CryptoNote::DynamicRingSizeCalculator::calculateOptimalRingSize(
      0, infos, CryptoNote::BLOCK_MAJOR_VERSION_10, /*minRing*/0, maxRing);
    if (opt == 0) {
      // No approved 8/16/32 fit — use whatever we have (bootstrap), at least 1
      return std::min(availableSameAmount, maxRing);
    }
    // Prefer not to go below mainnet min when pool can support it
    if (opt < minRingMainnet && availableSameAmount >= minRingMainnet) {
      return minRingMainnet;
    }
    return opt;
  }

  uint64_t normalizeMixinProbe(uint64_t mixin, size_t maxMixin) {
    // Clients may pass 0 meaning "default"; treat as max probe for dynamax.
    if (mixin == 0) {
      return static_cast<uint64_t>(maxMixin);
    }
    return mixin;
  }

  #pragma pack(push, 1)
  struct LegacyEncryptedWalletRecord {
    Crypto::chacha8_iv iv;
    uint8_t data[sizeof(Crypto::PublicKey) + sizeof(Crypto::SecretKey) + sizeof(uint64_t)];
  };

  struct LegacyContainerStoragePrefix {
    uint8_t version;
    Crypto::chacha8_iv nextIv;
    LegacyEncryptedWalletRecord encryptedViewKeys;
  };
  #pragma pack(pop)

  std::vector<uint64_t> split(uint64_t amount, uint64_t dustThreshold)
  {
    std::vector<uint64_t> amounts;

    decompose_amount_into_digits(
        amount, dustThreshold,
        [&](uint64_t chunk) { amounts.push_back(chunk); },
        [&](uint64_t dust) { amounts.push_back(dust); });

    return amounts;
  }

  uint64_t calculateDepositsAmount(
      const std::vector<CryptoNote::TransactionOutputInformation> &transfers,
      const CryptoNote::Currency &currency,
      const std::vector<uint32_t> heights)
  {
    int index = 0;
    return std::accumulate(transfers.begin(), transfers.end(), static_cast<uint64_t>(0), [&currency, &index, heights](uint64_t sum, const CryptoNote::TransactionOutputInformation &deposit) {
      // Interest calculation removed - no on-chain interest
      return sum + deposit.amount;
    });
  }

  void asyncRequestCompletion(System::Event &requestFinished)
  {
    requestFinished.set();
  }

  void parseAddressString(
      const std::string &string,
      const CryptoNote::Currency &currency,
      CryptoNote::AccountPublicAddress &address)
  {
    if (!currency.parseAccountAddressString(string, address))
    {
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
    }
  }

  uint64_t countNeededMoney(
      const std::vector<CryptoNote::WalletTransfer> &destinations,
      uint64_t fee)
  {
    uint64_t neededMoney = 0;
    for (const auto &transfer : destinations)
    {
      if (transfer.amount == 0)
      {
        throw std::system_error(make_error_code(CryptoNote::error::ZERO_DESTINATION));
      }
      else if (transfer.amount < 0)
      {
        throw std::system_error(make_error_code(std::errc::invalid_argument));
      }

      //to supress warning
      uint64_t uamount = static_cast<uint64_t>(transfer.amount);
      neededMoney += uamount;
      if (neededMoney < uamount)
      {
        throw std::system_error(make_error_code(CryptoNote::error::SUM_OVERFLOW));
      }
    }

    neededMoney += fee;
    if (neededMoney < fee)
    {
      throw std::system_error(make_error_code(CryptoNote::error::SUM_OVERFLOW));
    }

    return neededMoney;
  }

  void checkIfEnoughMixins(std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount> &mixinResult, uint64_t mixIn)
  {
    auto notEnoughIt = std::find_if(mixinResult.begin(), mixinResult.end(),
                                    [mixIn](const CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount &ofa) { return ofa.outs.size() < mixIn; });

    if (mixIn == 0 && mixinResult.empty())
    {
      throw std::system_error(make_error_code(CryptoNote::error::MIXIN_COUNT_TOO_BIG));
    }

    if (notEnoughIt != mixinResult.end())
    {
      throw std::system_error(make_error_code(CryptoNote::error::MIXIN_COUNT_TOO_BIG));
    }
  }

  CryptoNote::WalletEvent makeTransactionUpdatedEvent(size_t id)
  {
    CryptoNote::WalletEvent event;
    event.type = CryptoNote::WalletEventType::TRANSACTION_UPDATED;
    event.transactionUpdated.transactionIndex = id;

    return event;
  }

  CryptoNote::WalletEvent makeTransactionCreatedEvent(size_t id)
  {
    CryptoNote::WalletEvent event;
    event.type = CryptoNote::WalletEventType::TRANSACTION_CREATED;
    event.transactionCreated.transactionIndex = id;

    return event;
  }

  CryptoNote::WalletEvent makeMoneyUnlockedEvent()
  {
    CryptoNote::WalletEvent event;
    event.type = CryptoNote::WalletEventType::BALANCE_UNLOCKED;

    return event;
  }

  CryptoNote::WalletEvent makeSyncProgressUpdatedEvent(uint32_t current, uint32_t total)
  {
    CryptoNote::WalletEvent event;
    event.type = CryptoNote::WalletEventType::SYNC_PROGRESS_UPDATED;
    event.synchronizationProgressUpdated.processedBlockCount = current;
    event.synchronizationProgressUpdated.totalBlockCount = total;
    return event;
  }

  CryptoNote::WalletEvent makeSyncCompletedEvent()
  {
    CryptoNote::WalletEvent event;
    event.type = CryptoNote::WalletEventType::SYNC_COMPLETED;

    return event;
  }

  size_t getTransactionSize(const ITransactionReader &transaction)
  {
    return transaction.getTransactionData().size();
  }

  std::vector<WalletTransfer> convertOrdersToTransfers(const std::vector<WalletOrder> &orders)
  {
    std::vector<WalletTransfer> transfers;
    transfers.reserve(orders.size());

    for (const auto &order : orders)
    {
      WalletTransfer transfer;

      if (order.amount > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
      {
        throw std::system_error(make_error_code(CryptoNote::error::WRONG_AMOUNT),
                                "Order amount must not exceed " + std::to_string(std::numeric_limits<decltype(transfer.amount)>::max()));
      }

      transfer.type = WalletTransferType::USUAL;
      transfer.address = order.address;
      transfer.amount = static_cast<int64_t>(order.amount);

      transfers.emplace_back(std::move(transfer));
    }

    return transfers;
  }

  uint64_t calculateDonationAmount(uint64_t freeAmount, uint64_t donationThreshold, uint64_t dustThreshold)
  {
    std::vector<uint64_t> decomposedAmounts;
    decomposeAmount(freeAmount, dustThreshold, decomposedAmounts);

    std::sort(decomposedAmounts.begin(), decomposedAmounts.end(), std::greater<uint64_t>());

    uint64_t donationAmount = 0;
    for (auto amount : decomposedAmounts)
    {
      if (amount > donationThreshold - donationAmount)
      {
        continue;
      }

      donationAmount += amount;
    }

    assert(donationAmount <= freeAmount);
    return donationAmount;
  }

  uint64_t pushDonationTransferIfPossible(const DonationSettings &donation, uint64_t freeAmount, uint64_t dustThreshold, std::vector<WalletTransfer> &destinations)
  {
    uint64_t donationAmount = 0;
    if (!donation.address.empty() && donation.threshold != 0)
    {
      if (donation.threshold > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
      {
        throw std::system_error(make_error_code(error::WRONG_AMOUNT),
                                "Donation threshold must not exceed " + std::to_string(std::numeric_limits<int64_t>::max()));
      }

      donationAmount = calculateDonationAmount(freeAmount, donation.threshold, dustThreshold);
      if (donationAmount != 0)
      {
        destinations.emplace_back(WalletTransfer{WalletTransferType::DONATION, donation.address, static_cast<int64_t>(donationAmount)});
      }
    }

    return donationAmount;
  }

  CryptoNote::AccountPublicAddress parseAccountAddressString(
      const std::string &addressString,
      const CryptoNote::Currency &currency)
  {
    CryptoNote::AccountPublicAddress address;

    if (!currency.parseAccountAddressString(addressString, address))
    {
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
    }

    return address;
  }

} // namespace

namespace CryptoNote
{

  WalletGreen::WalletGreen(System::Dispatcher &dispatcher, const Currency &currency, INode &node, Logging::ILogger &logger, uint32_t transactionSoftLockTime) : m_dispatcher(dispatcher),
                                                                                                                                                                m_currency(currency),
                                                                                                                                                                m_node(node),
                                                                                                                                                                m_logger(logger, "WalletGreen"),
                                                                                                                                                                m_stopped(false),
                                                                                                                                                                m_blockchainSynchronizerStarted(false),
                                                                                                                                                                m_blockchainSynchronizer(node, currency.genesisBlockHash()),
                                                                                                                                                                m_synchronizer(currency, logger, m_blockchainSynchronizer, node),
                                                                                                                                                                m_eventOccurred(m_dispatcher),
                                                                                                                                                                m_readyEvent(m_dispatcher),
                                                                                                                                                                m_state(WalletState::NOT_INITIALIZED),
                                                                                                                                                                m_actualBalance(0),
                                                                                                                                                                m_pendingBalance(0),
                                                                                                                                                                m_lockedDepositBalance(0),
                                                                                                                                                                m_unlockedDepositBalance(0),
                                                                                                                                                                m_creationTimestamp(0),
                                                                                                                                                                m_transactionSoftLockTime(transactionSoftLockTime)  {
    m_upperTransactionSizeLimit = m_currency.transactionMaxSize();
    m_readyEvent.set();
  }

  WalletGreen::~WalletGreen()
  {
    if (m_state == WalletState::INITIALIZED)
    {
      doShutdown();
    }

    m_dispatcher.yield(); //let remote spawns finish
  }

  void WalletGreen::initialize(
      const std::string &path,
      const std::string &password)
  {
    Crypto::PublicKey viewPublicKey;
    Crypto::SecretKey viewSecretKey;
    Crypto::generate_keys(viewPublicKey, viewSecretKey);
    initWithKeys(path, password, viewPublicKey, viewSecretKey);
    m_logger(DEBUGGING, BRIGHT_WHITE) << "New container initialized, public view key " << Common::podToHex(viewPublicKey);
  }

  uint64_t WalletGreen::capInterestByPool(DepositId depositId, uint64_t formulaInterest,
                                          uint64_t& bonusOut, uint32_t term) {
    bonusOut = 0;
    if (formulaInterest == 0) return 0;
    Deposit deposit = getDeposit(depositId);
    INode::CdClaimInfo claimInfo;
    std::error_code ec = m_node.getCdClaimInfo(deposit.amount,
        static_cast<uint32_t>(deposit.height), getBlockCount(), claimInfo, term);
    if (ec || !claimInfo.poolInfoPresent) {
      // Daemon predates pool-aware estimates: keep formula (legacy behavior).
      return formulaInterest;
    }
    uint64_t backing = std::min(claimInfo.feePoolBalance, claimInfo.vaultBalance);
    if (claimInfo.baseInterest > 0 || claimInfo.bonusInterest > 0) {
      // v11+: consensus split — pool-backed base + BV-backed bonus.
      uint64_t baseClaim = std::min(claimInfo.baseInterest, backing);
      uint64_t bonusClaim = std::min(claimInfo.claimableBonus, claimInfo.bonusVaultBalance);
      if (backing < claimInfo.baseInterest) {
        m_logger(WARNING, BRIGHT_YELLOW)
            << "CD yield pool cannot back full base interest for deposit "
            << depositId << " (" << claimInfo.baseInterest << " accrued, "
            << backing << " HEAT backing) — rare event. The remainder stays "
            << "accrued and becomes claimable when the pool replenishes from "
            << "epoch fees.";
      }
      if (claimInfo.bonusVaultBalance < claimInfo.claimableBonus) {
        m_logger(WARNING, BRIGHT_YELLOW)
            << "Bonus vault cannot back the full tier bonus for deposit "
            << depositId << " (" << claimInfo.claimableBonus << " bonus, "
            << claimInfo.bonusVaultBalance << " HEAT BV backing) — rare event.";
      }
      bonusOut = bonusClaim;
      return (baseClaim > UINT64_MAX - bonusClaim) ? UINT64_MAX : (baseClaim + bonusClaim);
    }
    if (backing < formulaInterest) {
      m_logger(WARNING, BRIGHT_YELLOW)
          << "CD yield pool cannot back full accrued interest for deposit "
          << depositId << " (" << formulaInterest << " accrued, " << backing
          << " HEAT backing) — rare event. The remainder stays accrued and "
          << "becomes claimable when the pool replenishes from epoch fees.";
      return backing;
    }
    return formulaInterest;
  }

  void WalletGreen::withdrawDeposit(
      DepositId depositId,
      std::string &transactionHash)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    if (m_deposits.size() <= depositId) {
      throw std::system_error(make_error_code(CryptoNote::error::DEPOSIT_DOESNOT_EXIST));
    }

    Deposit deposit = getDeposit(depositId);
    WalletTransfer firstTransfer = getTransactionTransfer(deposit.creatingTransactionId, 0);
    std::string address = firstTransfer.address;

    if (deposit.unlockHeight > getBlockCount()) {
      throw std::system_error(make_error_code(CryptoNote::error::DEPOSIT_LOCKED));
    }

    const auto &wallet = getWalletRecord(address);
    ITransfersContainer *container = wallet.container;
    AccountKeys account = makeAccountKeys(wallet);
    ITransfersContainer::TransferState state;
    TransactionOutputInformation transfer;

    container->getTransfer(deposit.transactionHash, deposit.outputInTransaction, transfer, state);

    if (state != ITransfersContainer::TransferState::TransferAvailable) {
      throw std::system_error(make_error_code(CryptoNote::error::DEPOSIT_LOCKED));
    }

    m_logger(DEBUGGING, BRIGHT_WHITE) << "Withdraw deposit id=" << depositId
      << " amount=" << deposit.amount
      << " globalOutputIndex=" << transfer.globalOutputIndex
      << " type=" << static_cast<int>(transfer.type);

    // Accrued CD interest (pool-aware): claim what consensus accepts today.
    // Only finite-term HEAT CDs earn — HEAT_TERM (0xFFFFFFFF) outputs are
    // mint/burn outputs with no APY, and DEPOSIT_TERM_LP markers are pool
    // reserve tags. Pre-v11 deposits cannot claim (consensus rejects); an
    // empty yield pool is a rare event — capInterestByPool warns so the user
    // knows the remainder is forfeited now but becomes claimable once the
    // pool replenishes from epoch fees.
    uint64_t claimedInterest = 0;
    uint64_t claimedBonus = 0;
    if (deposit.term > 0 &&
        deposit.term != parameters::HEAT_TERM &&
        deposit.term != parameters::DEPOSIT_TERM_LP &&
        static_cast<uint32_t>(deposit.height) >=
            m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_11)) {
      INode::CdClaimInfo claimInfo;
      std::error_code ec = m_node.getCdClaimInfo(deposit.amount,
          static_cast<uint32_t>(deposit.height), getBlockCount(), claimInfo);
      if (!ec && claimInfo.formulaInterest > 0) {
        claimedInterest = claimInfo.poolInfoPresent
            ? capInterestByPool(depositId, claimInfo.formulaInterest, claimedBonus, deposit.term)
            : claimInfo.formulaInterest;
      }
    }

    std::unique_ptr<ITransaction> transaction = createTransaction();

    // Outputs: deposit amount + claimable interest minus fee, split back to
    // spendable key outputs. claimedInterest is added to the input side of the
    // conservation check by getTransactionInputAmount.
    const uint64_t fee = m_currency.minimumFee();
    std::vector<uint64_t> outputAmounts = split(deposit.amount + claimedInterest - fee, m_currency.defaultDustThreshold());
    for (auto amount : outputAmounts) {
      transaction->addOutput(amount, account.address);
    }
    transaction->setUnlockTime(0);

    if (transfer.type == TransactionTypes::OutputType::Commitment) {
      // --- v10+ ring-signature commitment withdrawal ---

      // Retrieve keyScalar stored at deposit creation time.
      Crypto::SecretKey keyScalar;
      uint64_t storedAmount;
      std::vector<uint8_t> meta;
      std::string txHashHex = Common::podToHex(deposit.transactionHash);

      if (!getBurnDepositSecret(txHashHex, keyScalar, storedAmount, meta)) {
        throw std::system_error(make_error_code(CryptoNote::error::DEPOSIT_LOCKED),
          "Commitment deposit secret not found — deposit may be a HEAT burn or secret was lost");
      }

      // Re-derive commitKey and keyImage from keyScalar.
      Crypto::PublicKey commitKey;
      if (!Crypto::secret_key_to_public_key(keyScalar, commitKey)) {
        throw std::system_error(make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR),
          "Failed to derive commitment public key from keyScalar");
      }
      Crypto::KeyImage keyImage;
      Crypto::generate_key_image(commitKey, keyScalar, keyImage);

      // Fetch ring decoys from daemon.
      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> decoys;
      System::Event requestFinished(m_dispatcher);
      std::error_code nodeError;

      throwIfStopped();
      m_node.getRandomCommitmentOutsForAmount(deposit.amount, m_currency.maxMixin(), deposit.height, decoys,
        [&requestFinished, &nodeError, this](std::error_code ec) {
          nodeError = ec;
          this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
        });
      requestFinished.wait();

      if (nodeError) {
        throw std::system_error(nodeError);
      }

      // Remove any decoy that duplicates the real output's global index.
      decoys.erase(std::remove_if(decoys.begin(), decoys.end(),
        [&](const CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry& d) {
          return d.global_amount_index == transfer.globalOutputIndex;
        }), decoys.end());

      const size_t numDecoys    = std::min(decoys.size(), static_cast<size_t>(m_currency.maxMixin() - 1));
      const size_t actualRing   = numDecoys + 1;
      const size_t realPos      = Crypto::rand<size_t>() % actualRing;

      std::vector<uint32_t>              absIndices;
      std::vector<const Crypto::PublicKey*> ringKeys;
      absIndices.reserve(actualRing);
      ringKeys.reserve(actualRing);

      size_t decoyPos = 0;
      for (size_t slot = 0; slot < actualRing; ++slot) {
        if (slot == realPos) {
          absIndices.push_back(transfer.globalOutputIndex);
          ringKeys.push_back(&commitKey);
        } else {
          absIndices.push_back(decoys[decoyPos].global_amount_index);
          ringKeys.push_back(&decoys[decoyPos].commit_key);
          ++decoyPos;
        }
      }

      // Sort ring by ascending global index; track new real position.
      std::vector<size_t> order(actualRing);
      std::iota(order.begin(), order.end(), 0);
      std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return absIndices[a] < absIndices[b];
      });
      size_t sortedRealPos = 0;
      std::vector<uint32_t>              sortedAbs(actualRing);
      std::vector<const Crypto::PublicKey*> sortedKeys(actualRing);
      for (size_t s = 0; s < actualRing; ++s) {
        sortedAbs[s]  = absIndices[order[s]];
        sortedKeys[s] = ringKeys[order[s]];
        if (order[s] == realPos) sortedRealPos = s;
      }

      // Delta-encode absolute indices to relative offsets.
      std::vector<uint32_t> relOffsets(actualRing);
      relOffsets[0] = sortedAbs[0];
      for (size_t s = 1; s < actualRing; ++s) {
        relOffsets[s] = sortedAbs[s] - sortedAbs[s - 1];
      }

      TransactionInputCommitmentSpend csInput;
      csInput.amount        = deposit.amount;
      csInput.claimedInterest = claimedInterest;
      csInput.outputIndexes = relOffsets;
      csInput.keyImage      = keyImage;
      transaction->addInput(csInput);

      KeyPair commitmentKeyPair{ commitKey, keyScalar };
      transaction->signInputCommitmentSpend(0, sortedKeys, commitmentKeyPair, sortedRealPos);

      // v11+: declare the BV-backed bonus portion (drawn from BONUS_VAULT).
      if (claimedBonus > 0) {
        TransactionExtraCdBonusClaim bc;
        bc.inputIndex = 0;
        bc.claimedBonus = claimedBonus;
        std::vector<uint8_t> extra;
        addCdBonusClaimToExtra(extra, bc);
        transaction->appendExtra(extra);
      }

      m_logger(DEBUGGING, BRIGHT_GREEN) << "Commitment withdrawal ring size=" << actualRing
        << " realPos=" << sortedRealPos;

    } else {
      // --- Legacy MultisignatureInput withdrawal path (pre-v10 deposits) ---
      std::vector<TransactionOutputInformation> selectedTransfers = { transfer };
      std::vector<MultisignatureInput> inputs = prepareMultisignatureInputs(selectedTransfers);
      for (const auto &input : inputs) {
        transaction->addInput(input);
      }
      for (size_t i = 0; i < inputs.size(); ++i) {
        transaction->signInputMultisignature(i, selectedTransfers[i].transactionPublicKey,
                                              selectedTransfers[i].outputInTransaction, account);
      }
    }

    transactionHash = Common::podToHex(transaction->getTransactionHash());
    size_t id = validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  Crypto::SecretKey WalletGreen::getTransactionDeterministicSecretKey(Crypto::Hash &transactionHash) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    Crypto::SecretKey txKey = CryptoNote::NULL_SECRET_KEY;

    auto getTransactionCompleted = std::promise<std::error_code>();
    auto getTransactionWaitFuture = getTransactionCompleted.get_future();
    CryptoNote::Transaction tx;
    m_node.getTransaction(std::move(transactionHash), std::ref(tx),
                          [&getTransactionCompleted](std::error_code ec) {
                            auto detachedPromise = std::move(getTransactionCompleted);
                            detachedPromise.set_value(ec);
                          });
    std::error_code ec = getTransactionWaitFuture.get();
    if (ec)
    {
      m_logger(ERROR) << "Failed to get tx: " << ec << ", " << ec.message();
      return CryptoNote::NULL_SECRET_KEY;
    }

    Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);
    KeyPair deterministicTxKeys;
    bool ok = generateDeterministicTransactionKeys(tx, m_viewSecretKey, deterministicTxKeys) && deterministicTxKeys.publicKey == txPubKey;

    return ok ? deterministicTxKeys.secretKey : CryptoNote::NULL_SECRET_KEY;

    return txKey;
  }

  std::vector<MultisignatureInput> WalletGreen::prepareMultisignatureInputs(const std::vector<TransactionOutputInformation> &selectedTransfers)
  {
    std::vector<MultisignatureInput> inputs;
    inputs.reserve(selectedTransfers.size());

    for (const auto &output : selectedTransfers)
    {
      assert(output.type == TransactionTypes::OutputType::Multisignature);
      assert(output.requiredSignatures == 1); //Other types are currently unsupported

      MultisignatureInput input;
      input.amount = output.amount;
      input.signatureCount = output.requiredSignatures;
      input.outputIndex = output.globalOutputIndex;
      input.term = output.term;

      inputs.emplace_back(std::move(input));
    }

    return inputs;
  }

  // Phase 5: Implementation - Get maturing deposits
  std::vector<DepositId> WalletGreen::getMaturingDeposits(uint32_t currentHeight, uint32_t maturingIn) const
  {
    std::vector<DepositId> result;
    uint32_t checkHeight = currentHeight + maturingIn;

    for (size_t i = 0; i < m_deposits.size(); ++i) {
      const Deposit& dep = m_deposits[i];
      // Check if deposit is unlocked (or will be within maturingIn blocks)
      if (dep.unlockHeight <= checkHeight) {
        result.push_back(i);
      }
    }

    return result;
  }

  // Phase 5: Rollover a mature CD to reinvest interest
  // Spends the CD (including claimedInterest) and creates a new CD with amount + interest
  bool WalletGreen::rolloverDeposit(
      DepositId depositId,
      uint32_t newTerm,
      const CommitmentIndex& commitmentIndex,
      std::string &txHashOut)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    if (m_deposits.size() <= depositId) {
      m_logger(ERROR) << "Rollover failed: deposit " << depositId << " does not exist";
      return false;
    }

    Deposit deposit = getDeposit(depositId);

    // Verify deposit is mature
    uint32_t currentHeight = getBlockCount();
    if (deposit.unlockHeight > currentHeight) {
      m_logger(ERROR) << "Rollover failed: deposit " << depositId << " is not yet mature"
        << " (unlockHeight=" << deposit.unlockHeight << " > currentHeight=" << currentHeight << ")";
      return false;
    }

    WalletTransfer firstTransfer = getTransactionTransfer(deposit.creatingTransactionId, 0);
    std::string address = firstTransfer.address;

    const auto &wallet = getWalletRecord(address);
    ITransfersContainer *container = wallet.container;
    AccountKeys account = makeAccountKeys(wallet);
    ITransfersContainer::TransferState state;
    TransactionOutputInformation transfer;

    container->getTransfer(deposit.transactionHash, deposit.outputInTransaction, transfer, state);

    if (state != ITransfersContainer::TransferState::TransferAvailable) {
      m_logger(ERROR) << "Rollover failed: deposit output is not available";
      return false;
    }

    // Calculate accumulated interest.
    // v11 zero-claim consensus rule: deposits created before v11 activation
    // cannot claim CD yield (Blockchain.cpp youngest-ring pre-v11 gate), so
    // zero the claim here to avoid building a tx the consensus rejects.
    // Only finite-term HEAT CDs earn: HEAT_TERM mint/burn outputs and
    // DEPOSIT_TERM_LP markers have no APY.
    uint64_t interest = 0;
    if (deposit.term > 0 &&
        deposit.term != parameters::HEAT_TERM &&
        deposit.term != parameters::DEPOSIT_TERM_LP) {
      interest = m_currency.calculateCdInterest(
          deposit.amount,
          deposit.height,
          currentHeight,
          commitmentIndex,
          false, deposit.term, false);
      if (deposit.height < m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_11)) {
        interest = 0;
      }
    }
    // Pool-aware cap: consensus only accepts claims backed by the fee pool and
    // CD_APY_POOL vault. Capping here keeps the rollover tx from being rejected.
    uint64_t rolloverBonus = 0;
    interest = capInterestByPool(depositId, interest, rolloverBonus, deposit.term);

    m_logger(DEBUGGING, BRIGHT_WHITE) << "Rollover deposit id=" << depositId
      << " amount=" << deposit.amount
      << " interest=" << interest
      << " newTerm=" << newTerm
      << " globalOutputIndex=" << transfer.globalOutputIndex;

    std::unique_ptr<ITransaction> transaction = createTransaction();

    // Output: reinvested amount (original + interest)
    uint64_t reinvestedAmount = deposit.amount + interest;
    const uint64_t fee = m_currency.minimumFee();

    m_logger(DEBUGGING, BRIGHT_GREEN) << "Creating new CD with amount=" << reinvestedAmount
      << " term=" << newTerm << " from rollover";

    // Create new commitment output
    std::array<uint8_t, 32> newDepositSecret;
    generate_random_bytes(sizeof(newDepositSecret), newDepositSecret.data());
    CryptoNote::DepositCommitmentKeys newCommitKeys = CryptoNote::deriveCommitmentKeys(newDepositSecret);
    CryptoNote::TransactionOutputCommitment newCommitOut;
    newCommitOut.commitKey = newCommitKeys.commitKey;
    newCommitOut.term = newTerm;

    transaction->addOutput(reinvestedAmount - fee, newCommitOut);
    transaction->setUnlockTime(0);

    // Add commitment spend input with claimed interest
    if (transfer.type == TransactionTypes::OutputType::Commitment) {
      // Retrieve keyScalar for the CD
      Crypto::SecretKey keyScalar;
      uint64_t storedAmount;
      std::vector<uint8_t> meta;
      std::string txHashHex = Common::podToHex(deposit.transactionHash);

      if (!getBurnDepositSecret(txHashHex, keyScalar, storedAmount, meta)) {
        m_logger(ERROR) << "Rollover failed: commitment secret not found";
        return false;
      }

      // Derive commitment key and key image
      Crypto::PublicKey commitKey;
      if (!Crypto::secret_key_to_public_key(keyScalar, commitKey)) {
        m_logger(ERROR) << "Rollover failed: could not derive commitment public key";
        return false;
      }
      Crypto::KeyImage keyImage;
      Crypto::generate_key_image(commitKey, keyScalar, keyImage);

      // Fetch ring decoys
      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> decoys;
      System::Event requestFinished(m_dispatcher);
      std::error_code nodeError;

      throwIfStopped();
      m_node.getRandomCommitmentOutsForAmount(deposit.amount, m_currency.maxMixin(), deposit.height, decoys,
        [&requestFinished, &nodeError, this](std::error_code ec) {
          nodeError = ec;
          this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
        });
      requestFinished.wait();

      if (nodeError) {
        m_logger(ERROR) << "Rollover failed: could not fetch ring decoys: " << nodeError.message();
        return false;
      }

      // Remove duplicates
      decoys.erase(std::remove_if(decoys.begin(), decoys.end(),
        [&](const CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry& d) {
          return d.global_amount_index == transfer.globalOutputIndex;
        }), decoys.end());

      const size_t numDecoys    = std::min(decoys.size(), static_cast<size_t>(m_currency.maxMixin() - 1));
      const size_t actualRing   = numDecoys + 1;
      const size_t realPos      = Crypto::rand<size_t>() % actualRing;

      std::vector<uint32_t>                      absIndices;
      std::vector<const Crypto::PublicKey*>      ringKeys;
      absIndices.reserve(actualRing);
      ringKeys.reserve(actualRing);

      size_t decoyPos = 0;
      for (size_t slot = 0; slot < actualRing; ++slot) {
        if (slot == realPos) {
          absIndices.push_back(transfer.globalOutputIndex);
          ringKeys.push_back(&commitKey);
        } else {
          absIndices.push_back(decoys[decoyPos].global_amount_index);
          ringKeys.push_back(&decoys[decoyPos].commit_key);
          ++decoyPos;
        }
      }

      // Sort ring by ascending global index
      std::vector<size_t> order(actualRing);
      std::iota(order.begin(), order.end(), 0);
      std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return absIndices[a] < absIndices[b];
      });
      size_t sortedRealPos = 0;
      std::vector<uint32_t>                      sortedAbs(actualRing);
      std::vector<const Crypto::PublicKey*>      sortedKeys(actualRing);
      for (size_t s = 0; s < actualRing; ++s) {
        sortedAbs[s]  = absIndices[order[s]];
        sortedKeys[s] = ringKeys[order[s]];
        if (order[s] == realPos) sortedRealPos = s;
      }

      // Delta-encode absolute indices to relative offsets
      std::vector<uint32_t> relOffsets(actualRing);
      relOffsets[0] = sortedAbs[0];
      for (size_t s = 1; s < actualRing; ++s) {
        relOffsets[s] = sortedAbs[s] - sortedAbs[s - 1];
      }

      TransactionInputCommitmentSpend csInput;
      csInput.amount        = deposit.amount;
      csInput.claimedInterest = interest;
      csInput.outputIndexes = relOffsets;
      csInput.keyImage      = keyImage;
      transaction->addInput(csInput);

      KeyPair commitmentKeyPair{ commitKey, keyScalar };
      transaction->signInputCommitmentSpend(0, sortedKeys, commitmentKeyPair, sortedRealPos);

      // v11+: declare the BV-backed bonus portion (drawn from BONUS_VAULT).
      if (rolloverBonus > 0) {
        TransactionExtraCdBonusClaim bc;
        bc.inputIndex = 0;
        bc.claimedBonus = rolloverBonus;
        std::vector<uint8_t> extra;
        addCdBonusClaimToExtra(extra, bc);
        transaction->appendExtra(extra);
      }

      m_logger(DEBUGGING, BRIGHT_GREEN) << "Rollover commitment spend ring size=" << actualRing
        << " realPos=" << sortedRealPos << " claimedInterest=" << interest;

    } else {
      m_logger(ERROR) << "Rollover failed: deposit is not a commitment output";
      return false;
    }

    // Send the transaction
    try {
      BinaryArray txData = transaction->getTransactionData();
      CryptoNote::Transaction cryptoNoteTx;
      if (!fromBinaryArray(cryptoNoteTx, txData)) {
        m_logger(ERROR) << "Rollover failed: could not serialize transaction";
        return false;
      }
      sendTransaction(cryptoNoteTx);
      txHashOut = Common::podToHex(transaction->getTransactionHash());
      m_logger(INFO) << "Rollover transaction sent: " << txHashOut;
      return true;
    } catch (const std::exception& e) {
      m_logger(ERROR) << "Rollover failed to send transaction: " << e.what();
      return false;
    }
  }

  // Overload: accepts pre-computed interest (used by WalletRpcServer without Core access)
  bool WalletGreen::rolloverDeposit(
      DepositId depositId,
      uint32_t newTerm,
      uint64_t precomputedInterest,
      std::string &txHashOut)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    if (m_deposits.size() <= depositId) {
      m_logger(ERROR) << "Rollover failed: deposit " << depositId << " does not exist";
      return false;
    }

    Deposit deposit = getDeposit(depositId);

    uint32_t currentHeight = getBlockCount();
    if (deposit.unlockHeight > currentHeight) {
      m_logger(ERROR) << "Rollover failed: deposit " << depositId << " is not yet mature"
        << " (unlockHeight=" << deposit.unlockHeight << " > currentHeight=" << currentHeight << ")";
      return false;
    }

    WalletTransfer firstTransfer = getTransactionTransfer(deposit.creatingTransactionId, 0);
    std::string address = firstTransfer.address;

    const auto &wallet = getWalletRecord(address);
    ITransfersContainer *container = wallet.container;
    AccountKeys account = makeAccountKeys(wallet);
    ITransfersContainer::TransferState state;
    TransactionOutputInformation transfer;

    container->getTransfer(deposit.transactionHash, deposit.outputInTransaction, transfer, state);

    if (state != ITransfersContainer::TransferState::TransferAvailable) {
      m_logger(ERROR) << "Rollover failed: deposit output is not available";
      return false;
    }

    // Use the pre-computed interest supplied by the caller.
    // v11 zero-claim consensus rule: pre-v11 deposits cannot claim CD yield,
    // so zero the claim to match the consensus gate (see rolloverCd).
    // Only finite-term HEAT CDs earn: HEAT_TERM mint/burn outputs and
    // DEPOSIT_TERM_LP markers have no APY.
    uint64_t interest = precomputedInterest;
    if (deposit.term == parameters::HEAT_TERM ||
        deposit.term == parameters::DEPOSIT_TERM_LP ||
        deposit.term == 0) {
      interest = 0;
    }
    if (deposit.height < m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_11)) {
      interest = 0;
    }
    // Pool-aware cap: consensus only accepts claims backed by the fee pool and
    // CD_APY_POOL vault. Capping here keeps the rollover tx from being rejected.
    uint64_t rolloverBonus = 0;
    interest = capInterestByPool(depositId, interest, rolloverBonus, deposit.term);

    m_logger(DEBUGGING, BRIGHT_WHITE) << "Rollover(precomputed) deposit id=" << depositId
      << " amount=" << deposit.amount
      << " interest=" << interest
      << " newTerm=" << newTerm
      << " globalOutputIndex=" << transfer.globalOutputIndex;

    std::unique_ptr<ITransaction> transaction = createTransaction();

    uint64_t reinvestedAmount = deposit.amount + interest;
    const uint64_t fee = m_currency.minimumFee();

    m_logger(DEBUGGING, BRIGHT_GREEN) << "Creating new CD with amount=" << reinvestedAmount
      << " term=" << newTerm << " from rollover";

    std::array<uint8_t, 32> newDepositSecret;
    generate_random_bytes(sizeof(newDepositSecret), newDepositSecret.data());
    CryptoNote::DepositCommitmentKeys newCommitKeys = CryptoNote::deriveCommitmentKeys(newDepositSecret);
    CryptoNote::TransactionOutputCommitment newCommitOut;
    newCommitOut.commitKey = newCommitKeys.commitKey;
    newCommitOut.term = newTerm;

    transaction->addOutput(reinvestedAmount - fee, newCommitOut);
    transaction->setUnlockTime(0);

    if (transfer.type == TransactionTypes::OutputType::Commitment) {
      Crypto::SecretKey keyScalar;
      uint64_t storedAmount;
      std::vector<uint8_t> meta;
      std::string txHashHex = Common::podToHex(deposit.transactionHash);

      if (!getBurnDepositSecret(txHashHex, keyScalar, storedAmount, meta)) {
        m_logger(ERROR) << "Rollover failed: commitment secret not found";
        return false;
      }

      Crypto::PublicKey commitKey;
      if (!Crypto::secret_key_to_public_key(keyScalar, commitKey)) {
        m_logger(ERROR) << "Rollover failed: could not derive commitment public key";
        return false;
      }
      Crypto::KeyImage keyImage;
      Crypto::generate_key_image(commitKey, keyScalar, keyImage);

      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> decoys;
      System::Event requestFinished(m_dispatcher);
      std::error_code nodeError;

      throwIfStopped();
      m_node.getRandomCommitmentOutsForAmount(deposit.amount, m_currency.maxMixin(), deposit.height, decoys,
        [&requestFinished, &nodeError, this](std::error_code ec) {
          nodeError = ec;
          this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
        });
      requestFinished.wait();

      if (nodeError) {
        m_logger(ERROR) << "Rollover failed: could not fetch ring decoys: " << nodeError.message();
        return false;
      }

      decoys.erase(std::remove_if(decoys.begin(), decoys.end(),
        [&](const CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry& d) {
          return d.global_amount_index == transfer.globalOutputIndex;
        }), decoys.end());

      const size_t numDecoys    = std::min(decoys.size(), static_cast<size_t>(m_currency.maxMixin() - 1));
      const size_t actualRing   = numDecoys + 1;
      const size_t realPos      = Crypto::rand<size_t>() % actualRing;

      std::vector<uint32_t>                      absIndices;
      std::vector<const Crypto::PublicKey*>      ringKeys;
      absIndices.reserve(actualRing);
      ringKeys.reserve(actualRing);

      size_t decoyPos = 0;
      for (size_t slot = 0; slot < actualRing; ++slot) {
        if (slot == realPos) {
          absIndices.push_back(transfer.globalOutputIndex);
          ringKeys.push_back(&commitKey);
        } else {
          absIndices.push_back(decoys[decoyPos].global_amount_index);
          ringKeys.push_back(&decoys[decoyPos].commit_key);
          ++decoyPos;
        }
      }

      std::vector<size_t> order(actualRing);
      std::iota(order.begin(), order.end(), 0);
      std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return absIndices[a] < absIndices[b];
      });
      size_t sortedRealPos = 0;
      std::vector<uint32_t>                      sortedAbs(actualRing);
      std::vector<const Crypto::PublicKey*>      sortedKeys(actualRing);
      for (size_t s = 0; s < actualRing; ++s) {
        sortedAbs[s]  = absIndices[order[s]];
        sortedKeys[s] = ringKeys[order[s]];
        if (order[s] == realPos) sortedRealPos = s;
      }

      std::vector<uint32_t> relOffsets(actualRing);
      relOffsets[0] = sortedAbs[0];
      for (size_t s = 1; s < actualRing; ++s) {
        relOffsets[s] = sortedAbs[s] - sortedAbs[s - 1];
      }

      TransactionInputCommitmentSpend csInput;
      csInput.amount          = deposit.amount;
      csInput.claimedInterest = interest;
      csInput.outputIndexes   = relOffsets;
      csInput.keyImage        = keyImage;
      transaction->addInput(csInput);

      KeyPair commitmentKeyPair{ commitKey, keyScalar };
      transaction->signInputCommitmentSpend(0, sortedKeys, commitmentKeyPair, sortedRealPos);

      // v11+: declare the BV-backed bonus portion (drawn from BONUS_VAULT).
      if (rolloverBonus > 0) {
        TransactionExtraCdBonusClaim bc;
        bc.inputIndex = 0;
        bc.claimedBonus = rolloverBonus;
        std::vector<uint8_t> extra;
        addCdBonusClaimToExtra(extra, bc);
        transaction->appendExtra(extra);
      }

      m_logger(DEBUGGING, BRIGHT_GREEN) << "Rollover(precomputed) commitment spend ring size=" << actualRing
        << " realPos=" << sortedRealPos << " claimedInterest=" << interest;

    } else {
      m_logger(ERROR) << "Rollover failed: deposit is not a commitment output";
      return false;
    }

    try {
      BinaryArray txData = transaction->getTransactionData();
      CryptoNote::Transaction cryptoNoteTx;
      if (!fromBinaryArray(cryptoNoteTx, txData)) {
        m_logger(ERROR) << "Rollover failed: could not serialize transaction";
        return false;
      }
      sendTransaction(cryptoNoteTx);
      txHashOut = Common::podToHex(transaction->getTransactionHash());
      m_logger(INFO) << "Rollover transaction sent: " << txHashOut;
      return true;
    } catch (const std::exception& e) {
      m_logger(ERROR) << "Rollover failed to send transaction: " << e.what();
      return false;
    }
  }

  void WalletGreen::createDeposit(
      uint64_t amount,
      uint64_t term,
      std::string sourceAddress,
      std::string destinationAddress,
      std::string &transactionHash,
      const DepositCommitment& commitment)
  {

    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    /* If a source address is not specified, use the primary (first) wallet
       address for the creation of the deposit */
    if (sourceAddress.empty())
    {
      sourceAddress = getAddress(0);
    }

    if (destinationAddress.empty())
    {
      destinationAddress = sourceAddress;
    }

    /* Ensure that the address is valid and a part of this container */
    validateSourceAddresses({sourceAddress});

    CryptoNote::AccountPublicAddress sourceAddr = parseAddress(sourceAddress);
    CryptoNote::AccountPublicAddress destAddr = parseAddress(destinationAddress);

    /* Create the transaction */
    std::unique_ptr<ITransaction> transaction = createTransaction();

    /* Select the wallet - If no source address was specified then it will pick funds from anywhere
     and the change will go to the primary address of the wallet container */
    std::vector<WalletOuts> wallets;
    wallets = pickWallets({sourceAddress});

    /* Select the transfers */
    uint64_t fee = m_currency.minimumFee();
    uint64_t neededMoney = amount + fee;
    std::vector<OutputToTransfer> selectedTransfers;
    uint64_t foundMoney = selectTransfers(neededMoney,
                                          0 == 0,
                                          m_currency.defaultDustThreshold(),
                                          std::move(wallets),
                                          selectedTransfers);

    /* Do we have enough funds */
    if (foundMoney < neededMoney)
    {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT));
    }

    /* Now we add the outputs to the transaction, starting with the deposits output
     which includes the term, and then after that the change outputs */

    // Generate a random 32-byte deposit secret
    std::array<uint8_t, 32> depositSecret;
    generate_random_bytes(sizeof(depositSecret), depositSecret.data());

    // Derive commitment keys from the deposit secret
    CryptoNote::DepositCommitmentKeys commitKeys = CryptoNote::deriveCommitmentKeys(depositSecret);

    // Create TransactionOutputCommitment instead of MultisignatureOutput
    CryptoNote::TransactionOutputCommitment commitOut;
    commitOut.commitKey = commitKeys.commitKey;
    commitOut.term = static_cast<uint32_t>(term);

    // Add the commitment output to the transaction
    auto bankingIndex = transaction->addOutput(
        neededMoney - fee,
        commitOut);

    // Deposit secret will be stored after inputs are signed (hash is final at that point).

    /* Let's add the change outputs to the transaction */

    std::vector<uint64_t> amounts;

    /* Breakdown the change into specific amounts */
    decompose_amount_into_digits(
        foundMoney - neededMoney,
        m_currency.defaultDustThreshold(),
        [&](uint64_t chunk) { amounts.push_back(chunk); },
        [&](uint64_t dust) { amounts.push_back(dust); });
    std::vector<uint64_t> decomposedChange = amounts;

    /* Now pair each of those amounts to the change address
     which in the case of a deposit is the source address */
    typedef std::pair<const AccountPublicAddress *, uint64_t> AmountToAddress;
    std::vector<AmountToAddress> amountsToAddresses;
    for (const auto &output : decomposedChange)
    {
      amountsToAddresses.emplace_back(AmountToAddress{&sourceAddr, output});
    }

    /* For the sake of privacy, we shuffle the output order randomly */
    std::shuffle(amountsToAddresses.begin(), amountsToAddresses.end(), std::default_random_engine{Crypto::rand<std::default_random_engine::result_type>()});
    std::sort(amountsToAddresses.begin(), amountsToAddresses.end(), [](const AmountToAddress &left, const AmountToAddress &right) {
      return left.second < right.second;
    });

    /* Add the change outputs to the transaction */
    try
    {
      for (const auto &amountToAddress : amountsToAddresses)
      {
        transaction->addOutput(amountToAddress.second,
                               *amountToAddress.first);
      }
    }

    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to add change outputs: " << e.what();
      throw;
    }

    /* Now add the other components of the transaction such as the transaction secret key, unlocktime
     since this is a deposit, we don't need to add messages or added extras beyond the transaction publick key */
    Crypto::SecretKey transactionSK;
    transaction->getTransactionSecretKey(transactionSK);
    transaction->setUnlockTime(0);

    /* Process commitment based on deposit type */
    if (term == CryptoNote::parameters::HEAT_TERM) {
      // HEAT burn/mint is handled exclusively by mintHeatV10().
      // createDeposit() with HEAT_TERM is NOT a valid mint path.
      // The legacy 10M ratio (convertXfgToHeat) must NOT be used for minting.
      throw std::system_error(make_error_code(CryptoNote::error::WRONG_PARAMETERS),
        "HEAT burn/mint must use mintHeatV10(), not createDeposit(HEAT_TERM). "
        "Use createDeposit() only for term-locked HEAT CDs (term != HEAT_TERM).");
    } else {
      // Term-locked HEAT CD (non-HEAT_TERM)
      // The TransactionOutputCommitment output with term field is sufficient;
      // no additional commitment extra needed for term-locked CDs.
      m_logger(DEBUGGING, BRIGHT_GREEN) << "Creating term-locked HEAT CD for " << amount << " XFG term=" << term;
    }

    /* Add the transaction extra for messages (if any) */
    std::vector<WalletMessage> messages;
    Crypto::PublicKey publicKey = transaction->getTransactionPublicKey();
    CryptoNote::KeyPair kp = {publicKey, transactionSK};
    for (size_t i = 0; i < messages.size(); ++i)
    {
      CryptoNote::AccountPublicAddress addressBin;
      if (!m_currency.parseAccountAddressString(messages[i].address, addressBin))
        continue;
      CryptoNote::tx_extra_message tag;
      if (!tag.encrypt(i, messages[i].message, &addressBin, kp))
        continue;
      BinaryArray ba;
      toBinaryArray(tag, ba);
      ba.insert(ba.begin(), TX_EXTRA_MESSAGE_TAG);
      transaction->appendExtra(ba);
    }

    /* Prepare the inputs */

    /* Get additional inputs for the mixin */
    typedef CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
    std::vector<outs_for_amount> mixinResult;
    std::vector<InputInfo> keysInfo;
    prepareInputs(selectedTransfers, mixinResult, m_currency.maxMixin(), keysInfo);

    /* Add the inputs to the transaction */
    std::vector<KeyPair> ephKeys;
    for (auto &input : keysInfo)
    {
      transaction->addInput(makeAccountKeys(*input.walletRecord), input.keyInfo, input.ephKeys);
    }

    /* Now sign the inputs so we can proceed with the transaction */
    size_t i = 0;
    for (auto &input : keysInfo)
    {
      transaction->signInputKey(i++, input.keyInfo, input.ephKeys);
    }

    /* Return the transaction hash — inputs are now signed so hash is final */
    transactionHash = Common::podToHex(transaction->getTransactionHash());

    /* Store deposit secret under the final (post-signing) transaction hash */
    addBurnDepositSecret(transactionHash, commitKeys.keyScalar, neededMoney - fee, std::vector<uint8_t>());

    size_t id = validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  // Split a HEAT amount into standard bill denominations so every output
  // at a given bill size pools into the same decoy set. Greedy largest-first.
  static std::vector<uint64_t> decomposeHeatIntoBills(uint64_t amount) {
    const auto& denoms = CryptoNote::parameters::HEAT_BILL_DENOMINATIONS;
    std::vector<uint64_t> bills;
    uint64_t rem = amount;
    for (uint64_t bill : denoms) {
      while (rem >= bill) {
        bills.push_back(bill);
        rem -= bill;
      }
    }
    if (rem > 0 && !bills.empty())
      bills.front() += rem;
    else if (bills.empty())
      bills.push_back(amount);
    return bills;
  }

  void WalletGreen::mintHeatV10(
      uint64_t xfgBurned,
      uint64_t heatMinted,
      uint64_t fee,
      uint64_t mixin,
      std::string &transactionHash)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    if (xfgBurned == 0) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT));
    }

    fee = m_currency.minimumFee();
    // Dynamax: probe at maxMixin (32); wallet ring construction uses available outs
    mixin = normalizeMixinProbe(mixin, m_currency.maxMixin());

    // Auto-compute heatMinted using the rolling 8-block TWAP of Hearth spot price.
    // Canonical scale: price = HEAT atomics per XFG atomic × COIN.
    // expectedHeat = xfgBurned × price / COIN.
    // Falls back to spot pool rate if TWAP unavailable. Fail closed if no price.
    {
      uint64_t twap = m_node.getHearthTwap();
      if (twap > 0) {
        heatMinted = static_cast<uint64_t>(
            (static_cast<uint128_t>(xfgBurned) * twap) / parameters::COIN);
      } else {
        INode::AmmPoolReserves reserves;
        if (!m_node.getAmmPoolReserves(reserves) && reserves.reserveXfg > 0 && reserves.reserveHeat > 0) {
          // Match the consensus spot fallback exactly: price = floor(rH × COIN / rX),
          // expectedHeat = floor(xfgBurned × price / COIN). Two-step floor avoids the
          // wallet over-quoting (and the mint being rejected).
          uint64_t spotPrice = static_cast<uint64_t>(
              (static_cast<uint128_t>(reserves.reserveHeat) * parameters::COIN) / reserves.reserveXfg);
          heatMinted = static_cast<uint64_t>(
              (static_cast<uint128_t>(xfgBurned) * spotPrice) / parameters::COIN);
        } else {
          throw std::system_error(make_error_code(error::WRONG_AMOUNT),
                                  "No pool price available for HEAT mint");
        }
      }
    }
    if (heatMinted == 0) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "HEAT amount too small for current pool rate");
    }

    // Select XFG inputs for xfgBurned + fee
    std::vector<WalletOuts> wallets = pickWalletsWithMoney();
    std::vector<OutputToTransfer> selectedTransfers;
    uint64_t neededMoney = xfgBurned + fee;
    uint64_t foundMoney = selectTransfers(neededMoney, false, m_currency.defaultDustThreshold(), std::move(wallets), selectedTransfers);

    if (foundMoney < neededMoney) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Insufficient XFG for burn");
    }

    // Create the transaction
    std::unique_ptr<ITransaction> transaction = createTransaction();

    // Build HEAT commitment outputs — split into bill denominations
    std::vector<uint64_t> heatBills = decomposeHeatIntoBills(heatMinted);

    Crypto::SecretKey txSecretKey;
    transaction->getTransactionSecretKey(txSecretKey);
    Crypto::KeyDerivation ecdh;
    Crypto::generate_key_derivation(m_viewPublicKey, txSecretKey, ecdh);

    for (uint64_t billAmount : heatBills) {
      const uint32_t commitOutputIndex = static_cast<uint32_t>(transaction->getOutputCount());
      std::array<uint8_t, 32> depositSecret;
      {
        uint8_t preimage[36];
        memcpy(preimage, &ecdh, 32);
        preimage[32] = commitOutputIndex & 0xFF;
        preimage[33] = (commitOutputIndex >> 8) & 0xFF;
        preimage[34] = (commitOutputIndex >> 16) & 0xFF;
        preimage[35] = (commitOutputIndex >> 24) & 0xFF;
        Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
        memcpy(depositSecret.data(), h.data, 32);
      }
      CryptoNote::DepositCommitmentKeys commitKeys = CryptoNote::deriveCommitmentKeys(depositSecret);
      CryptoNote::TransactionOutputCommitment heatOut;
      heatOut.commitKey = commitKeys.commitKey;
      heatOut.term = parameters::HEAT_TERM;
      transaction->addOutput(billAmount, heatOut);
    }

    // XFG change outputs
    uint64_t changeAmount = foundMoney - neededMoney;
    if (changeAmount > 0) {
      std::vector<uint64_t> decomposedChange = split(changeAmount, m_currency.defaultDustThreshold());
      for (uint64_t changeOut : decomposedChange) {
        transaction->addOutput(changeOut, AccountPublicAddress{selectedTransfers[0].wallet->spendPublicKey, m_viewPublicKey});
      }
    }

    transaction->setUnlockTime(0);

    // Auth tag extra: 0xF5 + 8 bytes LE xfgBurned + 8 bytes LE heatMinted
    std::vector<uint8_t> extra;
    addHeatMintAuthToExtra(extra, xfgBurned, heatMinted);
    CryptoNote::BinaryArray extraData(extra.begin(), extra.end());
    transaction->appendExtra(extraData);

    // XFG inputs with KeyInput ring signatures (dynamax probe mixin)
    typedef CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
    std::vector<outs_for_amount> mixinResult;
    requestMixinOuts(selectedTransfers, mixin, mixinResult);

    std::vector<InputInfo> keysInfo;
    prepareInputs(selectedTransfers, mixinResult, mixin, keysInfo);

    std::vector<KeyPair> ephKeys;
    for (auto &input : keysInfo) {
      transaction->addInput(makeAccountKeys(*input.walletRecord), input.keyInfo, input.ephKeys);
    }
    size_t i = 0;
    for (auto &input : keysInfo) {
      transaction->signInputKey(i++, input.keyInfo, input.ephKeys);
    }

    transactionHash = Common::podToHex(transaction->getTransactionHash());
    size_t id = validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  void WalletGreen::placeLimitOrderV13(
      uint8_t side,
      uint64_t amount,
      uint64_t targetPrice,
      uint32_t expiration,
      uint64_t fee,
      uint64_t mixin,
      std::string &transactionHash)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();
    if (amount == 0 || targetPrice == 0 || side > 1) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }
    fee = m_currency.minimumFee();
    mixin = normalizeMixinProbe(mixin, m_currency.maxMixin());
    std::vector<WalletOuts> wallets = pickWalletsWithMoney();
    std::vector<OutputToTransfer> selectedTransfers;
    uint64_t neededMoney = amount + fee;
    uint64_t foundMoney = selectTransfers(neededMoney, false, m_currency.defaultDustThreshold(), std::move(wallets), selectedTransfers);
    if (foundMoney < neededMoney) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Insufficient funds for limit order");
    }

    std::unique_ptr<ITransaction> transaction = createTransaction();
    Crypto::PublicKey poolKey = CryptoNote::computePoolCommitKey();
    uint32_t poolTerm = (side == 1)
      ? parameters::DEPOSIT_TERM_POOL_XFG
      : parameters::DEPOSIT_TERM_POOL_HEAT;
    CryptoNote::TransactionOutputCommitment poolOut;
    poolOut.commitKey = poolKey;
    poolOut.term = poolTerm;
    transaction->addOutput(amount, poolOut);

    uint64_t changeAmount = foundMoney - neededMoney;
    if (changeAmount > 0) {
      for (uint64_t chunk : split(changeAmount, m_currency.defaultDustThreshold())) {
        transaction->addOutput(chunk, AccountPublicAddress{selectedTransfers[0].wallet->spendPublicKey, m_viewPublicKey});
      }
    }
    transaction->setUnlockTime(0);

    Crypto::Hash orderId{};
    Crypto::generate_random_bytes(sizeof(orderId.data), orderId.data);
    Crypto::Hash addressHash{};
    {
      uint8_t keyData[64];
      memcpy(keyData, selectedTransfers[0].wallet->spendPublicKey.data, 32);
      memcpy(keyData + 32, m_viewPublicKey.data, 32);
      Crypto::cn_fast_hash(keyData, 64, addressHash);
    }
    std::vector<uint8_t> extra;
    addLimitDepositToExtra(extra, side, amount, targetPrice, expiration, orderId, addressHash);
    transaction->appendExtra(CryptoNote::BinaryArray(extra.begin(), extra.end()));

    typedef CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
    std::vector<outs_for_amount> mixinResult;
    requestMixinOuts(selectedTransfers, mixin, mixinResult);
    std::vector<InputInfo> keysInfo;
    prepareInputs(selectedTransfers, mixinResult, mixin, keysInfo);
    for (auto &input : keysInfo) {
      transaction->addInput(makeAccountKeys(*input.walletRecord), input.keyInfo, input.ephKeys);
    }
    size_t i = 0;
    for (auto &input : keysInfo) {
      transaction->signInputKey(i++, input.keyInfo, input.ephKeys);
    }
    transactionHash = Common::podToHex(transaction->getTransactionHash());
    validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  void WalletGreen::cancelLimitOrderV13(
      const Crypto::Hash &orderId,
      uint64_t fee,
      uint64_t mixin,
      std::string &transactionHash)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();
    fee = m_currency.minimumFee();
    mixin = normalizeMixinProbe(mixin, m_currency.maxMixin());

    // Resolve the order owner before building the cancellation transaction.
    // The order id is public, so it is not an authorization factor by itself.
    // The owner address hash from the daemon lets us select the corresponding
    // spend key and produce the consensus-checked withdrawal proof.
    const std::string orderIdHex = Common::podToHex(orderId);
    std::vector<INode::LimitDepositRpcEntry> deposits;
    std::error_code ownerLookupError = m_node.getLimitDeposits(deposits);
    if (ownerLookupError) {
      throw std::system_error(ownerLookupError, "Unable to resolve limit order owner");
    }

    Crypto::Hash ownerAddressHash{};
    bool orderFound = false;
    uint8_t orderSide = 0;
    uint64_t orderAmount = 0;
    uint64_t orderProceedsXfg = 0;
    uint64_t orderProceedsHeat = 0;
    for (const auto& deposit : deposits) {
      if (deposit.order_id == orderIdHex) {
        if (!Common::podFromHex(deposit.address_hash, ownerAddressHash)) {
          throw std::system_error(make_error_code(error::WRONG_PARAMETERS),
                                  "Limit order has an invalid owner hash");
        }
        orderSide = deposit.side;
        orderAmount = deposit.amount;
        orderProceedsXfg = deposit.proceeds_xfg;
        orderProceedsHeat = deposit.proceeds_heat;
        orderFound = true;
        break;
      }
    }
    if (!orderFound) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS),
                              "Limit order does not exist");
    }

    const WalletRecord* ownerWallet = nullptr;
    for (const auto& wallet : m_walletsContainer.get<RandomAccessIndex>()) {
      uint8_t keyData[sizeof(wallet.spendPublicKey.data) + sizeof(m_viewPublicKey.data)];
      memcpy(keyData, wallet.spendPublicKey.data, sizeof(wallet.spendPublicKey.data));
      memcpy(keyData + sizeof(wallet.spendPublicKey.data),
             m_viewPublicKey.data, sizeof(m_viewPublicKey.data));
      Crypto::Hash candidateHash{};
      Crypto::cn_fast_hash(keyData, sizeof(keyData), candidateHash);
      if (memcmp(candidateHash.data, ownerAddressHash.data, sizeof(candidateHash.data)) == 0) {
        ownerWallet = &wallet;
        break;
      }
    }
    if (ownerWallet == nullptr) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS),
                              "Limit order belongs to another wallet");
    }

    std::vector<WalletOuts> wallets = pickWalletsWithMoney();
    std::vector<OutputToTransfer> selectedTransfers;
    uint64_t foundMoney = selectTransfers(fee, false, m_currency.defaultDustThreshold(), std::move(wallets), selectedTransfers);
    if (foundMoney < fee) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Insufficient funds for cancel fee");
    }
    std::unique_ptr<ITransaction> transaction = createTransaction();
    transaction->setUnlockTime(0);
    uint64_t changeAmount = foundMoney - fee;
    if (changeAmount > 0) {
      for (uint64_t chunk : split(changeAmount, m_currency.defaultDustThreshold())) {
        transaction->addOutput(chunk, AccountPublicAddress{selectedTransfers[0].wallet->spendPublicKey, m_viewPublicKey});
      }
    }

    // Exact payout: return the remaining deposit and any fill proceeds so the
    // consensus equality check verifies the full claim.
    auto addHeatCommitmentOutput = [&](uint64_t heatAmount) {
      const uint32_t outIdx = static_cast<uint32_t>(transaction->getOutputCount());
      Crypto::SecretKey txSecretKey;
      transaction->getTransactionSecretKey(txSecretKey);
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(m_viewPublicKey, txSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      preimage[32] = outIdx & 0xFF; preimage[33] = (outIdx >> 8) & 0xFF;
      preimage[34] = (outIdx >> 16) & 0xFF; preimage[35] = (outIdx >> 24) & 0xFF;
      Crypto::Hash h;
      Crypto::cn_fast_hash(preimage, sizeof(preimage), h);
      std::array<uint8_t, 32> secret;
      memcpy(secret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys ck = CryptoNote::deriveCommitmentKeys(secret);
      CryptoNote::TransactionOutputCommitment heatOut;
      heatOut.commitKey = ck.commitKey;
      heatOut.term = parameters::HEAT_TERM;
      transaction->addOutput(heatAmount, heatOut);
    };

    if (orderSide == 1) {
      if (orderAmount > 0) {
        transaction->addOutput(orderAmount, AccountPublicAddress{ownerWallet->spendPublicKey, m_viewPublicKey});
      }
      if (orderProceedsHeat > 0) {
        addHeatCommitmentOutput(orderProceedsHeat);
      }
    } else {
      if (orderProceedsXfg > 0) {
        transaction->addOutput(orderProceedsXfg, AccountPublicAddress{ownerWallet->spendPublicKey, m_viewPublicKey});
      }
      if (orderAmount > 0) {
        addHeatCommitmentOutput(orderAmount);
      }
    }

    Crypto::Hash outputsHash = getLimitWithdrawOutputHash(transaction->getTransactionPrefix().outputs);
    Crypto::Hash authHash = getLimitWithdrawAuthHash(orderId, ownerAddressHash, outputsHash);
    Crypto::Signature proof;
    Crypto::generate_signature(authHash, ownerWallet->spendPublicKey,
                               ownerWallet->spendSecretKey, proof);
    std::vector<uint8_t> extra;
    addLimitWithdrawToExtra(extra, orderId, ownerWallet->spendPublicKey,
                            m_viewPublicKey, outputsHash, proof);
    transaction->appendExtra(CryptoNote::BinaryArray(extra.begin(), extra.end()));
    typedef CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
    std::vector<outs_for_amount> mixinResult;
    requestMixinOuts(selectedTransfers, mixin, mixinResult);
    std::vector<InputInfo> keysInfo;
    prepareInputs(selectedTransfers, mixinResult, mixin, keysInfo);
    for (auto &input : keysInfo) {
      transaction->addInput(makeAccountKeys(*input.walletRecord), input.keyInfo, input.ephKeys);
    }
    size_t i = 0;
    for (auto &input : keysInfo) {
      transaction->signInputKey(i++, input.keyInfo, input.ephKeys);
    }
    transactionHash = Common::podToHex(transaction->getTransactionHash());
    validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  void WalletGreen::heatDepositV10(
      uint64_t amount,
      uint32_t termEpochs,
      uint64_t bankingFee,
      uint64_t fee,
      uint64_t mixin,
      std::string &transactionHash)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    if (amount == 0 || termEpochs == 0) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "amount and term_epochs must be > 0");
    }
    // HEAT CD terms are epoch counts, never HEAT_TERM (mint marker) or bare createDeposit XFG terms
    if (termEpochs == parameters::HEAT_TERM) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "term_epochs must not be HEAT_TERM");
    }

    fee = m_currency.minimumFee();
    if (bankingFee == 0) {
      bankingFee = amount / 1000; // 0.1% default (matches SimpleWallet heat_deposit)
      if (bankingFee == 0) bankingFee = 1;
    }

    const uint64_t epochBlocks = m_currency.isTestnet()
      ? parameters::TESTNET_EPOCH_DURATION_BLOCKS
      : parameters::EPOCH_DURATION_BLOCKS;
    const uint32_t cdTermBlocks = static_cast<uint32_t>(termEpochs * epochBlocks);
    if (cdTermBlocks == 0) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "CD term blocks underflow");
    }

    const uint64_t neededHeat = amount + bankingFee;
    uint32_t currentHeight = getBlockCount();
    uint64_t totalHeat = 0;
    std::vector<size_t> selectedDepositIds;
    for (size_t i = 0; i < m_deposits.size(); ++i) {
      Deposit dep = m_deposits.get<RandomAccessIndex>()[i];
      if (dep.term == parameters::HEAT_TERM
          && !dep.locked
          && dep.unlockHeight <= currentHeight
          && dep.spendingTransactionId == WALLET_INVALID_DEPOSIT_ID) {
        totalHeat += dep.amount;
        selectedDepositIds.push_back(i);
        if (totalHeat >= neededHeat) break;
      }
    }
    if (totalHeat < neededHeat) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Insufficient unlocked HEAT for CD deposit");
    }

    std::unique_ptr<ITransaction> transaction = createTransaction();
    const uint64_t changeAmount = totalHeat - neededHeat;

    // Finite-term HEAT CD commitment (epoch-mapped blocks)
    {
      const uint32_t cdIdx = static_cast<uint32_t>(transaction->getOutputCount());
      std::array<uint8_t, 32> cdSecret;
      Crypto::SecretKey txSecretKey;
      transaction->getTransactionSecretKey(txSecretKey);
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(m_viewPublicKey, txSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      preimage[32] = cdIdx & 0xFF; preimage[33] = (cdIdx >> 8) & 0xFF;
      preimage[34] = (cdIdx >> 16) & 0xFF; preimage[35] = (cdIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      memcpy(cdSecret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys cdKeys = CryptoNote::deriveCommitmentKeys(cdSecret);
      CryptoNote::TransactionOutputCommitment cdOut;
      cdOut.commitKey = cdKeys.commitKey;
      cdOut.term = cdTermBlocks;
      transaction->addOutput(amount, cdOut);
    }

    // Banking fee → Treasury LP Manager (v11+): burned HEAT credited via the
    // TreasuryFund tag (no output — the burn is implicit). Pre-v12: dev-fund output.
    if (bankingFee > 0) {
      uint32_t v11Height = m_currency.upgradeHeight(BLOCK_MAJOR_VERSION_11);
      if (currentHeight >= v11Height) {
        std::vector<uint8_t> extra;
        CryptoNote::addTreasuryFundToExtra(extra, 1, bankingFee);
        CryptoNote::BinaryArray extraData(extra.begin(), extra.end());
        transaction->appendExtra(extraData);
      } else {
        AccountPublicAddress devAddr{};
        if (m_currency.parseAccountAddressString(CryptoNote::FUEGO_DEV_FUND_ADDRESS, devAddr)) {
          transaction->addOutput(bankingFee, devAddr);
        }
      }
    }

    // HEAT change remains FOREVER HEAT_TERM
    if (changeAmount > 0) {
      const uint32_t chIdx = static_cast<uint32_t>(transaction->getOutputCount());
      std::array<uint8_t, 32> chSecret;
      Crypto::SecretKey txSecretKey;
      transaction->getTransactionSecretKey(txSecretKey);
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(m_viewPublicKey, txSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      preimage[32] = chIdx & 0xFF; preimage[33] = (chIdx >> 8) & 0xFF;
      preimage[34] = (chIdx >> 16) & 0xFF; preimage[35] = (chIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      memcpy(chSecret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys cKeys = CryptoNote::deriveCommitmentKeys(chSecret);
      CryptoNote::TransactionOutputCommitment chOut;
      chOut.commitKey = cKeys.commitKey;
      chOut.term = parameters::HEAT_TERM;
      transaction->addOutput(changeAmount, chOut);
    }

    transaction->setUnlockTime(0);

    // Dynamax: probe at maxMixin (32); shrink to 16/8 or bootstrap ring when HEAT pool is thin
    mixin = normalizeMixinProbe(mixin, m_currency.maxMixin());
    const size_t probeCount = static_cast<size_t>(mixin);
    std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> allDecoys;
    {
      Deposit firstDep = m_deposits.get<RandomAccessIndex>()[selectedDepositIds[0]];
      System::Event requestFinished(m_dispatcher);
      std::error_code nodeError;
      m_node.getRandomCommitmentOutsForAmount(firstDep.amount, probeCount, firstDep.height, allDecoys,
        [&requestFinished, &nodeError, this](std::error_code ec) {
          nodeError = ec;
          this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
        });
      requestFinished.wait();
      if (nodeError) {
        // Empty/unknown commitment pool at launch — continue with real-only rings
        allDecoys.clear();
      }
    }

    size_t commitmentDepositIdx = 0;
    for (size_t depIdx = 0; depIdx < selectedDepositIds.size(); ++depIdx) {
      Deposit dep = m_deposits.get<RandomAccessIndex>()[selectedDepositIds[depIdx]];
      WalletTransfer firstTransfer = getTransactionTransfer(dep.creatingTransactionId, 0);
      std::string address = firstTransfer.address;
      const auto &walletRec = getWalletRecord(address);
      ITransfersContainer *container = walletRec.container;
      ITransfersContainer::TransferState state;
      TransactionOutputInformation transfer;
      container->getTransfer(dep.transactionHash, dep.outputInTransaction, transfer, state);
      if (state != ITransfersContainer::TransferState::TransferAvailable) {
        continue;
      }
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(transfer.transactionPublicKey, m_viewSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      const uint32_t outIdx = transfer.outputInTransaction;
      preimage[32] = outIdx & 0xFF; preimage[33] = (outIdx >> 8) & 0xFF;
      preimage[34] = (outIdx >> 16) & 0xFF; preimage[35] = (outIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      std::array<uint8_t, 32> depositSecret;
      memcpy(depositSecret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys ck = CryptoNote::deriveCommitmentKeys(depositSecret);
      KeyPair commitmentKeyPair = {ck.commitKey, ck.keyScalar};

      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> filteredDecoys;
      for (const auto& d : allDecoys) {
        if (d.global_amount_index != static_cast<uint32_t>(transfer.globalOutputIndex)) {
          filteredDecoys.push_back(d);
        }
      }
      // available same-amount outs = decoys + real
      const size_t availablePool = filteredDecoys.size() + 1;
      const size_t targetRing = pickDynamaxCommitmentRingSize(
        availablePool, m_currency.maxMixin(),
        m_currency.minMixin(CryptoNote::BLOCK_MAJOR_VERSION_10));
      const size_t numDecoys = std::min(filteredDecoys.size(), targetRing > 0 ? targetRing - 1 : 0);
      const size_t actualRing = numDecoys + 1;
      if (actualRing == 0) continue;
      const size_t realPos = Crypto::rand<size_t>() % actualRing;

      std::vector<uint32_t> absIndices;
      std::vector<const Crypto::PublicKey*> ringKeys;
      size_t decoyPos = 0;
      for (size_t slot = 0; slot < actualRing; ++slot) {
        if (slot == realPos) {
          absIndices.push_back(transfer.globalOutputIndex);
          ringKeys.push_back(&commitmentKeyPair.publicKey);
        } else {
          absIndices.push_back(filteredDecoys[decoyPos].global_amount_index);
          ringKeys.push_back(&filteredDecoys[decoyPos].commit_key);
          ++decoyPos;
        }
      }
      std::vector<size_t> order(actualRing);
      std::iota(order.begin(), order.end(), 0);
      std::sort(order.begin(), order.end(), [&](size_t a, size_t b) { return absIndices[a] < absIndices[b]; });
      size_t sortedRealPos = 0;
      std::vector<uint32_t> sortedAbs(actualRing);
      std::vector<const Crypto::PublicKey*> sortedKeys(actualRing);
      for (size_t s = 0; s < actualRing; ++s) {
        sortedAbs[s] = absIndices[order[s]];
        sortedKeys[s] = ringKeys[order[s]];
        if (order[s] == realPos) sortedRealPos = s;
      }
      std::vector<uint32_t> relOffsets(actualRing);
      relOffsets[0] = sortedAbs[0];
      for (size_t s = 1; s < actualRing; ++s) {
        relOffsets[s] = sortedAbs[s] - sortedAbs[s - 1];
      }
      TransactionInputCommitmentSpend csInput;
      csInput.amount = dep.amount;
      csInput.outputIndexes = relOffsets;
      csInput.keyImage = ck.keyImage;
      transaction->addInput(csInput);
      transaction->signInputCommitmentSpend(commitmentDepositIdx, sortedKeys, commitmentKeyPair, sortedRealPos);
      commitmentDepositIdx++;
    }

    transactionHash = Common::podToHex(transaction->getTransactionHash());
    validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  void WalletGreen::ammSwapV10(
      uint8_t direction,
      uint64_t inputAmount,
      uint64_t expectedOutput,
      uint64_t minOutput,
      uint64_t fee,
      uint64_t mixin,
      std::string &transactionHash)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();
    if (direction > 1 || inputAmount == 0) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }
    fee = m_currency.minimumFee();

    if (direction == 0) {
      // XFG→HEAT: spend XFG KeyInputs + mint HEAT (mintHeatV10)
      uint64_t heatOut = expectedOutput > 0 ? expectedOutput : minOutput;
      if (heatOut == 0) {
        INode::AmmPoolReserves reserves;
        std::error_code pec = m_node.getAmmPoolReserves(reserves);
        if (!pec && reserves.reserveXfg > 0) {
          heatOut = inputAmount * reserves.reserveHeat / reserves.reserveXfg;
        } else {
          heatOut = inputAmount / 10;
        }
      }
      if (heatOut < minOutput) {
        heatOut = minOutput;
      }
      mintHeatV10(inputAmount, heatOut, fee, mixin, transactionHash);
      return;
    }

    // direction == 1: HEAT→XFG — spend unlocked HEAT_TERM deposits as commitment inputs
    uint64_t outputAmount = expectedOutput > 0 ? expectedOutput : minOutput;
    if (outputAmount == 0) {
      INode::AmmPoolReserves reserves;
      std::error_code pec = m_node.getAmmPoolReserves(reserves);
      if (!pec && reserves.reserveHeat > 0) {
        outputAmount = inputAmount * reserves.reserveXfg / reserves.reserveHeat;
      } else {
        outputAmount = inputAmount * 10; // inverse of launch 10:1
      }
    }
    if (outputAmount < minOutput) {
      outputAmount = minOutput;
    }

    uint32_t currentHeight = getBlockCount();
    uint64_t totalHeat = 0;
    std::vector<size_t> selectedDepositIds;
    for (size_t i = 0; i < m_deposits.size(); ++i) {
      Deposit dep = m_deposits.get<RandomAccessIndex>()[i];
      if (dep.term == parameters::HEAT_TERM
          && !dep.locked
          && dep.unlockHeight <= currentHeight
          && dep.spendingTransactionId == WALLET_INVALID_DEPOSIT_ID) {
        totalHeat += dep.amount;
        selectedDepositIds.push_back(i);
        if (totalHeat >= inputAmount) break;
      }
    }
    if (totalHeat < inputAmount || selectedDepositIds.empty()) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Insufficient unlocked HEAT for AMM swap");
    }

    std::unique_ptr<ITransaction> transaction = createTransaction();

    // Pool receives HEAT
    Crypto::PublicKey poolKey = CryptoNote::computePoolCommitKey();
    CryptoNote::TransactionOutputCommitment poolOut;
    poolOut.commitKey = poolKey;
    poolOut.term = parameters::DEPOSIT_TERM_POOL_HEAT;
    transaction->addOutput(inputAmount, poolOut);

    // User receives XFG commitment (SWRX)
    uint64_t netXfg = (outputAmount > fee) ? (outputAmount - fee) : 0;
    if (netXfg > 0) {
      const uint32_t commitIdx = static_cast<uint32_t>(transaction->getOutputCount());
      std::array<uint8_t, 32> receiveSecret;
      Crypto::SecretKey txSecretKey;
      transaction->getTransactionSecretKey(txSecretKey);
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(m_viewPublicKey, txSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      preimage[32] = commitIdx & 0xFF; preimage[33] = (commitIdx >> 8) & 0xFF;
      preimage[34] = (commitIdx >> 16) & 0xFF; preimage[35] = (commitIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      memcpy(receiveSecret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys receiveKeys = CryptoNote::deriveCommitmentKeys(receiveSecret);
      CryptoNote::TransactionOutputCommitment receiveOut;
      receiveOut.commitKey = receiveKeys.commitKey;
      receiveOut.term = parameters::DEPOSIT_TERM_SWAP_RECEIVE_XFG;
      transaction->addOutput(netXfg, receiveOut);
    }

    // HEAT change (FOREVER)
    if (totalHeat > inputAmount) {
      uint64_t changeHeat = totalHeat - inputAmount;
      const uint32_t chIdx = static_cast<uint32_t>(transaction->getOutputCount());
      std::array<uint8_t, 32> changeSecret;
      Crypto::SecretKey txSecretKey;
      transaction->getTransactionSecretKey(txSecretKey);
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(m_viewPublicKey, txSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      preimage[32] = chIdx & 0xFF; preimage[33] = (chIdx >> 8) & 0xFF;
      preimage[34] = (chIdx >> 16) & 0xFF; preimage[35] = (chIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      memcpy(changeSecret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys cKeys = CryptoNote::deriveCommitmentKeys(changeSecret);
      CryptoNote::TransactionOutputCommitment changeOut;
      changeOut.commitKey = cKeys.commitKey;
      changeOut.term = parameters::HEAT_TERM;
      transaction->addOutput(changeHeat, changeOut);
    }

    transaction->setUnlockTime(0);
    std::vector<uint8_t> extra;
    addAmmSwapAuthToExtra(extra, direction, inputAmount, outputAmount, minOutput);
    transaction->appendExtra(CryptoNote::BinaryArray(extra.begin(), extra.end()));

    // Dynamax commitment rings: probe maxMixin, settle 32/16/8 or bootstrap if HEAT pool empty
    mixin = normalizeMixinProbe(mixin, m_currency.maxMixin());
    const size_t probeCount = static_cast<size_t>(mixin);
    std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> allDecoys;
    {
      Deposit firstDep = m_deposits.get<RandomAccessIndex>()[selectedDepositIds[0]];
      System::Event requestFinished(m_dispatcher);
      std::error_code nodeError;
      m_node.getRandomCommitmentOutsForAmount(firstDep.amount, probeCount, firstDep.height, allDecoys,
        [&requestFinished, &nodeError, this](std::error_code ec) {
          nodeError = ec;
          this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
        });
      requestFinished.wait();
      if (nodeError) {
        allDecoys.clear(); // empty HEAT decoy pool at launch
      }
    }

    size_t commitmentDepositIdx = 0;
    for (size_t depIdx = 0; depIdx < selectedDepositIds.size(); ++depIdx) {
      Deposit dep = m_deposits.get<RandomAccessIndex>()[selectedDepositIds[depIdx]];
      WalletTransfer firstTransfer = getTransactionTransfer(dep.creatingTransactionId, 0);
      const auto &walletRec = getWalletRecord(firstTransfer.address);
      ITransfersContainer::TransferState state;
      TransactionOutputInformation transfer;
      walletRec.container->getTransfer(dep.transactionHash, dep.outputInTransaction, transfer, state);
      if (state != ITransfersContainer::TransferState::TransferAvailable) {
        continue;
      }
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(transfer.transactionPublicKey, m_viewSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      const uint32_t outIdx = transfer.outputInTransaction;
      preimage[32] = outIdx & 0xFF; preimage[33] = (outIdx >> 8) & 0xFF;
      preimage[34] = (outIdx >> 16) & 0xFF; preimage[35] = (outIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      std::array<uint8_t, 32> depositSecret;
      memcpy(depositSecret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys ck = CryptoNote::deriveCommitmentKeys(depositSecret);
      KeyPair commitmentKeyPair = {ck.commitKey, ck.keyScalar};

      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> filteredDecoys;
      for (const auto& d : allDecoys) {
        if (d.global_amount_index != static_cast<uint32_t>(transfer.globalOutputIndex)) {
          filteredDecoys.push_back(d);
        }
      }
      const size_t availablePool = filteredDecoys.size() + 1;
      const size_t targetRing = pickDynamaxCommitmentRingSize(
        availablePool, m_currency.maxMixin(),
        m_currency.minMixin(CryptoNote::BLOCK_MAJOR_VERSION_10));
      const size_t numDecoys = std::min(filteredDecoys.size(), targetRing > 0 ? targetRing - 1 : 0);
      const size_t actualRing = numDecoys + 1;
      if (actualRing == 0) continue;
      const size_t realPos = Crypto::rand<size_t>() % actualRing;
      std::vector<uint32_t> absIndices;
      std::vector<const Crypto::PublicKey*> ringKeys;
      size_t decoyPos = 0;
      for (size_t slot = 0; slot < actualRing; ++slot) {
        if (slot == realPos) {
          absIndices.push_back(transfer.globalOutputIndex);
          ringKeys.push_back(&commitmentKeyPair.publicKey);
        } else {
          absIndices.push_back(filteredDecoys[decoyPos].global_amount_index);
          ringKeys.push_back(&filteredDecoys[decoyPos].commit_key);
          ++decoyPos;
        }
      }
      std::vector<size_t> order(actualRing);
      std::iota(order.begin(), order.end(), 0);
      std::sort(order.begin(), order.end(), [&](size_t a, size_t b) { return absIndices[a] < absIndices[b]; });
      size_t sortedRealPos = 0;
      std::vector<uint32_t> sortedAbs(actualRing);
      std::vector<const Crypto::PublicKey*> sortedKeys(actualRing);
      for (size_t s = 0; s < actualRing; ++s) {
        sortedAbs[s] = absIndices[order[s]];
        sortedKeys[s] = ringKeys[order[s]];
        if (order[s] == realPos) sortedRealPos = s;
      }
      std::vector<uint32_t> relOffsets(actualRing);
      relOffsets[0] = sortedAbs[0];
      for (size_t s = 1; s < actualRing; ++s) {
        relOffsets[s] = sortedAbs[s] - sortedAbs[s - 1];
      }
      TransactionInputCommitmentSpend csInput;
      csInput.amount = dep.amount;
      csInput.outputIndexes = relOffsets;
      csInput.keyImage = ck.keyImage;
      transaction->addInput(csInput);
      transaction->signInputCommitmentSpend(commitmentDepositIdx, sortedKeys, commitmentKeyPair, sortedRealPos);
      commitmentDepositIdx++;
    }
    if (commitmentDepositIdx == 0) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "No spendable HEAT deposit transfers");
    }

    transactionHash = Common::podToHex(transaction->getTransactionHash());
    validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  void WalletGreen::sendHeatV10(
      const std::string &recipient,
      uint64_t amount,
      uint64_t fee,
      uint64_t mixin,
      std::string &transactionHash)
  {
    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    if (amount == 0) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT));
    }

    if (!CryptoNote::validateAddress(recipient, m_currency)) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS));
    }

    fee = m_currency.minimumFee();

    // Parse recipient address to get view public key
    AccountPublicAddress recipientAddr;
    if (!m_currency.parseAccountAddressString(recipient, recipientAddr)) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS));
    }

    // Find unspent HEAT deposits
    uint32_t currentHeight = getBlockCount();
    uint64_t totalHeat = 0;
    std::vector<size_t> selectedDepositIds;

    for (size_t i = 0; i < m_deposits.size(); ++i) {
      Deposit dep = m_deposits.get<RandomAccessIndex>()[i];
      if (dep.term == parameters::HEAT_TERM
          && !dep.locked
          && dep.unlockHeight <= currentHeight
          && dep.spendingTransactionId == WALLET_INVALID_DEPOSIT_ID) {
        totalHeat += dep.amount;
        selectedDepositIds.push_back(i);
        if (totalHeat >= amount) break;
      }
    }

    if (totalHeat < amount) {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Insufficient HEAT balance");
    }

    // Create the transaction
    std::unique_ptr<ITransaction> transaction = createTransaction();
    uint64_t changeAmount = (totalHeat > amount) ? (totalHeat - amount) : 0;

    // HEAT commitment output for recipient (using recipient's view key)
    const uint32_t rcptIdx = static_cast<uint32_t>(transaction->getOutputCount());
    std::array<uint8_t, 32> rcptSecret;
    {
      Crypto::SecretKey txSecretKey;
      transaction->getTransactionSecretKey(txSecretKey);
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(recipientAddr.viewPublicKey, txSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      preimage[32] = rcptIdx & 0xFF;
      preimage[33] = (rcptIdx >> 8) & 0xFF;
      preimage[34] = (rcptIdx >> 16) & 0xFF;
      preimage[35] = (rcptIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      memcpy(rcptSecret.data(), h.data, 32);
    }
    CryptoNote::DepositCommitmentKeys rcptKeys = CryptoNote::deriveCommitmentKeys(rcptSecret);
    CryptoNote::TransactionOutputCommitment rcptOut;
    rcptOut.commitKey = rcptKeys.commitKey;
    rcptOut.term = parameters::HEAT_TERM;
    transaction->addOutput(amount, rcptOut);

    // HEAT change output (sender's view key)
    if (changeAmount > 0) {
      const uint32_t chIdx = static_cast<uint32_t>(transaction->getOutputCount());
      std::array<uint8_t, 32> chSecret;
      {
        Crypto::SecretKey txSecretKey;
        transaction->getTransactionSecretKey(txSecretKey);
        Crypto::KeyDerivation ecdh;
        Crypto::generate_key_derivation(m_viewPublicKey, txSecretKey, ecdh);
        uint8_t preimage[36];
        memcpy(preimage, &ecdh, 32);
        preimage[32] = chIdx & 0xFF;
        preimage[33] = (chIdx >> 8) & 0xFF;
        preimage[34] = (chIdx >> 16) & 0xFF;
        preimage[35] = (chIdx >> 24) & 0xFF;
        Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
        memcpy(chSecret.data(), h.data, 32);
      }
      CryptoNote::DepositCommitmentKeys cKeys = CryptoNote::deriveCommitmentKeys(chSecret);
      CryptoNote::TransactionOutputCommitment chOut;
      chOut.commitKey = cKeys.commitKey;
      chOut.term = parameters::HEAT_TERM;
      transaction->addOutput(changeAmount, chOut);
    }

    transaction->setUnlockTime(0);

    // Auth tag extra: 0xF9 + 8 bytes LE heatAmount
    std::vector<uint8_t> extra;
    addHeatSendAuthToExtra(extra, amount);
    CryptoNote::BinaryArray extraData(extra.begin(), extra.end());
    transaction->appendExtra(extraData);

    // Dynamax HEAT rings: probe maxMixin (32), settle 32/16/8 or bootstrap if pool empty
    mixin = normalizeMixinProbe(mixin, m_currency.maxMixin());
    const size_t probeCount = static_cast<size_t>(mixin);

    std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> allDecoys;
    {
      Deposit firstDep = m_deposits.get<RandomAccessIndex>()[selectedDepositIds[0]];
      System::Event requestFinished(m_dispatcher);
      std::error_code nodeError;

      throwIfStopped();
      m_node.getRandomCommitmentOutsForAmount(firstDep.amount, probeCount, firstDep.height, allDecoys,
        [&requestFinished, &nodeError, this](std::error_code ec) {
          nodeError = ec;
          this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
        });
      requestFinished.wait();

      if (nodeError) {
        // Empty commitment decoy pool at HEAT launch — proceed real-only
        allDecoys.clear();
      }
    }

    size_t commitmentDepositIdx = 0;
    for (size_t depIdx = 0; depIdx < selectedDepositIds.size(); ++depIdx) {
      Deposit dep = m_deposits.get<RandomAccessIndex>()[selectedDepositIds[depIdx]];

      // Get the transfer info for this deposit
      WalletTransfer firstTransfer = getTransactionTransfer(dep.creatingTransactionId, 0);
      std::string address = firstTransfer.address;
      const auto &wallet = getWalletRecord(address);
      ITransfersContainer *container = wallet.container;
      ITransfersContainer::TransferState state;
      TransactionOutputInformation transfer;

      container->getTransfer(dep.transactionHash, dep.outputInTransaction, transfer, state);

      if (state != ITransfersContainer::TransferState::TransferAvailable) {
        continue;
      }

      // Re-derive deposit secret from transaction public key + output index
      Crypto::KeyDerivation ecdh;
      Crypto::generate_key_derivation(transfer.transactionPublicKey, m_viewSecretKey, ecdh);
      uint8_t preimage[36];
      memcpy(preimage, &ecdh, 32);
      const uint32_t outIdx = transfer.outputInTransaction;
      preimage[32] = outIdx & 0xFF;
      preimage[33] = (outIdx >> 8) & 0xFF;
      preimage[34] = (outIdx >> 16) & 0xFF;
      preimage[35] = (outIdx >> 24) & 0xFF;
      Crypto::Hash h = Crypto::cn_fast_hash(preimage, sizeof(preimage));
      std::array<uint8_t, 32> depositSecret;
      memcpy(depositSecret.data(), h.data, 32);
      CryptoNote::DepositCommitmentKeys ck = CryptoNote::deriveCommitmentKeys(depositSecret);
      KeyPair commitmentKeyPair = {ck.commitKey, ck.keyScalar};

      // Filter decoys to exclude the real output
      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_COMMITMENT_OUTPUTS::out_entry> filteredDecoys;
      for (const auto& d : allDecoys) {
        if (d.global_amount_index != static_cast<uint32_t>(transfer.globalOutputIndex)) {
          filteredDecoys.push_back(d);
        }
      }
      const size_t availablePool = filteredDecoys.size() + 1;
      const size_t targetRing = pickDynamaxCommitmentRingSize(
        availablePool, m_currency.maxMixin(),
        m_currency.minMixin(CryptoNote::BLOCK_MAJOR_VERSION_10));
      const size_t numDecoys = std::min(filteredDecoys.size(), targetRing > 0 ? targetRing - 1 : 0);
      const size_t actualRing = numDecoys + 1;
      if (actualRing == 0) continue;
      const size_t realPos = Crypto::rand<size_t>() % actualRing;

      std::vector<uint32_t> absIndices;
      std::vector<const Crypto::PublicKey*> ringKeys;
      size_t decoyPos = 0;
      for (size_t slot = 0; slot < actualRing; ++slot) {
        if (slot == realPos) {
          absIndices.push_back(transfer.globalOutputIndex);
          ringKeys.push_back(&commitmentKeyPair.publicKey);
        } else {
          absIndices.push_back(filteredDecoys[decoyPos].global_amount_index);
          ringKeys.push_back(&filteredDecoys[decoyPos].commit_key);
          ++decoyPos;
        }
      }

      // Sort ring by ascending global index; track new real position
      std::vector<size_t> order(actualRing);
      std::iota(order.begin(), order.end(), 0);
      std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return absIndices[a] < absIndices[b];
      });
      size_t sortedRealPos = 0;
      std::vector<uint32_t> sortedAbs(actualRing);
      std::vector<const Crypto::PublicKey*> sortedKeys(actualRing);
      for (size_t s = 0; s < actualRing; ++s) {
        sortedAbs[s] = absIndices[order[s]];
        sortedKeys[s] = ringKeys[order[s]];
        if (order[s] == realPos) sortedRealPos = s;
      }

      // Delta-encode absolute indices to relative offsets
      std::vector<uint32_t> relOffsets(actualRing);
      relOffsets[0] = sortedAbs[0];
      for (size_t s = 1; s < actualRing; ++s) {
        relOffsets[s] = sortedAbs[s] - sortedAbs[s - 1];
      }

      TransactionInputCommitmentSpend csInput;
      csInput.amount = dep.amount;
      csInput.outputIndexes = relOffsets;
      csInput.keyImage = ck.keyImage;
      transaction->addInput(csInput);
      transaction->signInputCommitmentSpend(commitmentDepositIdx, sortedKeys, commitmentKeyPair, sortedRealPos);
      commitmentDepositIdx++;
    }

    transactionHash = Common::podToHex(transaction->getTransactionHash());
    size_t id = validateSaveAndSendTransaction(*transaction, {}, false, true);
  }

  void WalletGreen::validateOrders(const std::vector<WalletOrder> &orders) const
  {
    for (const auto &order : orders)
    {
      if (!CryptoNote::validateAddress(order.address, m_currency))
      {
        throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
      }

      if (order.amount >= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
      {
        std::string message = "Order amount must not exceed " + m_currency.formatAmount(std::numeric_limits<int64_t>::max());
        throw std::system_error(make_error_code(CryptoNote::error::WRONG_AMOUNT), message);
      }
    }
  }

  void WalletGreen::decryptKeyPair(const EncryptedWalletRecord &cipher, PublicKey &publicKey, SecretKey &secretKey,
                                   uint64_t &creationTimestamp, const Crypto::chacha8_key &key, uint8_t version)
  {
    if (version >= 8) {
      uint8_t macKey[32];
      deriveMacKey(key, macKey);

      uint8_t computedTag[32];
      unsigned int computedLen = 32;

      // Compute HMAC-SHA256(macKey, iv || encryptedData)
      HMAC_CTX* hmacCtx = HMAC_CTX_new();
      HMAC_Init_ex(hmacCtx, macKey, 32, EVP_sha256(), nullptr);
      HMAC_Update(hmacCtx, reinterpret_cast<const unsigned char*>(&cipher.iv), sizeof(cipher.iv));
      HMAC_Update(hmacCtx, cipher.data, sizeof(cipher.data));
      HMAC_Final(hmacCtx, computedTag, &computedLen);
      HMAC_CTX_free(hmacCtx);

      if (computedLen != 32 || CRYPTO_memcmp(computedTag, cipher.tag, 32) != 0) {
        throw std::runtime_error("Key record integrity check failed — data may be tampered");
      }
    }

    std::array<char, sizeof(cipher.data)> buffer;
    chacha8(cipher.data, sizeof(cipher.data), key, cipher.iv, buffer.data());

    MemoryInputStream stream(buffer.data(), buffer.size());
    BinaryInputStreamSerializer serializer(stream);

    serializer(publicKey, "publicKey");
    serializer(secretKey, "secretKey");
    serializer.binary(&creationTimestamp, sizeof(uint64_t), "creationTimestamp");
  }

  void WalletGreen::decryptKeyPair(const EncryptedWalletRecord &cipher, PublicKey &publicKey, SecretKey &secretKey, uint64_t &creationTimestamp) const
  {
    uint8_t version = reinterpret_cast<const ContainerStoragePrefix *>(m_containerStorage.prefix())->version;
    decryptKeyPair(cipher, publicKey, secretKey, creationTimestamp, m_key, version);
  }

  EncryptedWalletRecord WalletGreen::encryptKeyPair(const PublicKey &publicKey, const SecretKey &secretKey, uint64_t creationTimestamp, const Crypto::chacha8_key &key, const Crypto::chacha8_iv &iv)
  {

    EncryptedWalletRecord result;

    std::string serializedKeys;
    StringOutputStream outputStream(serializedKeys);
    BinaryOutputStreamSerializer serializer(outputStream);

    serializer(const_cast<PublicKey &>(publicKey), "publicKey");
    serializer(const_cast<SecretKey &>(secretKey), "secretKey");
    serializer.binary(&creationTimestamp, sizeof(uint64_t), "creationTimestamp");

    assert(serializedKeys.size() == sizeof(result.data));

    result.iv = iv;
    chacha8(serializedKeys.data(), serializedKeys.size(), key, result.iv, reinterpret_cast<char *>(result.data));

    // Compute HMAC-SHA256(macKey, iv || encryptedData) for AEAD
    uint8_t macKey[32];
    deriveMacKey(key, macKey);
    unsigned int tagLen = 32;

    HMAC_CTX* hmacCtx = HMAC_CTX_new();
    HMAC_Init_ex(hmacCtx, macKey, 32, EVP_sha256(), nullptr);
    HMAC_Update(hmacCtx, reinterpret_cast<const unsigned char*>(&result.iv), sizeof(result.iv));
    HMAC_Update(hmacCtx, result.data, sizeof(result.data));
    HMAC_Final(hmacCtx, result.tag, &tagLen);
    HMAC_CTX_free(hmacCtx);

    return result;
  }

  Crypto::chacha8_iv WalletGreen::getNextIv() const
  {
    const auto *prefix = reinterpret_cast<const ContainerStoragePrefix *>(m_containerStorage.prefix());
    return prefix->nextIv;
  }

  EncryptedWalletRecord WalletGreen::encryptKeyPair(const PublicKey &publicKey, const SecretKey &secretKey, uint64_t creationTimestamp) const
  {
    return encryptKeyPair(publicKey, secretKey, creationTimestamp, m_key, getNextIv());
  }

  void WalletGreen::deriveMacKey(const Crypto::chacha8_key &key, uint8_t macKey[32]) {
    unsigned int macKeyLen = 32;
    if (!HMAC(EVP_sha256(),
              key.data, sizeof(key.data),
              reinterpret_cast<const unsigned char*>("fuego-wallet-hmac"), 18,
              macKey, &macKeyLen) || macKeyLen != 32) {
      throw std::runtime_error("MAC key derivation failed");
    }
  }

  void WalletGreen::loadSpendKeys()
  {
    bool isTrackingMode;
    for (size_t i = 0; i < m_containerStorage.size(); ++i)
    {
      WalletRecord wallet;
      uint64_t creationTimestamp;
      decryptKeyPair(m_containerStorage[i], wallet.spendPublicKey, wallet.spendSecretKey, creationTimestamp);
      wallet.creationTimestamp = creationTimestamp;

      if (i == 0)
      {
        isTrackingMode = wallet.spendSecretKey == NULL_SECRET_KEY;
      }
      else if ((isTrackingMode && wallet.spendSecretKey != NULL_SECRET_KEY) || (!isTrackingMode && wallet.spendSecretKey == NULL_SECRET_KEY))
      {
        throw std::system_error(make_error_code(error::BAD_ADDRESS), "All addresses must be whether tracking or not");
      }

      if (wallet.spendSecretKey != NULL_SECRET_KEY)
      {
        throwIfKeysMissmatch(wallet.spendSecretKey, wallet.spendPublicKey, "Restored spend public key doesn't correspond to secret key");
      }
      else
      {
        if (!Crypto::check_key(wallet.spendPublicKey))
        {
          throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Public spend key is incorrect");
        }
      }

      wallet.actualBalance = 0;
      wallet.pendingBalance = 0;
      wallet.lockedDepositBalance = 0;
      wallet.unlockedDepositBalance = 0;
      wallet.container = nullptr;

      m_walletsContainer.emplace_back(std::move(wallet));
    }
  }

  void WalletGreen::validateAddresses(const std::vector<std::string> &addresses) const
  {
    for (const auto &address : addresses)
    {
      if (!CryptoNote::validateAddress(address, m_currency))
      {
        throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
      }
    }
  }

  void WalletGreen::initializeWithViewKey(const std::string &path, const std::string &password, const Crypto::SecretKey &viewSecretKey)
  {
    Crypto::PublicKey viewPublicKey;
    if (!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey))
    {
      m_logger(ERROR, BRIGHT_RED) << "initializeWithViewKey Failed to convert secret key to public key";
      throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
    }

    initWithKeys(path, password, viewPublicKey, viewSecretKey);
    m_logger(INFO, BRIGHT_WHITE) << "Container initialized with view secret key, public view key " << Common::podToHex(viewPublicKey);
  }

  void WalletGreen::shutdown()
  {
    throwIfNotInitialized();
    doShutdown();

    m_dispatcher.yield(); //let remote spawns finish
  }

  void WalletGreen::initBlockchain(const Crypto::PublicKey &viewPublicKey)
  {
    std::vector<Crypto::Hash> blockchain = m_synchronizer.getViewKeyKnownBlocks(m_viewPublicKey);
    m_blockchain.insert(m_blockchain.end(), blockchain.begin(), blockchain.end());
  }

  void WalletGreen::deleteOrphanTransactions(const std::unordered_set<Crypto::PublicKey> &deletedKeys)
  {
    for (auto spendPublicKey : deletedKeys)
    {
      AccountPublicAddress deletedAccountAddress;
      deletedAccountAddress.spendPublicKey = spendPublicKey;
      deletedAccountAddress.viewPublicKey = m_viewPublicKey;
      auto deletedAddressString = m_currency.accountAddressAsString(deletedAccountAddress);

      std::vector<size_t> deletedTransactions;
      std::vector<size_t> updatedTransactions = deleteTransfersForAddress(deletedAddressString, deletedTransactions);
      deleteFromUncommitedTransactions(deletedTransactions);
    }
  }

  void WalletGreen::saveWalletCache(ContainerStorage &storage, const Crypto::chacha8_key &key, WalletSaveLevel saveLevel, const std::string &extra)
  {
    m_logger(INFO) << "Saving cache...";

    WalletTransactions transactions;
    WalletTransfers transfers;
    if (saveLevel == WalletSaveLevel::SAVE_KEYS_AND_TRANSACTIONS)
    {
      filterOutTransactions(transactions, transfers, [](const WalletTransaction &tx) {
        return tx.state == WalletTransactionState::CREATED || tx.state == WalletTransactionState::DELETED;
      });

      for (auto it = transactions.begin(); it != transactions.end(); ++it)
      {
        transactions.modify(it, [](WalletTransaction &tx) {
          tx.state = WalletTransactionState::CANCELLED;
          tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
        });
      }
    }
    else if (saveLevel == WalletSaveLevel::SAVE_ALL)
    {
      filterOutTransactions(transactions, transfers, [](const WalletTransaction &tx) {
        return tx.state == WalletTransactionState::DELETED;
      });
    }

    std::string containerData;
    Common::StringOutputStream containerStream(containerData);
    WalletSerializerV2 s(
        *this,
        m_viewPublicKey,
        m_viewSecretKey,
        m_actualBalance,
        m_pendingBalance,
        m_lockedDepositBalance,
        m_unlockedDepositBalance,
        m_walletsContainer,
        m_synchronizer,
        m_unlockTransactionsJob,
        transactions,
        transfers,
        m_deposits,
        m_uncommitedTransactions,
        const_cast<std::string &>(extra),
        m_transactionSoftLockTime);
    s.save(containerStream, saveLevel);
    encryptAndSaveContainerData(storage, key, containerData.data(), containerData.size());
    storage.flush();

    m_extra = extra;

    m_logger(INFO) << "Container saving finished";
  }

  void WalletGreen::doShutdown()
  {
    if (m_walletsContainer.size() != 0)
    {
      m_synchronizer.unsubscribeConsumerNotifications(m_viewPublicKey, this);
    }

    stopBlockchainSynchronizer();
    m_blockchainSynchronizer.removeObserver(this);

    m_containerStorage.close();
    m_walletsContainer.clear();
    clearCaches(true, true);

    std::queue<WalletEvent> noEvents;
    std::swap(m_events, noEvents);

    memset(m_viewSecretKey.data, 0, sizeof(m_viewSecretKey.data));
    m_password.assign(m_password.capacity(), '\0');
    m_password.clear();

    m_state = WalletState::NOT_INITIALIZED;
  }

  void WalletGreen::initTransactionPool()
  {
    std::unordered_set<Crypto::Hash> uncommitedTransactionsSet;
    std::transform(m_uncommitedTransactions.begin(), m_uncommitedTransactions.end(), std::inserter(uncommitedTransactionsSet, uncommitedTransactionsSet.end()),
                   [](const UncommitedTransactions::value_type &pair) {
                     return getObjectHash(pair.second);
                   });
    m_synchronizer.initTransactionPool(uncommitedTransactionsSet);
  }

  void WalletGreen::initWithKeys(const std::string &path, const std::string &password,
                                 const Crypto::PublicKey &viewPublicKey, const Crypto::SecretKey &viewSecretKey)
  {

    if (m_state != WalletState::NOT_INITIALIZED)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to initialize with keys: already initialized.";
      throw std::system_error(make_error_code(CryptoNote::error::ALREADY_INITIALIZED));
    }

    throwIfStopped();

    ContainerStorage newStorage(path, Common::FileMappedVectorOpenMode::CREATE, sizeof(ContainerStoragePrefix));
    ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(newStorage.prefix());
    prefix->version = static_cast<uint8_t>(WalletSerializerV2::SERIALIZATION_VERSION);
    prefix->nextIv = Crypto::rand<Crypto::chacha8_iv>();

    Crypto::cn_context cnContext;
    Crypto::generate_chacha8_key(cnContext, password, m_key);

    uint64_t creationTimestamp = time(nullptr);
    prefix->encryptedViewKeys = encryptKeyPair(viewPublicKey, viewSecretKey, creationTimestamp, m_key, prefix->nextIv);

    newStorage.flush();
    m_containerStorage.swap(newStorage);
#ifndef _WIN32
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
      m_logger(WARNING) << "Failed to set restrictive permissions on wallet file";
    }
#endif
    incNextIv();

    m_viewPublicKey = viewPublicKey;
    m_viewSecretKey = viewSecretKey;
    m_password = password;
    m_path = path;
    m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/" + podToHex(m_viewPublicKey).substr(0, 5));

    assert(m_blockchain.empty());
    m_blockchain.push_back(m_currency.genesisBlockHash());

    m_blockchainSynchronizer.addObserver(this);

    m_state = WalletState::INITIALIZED;
  }

  void WalletGreen::save(WalletSaveLevel saveLevel, const std::string &extra)
  {
    m_logger(INFO, BRIGHT_WHITE) << "Saving container...";

    throwIfNotInitialized();
    throwIfStopped();

    stopBlockchainSynchronizer();

    try
    {
      saveWalletCache(m_containerStorage, m_key, saveLevel, extra);
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to save container: " << e.what();
      startBlockchainSynchronizer();
      throw;
    }

    startBlockchainSynchronizer();
    m_logger(INFO, BRIGHT_WHITE) << "Container saved";
  }

  void WalletGreen::copyContainerStorageKeys(ContainerStorage &src, const chacha8_key &srcKey, ContainerStorage &dst, const chacha8_key &dstKey)
  {
    dst.reserve(src.size());

    dst.setAutoFlush(false);
    Tools::ScopeExit exitHandler([&dst] {
      dst.setAutoFlush(true);
      dst.flush();
    });

    size_t counter = 0;
    ContainerStoragePrefix *srcPrefix = reinterpret_cast<ContainerStoragePrefix *>(src.prefix());

    for (auto &encryptedSpendKeys : src)
    {
      Crypto::PublicKey publicKey;
      Crypto::SecretKey secretKey;
      uint64_t creationTimestamp;
      decryptKeyPair(encryptedSpendKeys, publicKey, secretKey, creationTimestamp, srcKey, srcPrefix->version);

      // push_back() can resize container, and dstPrefix address can be changed, so it is requested for each key pair
      ContainerStoragePrefix *dstPrefix = reinterpret_cast<ContainerStoragePrefix *>(dst.prefix());
      Crypto::chacha8_iv keyPairIv = dstPrefix->nextIv;
      incIv(dstPrefix->nextIv);

      dst.push_back(encryptKeyPair(publicKey, secretKey, creationTimestamp, dstKey, keyPairIv));
    }
  }

  void WalletGreen::copyContainerStoragePrefix(ContainerStorage &src, const chacha8_key &srcKey, ContainerStorage &dst, const chacha8_key &dstKey)
  {
    ContainerStoragePrefix *srcPrefix = reinterpret_cast<ContainerStoragePrefix *>(src.prefix());
    ContainerStoragePrefix *dstPrefix = reinterpret_cast<ContainerStoragePrefix *>(dst.prefix());
    dstPrefix->version = srcPrefix->version;
    dstPrefix->nextIv = Crypto::randomChachaIV();

    Crypto::PublicKey publicKey;
    Crypto::SecretKey secretKey;
    uint64_t creationTimestamp;
    decryptKeyPair(srcPrefix->encryptedViewKeys, publicKey, secretKey, creationTimestamp, srcKey, srcPrefix->version);
    dstPrefix->encryptedViewKeys = encryptKeyPair(publicKey, secretKey, creationTimestamp, dstKey, dstPrefix->nextIv);
    incIv(dstPrefix->nextIv);
  }

  void WalletGreen::exportWalletKeys(const std::string &path, bool encrypt, WalletSaveLevel saveLevel, const std::string &extra)
  {
    m_logger(INFO, BRIGHT_WHITE) << "Exporting container...";

    throwIfNotInitialized();
    throwIfStopped();
    stopBlockchainSynchronizer();

    try
    {
      bool storageCreated = false;
      Tools::ScopeExit failExitHandler([path, &storageCreated] {
        // Don't delete file if it has existed
        if (storageCreated)
        {
          boost::system::error_code ignore;
          boost::filesystem::remove(path, ignore);
        }
      });

      ContainerStorage newStorage(path, FileMappedVectorOpenMode::CREATE, m_containerStorage.prefixSize());
      storageCreated = true;

      chacha8_key newStorageKey;
      if (encrypt)
      {
        newStorageKey = m_key;
      }
      else
      {
        cn_context cnContext;
        generate_chacha8_key(cnContext, "", newStorageKey);
      }

      copyContainerStoragePrefix(m_containerStorage, m_key, newStorage, newStorageKey);
      copyContainerStorageKeys(m_containerStorage, m_key, newStorage, newStorageKey);
      saveWalletCache(newStorage, newStorageKey, saveLevel, extra);
#ifndef _WIN32
      if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        m_logger(WARNING) << "Failed to set restrictive permissions on exported keys";
      }
#endif

      failExitHandler.cancel();

      m_logger(INFO) << "Container export finished";
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to export container: " << e.what();
      startBlockchainSynchronizer();
      throw;
    }

    startBlockchainSynchronizer();
    m_logger(INFO, BRIGHT_WHITE) << "Container exported";
  }

  void WalletGreen::exportWallet(const std::string &path, bool encrypt, WalletSaveLevel saveLevel, const std::string &extra)
  {
    m_logger(INFO, BRIGHT_WHITE) << "Exporting container...";

    throwIfNotInitialized();
    throwIfStopped();
    stopBlockchainSynchronizer();

    try
    {
      bool storageCreated = false;
      Tools::ScopeExit failExitHandler([path, &storageCreated] {
        // Don't delete file if it has existed
        if (storageCreated)
        {
          boost::system::error_code ignore;
          boost::filesystem::remove(path, ignore);
        }
      });

      ContainerStorage newStorage(path, FileMappedVectorOpenMode::CREATE, m_containerStorage.prefixSize());
      storageCreated = true;

      chacha8_key newStorageKey;
      if (encrypt)
      {
        newStorageKey = m_key;
      }
      else
      {
        cn_context cnContext;
        generate_chacha8_key(cnContext, "", newStorageKey);
      }

      copyContainerStoragePrefix(m_containerStorage, m_key, newStorage, newStorageKey);
      copyContainerStorageKeys(m_containerStorage, m_key, newStorage, newStorageKey);
      saveWalletCache(newStorage, newStorageKey, saveLevel, extra);
#ifndef _WIN32
      if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        m_logger(WARNING) << "Failed to set restrictive permissions on exported wallet";
      }
#endif

      failExitHandler.cancel();

      m_logger(INFO) << "Container export finished";
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to export container: " << e.what();
      startBlockchainSynchronizer();
      throw;
    }

    startBlockchainSynchronizer();
    m_logger(INFO, BRIGHT_WHITE) << "Container exported";
  }

  void WalletGreen::convertAndLoadWalletFile(const std::string &path, std::ifstream &&walletFileStream)
  {

    WalletSerializer s(
        *this,
        m_viewPublicKey,
        m_viewSecretKey,
        m_actualBalance,
        m_pendingBalance,
        m_walletsContainer,
        m_synchronizer,
        m_unlockTransactionsJob,
        m_transactions,
        m_transfers,
        m_transactionSoftLockTime,
        m_uncommitedTransactions);

    StdInputStream stream(walletFileStream);
    s.load(m_key, stream);
    walletFileStream.close();

    boost::filesystem::path bakPath = path + ".backup";
    boost::filesystem::path tmpPath = boost::filesystem::unique_path(path + ".tmp.%%%%-%%%%");
    if (boost::filesystem::exists(bakPath))
    {
      m_logger(INFO) << "Wallet backup already exists! Creating random file name backup.";
      bakPath = boost::filesystem::unique_path(path + ".%%%%-%%%%" + ".backup");
    }

    Tools::ScopeExit tmpFileDeleter([&tmpPath] {
      boost::system::error_code ignore;
      boost::filesystem::remove(tmpPath, ignore);
    });
    m_containerStorage.open(tmpPath.string(), Common::FileMappedVectorOpenMode::CREATE, sizeof(ContainerStoragePrefix));
    ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());
    prefix->version = WalletSerializerV2::SERIALIZATION_VERSION;
    prefix->nextIv = Crypto::randomChachaIV();
    uint64_t creationTimestamp = time(nullptr);
    prefix->encryptedViewKeys = encryptKeyPair(m_viewPublicKey, m_viewSecretKey, creationTimestamp);
    for (auto spendKeys : m_walletsContainer.get<RandomAccessIndex>())
    {
      m_containerStorage.push_back(encryptKeyPair(spendKeys.spendPublicKey, spendKeys.spendSecretKey, spendKeys.creationTimestamp));
      incNextIv();
    }
    saveWalletCache(m_containerStorage, m_key, WalletSaveLevel::SAVE_ALL, "");
    boost::filesystem::rename(path, bakPath);
    std::error_code ec;
    m_containerStorage.rename(path, ec);
    if (ec)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to rename " << tmpPath << " to " << path;

      boost::system::error_code ignore;
      boost::filesystem::rename(bakPath, path, ignore);
      throw std::system_error(ec, "Failed to replace wallet file");
    }

    tmpFileDeleter.cancel();
#ifndef _WIN32
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
      m_logger(WARNING) << "Failed to set restrictive permissions on converted wallet";
    }
#endif
    m_logger(INFO, BRIGHT_WHITE) << "Wallet file converted! Previous version: " << bakPath;
  }

  void WalletGreen::incNextIv()
  {
    static_assert(sizeof(uint64_t) == sizeof(Crypto::chacha8_iv), "Bad Crypto::chacha8_iv size");
    auto *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());
    incIv(prefix->nextIv);
  }

  void WalletGreen::loadAndDecryptContainerData(ContainerStorage &storage, const Crypto::chacha8_key &key, BinaryArray &containerData)
  {
    Common::MemoryInputStream suffixStream(storage.suffix(), storage.suffixSize());
    BinaryInputStreamSerializer suffixSerializer(suffixStream);
    Crypto::chacha8_iv suffixIv;
    BinaryArray encryptedContainer;
    suffixSerializer(suffixIv, "suffixIv");
    suffixSerializer(encryptedContainer, "encryptedContainer");

    BinaryArray decrypted(encryptedContainer.size());
    chacha8(encryptedContainer.data(), encryptedContainer.size(), key, suffixIv, reinterpret_cast<char *>(decrypted.data()));

    if (decrypted.size() < 32) {
      throw std::runtime_error("Container data too short: missing integrity tag");
    }

    uint8_t expectedTag[32];
    memcpy(expectedTag, decrypted.data(), 32);

    ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(storage.prefix());
    bool valid = false;

    if (prefix->version >= 7) {
      // v7+: HMAC-SHA256 integrity check with independent MAC key
      uint8_t macKey[32];
      unsigned int macKeyLen = 32;
      if (!HMAC(EVP_sha256(),
                key.data, sizeof(key.data),
                reinterpret_cast<const unsigned char*>("fuego-wallet-hmac"), 18,
                macKey, &macKeyLen) || macKeyLen != 32) {
        throw std::runtime_error("Container decryption: MAC key derivation failed");
      }

      uint8_t computedTag[32];
      unsigned int computedLen = 32;
      if (!HMAC(EVP_sha256(),
                macKey, sizeof(macKey),
                decrypted.data() + 32, decrypted.size() - 32,
                computedTag, &computedLen)) {
        throw std::runtime_error("Container decryption: HMAC tag recomputation failed");
      }
      valid = (computedLen == 32) && (CRYPTO_memcmp(computedTag, expectedTag, 32) == 0);
    } else {
      // v6: keccak integrity check (legacy)
      Crypto::Hash computedHash;
      keccak(decrypted.data() + 32, decrypted.size() - 32, computedHash.data, sizeof(computedHash.data));
      valid = (CRYPTO_memcmp(computedHash.data, expectedTag, 32) == 0);
    }

    if (!valid) {
      throw std::runtime_error("Container integrity check failed — wallet data may be corrupted or tampered");
    }

    containerData.assign(decrypted.begin() + 32, decrypted.end());
  }

  void WalletGreen::loadWalletCache(std::unordered_set<Crypto::PublicKey> &addedKeys, std::unordered_set<Crypto::PublicKey> &deletedKeys, std::string &extra)
  {
    assert(m_containerStorage.isOpened());

    BinaryArray contanerData;
    loadAndDecryptContainerData(m_containerStorage, m_key, contanerData);

    WalletSerializerV2 s(
        *this,
        m_viewPublicKey,
        m_viewSecretKey,
        m_actualBalance,
        m_pendingBalance,
        m_lockedDepositBalance,
        m_unlockedDepositBalance,
        m_walletsContainer,
        m_synchronizer,
        m_unlockTransactionsJob,
        m_transactions,
        m_transfers,
        m_deposits,
        m_uncommitedTransactions,
        extra,
        m_transactionSoftLockTime);

    Common::MemoryInputStream containerStream(contanerData.data(), contanerData.size());
    s.load(containerStream, reinterpret_cast<const ContainerStoragePrefix *>(m_containerStorage.prefix())->version);
    addedKeys = std::move(s.addedKeys());
    deletedKeys = std::move(s.deletedKeys());

    m_logger(INFO) << "Container cache loaded";
  }

  void WalletGreen::loadContainerStorage(const std::string &path)
  {
    try
    {
      uint8_t version = 0;
      {
        std::ifstream file(path, std::ios::binary);
        if (file.is_open()) {
          file.read(reinterpret_cast<char*>(&version), 1);
        }
      }

      if (version > 0 && version < 8) {
        m_logger(INFO, BRIGHT_WHITE) << "Migrating wallet from version " << (int)version << " to AEAD (v8)...";
        
        // Read old data manually
        std::ifstream oldFile(path, std::ios::binary);
        LegacyContainerStoragePrefix oldPrefix;
        if (!oldFile.read(reinterpret_cast<char*>(&oldPrefix), sizeof(LegacyContainerStoragePrefix))) {
          throw std::runtime_error("Failed to read legacy prefix");
        }

        uint64_t capacity, size;
        if (!oldFile.read(reinterpret_cast<char*>(&capacity), sizeof(uint64_t)) ||
            !oldFile.read(reinterpret_cast<char*>(&size), sizeof(uint64_t))) {
          throw std::runtime_error("Failed to read legacy metadata");
        }

        std::vector<LegacyEncryptedWalletRecord> oldRecords(size);
        if (size > 0 && !oldFile.read(reinterpret_cast<char*>(oldRecords.data()), size * sizeof(LegacyEncryptedWalletRecord))) {
          throw std::runtime_error("Failed to read legacy records");
        }

        std::vector<uint8_t> suffix((std::istreambuf_iterator<char>(oldFile)), std::istreambuf_iterator<char>());
        oldFile.close();

        // Perform migration in memory
        decryptKeyPair(*reinterpret_cast<const EncryptedWalletRecord*>(&oldPrefix.encryptedViewKeys), m_viewPublicKey, m_viewSecretKey, m_creationTimestamp, m_key, version);
        
        for (const auto& oldRec : oldRecords) {
          WalletRecord wallet;
          uint64_t creationTimestamp;
          decryptKeyPair(*reinterpret_cast<const EncryptedWalletRecord*>(&oldRec), wallet.spendPublicKey, wallet.spendSecretKey, creationTimestamp, m_key, version);
          wallet.creationTimestamp = creationTimestamp;
          wallet.actualBalance = 0;
          wallet.pendingBalance = 0;
          wallet.lockedDepositBalance = 0;
          wallet.unlockedDepositBalance = 0;
          wallet.container = nullptr;
          m_walletsContainer.emplace_back(std::move(wallet));
        }

        // We have everything in m_walletsContainer now.
        // Re-create the container storage in the NEW format.
        m_containerStorage.open(path, FileMappedVectorOpenMode::CREATE, sizeof(ContainerStoragePrefix));
        ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());
        prefix->version = WalletSerializerV2::SERIALIZATION_VERSION;
        prefix->nextIv = oldPrefix.nextIv;
        prefix->encryptedViewKeys = encryptKeyPair(m_viewPublicKey, m_viewSecretKey, m_creationTimestamp);
        
        for (const auto& wallet : m_walletsContainer) {
          m_containerStorage.push_back(encryptKeyPair(wallet.spendPublicKey, wallet.spendSecretKey, wallet.creationTimestamp));
        }

        // Save suffix (cache)
        if (!suffix.empty()) {
          // The suffix is already encrypted. We need to handle it.
          // For simplicity, we'll just let save() overwrite it later or handle it here if needed.
          // WalletGreen::load() will call loadWalletCache() after loadContainerStorage().
          // So we need to make sure m_containerStorage has the suffix.
          m_containerStorage.reserve(m_containerStorage.size()); // Ensure file is large enough
          // FileMappedVector doesn't have a direct suffix write, so we'll do it manually.
          std::ofstream outFile(path, std::ios::binary | std::ios::app);
          outFile.write(reinterpret_cast<const char*>(suffix.data()), suffix.size());
          outFile.close();
        }

        m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/" + podToHex(m_viewPublicKey).substr(0, 5));
        m_logger(INFO, BRIGHT_GREEN) << "Wallet migration successful";
        return;
      }

      m_containerStorage.open(path, FileMappedVectorOpenMode::OPEN, sizeof(ContainerStoragePrefix));

      ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());
      assert(prefix->version >= WalletSerializerV2::MIN_VERSION);

      uint64_t creationTimestamp;
      decryptKeyPair(prefix->encryptedViewKeys, m_viewPublicKey, m_viewSecretKey, creationTimestamp);
      m_creationTimestamp = creationTimestamp;
      throwIfKeysMissmatch(m_viewSecretKey, m_viewPublicKey, "Restored view public key doesn't correspond to secret key");
      m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/" + podToHex(m_viewPublicKey).substr(0, 5));

      loadSpendKeys();

      m_logger(DEBUGGING) << "Container keys were successfully loaded";
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to load container keys: " << e.what();

      m_walletsContainer.clear();
      m_containerStorage.close();

      throw;
    }
  }

  void WalletGreen::encryptAndSaveContainerData(ContainerStorage &storage, const Crypto::chacha8_key &key, const void *containerData, size_t containerDataSize)
  {
    ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(storage.prefix());

    Crypto::chacha8_iv suffixIv = prefix->nextIv;
    incIv(prefix->nextIv);

    // Derive independent MAC key from encryption key
    uint8_t macKey[32];
    unsigned int macKeyLen = 32;
    if (!HMAC(EVP_sha256(),
              key.data, sizeof(key.data),
              reinterpret_cast<const unsigned char*>("fuego-wallet-hmac"), 18,
              macKey, &macKeyLen) || macKeyLen != 32) {
      throw std::runtime_error("Container encryption: MAC key derivation failed");
    }

    // Compute HMAC-SHA256 tag over plaintext
    uint8_t tag[32];
    unsigned int tagLen = 32;
    if (!HMAC(EVP_sha256(),
              macKey, sizeof(macKey),
              static_cast<const unsigned char*>(containerData), containerDataSize,
              tag, &tagLen)) {
      throw std::runtime_error("Container encryption: HMAC tag computation failed");
    }

    BinaryArray plaintextWithTag(32 + containerDataSize);
    memcpy(plaintextWithTag.data(), tag, 32);
    memcpy(plaintextWithTag.data() + 32, containerData, containerDataSize);

    BinaryArray encryptedContainer;
    encryptedContainer.resize(plaintextWithTag.size());
    chacha8(plaintextWithTag.data(), plaintextWithTag.size(), key, suffixIv, reinterpret_cast<char *>(encryptedContainer.data()));

    std::string suffix;
    Common::StringOutputStream suffixStream(suffix);
    BinaryOutputStreamSerializer suffixSerializer(suffixStream);
    suffixSerializer(suffixIv, "suffixIv");
    suffixSerializer(encryptedContainer, "encryptedContainer");

    storage.resizeSuffix(suffix.size());
    std::copy(suffix.begin(), suffix.end(), storage.suffix());
  }

  void WalletGreen::incIv(Crypto::chacha8_iv &iv)
  {
    static_assert(sizeof(uint64_t) == sizeof(Crypto::chacha8_iv), "Bad Crypto::chacha8_iv size");
    uint64_t *i = reinterpret_cast<uint64_t *>(&iv);
    if (*i < std::numeric_limits<uint64_t>::max())
    {
      ++(*i);
    }
    else
    {
      throw std::runtime_error("ChaCha8 IV overflow — keystream reuse risk. Reset wallet container.");
    }
  }

  void WalletGreen::load(const std::string &path, const std::string &password, std::string &extra)
  {
    m_logger(INFO, BRIGHT_WHITE) << "Loading container...";

    if (m_state != WalletState::NOT_INITIALIZED)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to load: already initialized.";
      throw std::system_error(make_error_code(error::WRONG_STATE));
    }

    throwIfStopped();

    stopBlockchainSynchronizer();

    Crypto::cn_context cnContext;
    generate_chacha8_key(cnContext, password, m_key);

    std::ifstream walletFileStream(path, std::ios_base::binary);
    int version = walletFileStream.peek();
    if (version == EOF)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to read wallet version";
      throw std::system_error(make_error_code(error::WRONG_VERSION), "Failed to read wallet version");
    }

    if (version < WalletSerializerV2::MIN_VERSION)
    {
      convertAndLoadWalletFile(path, std::move(walletFileStream));
    }
    else
    {
      walletFileStream.close();

      if (version > WalletSerializerV2::SERIALIZATION_VERSION)
      {
        m_logger(ERROR, BRIGHT_RED) << "Unsupported wallet version: " << version;
        throw std::system_error(make_error_code(error::WRONG_VERSION), "Unsupported wallet version");
      }

      loadContainerStorage(path);
      subscribeWallets();

      if (m_containerStorage.suffixSize() > 0)
      {
        try
        {
          std::unordered_set<Crypto::PublicKey> addedSpendKeys;
          std::unordered_set<Crypto::PublicKey> deletedSpendKeys;
          loadWalletCache(addedSpendKeys, deletedSpendKeys, extra);

          if (!addedSpendKeys.empty())
          {
            m_logger(WARNING, BRIGHT_YELLOW) << "Found addresses not saved in container cache. Resynchronize container";
            clearCaches(false, true);
            subscribeWallets();
          }

          if (!deletedSpendKeys.empty())
          {
            m_logger(WARNING, BRIGHT_YELLOW) << "Found deleted addresses saved in container cache. Remove its transactions";
            deleteOrphanTransactions(deletedSpendKeys);
          }

          if (!addedSpendKeys.empty() || !deletedSpendKeys.empty())
          {
            saveWalletCache(m_containerStorage, m_key, WalletSaveLevel::SAVE_ALL, extra);
          }
        }
        catch (const std::exception &e)
        {
          m_logger(ERROR, BRIGHT_RED) << "Failed to load cache: " << e.what() << ", reset wallet data";
          clearCaches(true, true);
          subscribeWallets();
        }
      }
    }

    // Read all output keys cache
    try
    {
      std::vector<AccountPublicAddress> subscriptionList;
      m_synchronizer.getSubscriptions(subscriptionList);
      for (auto &addr : subscriptionList)
      {
        auto sub = m_synchronizer.getSubscription(addr);
        if (sub != nullptr)
        {
          std::vector<TransactionOutputInformation> allTransfers;
          ITransfersContainer *container = &sub->getContainer();
          container->getOutputs(allTransfers, ITransfersContainer::IncludeAll);
          m_logger(INFO, BRIGHT_WHITE) << "Known Transfers " << allTransfers.size();
          for (auto &o : allTransfers)
          {
            if (o.type != TransactionTypes::OutputType::Invalid)
            {
              m_synchronizer.addPublicKeysSeen(addr, o.transactionHash, o.outputKey);
            }
          }
        }
      }
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to read output keys!! Continue without output keys: " << e.what();
    }

    m_blockchainSynchronizer.addObserver(this);

    initTransactionPool();

    assert(m_blockchain.empty());
    if (m_walletsContainer.get<RandomAccessIndex>().size() != 0)
    {
      m_synchronizer.subscribeConsumerNotifications(m_viewPublicKey, this);
      initBlockchain(m_viewPublicKey);

      startBlockchainSynchronizer();
    }
    else
    {
      m_blockchain.push_back(m_currency.genesisBlockHash());
      m_logger(DEBUGGING) << "Add genesis block hash to blockchain";
    }

    m_password = password;
    m_path = path;
    m_extra = extra;

    m_state = WalletState::INITIALIZED;
    m_logger(INFO, BRIGHT_WHITE) << "Container loaded, view public key " << Common::podToHex(m_viewPublicKey) << ", wallet count " << m_walletsContainer.size() << ", actual balance " << m_currency.formatAmount(m_actualBalance) << ", pending balance " << m_currency.formatAmount(m_pendingBalance);
  }

  void WalletGreen::clearCaches(bool clearTransactions, bool clearCachedData)
  {
    if (clearTransactions)
    {
      m_transactions.clear();
      m_transfers.clear();
      m_deposits.clear();
    }

    if (clearCachedData)
    {
      for (auto it = m_walletsContainer.begin(); it != m_walletsContainer.end(); ++it) {
        m_walletsContainer.modify(it, [](WalletRecord &wallet) {
          wallet.actualBalance = 0;
          wallet.pendingBalance = 0;
          wallet.lockedDepositBalance = 0;
          wallet.unlockedDepositBalance = 0;
          wallet.container = nullptr;
        });
      }

      if (!clearTransactions)
      {
        for (auto it = m_transactions.begin(); it != m_transactions.end(); ++it)
        {
          m_transactions.modify(it, [](WalletTransaction &tx) {
            tx.state = WalletTransactionState::CANCELLED;
            tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
          });
        }
      }

      std::vector<AccountPublicAddress> subscriptions;
      m_synchronizer.getSubscriptions(subscriptions);
      std::for_each(subscriptions.begin(), subscriptions.end(), [this](const AccountPublicAddress &address) { m_synchronizer.removeSubscription(address); });

      m_uncommitedTransactions.clear();
      m_unlockTransactionsJob.clear();
      m_actualBalance = 0;
      m_pendingBalance = 0;
      m_lockedDepositBalance = 0;
      m_unlockedDepositBalance = 0;
      m_fusionTxsCache.clear();
      m_blockchain.clear();
    }
  }

  void WalletGreen::subscribeWallets()
  {
    try
    {
      auto &index = m_walletsContainer.get<RandomAccessIndex>();

      for (auto it = index.begin(); it != index.end(); ++it)
      {
        const auto &wallet = *it;

        AccountSubscription sub;
        sub.keys.address.viewPublicKey = m_viewPublicKey;
        sub.keys.address.spendPublicKey = wallet.spendPublicKey;
        sub.keys.viewSecretKey = m_viewSecretKey;
        sub.keys.spendSecretKey = wallet.spendSecretKey;
        sub.transactionSpendableAge = m_transactionSoftLockTime;
        sub.syncStart.height = 0;
        sub.syncStart.timestamp = std::max(static_cast<uint64_t>(wallet.creationTimestamp), ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;

        auto &subscription = m_synchronizer.addSubscription(sub);
        bool r = index.modify(it, [&subscription](WalletRecord &rec) { rec.container = &subscription.getContainer(); });
        assert(r);
        if (r)
        {
        };
        subscription.addObserver(this);
      }
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to subscribe wallets: " << e.what();

      std::vector<AccountPublicAddress> subscriptionList;
      m_synchronizer.getSubscriptions(subscriptionList);
      for (auto &subscription : subscriptionList)
      {
        m_synchronizer.removeSubscription(subscription);
      }

      throw;
    }
  }

  void WalletGreen::load(const std::string &path, const std::string &password)
  {
    std::string extra;
    load(path, password, extra);
  }

  void WalletGreen::changePassword(const std::string &oldPassword, const std::string &newPassword)
  {
    throwIfNotInitialized();
    throwIfStopped();

    if (m_password.compare(oldPassword))
    {
      throw std::system_error(make_error_code(error::WRONG_PASSWORD));
    }

    m_password = newPassword;
  }

  size_t WalletGreen::getAddressCount() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return m_walletsContainer.get<RandomAccessIndex>().size();
  }

  size_t WalletGreen::getWalletDepositCount() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return m_deposits.get<RandomAccessIndex>().size();
  }

  std::string WalletGreen::getAddress(size_t index) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    if (index >= m_walletsContainer.get<RandomAccessIndex>().size())
    {
      throw std::system_error(make_error_code(std::errc::invalid_argument));
    }

    const WalletRecord &wallet = m_walletsContainer.get<RandomAccessIndex>()[index];
    return m_currency.accountAddressAsString({wallet.spendPublicKey, m_viewPublicKey});
  }

  KeyPair WalletGreen::getAddressSpendKey(size_t index) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    if (index >= m_walletsContainer.get<RandomAccessIndex>().size())
    {
      throw std::system_error(make_error_code(std::errc::invalid_argument));
    }

    const WalletRecord &wallet = m_walletsContainer.get<RandomAccessIndex>()[index];
    return {wallet.spendPublicKey, wallet.spendSecretKey};
  }

  KeyPair WalletGreen::getAddressSpendKey(const std::string &address) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    CryptoNote::AccountPublicAddress pubAddr = parseAddress(address);

    auto it = m_walletsContainer.get<KeysIndex>().find(pubAddr.spendPublicKey);
    if (it == m_walletsContainer.get<KeysIndex>().end())
    {
      throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
    }

    return {it->spendPublicKey, it->spendSecretKey};
  }

  KeyPair WalletGreen::getViewKey() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return {m_viewPublicKey, m_viewSecretKey};
  }

  std::string WalletGreen::createAddress()
  {
    KeyPair spendKey;
    Crypto::generate_keys(spendKey.publicKey, spendKey.secretKey);
    uint64_t creationTimestamp = static_cast<uint64_t>(time(nullptr));

    return doCreateAddress(spendKey.publicKey, spendKey.secretKey, creationTimestamp);
  }

  std::string WalletGreen::createAddress(const Crypto::SecretKey &spendSecretKey)
  {
    Crypto::PublicKey spendPublicKey;
    if (!Crypto::secret_key_to_public_key(spendSecretKey, spendPublicKey))
    {
      throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
    }
    uint64_t creationTimestamp = static_cast<uint64_t>(time(nullptr));
    return doCreateAddress(spendPublicKey, spendSecretKey, creationTimestamp);
  }

  std::string WalletGreen::createAddress(const Crypto::PublicKey &spendPublicKey)
  {
    if (!Crypto::check_key(spendPublicKey))
    {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "Wrong public key format");
    }
    uint64_t creationTimestamp = static_cast<uint64_t>(time(nullptr));
    return doCreateAddress(spendPublicKey, NULL_SECRET_KEY, creationTimestamp);
  }

  std::vector<std::string> WalletGreen::createAddressList(const std::vector<Crypto::SecretKey> &spendSecretKeys, bool reset)
  {
    std::vector<NewAddressData> addressDataList(spendSecretKeys.size());
    for (size_t i = 0; i < spendSecretKeys.size(); ++i)
    {
      Crypto::PublicKey spendPublicKey;
      if (!Crypto::secret_key_to_public_key(spendSecretKeys[i], spendPublicKey))
      {
        m_logger(ERROR) << "createAddressList(): failed to convert secret key to public key";
        throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
      }

      addressDataList[i].spendSecretKey = spendSecretKeys[i];
      addressDataList[i].spendPublicKey = spendPublicKey;
      addressDataList[i].creationTimestamp = reset ? 0 : static_cast<uint64_t>(time(nullptr));
    }

    return doCreateAddressList(addressDataList);
  }

  std::vector<std::string> WalletGreen::doCreateAddressList(const std::vector<NewAddressData> &addressDataList)
  {
    throwIfNotInitialized();
    throwIfStopped();

    stopBlockchainSynchronizer();

    std::vector<std::string> addresses;
    try
    {
      uint64_t minCreationTimestamp = std::numeric_limits<uint64_t>::max();

      {
        if (addressDataList.size() > 1)
        {
          m_containerStorage.setAutoFlush(false);
        }

        Tools::ScopeExit exitHandler([this] {
          if (!m_containerStorage.getAutoFlush())
          {
            m_containerStorage.setAutoFlush(true);
            m_containerStorage.flush();
          }
        });

        for (auto &addressData : addressDataList)
        {
          assert(addressData.creationTimestamp <= std::numeric_limits<uint64_t>::max() - m_currency.blockFutureTimeLimit());
          std::string address = addWallet(addressData.spendPublicKey, addressData.spendSecretKey, addressData.creationTimestamp);
          m_logger(INFO, BRIGHT_WHITE) << "New wallet added " << address << ", creation timestamp " << addressData.creationTimestamp;
          addresses.push_back(std::move(address));

          minCreationTimestamp = std::min(minCreationTimestamp, addressData.creationTimestamp);
        }
      }

      m_containerStorage.setAutoFlush(true);
      auto currentTime = static_cast<uint64_t>(time(nullptr));
      if (minCreationTimestamp + m_currency.blockFutureTimeLimit() < currentTime)
      {
        m_logger(DEBUGGING) << "Reset is required";
        save(WalletSaveLevel::SAVE_KEYS_AND_TRANSACTIONS, m_extra);
        shutdown();
        load(m_path, m_password);
      }
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to add wallets: " << e.what();
      startBlockchainSynchronizer();
      throw;
    }

    startBlockchainSynchronizer();

    return addresses;
  }

  std::string WalletGreen::doCreateAddress(const Crypto::PublicKey &spendPublicKey, const Crypto::SecretKey &spendSecretKey, uint64_t creationTimestamp)
  {
    assert(creationTimestamp <= std::numeric_limits<uint64_t>::max() - m_currency.blockFutureTimeLimit());

    std::vector<NewAddressData> addressDataList;
    addressDataList.push_back(NewAddressData{spendPublicKey, spendSecretKey, creationTimestamp});
    std::vector<std::string> addresses = doCreateAddressList(addressDataList);
    assert(addresses.size() == 1);

    return addresses.front();
  }

  std::string WalletGreen::addWallet(const Crypto::PublicKey &spendPublicKey, const Crypto::SecretKey &spendSecretKey, uint64_t creationTimestamp)
  {
    auto &index = m_walletsContainer.get<KeysIndex>();

    auto trackingMode = getTrackingMode();

    if ((trackingMode == WalletTrackingMode::TRACKING && spendSecretKey != NULL_SECRET_KEY) ||
        (trackingMode == WalletTrackingMode::NOT_TRACKING && spendSecretKey == NULL_SECRET_KEY))
    {

      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }

    auto insertIt = index.find(spendPublicKey);
    if (insertIt != index.end())
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to add wallet: address already exists, " << m_currency.accountAddressAsString(AccountPublicAddress{spendPublicKey, m_viewPublicKey});
      throw std::system_error(make_error_code(error::ADDRESS_ALREADY_EXISTS));
    }

    m_containerStorage.push_back(encryptKeyPair(spendPublicKey, spendSecretKey, creationTimestamp));
    incNextIv();

    try
    {
      AccountSubscription sub;
      sub.keys.address.viewPublicKey = m_viewPublicKey;
      sub.keys.address.spendPublicKey = spendPublicKey;
      sub.keys.viewSecretKey = m_viewSecretKey;
      sub.keys.spendSecretKey = spendSecretKey;
      sub.transactionSpendableAge = m_transactionSoftLockTime;
      sub.syncStart.height = 0;
      sub.syncStart.timestamp = std::max(creationTimestamp, ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;

      auto &trSubscription = m_synchronizer.addSubscription(sub);
      ITransfersContainer *container = &trSubscription.getContainer();

      WalletRecord wallet;
      wallet.spendPublicKey = spendPublicKey;
      wallet.spendSecretKey = spendSecretKey;
      wallet.container = container;
      wallet.creationTimestamp = static_cast<time_t>(creationTimestamp);
      trSubscription.addObserver(this);

      index.insert(insertIt, std::move(wallet));
      m_logger(DEBUGGING) << "Wallet count " << m_walletsContainer.size();

      if (index.size() == 1)
      {
        m_synchronizer.subscribeConsumerNotifications(m_viewPublicKey, this);
        initBlockchain(m_viewPublicKey);
      }

      auto address = m_currency.accountAddressAsString({spendPublicKey, m_viewPublicKey});
      m_logger(DEBUGGING) << "Wallet added " << address << ", creation timestamp " << creationTimestamp;
      return address;
    }
    catch (const std::exception &e)
    {
      m_logger(ERROR) << "Failed to add wallet: " << e.what();

      try
      {
        m_containerStorage.pop_back();
      }
      catch (...)
      {
        m_logger(ERROR) << "Failed to rollback adding wallet to storage";
      }

      throw;
    }
  }

  std::string WalletGreen::createSubAddress(uint32_t major, uint32_t minor, uint64_t creationTimestamp)
  {
    throwIfNotInitialized();
    throwIfStopped();
    throwIfTrackingMode();

    if (major == 0 && minor == 0) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS),
                              "Sub-address index (0,0) is reserved for the primary address");
    }

    // Get master spend public key (index 0 = primary wallet)
    if (m_walletsContainer.get<RandomAccessIndex>().empty()) {
      throw std::system_error(make_error_code(error::NOT_INITIALIZED));
    }
    const WalletRecord& primary = m_walletsContainer.get<RandomAccessIndex>()[0];
    const Crypto::SecretKey* spendSec = (primary.spendSecretKey != NULL_SECRET_KEY)
                                        ? &primary.spendSecretKey : nullptr;

    Crypto::SubAddressKeys subKeys = Crypto::deriveSubAddressKeys(
        m_viewSecretKey,
        primary.spendPublicKey,
        spendSec,
        major, minor);

    if (creationTimestamp == 0) {
      creationTimestamp = static_cast<uint64_t>(time(nullptr));
    }

    // Register the sub-address spend key as a new wallet entry (reuses multi-wallet infrastructure).
    // The sub spend secret key (b_ij = b + m) is stored so spending works automatically.
    std::string addr = doCreateAddress(subKeys.spendPublicKey,
                                       subKeys.hasSpendSecretKey ? subKeys.spendSecretKey : NULL_SECRET_KEY,
                                       creationTimestamp);

    // Tag the newly-created wallet record with its sub-address index.
    auto& index = m_walletsContainer.get<KeysIndex>();
    auto it = index.find(subKeys.spendPublicKey);
    if (it != index.end()) {
      index.modify(it, [major, minor](WalletRecord& w) {
        w.isSubAddress  = true;
        w.subaddrMajor  = major;
        w.subaddrMinor  = minor;
      });
    }

    // Return address string with sub-address prefix.
    AccountPublicAddress subAddr{subKeys.spendPublicKey, subKeys.viewPublicKey};
    return m_currency.subAddressAsString(subAddr);
  }

  std::vector<std::tuple<uint32_t, uint32_t, std::string>> WalletGreen::listSubAddresses() const
  {
    throwIfNotInitialized();

    std::vector<std::tuple<uint32_t, uint32_t, std::string>> result;
    for (const auto& w : m_walletsContainer.get<RandomAccessIndex>()) {
      if (!w.isSubAddress) continue;
      // Reconstruct sub view public key: C_ij = a * D_ij
      // We use generate_key_derivation which does cofactor-multiply internally,
      // so we instead derive via deriveSubAddressKeys (view-only, no spend secret needed).
      Crypto::SubAddressKeys subKeys = Crypto::deriveSubAddressKeys(
          m_viewSecretKey,
          m_walletsContainer.get<RandomAccessIndex>()[0].spendPublicKey,
          nullptr,
          w.subaddrMajor, w.subaddrMinor);
      AccountPublicAddress subAddr{w.spendPublicKey, subKeys.viewPublicKey};
      std::string addrStr = m_currency.subAddressAsString(subAddr);
      result.emplace_back(w.subaddrMajor, w.subaddrMinor, addrStr);
    }
    return result;
  }

  void WalletGreen::deleteAddress(const std::string &address)
  {
    throwIfNotInitialized();
    throwIfStopped();

    CryptoNote::AccountPublicAddress pubAddr = parseAddress(address);

    auto it = m_walletsContainer.get<KeysIndex>().find(pubAddr.spendPublicKey);
    if (it == m_walletsContainer.get<KeysIndex>().end())
    {
      throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
    }

    stopBlockchainSynchronizer();

    m_actualBalance -= it->actualBalance;
    m_pendingBalance -= it->pendingBalance;

    m_synchronizer.removeSubscription(pubAddr);

    deleteContainerFromUnlockTransactionJobs(it->container);
    std::vector<size_t> deletedTransactions;
    std::vector<size_t> updatedTransactions = deleteTransfersForAddress(address, deletedTransactions);
    deleteFromUncommitedTransactions(deletedTransactions);

    m_walletsContainer.get<KeysIndex>().erase(it);

    auto addressIndex = std::distance(
        m_walletsContainer.get<RandomAccessIndex>().begin(), m_walletsContainer.project<RandomAccessIndex>(it));

    m_containerStorage.erase(std::next(m_containerStorage.begin(), addressIndex));

    if (m_walletsContainer.get<RandomAccessIndex>().size() != 0)
    {
      startBlockchainSynchronizer();
    }
    else
    {
      m_blockchain.clear();
      m_blockchain.push_back(m_currency.genesisBlockHash());
    }

    for (auto transactionId : updatedTransactions)
    {
      pushEvent(makeTransactionUpdatedEvent(transactionId));
    }
  }

  uint64_t WalletGreen::getActualBalance() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return m_actualBalance;
  }

  uint64_t WalletGreen::getActualBalance(const std::string &address) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    const auto &wallet = getWalletRecord(address);
    return wallet.actualBalance;
  }

  uint64_t WalletGreen::getPendingBalance() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return m_pendingBalance;
  }

  uint64_t WalletGreen::getLockedDepositBalance(const std::string &address) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    const auto &wallet = getWalletRecord(address);
    return wallet.lockedDepositBalance;
  }

  uint64_t WalletGreen::getUnlockedDepositBalance(const std::string &address) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    const auto &wallet = getWalletRecord(address);
    return wallet.unlockedDepositBalance;
  }

  uint64_t WalletGreen::getLockedDepositBalance() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return m_lockedDepositBalance;
  }

  uint64_t WalletGreen::getUnlockedDepositBalance() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return m_unlockedDepositBalance;
  }

  uint64_t WalletGreen::getLockedHeatBalance() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    uint64_t total = 0;
    for (const auto& dep : m_deposits.get<RandomAccessIndex>()) {
      if (dep.depositType == Deposit::Type::HEAT && dep.locked)
        total += dep.amount + dep.interest;
    }
    return total;
  }

  uint64_t WalletGreen::getUnlockedHeatBalance() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    uint64_t total = 0;
    for (const auto& dep : m_deposits.get<RandomAccessIndex>()) {
      if (dep.depositType == Deposit::Type::HEAT && !dep.locked)
        total += dep.amount + dep.interest;
    }
    return total;
  }

  uint64_t WalletGreen::getPendingBalance(const std::string &address) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    const auto &wallet = getWalletRecord(address);
    return wallet.pendingBalance;
  }

  size_t WalletGreen::getTransactionCount() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return m_transactions.get<RandomAccessIndex>().size();
  }

  WalletTransaction WalletGreen::getTransaction(size_t transactionIndex) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    if (m_transactions.size() <= transactionIndex)
    {
      throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
    }

    return m_transactions.get<RandomAccessIndex>()[transactionIndex];
  }

  Deposit WalletGreen::getDeposit(size_t bankingIndex) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    if (m_deposits.size() <= bankingIndex)
    {
      throw std::system_error(make_error_code(CryptoNote::error::DEPOSIT_DOESNOT_EXIST));
    }

    return m_deposits.get<RandomAccessIndex>()[bankingIndex];
  }

  size_t WalletGreen::getTransactionTransferCount(size_t transactionIndex) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    auto bounds = getTransactionTransfersRange(transactionIndex);
    return static_cast<size_t>(std::distance(bounds.first, bounds.second));
  }

  WalletTransfer WalletGreen::getTransactionTransfer(size_t transactionIndex, size_t transferIndex) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    auto bounds = getTransactionTransfersRange(transactionIndex);

    if (transferIndex >= static_cast<size_t>(std::distance(bounds.first, bounds.second)))
    {
      throw std::system_error(make_error_code(std::errc::invalid_argument));
    }

    return std::next(bounds.first, transferIndex)->second;
  }

  WalletGreen::TransfersRange WalletGreen::getTransactionTransfersRange(size_t transactionIndex) const
  {
    auto val = std::make_pair(transactionIndex, WalletTransfer());

    auto bounds = std::equal_range(m_transfers.begin(), m_transfers.end(), val, [](const TransactionTransferPair &a, const TransactionTransferPair &b) {
      return a.first < b.first;
    });

    return bounds;
  }

  size_t WalletGreen::transfer(const TransactionParameters &transactionParameters, Crypto::SecretKey &transactionSK)
  {
    Tools::ScopeExit releaseContext([this] {
      m_dispatcher.yield();
    });

    System::EventLock lk(m_readyEvent);

    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    return doTransfer(transactionParameters, transactionSK);
  }

  void WalletGreen::prepareTransaction(
      std::vector<WalletOuts> &&wallets,
      const std::vector<WalletOrder> &orders,
      const std::vector<WalletMessage> &messages,
      uint64_t fee,
      uint64_t mixIn,
      const std::string &extra,
      uint64_t unlockTimestamp,
      const DonationSettings &donation,
      const CryptoNote::AccountPublicAddress &changeDestination,
      PreparedTransaction &preparedTransaction,
      Crypto::SecretKey &transactionSK)
  {

    preparedTransaction.destinations = convertOrdersToTransfers(orders);
    preparedTransaction.neededMoney = countNeededMoney(preparedTransaction.destinations, fee);

    std::vector<OutputToTransfer> selectedTransfers;
    uint64_t foundMoney = selectTransfers(preparedTransaction.neededMoney, mixIn == 0, m_currency.defaultDustThreshold(), std::move(wallets), selectedTransfers);

    if (foundMoney < preparedTransaction.neededMoney)
    {
      throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Not enough money");
    }

    typedef CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
    std::vector<outs_for_amount> mixinResult;

    if (mixIn != 0)
    {
      requestMixinOuts(selectedTransfers, mixIn, mixinResult);
    }

    std::vector<InputInfo> keysInfo;
    prepareInputs(selectedTransfers, mixinResult, mixIn, keysInfo);

    uint64_t donationAmount = pushDonationTransferIfPossible(donation, foundMoney - preparedTransaction.neededMoney, m_currency.defaultDustThreshold(), preparedTransaction.destinations);
    preparedTransaction.changeAmount = foundMoney - preparedTransaction.neededMoney - donationAmount;

    std::vector<ReceiverAmounts> decomposedOutputs = splitDestinations(preparedTransaction.destinations, m_currency.defaultDustThreshold(), m_currency);
    if (preparedTransaction.changeAmount != 0)
    {
      WalletTransfer changeTransfer;
      changeTransfer.type = WalletTransferType::CHANGE;
      changeTransfer.address = m_currency.accountAddressAsString(changeDestination);
      changeTransfer.amount = static_cast<int64_t>(preparedTransaction.changeAmount);
      preparedTransaction.destinations.emplace_back(std::move(changeTransfer));

      auto splittedChange = splitAmount(preparedTransaction.changeAmount, changeDestination, m_currency.defaultDustThreshold());
      decomposedOutputs.emplace_back(std::move(splittedChange));
    }

    preparedTransaction.transaction = makeTransaction(decomposedOutputs, keysInfo, messages, extra, unlockTimestamp, transactionSK);
  }

  void WalletGreen::validateTransactionParameters(const TransactionParameters &transactionParameters) const
  {
    if (transactionParameters.destinations.empty())
    {
      throw std::system_error(make_error_code(error::ZERO_DESTINATION));
    }

    if (transactionParameters.donation.address.empty() != (transactionParameters.donation.threshold == 0))
    {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }

    validateSourceAddresses(transactionParameters.sourceAddresses);
    validateChangeDestination(transactionParameters.sourceAddresses, transactionParameters.changeDestination, false);
    validateOrders(transactionParameters.destinations);
  }

  size_t WalletGreen::doTransfer(const TransactionParameters &transactionParameters, Crypto::SecretKey &transactionSK)
  {
    validateTransactionParameters(transactionParameters);
    CryptoNote::AccountPublicAddress changeDestination = getChangeDestination(transactionParameters.changeDestination, transactionParameters.sourceAddresses);

    std::vector<WalletOuts> wallets;
    if (!transactionParameters.sourceAddresses.empty())
    {
      wallets = pickWallets(transactionParameters.sourceAddresses);
    }
    else
    {
      wallets = pickWalletsWithMoney();
    }

    PreparedTransaction preparedTransaction;
    prepareTransaction(
        std::move(wallets),
        transactionParameters.destinations,
        transactionParameters.messages,
        transactionParameters.fee,
        transactionParameters.mixIn,
        transactionParameters.extra,
        transactionParameters.unlockTimestamp,
        transactionParameters.donation,
        changeDestination,
        preparedTransaction,
        transactionSK);

    return validateSaveAndSendTransaction(*preparedTransaction.transaction, preparedTransaction.destinations, false, true);
  }

  size_t WalletGreen::makeTransaction(const TransactionParameters &sendingTransaction)
  {
    size_t id = WALLET_INVALID_TRANSACTION_ID;
    Tools::ScopeExit releaseContext([this, &id] {
      m_dispatcher.yield();

      if (id != WALLET_INVALID_TRANSACTION_ID)
      {
        auto &tx = m_transactions[id];
      }
    });

    System::EventLock lk(m_readyEvent);

    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    validateTransactionParameters(sendingTransaction);
    CryptoNote::AccountPublicAddress changeDestination = getChangeDestination(sendingTransaction.changeDestination, sendingTransaction.sourceAddresses);
    m_logger(DEBUGGING) << "Change address " << m_currency.accountAddressAsString(changeDestination);

    std::vector<WalletOuts> wallets;
    if (!sendingTransaction.sourceAddresses.empty())
    {
      wallets = pickWallets(sendingTransaction.sourceAddresses);
    }
    else
    {
      wallets = pickWalletsWithMoney();
    }

    PreparedTransaction preparedTransaction;
    Crypto::SecretKey txSecretKey;
    prepareTransaction(
        std::move(wallets),
        sendingTransaction.destinations,
        sendingTransaction.messages,
        sendingTransaction.fee,
        sendingTransaction.mixIn,
        sendingTransaction.extra,
        sendingTransaction.unlockTimestamp,
        sendingTransaction.donation,
        changeDestination,
        preparedTransaction,
        txSecretKey);

    id = validateSaveAndSendTransaction(*preparedTransaction.transaction, preparedTransaction.destinations, false, false);
    return id;
  }

  void WalletGreen::commitTransaction(size_t transactionId)
  {
    System::EventLock lk(m_readyEvent);

    throwIfNotInitialized();
    throwIfStopped();
    throwIfTrackingMode();

    if (transactionId >= m_transactions.size())
    {
      m_logger(ERROR, BRIGHT_RED) << "Failed to commit transaction: invalid index " << transactionId << ". Number of transactions: " << m_transactions.size();
      throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
    }

    auto txIt = std::next(m_transactions.get<RandomAccessIndex>().begin(), transactionId);
    if (m_uncommitedTransactions.count(transactionId) == 0 || txIt->state != WalletTransactionState::CREATED)
    {
      throw std::system_error(make_error_code(error::TX_TRANSFER_IMPOSSIBLE));
    }

    std::error_code ec;

    try {
        auto relayTransactionCompleted = std::promise<std::error_code>();
        auto relayTransactionWaitFuture = relayTransactionCompleted.get_future();

        m_node.relayTransaction(m_uncommitedTransactions[transactionId], [&ec, &relayTransactionCompleted, this](std::error_code error) {
          auto detachedPromise = std::move(relayTransactionCompleted);
          detachedPromise.set_value(ec);
          });
        ec = relayTransactionWaitFuture.get();
      }
      catch (const std::exception& e) {
        m_logger(ERROR, BRIGHT_RED) << "Failed to relay uncommited transaction: " << e.what();
      }


    if (!ec)
    {
      updateTransactionStateAndPushEvent(transactionId, WalletTransactionState::SUCCEEDED);
      m_uncommitedTransactions.erase(transactionId);
    }
    else
    {
      throw std::system_error(ec);
    }
  }

  void WalletGreen::rollbackUncommitedTransaction(size_t transactionId)
  {
    Tools::ScopeExit releaseContext([this] {
      m_dispatcher.yield();
    });

    System::EventLock lk(m_readyEvent);

    throwIfNotInitialized();
    throwIfStopped();
    throwIfTrackingMode();

    if (transactionId >= m_transactions.size())
    {
      throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
    }

    auto txIt = m_transactions.get<RandomAccessIndex>().begin();
    std::advance(txIt, transactionId);
    if (m_uncommitedTransactions.count(transactionId) == 0 || txIt->state != WalletTransactionState::CREATED)
    {
      throw std::system_error(make_error_code(error::TX_CANCEL_IMPOSSIBLE));
    }

    removeUnconfirmedTransaction(getObjectHash(m_uncommitedTransactions[transactionId]));
    m_uncommitedTransactions.erase(transactionId);
  }

  void WalletGreen::pushBackOutgoingTransfers(size_t txId, const std::vector<WalletTransfer> &destinations)
  {

    for (const auto &dest : destinations)
    {
      WalletTransfer d;
      d.type = dest.type;
      d.address = dest.address;
      d.amount = dest.amount;

      m_transfers.emplace_back(txId, std::move(d));
    }
  }

  size_t WalletGreen::insertOutgoingTransactionAndPushEvent(const Hash &transactionHash, uint64_t fee, const BinaryArray &extra, uint64_t unlockTimestamp)
  {
    WalletTransaction insertTx;
    insertTx.state = WalletTransactionState::CREATED;
    insertTx.creationTime = static_cast<uint64_t>(time(nullptr));
    insertTx.unlockTime = unlockTimestamp;
    insertTx.firstDepositId = CryptoNote::WALLET_INVALID_DEPOSIT_ID;
    insertTx.blockHeight = CryptoNote::WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
    insertTx.extra.assign(reinterpret_cast<const char *>(extra.data()), extra.size());
    insertTx.fee = fee;
    insertTx.depositCount = 77;
    insertTx.hash = transactionHash;
    insertTx.totalAmount = 0; // 0 until transactionHandlingEnd() is called
    insertTx.timestamp = 0;   //0 until included in a block
    insertTx.isBase = false;

    size_t txId = m_transactions.get<RandomAccessIndex>().size();
    m_transactions.get<RandomAccessIndex>().push_back(std::move(insertTx));

    pushEvent(makeTransactionCreatedEvent(txId));

    return txId;
  }

  void WalletGreen::updateTransactionStateAndPushEvent(size_t transactionId, WalletTransactionState state)
  {
    auto it = std::next(m_transactions.get<RandomAccessIndex>().begin(), transactionId);

    if (it->state != state)
    {
      m_transactions.get<RandomAccessIndex>().modify(it, [state](WalletTransaction &tx) {
        tx.state = state;
      });

      pushEvent(makeTransactionUpdatedEvent(transactionId));
    }
  }

  bool WalletGreen::updateWalletDepositInfo(size_t depositId, const CryptoNote::Deposit &info)
  {
    auto &txIdIndex = m_deposits.get<RandomAccessIndex>();
    assert(depositId < txIdIndex.size());
    auto it = std::next(txIdIndex.begin(), depositId);

    bool updated = false;
    bool r = txIdIndex.modify(it, [&info, &updated](Deposit &deposit) {
      if (deposit.spendingTransactionId != info.spendingTransactionId)
      {
        deposit.spendingTransactionId = info.spendingTransactionId;
        updated = true;
      }
    });

    assert(r);

    return updated;
  }

  bool WalletGreen::updateWalletTransactionInfo(size_t transactionId, const CryptoNote::TransactionInformation &info, int64_t totalAmount)
  {
    auto &txIdIndex = m_transactions.get<RandomAccessIndex>();
    assert(transactionId < txIdIndex.size());
    auto it = std::next(txIdIndex.begin(), transactionId);

    bool updated = false;
    bool r = txIdIndex.modify(it, [&info, totalAmount, &updated](WalletTransaction &transaction) {
      if (transaction.firstDepositId != info.firstDepositId)
      {
        transaction.firstDepositId = info.firstDepositId;
        updated = true;
        transaction.depositCount = 1;
      }

      if (transaction.blockHeight != info.blockHeight)
      {
        transaction.blockHeight = info.blockHeight;
        updated = true;
      }

      if (transaction.timestamp != info.timestamp)
      {
        transaction.timestamp = info.timestamp;
        updated = true;
      }

      bool isSucceeded = transaction.state == WalletTransactionState::SUCCEEDED;
      // If transaction was sent to daemon, it can not have CREATED and FAILED states, its state can be SUCCEEDED, CANCELLED or DELETED
      bool wasSent = transaction.state != WalletTransactionState::CREATED && transaction.state != WalletTransactionState::FAILED;
      bool isConfirmed = transaction.blockHeight != WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
      if (!isSucceeded && (wasSent || isConfirmed))
      {
        //transaction may be deleted first then added again
        transaction.state = WalletTransactionState::SUCCEEDED;
        updated = true;
      }

      if (transaction.totalAmount != totalAmount)
      {
        transaction.totalAmount = totalAmount;
        updated = true;
      }

      // Fix LegacyWallet error. Some old versions didn't fill extra field
      if (transaction.extra.empty() && !info.extra.empty())
      {
        transaction.extra = Common::asString(info.extra);
        updated = true;
      }

      bool isBase = info.totalAmountIn == 0;
      if (transaction.isBase != isBase)
      {
        transaction.isBase = isBase;
        updated = true;
      }
    });

    assert(r);

    return updated;
  }

  size_t WalletGreen::insertBlockchainTransaction(const TransactionInformation &info, int64_t txBalance)
  {
    auto &index = m_transactions.get<RandomAccessIndex>();

    WalletTransaction tx;
    tx.state = WalletTransactionState::SUCCEEDED;
    tx.timestamp = info.timestamp;
    tx.blockHeight = info.blockHeight;
    tx.hash = info.transactionHash;
    tx.depositCount = 0;
    tx.firstDepositId = WALLET_INVALID_DEPOSIT_ID;
    tx.isBase = info.totalAmountIn == 0;
    if (tx.isBase)
    {
      tx.fee = 0;
    }
    else
    {
      tx.fee = info.totalAmountIn < info.totalAmountOut ? m_currency.minimumFee() : info.totalAmountIn - info.totalAmountOut;
    }

    tx.unlockTime = info.unlockTime;
    tx.extra.assign(reinterpret_cast<const char *>(info.extra.data()), info.extra.size());
    tx.totalAmount = txBalance;
    tx.creationTime = info.timestamp;

    size_t txId = index.size();
    index.push_back(std::move(tx));

    return txId;
  }

  uint64_t WalletGreen::scanHeightToTimestamp(const uint32_t scanHeight)
  {
    if (scanHeight == 0)
    {
      return 0;
    }

    /* Get the block timestamp from the node if the node has it */
    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));

    /* Get the amount of seconds since the blockchain launched */
    uint64_t secondsSinceLaunch = scanHeight * CryptoNote::parameters::DIFFICULTY_TARGET;

    /* Add a bit of a buffer in case of difficulty weirdness, blocks coming
	   out too fast */
    secondsSinceLaunch = static_cast<uint64_t>(secondsSinceLaunch * 0.95);

    /* Get the genesis block timestamp and add the time since launch */
    timestamp = UINT64_C(1527135120) + secondsSinceLaunch;

    /* Timestamp in the future */
    if (timestamp >= static_cast<uint64_t>(std::time(nullptr)))
    {
      return getCurrentTimestampAdjusted();
    }

    return timestamp;
  }

  uint64_t WalletGreen::getCurrentTimestampAdjusted()
  {
    /* Get the current time as a unix timestamp */
    std::time_t time = std::time(nullptr);

    /* Take the amount of time a block can potentially be in the past/future */
    std::initializer_list<uint64_t> limits = {
        CryptoNote::parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT,
        CryptoNote::parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V1};

    /* Get the largest adjustment possible */
    uint64_t adjust = std::max(limits);

    /* Take the earliest timestamp that will include all possible blocks */
    return time - adjust;
  }

  void WalletGreen::reset(const uint64_t scanHeight)
  {
    throwIfNotInitialized();
    throwIfStopped();

    /* Stop so things can't be added to the container as we're looping */
    stop();

    /* Grab the wallet encrypted prefix */
    auto *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());
    m_logger(INFO, BRIGHT_WHITE) << "reset with height " << scanHeight;
    uint64_t newTimestamp = scanHeightToTimestamp((uint32_t)scanHeight);

    m_logger(INFO, BRIGHT_WHITE) << "new timestamp " << newTimestamp;

    /* Reencrypt with the new creation timestamp so we rescan from here when we relaunch */
    prefix->encryptedViewKeys = encryptKeyPair(m_viewPublicKey, m_viewSecretKey, newTimestamp);

    /* As a reference so we can update it */
    for (auto &encryptedSpendKeys : m_containerStorage)
    {
      Crypto::PublicKey publicKey;
      Crypto::SecretKey secretKey;
      uint64_t oldTimestamp;

      /* Decrypt the key pair we're pointing to */
      decryptKeyPair(encryptedSpendKeys, publicKey, secretKey, oldTimestamp);

      /* Re-encrypt with the new timestamp */
      encryptedSpendKeys = encryptKeyPair(publicKey, secretKey, newTimestamp);
    }

    /* Start again so we can save */
    start();

    /* Save just the keys + timestamp to file */
    save(CryptoNote::WalletSaveLevel::SAVE_KEYS_ONLY);

    /* Stop and shutdown */
    stop();

    /* Shutdown the wallet */
    shutdown();

    start();

    /* Reopen from truncated storage */
    load(m_path, m_password);
  }

  bool WalletGreen::updateTransactionTransfers(size_t transactionId, const std::vector<ContainerAmounts> &containerAmountsList,
                                               int64_t allInputsAmount, int64_t allOutputsAmount)
  {

    assert(allInputsAmount <= 0);
    assert(allOutputsAmount >= 0);

    bool updated = false;

    auto transfersRange = getTransactionTransfersRange(transactionId);
    // Iterators can be invalidated, so the first transfer is addressed by its index
    size_t firstTransferIdx = std::distance(m_transfers.cbegin(), transfersRange.first);

    TransfersMap initialTransfers = getKnownTransfersMap(transactionId, firstTransferIdx);

    std::unordered_set<std::string> myInputAddresses;
    std::unordered_set<std::string> myOutputAddresses;
    int64_t myInputsAmount = 0;
    int64_t myOutputsAmount = 0;
    for (auto containerAmount : containerAmountsList)
    {
      AccountPublicAddress address{getWalletRecord(containerAmount.container).spendPublicKey, m_viewPublicKey};
      std::string addressString = m_currency.accountAddressAsString(address);

      updated |= updateAddressTransfers(transactionId, firstTransferIdx, addressString, initialTransfers[addressString].input, containerAmount.amounts.input);
      updated |= updateAddressTransfers(transactionId, firstTransferIdx, addressString, initialTransfers[addressString].output, containerAmount.amounts.output);

      myInputsAmount += containerAmount.amounts.input;
      myOutputsAmount += containerAmount.amounts.output;

      if (containerAmount.amounts.input != 0)
      {
        myInputAddresses.emplace(addressString);
      }

      if (containerAmount.amounts.output != 0)
      {
        myOutputAddresses.emplace(addressString);
      }
    }

    assert(myInputsAmount >= allInputsAmount);
    assert(myOutputsAmount <= allOutputsAmount);

    int64_t knownInputsAmount = 0;
    int64_t knownOutputsAmount = 0;
    auto updatedTransfers = getKnownTransfersMap(transactionId, firstTransferIdx);
    for (const auto &pair : updatedTransfers)
    {
      knownInputsAmount += pair.second.input;
      knownOutputsAmount += pair.second.output;
    }

    assert(myInputsAmount >= knownInputsAmount);
    assert(myOutputsAmount <= knownOutputsAmount);

    updated |= updateUnknownTransfers(transactionId, firstTransferIdx, myInputAddresses, knownInputsAmount, myInputsAmount, allInputsAmount, false);
    updated |= updateUnknownTransfers(transactionId, firstTransferIdx, myOutputAddresses, knownOutputsAmount, myOutputsAmount, allOutputsAmount, true);

    return updated;
  }

  WalletGreen::TransfersMap WalletGreen::getKnownTransfersMap(size_t transactionId, size_t firstTransferIdx) const
  {
    TransfersMap result;

    for (auto it = std::next(m_transfers.begin(), firstTransferIdx); it != m_transfers.end() && it->first == transactionId; ++it)
    {
      const auto &address = it->second.address;

      if (!address.empty())
      {
        if (it->second.amount < 0)
        {
          result[address].input += it->second.amount;
        }
        else
        {
          assert(it->second.amount > 0);
          result[address].output += it->second.amount;
        }
      }
    }

    return result;
  }

  bool WalletGreen::updateAddressTransfers(size_t transactionId, size_t firstTransferIdx, const std::string &address, int64_t knownAmount, int64_t targetAmount)
  {
    assert((knownAmount > 0 && targetAmount > 0) || (knownAmount < 0 && targetAmount < 0) || knownAmount == 0 || targetAmount == 0);

    bool updated = false;

    if (knownAmount != targetAmount)
    {
      if (knownAmount == 0)
      {
        appendTransfer(transactionId, firstTransferIdx, address, targetAmount);
        updated = true;
      }
      else if (targetAmount == 0)
      {
        assert(knownAmount != 0);
        updated |= eraseTransfersByAddress(transactionId, firstTransferIdx, address, knownAmount > 0);
      }
      else
      {
        updated |= adjustTransfer(transactionId, firstTransferIdx, address, targetAmount);
      }
    }

    return updated;
  }

  bool WalletGreen::updateUnknownTransfers(size_t transactionId, size_t firstTransferIdx, const std::unordered_set<std::string> &myAddresses,
                                           int64_t knownAmount, int64_t myAmount, int64_t totalAmount, bool isOutput)
  {

    bool updated = false;

    if (std::abs(knownAmount) > std::abs(totalAmount))
    {
      updated |= eraseForeignTransfers(transactionId, firstTransferIdx, myAddresses, isOutput);
      if (totalAmount == myAmount)
      {
        updated |= eraseTransfersByAddress(transactionId, firstTransferIdx, std::string(), isOutput);
      }
      else
      {
        assert(std::abs(totalAmount) > std::abs(myAmount));
        updated |= adjustTransfer(transactionId, firstTransferIdx, std::string(), totalAmount - myAmount);
      }
    }
    else if (knownAmount == totalAmount)
    {
      updated |= eraseTransfersByAddress(transactionId, firstTransferIdx, std::string(), isOutput);
    }
    else
    {
      assert(std::abs(totalAmount) > std::abs(knownAmount));
      updated |= adjustTransfer(transactionId, firstTransferIdx, std::string(), totalAmount - knownAmount);
    }

    return updated;
  }

  void WalletGreen::appendTransfer(size_t transactionId, size_t firstTransferIdx, const std::string &address, int64_t amount)
  {
    auto it = std::next(m_transfers.begin(), firstTransferIdx);
    auto insertIt = std::upper_bound(it, m_transfers.end(), transactionId, [](size_t transactionId, const TransactionTransferPair &pair) {
      return transactionId < pair.first;
    });

    WalletTransfer transfer{WalletTransferType::USUAL, address, amount};
    m_transfers.emplace(insertIt, std::piecewise_construct, std::forward_as_tuple(transactionId), std::forward_as_tuple(transfer));
  }

  bool WalletGreen::adjustTransfer(size_t transactionId, size_t firstTransferIdx, const std::string &address, int64_t amount)
  {
    assert(amount != 0);

    bool updated = false;
    bool updateOutputTransfers = amount > 0;
    bool firstAddressTransferFound = false;
    auto it = std::next(m_transfers.begin(), firstTransferIdx);
    while (it != m_transfers.end() && it->first == transactionId)
    {
      assert(it->second.amount != 0);
      bool transferIsOutput = it->second.amount > 0;
      if (transferIsOutput == updateOutputTransfers && it->second.address == address)
      {
        if (firstAddressTransferFound)
        {
          it = m_transfers.erase(it);
          updated = true;
        }
        else
        {
          if (it->second.amount != amount)
          {
            it->second.amount = amount;
            updated = true;
          }

          firstAddressTransferFound = true;
          ++it;
        }
      }
      else
      {
        ++it;
      }
    }

    if (!firstAddressTransferFound)
    {
      WalletTransfer transfer{WalletTransferType::USUAL, address, amount};
      m_transfers.emplace(it, std::piecewise_construct, std::forward_as_tuple(transactionId), std::forward_as_tuple(transfer));
      updated = true;
    }

    return updated;
  }

  bool WalletGreen::eraseTransfers(size_t transactionId, size_t firstTransferIdx, std::function<bool(bool, const std::string &)> &&predicate)
  {
    bool erased = false;
    auto it = std::next(m_transfers.begin(), firstTransferIdx);
    while (it != m_transfers.end() && it->first == transactionId)
    {
      bool transferIsOutput = it->second.amount > 0;
      if (predicate(transferIsOutput, it->second.address))
      {
        it = m_transfers.erase(it);
        erased = true;
      }
      else
      {
        ++it;
      }
    }

    return erased;
  }

  bool WalletGreen::eraseTransfersByAddress(size_t transactionId, size_t firstTransferIdx, const std::string &address, bool eraseOutputTransfers)
  {
    return eraseTransfers(transactionId, firstTransferIdx, [&address, eraseOutputTransfers](bool isOutput, const std::string &transferAddress) {
      return eraseOutputTransfers == isOutput && address == transferAddress;
    });
  }

  bool WalletGreen::eraseForeignTransfers(size_t transactionId, size_t firstTransferIdx, const std::unordered_set<std::string> &knownAddresses,
                                          bool eraseOutputTransfers)
  {

    return eraseTransfers(transactionId, firstTransferIdx, [this, &knownAddresses, eraseOutputTransfers](bool isOutput, const std::string &transferAddress) {
      return eraseOutputTransfers == isOutput && knownAddresses.count(transferAddress) == 0;
    });
  }

  std::unique_ptr<CryptoNote::ITransaction> WalletGreen::makeTransaction(const std::vector<ReceiverAmounts> &decomposedOutputs,
                                                                         std::vector<InputInfo> &keysInfo, const std::vector<WalletMessage> &messages, const std::string &extra, uint64_t unlockTimestamp, Crypto::SecretKey &transactionSK)
  {

    std::unique_ptr<ITransaction> tx = createTransaction();

    tx->getTransactionSecretKey(transactionSK);
    Crypto::PublicKey publicKey = tx->getTransactionPublicKey();
    CryptoNote::KeyPair kp = {publicKey, transactionSK};
    for (size_t i = 0; i < messages.size(); ++i)
    {
      CryptoNote::AccountPublicAddress addressBin;
      if (!m_currency.parseAccountAddressString(messages[i].address, addressBin))
        continue;
      CryptoNote::tx_extra_message tag;
      if (!tag.encrypt(i, messages[i].message, &addressBin, kp))
        continue;
      BinaryArray ba;
      toBinaryArray(tag, ba);
      ba.insert(ba.begin(), TX_EXTRA_MESSAGE_TAG);
      tx->appendExtra(ba);
    }

    typedef std::pair<const AccountPublicAddress *, uint64_t> AmountToAddress;
    std::vector<AmountToAddress> amountsToAddresses;
    for (const auto &output : decomposedOutputs)
    {
      for (auto amount : output.amounts)
      {
        amountsToAddresses.emplace_back(AmountToAddress{&output.receiver, amount});
      }
    }

    std::shuffle(amountsToAddresses.begin(), amountsToAddresses.end(), std::default_random_engine{Crypto::rand<std::default_random_engine::result_type>()});
    std::sort(amountsToAddresses.begin(), amountsToAddresses.end(), [](const AmountToAddress &left, const AmountToAddress &right) {
      return left.second < right.second;
    });

    for (const auto &amountToAddress : amountsToAddresses)
    {
      tx->addOutput(amountToAddress.second, *amountToAddress.first);
    }

    tx->setUnlockTime(unlockTimestamp);
    tx->appendExtra(Common::asBinaryArray(extra));

    for (auto &input : keysInfo)
    {
      tx->addInput(makeAccountKeys(*input.walletRecord), input.keyInfo, input.ephKeys);
    }

    size_t i = 0;
    for (auto &input : keysInfo)
    {
      tx->signInputKey(i++, input.keyInfo, input.ephKeys);
    }

    return tx;
  }

  void WalletGreen::sendTransaction(const CryptoNote::Transaction &cryptoNoteTransaction)
  {
    System::Event completion(m_dispatcher);
    std::error_code ec;

    throwIfStopped();
    m_node.relayTransaction(cryptoNoteTransaction, [&ec, &completion, this](std::error_code error) {
      ec = error;
      this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(completion)));
    });
    completion.wait();

    if (ec)
    {
      throw std::system_error(ec);
    }
  }

  size_t WalletGreen::validateSaveAndSendTransaction(
      const ITransactionReader &transaction,
      const std::vector<WalletTransfer> &destinations,
      bool isFusion,
      bool send)
  {
    BinaryArray transactionData = transaction.getTransactionData();

    if ((transactionData.size() > m_upperTransactionSizeLimit) && (isFusion == false))
    {
      m_logger(ERROR, BRIGHT_RED) << "Transaction is too big";
      throw std::system_error(make_error_code(error::TRANSACTION_SIZE_TOO_BIG));
    }

    if ((transactionData.size() > m_currency.fusionTxMaxSize()) && (isFusion == true))
    {
      m_logger(ERROR, BRIGHT_RED) << "Fusion transaction is too big. Transaction hash";
      throw std::system_error(make_error_code(error::TRANSACTION_SIZE_TOO_BIG));
    }

    CryptoNote::Transaction cryptoNoteTransaction;
    if (!fromBinaryArray(cryptoNoteTransaction, transactionData))
    {
      throw std::system_error(make_error_code(error::INTERNAL_WALLET_ERROR), "Failed to deserialize created transaction");
    }

    uint64_t fee = transaction.getInputTotalAmount() < transaction.getOutputTotalAmount() ? m_currency.minimumFee() : transaction.getInputTotalAmount() - transaction.getOutputTotalAmount();
    size_t transactionId = insertOutgoingTransactionAndPushEvent(transaction.getTransactionHash(), fee, transaction.getExtra(), transaction.getUnlockTime());
    Tools::ScopeExit rollbackTransactionInsertion([this, transactionId] {
      updateTransactionStateAndPushEvent(transactionId, WalletTransactionState::FAILED);
    });

    m_fusionTxsCache.emplace(transactionId, isFusion);
    pushBackOutgoingTransfers(transactionId, destinations);

    addUnconfirmedTransaction(transaction);
    Tools::ScopeExit rollbackAddingUnconfirmedTransaction([this, &transaction] {
      try
      {
        removeUnconfirmedTransaction(transaction.getTransactionHash());
      }
      catch (...)
      {
        // Ignore any exceptions. If rollback fails then the transaction is stored as unconfirmed and will be deleted after wallet relaunch
        // during transaction pool synchronization
      }
    });

    if (send)
    {
      sendTransaction(cryptoNoteTransaction);
      updateTransactionStateAndPushEvent(transactionId, WalletTransactionState::SUCCEEDED);
    }
    else
    {
      assert(m_uncommitedTransactions.count(transactionId) == 0);
      m_uncommitedTransactions.emplace(transactionId, std::move(cryptoNoteTransaction));
    }

    rollbackAddingUnconfirmedTransaction.cancel();
    rollbackTransactionInsertion.cancel();

    return transactionId;
  }

  AccountKeys WalletGreen::makeAccountKeys(const WalletRecord &wallet) const
  {
    AccountKeys keys;
    keys.address.spendPublicKey = wallet.spendPublicKey;
    keys.address.viewPublicKey = m_viewPublicKey;
    keys.spendSecretKey = wallet.spendSecretKey;
    keys.viewSecretKey = m_viewSecretKey;

    return keys;
  }

  void WalletGreen::requestMixinOuts(
      const std::vector<OutputToTransfer> &selectedTransfers,
      uint64_t mixIn,
      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount> &mixinResult)
  {

    std::vector<uint64_t> amounts;
    for (const auto &out : selectedTransfers)
    {
      amounts.push_back(out.out.amount);
    }

    System::Event requestFinished(m_dispatcher);
    std::error_code mixinError;

    throwIfStopped();

    m_node.getRandomOutsByAmounts(std::move(amounts), mixIn, mixinResult, [&requestFinished, &mixinError, this](std::error_code ec) {
      mixinError = ec;
      this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
    });

    requestFinished.wait();

    checkIfEnoughMixins(mixinResult, mixIn);

    if (mixinError)
    {
      throw std::system_error(mixinError);
    }
  }

  uint64_t WalletGreen::selectTransfers(
      uint64_t neededMoney,
      bool dust,
      uint64_t dustThreshold,
      std::vector<WalletOuts> &&wallets,
      std::vector<OutputToTransfer> &selectedTransfers)
  {
    uint64_t foundMoney = 0;

    typedef std::pair<WalletRecord *, TransactionOutputInformation> OutputData;
    std::vector<OutputData> walletOuts;
    std::unordered_map<uint64_t, std::vector<OutputData>> buckets;

    for (auto walletIt = wallets.begin(); walletIt != wallets.end(); ++walletIt)
    {
      for (auto outIt = walletIt->outs.begin(); outIt != walletIt->outs.end(); ++outIt)
      {
        int numberOfDigits = floor(log10(outIt->amount)) + 1;

        if (outIt->amount > dustThreshold)
        {
          buckets[numberOfDigits].emplace_back(
              std::piecewise_construct,
              std::forward_as_tuple(walletIt->wallet),
              std::forward_as_tuple(*outIt));
        }
      }
    }

    while (foundMoney < neededMoney && !buckets.empty())
    {
      /* Take one element from each bucket, smallest first. */
      for (auto bucket = buckets.begin(); bucket != buckets.end();)
      {
        /* Bucket has been exhausted, remove from list */
        if (bucket->second.empty())
        {
          bucket = buckets.erase(bucket);
        }
        else
        {
          /** Add the amount to the selected transfers so long as
           * foundMoney is still less than neededMoney. This prevents
           * larger outputs than we need when we already have enough funds */
          if (foundMoney < neededMoney)
          {
            auto out = bucket->second.back();
            selectedTransfers.emplace_back(OutputToTransfer{std::move(out.second), std::move(out.first)});
            foundMoney += out.second.amount;
          }

          /* Remove amount we just added */
          bucket->second.pop_back();
          bucket++;
        }
      }
    }
    return foundMoney;
  };

  std::vector<WalletGreen::WalletOuts> WalletGreen::pickWalletsWithMoney() const
  {
    auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();

    std::vector<WalletOuts> walletOuts;
    for (const auto &wallet : walletsIndex)
    {
      if (wallet.actualBalance == 0)
      {
        continue;
      }

      ITransfersContainer *container = wallet.container;

      WalletOuts outs;
      container->getOutputs(outs.outs, ITransfersContainer::IncludeKeyUnlocked);
      outs.wallet = const_cast<WalletRecord *>(&wallet);

      walletOuts.push_back(std::move(outs));
    };

    return walletOuts;
  }

  WalletGreen::WalletOuts WalletGreen::pickWallet(const std::string &address) const
  {
    const auto &wallet = getWalletRecord(address);

    ITransfersContainer *container = wallet.container;
    WalletOuts outs;
    container->getOutputs(outs.outs, ITransfersContainer::IncludeKeyUnlocked);
    outs.wallet = const_cast<WalletRecord *>(&wallet);

    return outs;
  }

  std::vector<WalletGreen::WalletOuts> WalletGreen::pickWallets(const std::vector<std::string> &addresses) const
  {
    std::vector<WalletOuts> wallets;
    wallets.reserve(addresses.size());

    for (const auto &address : addresses)
    {
      WalletOuts wallet = pickWallet(address);
      if (!wallet.outs.empty())
      {
        wallets.emplace_back(std::move(wallet));
      }
    }

    return wallets;
  }

  std::vector<CryptoNote::WalletGreen::ReceiverAmounts> WalletGreen::splitDestinations(const std::vector<CryptoNote::WalletTransfer> &destinations,
                                                                                       uint64_t dustThreshold,
                                                                                       const CryptoNote::Currency &currency)
  {

    std::vector<ReceiverAmounts> decomposedOutputs;
    for (const auto &destination : destinations)
    {
      AccountPublicAddress address;
      parseAddressString(destination.address, currency, address);
      decomposedOutputs.push_back(splitAmount(destination.amount, address, dustThreshold));
    }

    return decomposedOutputs;
  }

  CryptoNote::WalletGreen::ReceiverAmounts WalletGreen::splitAmount(
      uint64_t amount,
      const AccountPublicAddress &destination,
      uint64_t dustThreshold)
  {

    ReceiverAmounts receiverAmounts;

    receiverAmounts.receiver = destination;
    decomposeAmount(amount, dustThreshold, receiverAmounts.amounts);
    return receiverAmounts;
  }

  void WalletGreen::prepareInputs(
      const std::vector<OutputToTransfer> &selectedTransfers,
      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount> &mixinResult,
      uint64_t mixIn,
      std::vector<InputInfo> &keysInfo)
  {

    typedef CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;

    size_t i = 0;
    for (const auto &input : selectedTransfers)
    {
      TransactionTypes::InputKeyInfo keyInfo;
      keyInfo.amount = input.out.amount;

      if (mixinResult.size())
      {
        std::sort(mixinResult[i].outs.begin(), mixinResult[i].outs.end(),
                  [](const out_entry &a, const out_entry &b) { return a.global_amount_index < b.global_amount_index; });
        for (auto &fakeOut : mixinResult[i].outs)
        {

          if (input.out.globalOutputIndex == fakeOut.global_amount_index)
          {
            continue;
          }

          TransactionTypes::GlobalOutput globalOutput;
          globalOutput.outputIndex = static_cast<uint32_t>(fakeOut.global_amount_index);
          globalOutput.targetKey = reinterpret_cast<PublicKey &>(fakeOut.out_key);
          keyInfo.outputs.push_back(std::move(globalOutput));
          if (keyInfo.outputs.size() >= mixIn)
            break;
        }
      }

      //paste real transaction to the random index
      auto insertIn = std::find_if(keyInfo.outputs.begin(), keyInfo.outputs.end(), [&](const TransactionTypes::GlobalOutput &a) {
        return a.outputIndex >= input.out.globalOutputIndex;
      });

      TransactionTypes::GlobalOutput realOutput;
      realOutput.outputIndex = input.out.globalOutputIndex;
      realOutput.targetKey = reinterpret_cast<const PublicKey &>(input.out.outputKey);

      auto insertedIn = keyInfo.outputs.insert(insertIn, realOutput);

      keyInfo.realOutput.transactionPublicKey = reinterpret_cast<const PublicKey &>(input.out.transactionPublicKey);
      keyInfo.realOutput.transactionIndex = static_cast<size_t>(insertedIn - keyInfo.outputs.begin());
      keyInfo.realOutput.outputInTransaction = input.out.outputInTransaction;

      //Important! outputs in selectedTransfers and in keysInfo must have the same order!
      InputInfo inputInfo;
      inputInfo.keyInfo = std::move(keyInfo);
      inputInfo.walletRecord = input.wallet;
      keysInfo.push_back(std::move(inputInfo));
      ++i;
    }
  }

  WalletTransactionWithTransfers WalletGreen::getTransaction(const Crypto::Hash &transactionHash) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    auto &hashIndex = m_transactions.get<TransactionIndex>();
    auto it = hashIndex.find(transactionHash);
    if (it == hashIndex.end())
    {
      throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND), "Transaction not found");
    }

    WalletTransactionWithTransfers walletTransaction;
    walletTransaction.transaction = *it;
    walletTransaction.transfers = getTransactionTransfers(*it);

    return walletTransaction;
  }

  std::vector<TransactionsInBlockInfo> WalletGreen::getTransactions(const Crypto::Hash &blockHash, size_t count) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    auto &hashIndex = m_blockchain.get<BlockHashIndex>();
    auto it = hashIndex.find(blockHash);
    if (it == hashIndex.end())
    {
      return std::vector<TransactionsInBlockInfo>();
    }

    auto heightIt = m_blockchain.project<BlockHeightIndex>(it);

    uint32_t blockIndex = static_cast<uint32_t>(std::distance(m_blockchain.get<BlockHeightIndex>().begin(), heightIt));
    return getTransactionsInBlocks(blockIndex, count);
  }

  std::vector<DepositsInBlockInfo> WalletGreen::getDeposits(const Crypto::Hash &blockHash, size_t count) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    auto &hashIndex = m_blockchain.get<BlockHashIndex>();
    auto it = hashIndex.find(blockHash);
    if (it == hashIndex.end())
    {
      return std::vector<DepositsInBlockInfo>();
    }

    auto heightIt = m_blockchain.project<BlockHeightIndex>(it);

    uint32_t blockIndex = static_cast<uint32_t>(std::distance(m_blockchain.get<BlockHeightIndex>().begin(), heightIt));
    return getDepositsInBlocks(blockIndex, count);
  }

  std::vector<TransactionsInBlockInfo> WalletGreen::getTransactions(uint32_t blockIndex, size_t count) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return getTransactionsInBlocks(blockIndex, count);
  }

  std::vector<DepositsInBlockInfo> WalletGreen::getDeposits(uint32_t blockIndex, size_t count) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    return getDepositsInBlocks(blockIndex, count);
  }

  std::vector<Crypto::Hash> WalletGreen::getBlockHashes(uint32_t blockIndex, size_t count) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    auto &index = m_blockchain.get<BlockHeightIndex>();

    if (blockIndex >= index.size())
    {
      return std::vector<Crypto::Hash>();
    }

    auto start = std::next(index.begin(), blockIndex);
    auto end = std::next(index.begin(), std::min(index.size(), blockIndex + count));
    return std::vector<Crypto::Hash>(start, end);
  }

  uint32_t WalletGreen::getBlockCount() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    uint32_t blockCount = static_cast<uint32_t>(m_blockchain.size());
    assert(blockCount != 0);

    return blockCount;
  }

  std::vector<WalletTransactionWithTransfers> WalletGreen::getUnconfirmedTransactions() const
  {
    throwIfNotInitialized();
    throwIfStopped();

    std::vector<WalletTransactionWithTransfers> result;
    auto lowerBound = m_transactions.get<BlockHeightIndex>().lower_bound(WALLET_UNCONFIRMED_TRANSACTION_HEIGHT);
    for (auto it = lowerBound; it != m_transactions.get<BlockHeightIndex>().end(); ++it)
    {
      if (it->state != WalletTransactionState::SUCCEEDED)
      {
        continue;
      }

      WalletTransactionWithTransfers transaction;
      transaction.transaction = *it;
      transaction.transfers = getTransactionTransfers(*it);

      result.push_back(transaction);
    }

    return result;
  }

  std::vector<size_t> WalletGreen::getDelayedTransactionIds() const
  {
    throwIfNotInitialized();
    throwIfStopped();
    throwIfTrackingMode();

    std::vector<size_t> result;
    result.reserve(m_uncommitedTransactions.size());

    for (const auto &kv : m_uncommitedTransactions)
    {
      result.push_back(kv.first);
    }

    return result;
  }

  void WalletGreen::start()
  {
    m_stopped = false;
  }

  void WalletGreen::stop()
  {
    m_stopped = true;
    m_eventOccurred.set();
  }

  WalletEvent WalletGreen::getEvent()
  {
    throwIfNotInitialized();
    throwIfStopped();

    while (m_events.empty())
    {
      m_eventOccurred.wait();
      m_eventOccurred.clear();
      throwIfStopped();
    }

    WalletEvent event = std::move(m_events.front());
    m_events.pop();

    return event;
  }

  void WalletGreen::throwIfNotInitialized() const
  {
    if (m_state != WalletState::INITIALIZED)
    {
      throw std::system_error(make_error_code(CryptoNote::error::NOT_INITIALIZED));
    }
  }

  void WalletGreen::onError(ITransfersSubscription *object, uint32_t height, std::error_code ec)
  {
  }

  void WalletGreen::synchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount)
  {
    m_dispatcher.remoteSpawn([processedBlockCount, totalBlockCount, this]() { onSynchronizationProgressUpdated(processedBlockCount, totalBlockCount); });
  }

  void WalletGreen::synchronizationCompleted(std::error_code result)
  {
    m_dispatcher.remoteSpawn([this]() { onSynchronizationCompleted(); });
  }

  void WalletGreen::onSynchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount)
  {
    assert(processedBlockCount > 0);

    System::EventLock lk(m_readyEvent);

    if (m_state == WalletState::NOT_INITIALIZED)
    {
      return;
    }

    pushEvent(makeSyncProgressUpdatedEvent(processedBlockCount, totalBlockCount));

    uint32_t currentHeight = processedBlockCount - 1;
    unlockBalances(currentHeight);
  }

  void WalletGreen::onSynchronizationCompleted()
  {
    System::EventLock lk(m_readyEvent);

    if (m_state == WalletState::NOT_INITIALIZED)
    {
      return;
    }

    pushEvent(makeSyncCompletedEvent());
  }

  void WalletGreen::onBlocksAdded(const Crypto::PublicKey &viewPublicKey, const std::vector<Crypto::Hash> &blockHashes)
  {
    m_dispatcher.remoteSpawn([this, blockHashes]() { blocksAdded(blockHashes); });
  }

  void WalletGreen::blocksAdded(const std::vector<Crypto::Hash> &blockHashes)
  {
    System::EventLock lk(m_readyEvent);

    if (m_state == WalletState::NOT_INITIALIZED)
    {
      return;
    }
    m_blockchain.insert(m_blockchain.end(), blockHashes.begin(), blockHashes.end());
  }

  void WalletGreen::onBlockchainDetach(const Crypto::PublicKey &viewPublicKey, uint32_t blockIndex)
  {
    m_dispatcher.remoteSpawn([this, blockIndex]() { blocksRollback(blockIndex); });
  }

  void WalletGreen::blocksRollback(uint32_t blockIndex)
  {
    System::EventLock lk(m_readyEvent);

    if (m_state == WalletState::NOT_INITIALIZED)
    {
      return;
    }

    auto &blockHeightIndex = m_blockchain.get<BlockHeightIndex>();
    blockHeightIndex.erase(std::next(blockHeightIndex.begin(), blockIndex), blockHeightIndex.end());
  }

  void WalletGreen::onTransactionDeleteBegin(const Crypto::PublicKey &viewPublicKey, Crypto::Hash transactionHash)
  {
    m_dispatcher.remoteSpawn([=]() { transactionDeleteBegin(transactionHash); });
  }

  // TODO remove
  void WalletGreen::transactionDeleteBegin(Crypto::Hash /*transactionHash*/)
  {
  }

  void WalletGreen::onTransactionDeleteEnd(const Crypto::PublicKey &viewPublicKey, Crypto::Hash transactionHash)
  {
    m_dispatcher.remoteSpawn([=]() { transactionDeleteEnd(transactionHash); });
  }

  // TODO remove
  void WalletGreen::transactionDeleteEnd(Crypto::Hash transactionHash)
  {
  }

  void WalletGreen::unlockBalances(uint32_t height)
  {
    auto &index = m_unlockTransactionsJob.get<BlockHeightIndex>();
    auto upper = index.upper_bound(height);

    if (index.begin() != upper)
    {
      for (auto it = index.begin(); it != upper; ++it)
      {
        updateBalance(it->container);
      }

      index.erase(index.begin(), upper);
      pushEvent(makeMoneyUnlockedEvent());
    }
  }

  void WalletGreen::onTransactionUpdated(ITransfersSubscription * /*object*/, const Crypto::Hash & /*transactionHash*/)
  {
    // Deprecated, ignore it. New event handler is onTransactionUpdated(const Crypto::PublicKey&, const Crypto::Hash&, const std::vector<ITransfersContainer*>&)
  }

  void WalletGreen::onTransactionUpdated(
      const Crypto::PublicKey &,
      const Crypto::Hash &transactionHash,
      const std::vector<ITransfersContainer *> &containers)
  {
    assert(!containers.empty());

    TransactionInformation info;
    std::vector<ContainerAmounts> containerAmountsList;
    containerAmountsList.reserve(containers.size());
    for (auto container : containers)
    {
      uint64_t inputsAmount;
      // Don't move this code to the following remote spawn, because it guarantees that the container has the
      // transaction
      uint64_t outputsAmount;
      bool found = container->getTransactionInformation(transactionHash, info, &inputsAmount, &outputsAmount);
      if (found)
      {
      }
      assert(found);

      ContainerAmounts containerAmounts;
      containerAmounts.container = container;
      containerAmounts.amounts.input = -static_cast<int64_t>(inputsAmount);
      containerAmounts.amounts.output = static_cast<int64_t>(outputsAmount);
      containerAmountsList.emplace_back(std::move(containerAmounts));
    }

    m_dispatcher.remoteSpawn(
        [this, info, containerAmountsList] { this->transactionUpdated(info, containerAmountsList); });
  }

  /* Insert a new deposit into the deposit index */
  DepositId WalletGreen::insertNewDeposit(
      const TransactionOutputInformation &depositOutput,
      TransactionId creatingTransactionId,
      const Currency &currency,
      uint32_t height,
      const std::vector<uint8_t> &transactionExtra)
  {
    assert(depositOutput.type == TransactionTypes::OutputType::Commitment ||
           depositOutput.type == TransactionTypes::OutputType::Multisignature);
    assert(depositOutput.term != 0);

    Deposit deposit;
    deposit.amount = depositOutput.amount;
    deposit.creatingTransactionId = creatingTransactionId;
    deposit.term = depositOutput.term;
    deposit.spendingTransactionId = WALLET_INVALID_TRANSACTION_ID;
    // Interest calculation removed - no on-chain interest
    deposit.height = height;
    deposit.unlockHeight = height + depositOutput.term;
    deposit.locked = true;

    // Populate depositType and extra from transaction extra field
    deposit.extra = std::string(transactionExtra.begin(), transactionExtra.end());

    // Parse transaction extra to determine deposit type and lock state
    bool isMintAuth = false;
    std::vector<TransactionExtraField> extraFields;
    if (parseTransactionExtra(transactionExtra, extraFields)) {
      for (const auto& field : extraFields) {
        if (field.type() == typeid(TransactionExtraHeatMintAuth)) {
          deposit.depositType = Deposit::Type::HEAT;
          isMintAuth = true;
          break;
        } else if (field.type() == typeid(TransactionExtraHeatCommitment)) {
          deposit.depositType = Deposit::Type::HEAT;
          break;
        } else if (field.type() == typeid(TransactionExtraHeatSendAuth)) {
          deposit.depositType = Deposit::Type::HEAT;
          break;
        } else if (field.type() == typeid(TransactionExtraLegacyBond)) {
          deposit.depositType = Deposit::Type::LEGACY_BOND;
          break;
        }
        // REMOVED: COLD deposit type detection
        // } else if (field.type() == typeid(TransactionExtraSimpleCD)) {
        //   deposit.depositType = Deposit::Type::COLD;
        //   break;
        // }
      }
    } else {
      deposit.depositType = Deposit::Type::HEAT;  // Default to HEAT (COLD removed)
    }

    // Mint outputs are spendable HEAT, not time-locked CDs.
    if (isMintAuth) {
      deposit.locked = false;
    }

    return insertDeposit(deposit, depositOutput.outputInTransaction, depositOutput.transactionHash);
  }

  DepositId WalletGreen::insertDeposit(
      const Deposit &deposit,
      size_t bankingIndexInTransaction,
      const Hash &transactionHash)
  {

    Deposit info = deposit;

    info.outputInTransaction = static_cast<uint32_t>(bankingIndexInTransaction);
    info.transactionHash = transactionHash;

    auto &hashIndex = m_transactions.get<TransactionIndex>();
    auto it = hashIndex.find(transactionHash);
    if (it == hashIndex.end())
    {
      throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND), "Transaction not found");
    }

    WalletTransactionWithTransfers walletTransaction;
    walletTransaction.transaction = *it;
    walletTransaction.transfers = getTransactionTransfers(*it);

    DepositId id = m_deposits.size();
    m_deposits.push_back(std::move(info));

    m_logger(DEBUGGING, BRIGHT_GREEN) << "New deposit created, id "
                                      << id << ", locking "
                                      << m_currency.formatAmount(deposit.amount) << " ,for a term of "
                                      << deposit.term << " blocks, at block "
                                      << deposit.height;

    return id;
  }

  /* Process transactions, this covers both new transactions AND confirmed transactions */
  void WalletGreen::transactionUpdated(
      TransactionInformation transactionInfo,
      const std::vector<ContainerAmounts> &containerAmountsList)
  {
    System::EventLock lk(m_readyEvent);

    if (m_state == WalletState::NOT_INITIALIZED)
    {
      return;
    }

    size_t firstDepositId = std::numeric_limits<DepositId>::max();
    size_t depositCount = 0;

    bool updated = false;
    bool isNew = false;

    int64_t totalAmount = std::accumulate(containerAmountsList.begin(), containerAmountsList.end(), static_cast<int64_t>(0),
                                          [](int64_t sum, const ContainerAmounts &containerAmounts) { return sum + containerAmounts.amounts.input + containerAmounts.amounts.output; });

    size_t transactionId;
    auto &hashIndex = m_transactions.get<TransactionIndex>();
    auto it = hashIndex.find(transactionInfo.transactionHash);
    if (it != hashIndex.end())
    {
      transactionId = std::distance(m_transactions.get<RandomAccessIndex>().begin(), m_transactions.project<RandomAccessIndex>(it));
      updated |= updateWalletTransactionInfo(transactionId, transactionInfo, totalAmount);
    }
    else
    {
      isNew = true;
      transactionId = insertBlockchainTransaction(transactionInfo, totalAmount);
      m_fusionTxsCache.emplace(transactionId, isFusionTransaction(*it));
    }

    for (auto containerAmounts : containerAmountsList)
    {
      auto newDepositOuts = containerAmounts.container->getTransactionOutputs(transactionInfo.transactionHash, ITransfersContainer::IncludeTypeDeposit | ITransfersContainer::IncludeStateAll);
      auto spentDepositOutputs = containerAmounts.container->getTransactionInputs(transactionInfo.transactionHash, ITransfersContainer::IncludeTypeDeposit);

      std::vector<DepositId> updatedDepositIds;

      /* Check for new deposits in this transaction, and create them */
      for (size_t i = 0; i < newDepositOuts.size(); i++)
      {
        /* We only add confirmed deposit entries, so this condition prevents the same deposit
        in the deposit index during creation and during confirmation */
        if (transactionInfo.blockHeight == WALLET_UNCONFIRMED_TRANSACTION_HEIGHT)
        {
          continue;
        }
        auto id = insertNewDeposit(newDepositOuts[i], transactionId, m_currency, transactionInfo.blockHeight, transactionInfo.extra);
        updatedDepositIds.push_back(id);
      }

      /* Now check for any deposit withdrawals in the transactions */
      for (size_t i = 0; i < spentDepositOutputs.size(); i++)
      {
        auto depositId = getDepositId(spentDepositOutputs[i].transactionHash);
        assert(depositId != WALLET_INVALID_DEPOSIT_ID);
        if (depositId == WALLET_INVALID_DEPOSIT_ID)
        {
          throw std::invalid_argument("processSpentDeposits error: requested deposit doesn't exist");
        }

        auto info = m_deposits[depositId];
        info.spendingTransactionId = transactionId;
        updated |= updateWalletDepositInfo(depositId, info);
      }

      /* If there are new deposits, update the transaction information with the
         firstDepositId and the depositCount */
      if (!updatedDepositIds.empty())
      {
        firstDepositId = updatedDepositIds[0];
        depositCount = updatedDepositIds.size();
        transactionInfo.depositCount = depositCount;
        transactionInfo.firstDepositId = firstDepositId;
        updated |= updateWalletTransactionInfo(transactionId, transactionInfo, totalAmount);
      }
    }

    if (transactionInfo.blockHeight != CryptoNote::WALLET_UNCONFIRMED_TRANSACTION_HEIGHT)
    {
      // In some cases a transaction can be included to a block but not removed from m_uncommitedTransactions. Fix it
      m_uncommitedTransactions.erase(transactionId);
    }

    // Update cached balance
    for (auto containerAmounts : containerAmountsList)
    {
      updateBalance(containerAmounts.container);

      if (transactionInfo.blockHeight != CryptoNote::WALLET_UNCONFIRMED_TRANSACTION_HEIGHT)
      {
        uint32_t unlockHeight = std::max(transactionInfo.blockHeight + m_transactionSoftLockTime, static_cast<uint32_t>(transactionInfo.unlockTime));
        insertUnlockTransactionJob(transactionInfo.transactionHash, unlockHeight, containerAmounts.container);
      }
    }

    updated |= updateTransactionTransfers(transactionId, containerAmountsList, -static_cast<int64_t>(transactionInfo.totalAmountIn),
                                          static_cast<int64_t>(transactionInfo.totalAmountOut));

    if (isNew)
    {
      pushEvent(makeTransactionCreatedEvent(transactionId));
    }
    else if (updated)
    {
      pushEvent(makeTransactionUpdatedEvent(transactionId));
    }
  }

  void WalletGreen::pushEvent(const WalletEvent &event)
  {
    m_events.push(event);
    m_eventOccurred.set();
  }

  size_t WalletGreen::getTransactionId(const Hash &transactionHash) const
  {
    auto it = m_transactions.get<TransactionIndex>().find(transactionHash);

    if (it == m_transactions.get<TransactionIndex>().end())
    {
      throw std::system_error(make_error_code(std::errc::invalid_argument));
    }

    auto rndIt = m_transactions.project<RandomAccessIndex>(it);
    auto txId = std::distance(m_transactions.get<RandomAccessIndex>().begin(), rndIt);

    return txId;
  }

  size_t WalletGreen::getDepositId(const Hash &transactionHash) const
  {
    auto it = m_deposits.get<TransactionIndex>().find(transactionHash);

    if (it == m_deposits.get<TransactionIndex>().end())
    {
      return WALLET_INVALID_DEPOSIT_ID;
    }

    auto rndIt = m_deposits.project<RandomAccessIndex>(it);
    auto depositId = std::distance(m_deposits.get<RandomAccessIndex>().begin(), rndIt);

    return depositId;
  }

  void WalletGreen::onTransactionDeleted(ITransfersSubscription *object, const Hash &transactionHash)
  {
    m_dispatcher.remoteSpawn([object, transactionHash, this]() { this->transactionDeleted(object, transactionHash); });
  }

  void WalletGreen::transactionDeleted(ITransfersSubscription *object, const Hash &transactionHash)
  {
    System::EventLock lk(m_readyEvent);

    if (m_state == WalletState::NOT_INITIALIZED)
    {
      return;
    }

    auto it = m_transactions.get<TransactionIndex>().find(transactionHash);
    if (it == m_transactions.get<TransactionIndex>().end())
    {
      return;
    }

    CryptoNote::ITransfersContainer *container = &object->getContainer();
    updateBalance(container);
    deleteUnlockTransactionJob(transactionHash);

    bool updated = false;
    m_transactions.get<TransactionIndex>().modify(it, [&updated](CryptoNote::WalletTransaction &tx) {
      if (tx.state == WalletTransactionState::CREATED || tx.state == WalletTransactionState::SUCCEEDED)
      {
        tx.state = WalletTransactionState::CANCELLED;
        updated = true;
      }

      if (tx.blockHeight != WALLET_UNCONFIRMED_TRANSACTION_HEIGHT)
      {
        tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
        updated = true;
      }
    });

    if (updated)
    {
      auto transactionId = getTransactionId(transactionHash);
      pushEvent(makeTransactionUpdatedEvent(transactionId));
    }
  }

  void WalletGreen::insertUnlockTransactionJob(const Hash &transactionHash, uint32_t blockHeight, CryptoNote::ITransfersContainer *container)
  {
    auto &index = m_unlockTransactionsJob.get<BlockHeightIndex>();
    index.insert({blockHeight, container, transactionHash});
  }

  void WalletGreen::deleteUnlockTransactionJob(const Hash &transactionHash)
  {
    auto &index = m_unlockTransactionsJob.get<TransactionHashIndex>();
    index.erase(transactionHash);
  }

  void WalletGreen::startBlockchainSynchronizer()
  {
    if (!m_walletsContainer.empty() && !m_blockchainSynchronizerStarted)
    {
      m_blockchainSynchronizer.start();
      m_blockchainSynchronizerStarted = true;
    }
  }

  void WalletGreen::stopBlockchainSynchronizer()
  {
    if (m_blockchainSynchronizerStarted)
    {
      m_blockchainSynchronizer.stop();
      m_blockchainSynchronizerStarted = false;
    }
  }

  void WalletGreen::addUnconfirmedTransaction(const ITransactionReader &transaction)
  {
    System::RemoteContext<std::error_code> context(m_dispatcher, [this, &transaction] {
      return m_blockchainSynchronizer.addUnconfirmedTransaction(transaction).get();
    });

    auto ec = context.get();
    if (ec)
    {
      throw std::system_error(ec, "Failed to add unconfirmed transaction");
    }
  }

  void WalletGreen::removeUnconfirmedTransaction(const Crypto::Hash &transactionHash)
  {
    System::RemoteContext<void> context(m_dispatcher, [this, &transactionHash] {
      m_blockchainSynchronizer.removeUnconfirmedTransaction(transactionHash).get();
    });

    context.get();
  }

  void WalletGreen::updateBalance(CryptoNote::ITransfersContainer *container)
  {
    auto it = m_walletsContainer.get<TransfersContainerIndex>().find(container);

    if (it == m_walletsContainer.get<TransfersContainerIndex>().end())
    {
      return;
    }

    bool updated = false;

    /* First get the available and pending balances from the container */
    uint64_t actual = container->balance(ITransfersContainer::IncludeAllUnlocked);
    uint64_t pending = container->balance(ITransfersContainer::IncludeKeyNotUnlocked);

    /* Now update the overall balance (getBalance without parameters) */
    if (it->actualBalance < actual)
    {
      m_actualBalance += actual - it->actualBalance;
      updated = true;
    }
    else
    {
      m_actualBalance -= it->actualBalance - actual;
      updated = true;
    }

    if (it->pendingBalance < pending)
    {
      m_pendingBalance += pending - it->pendingBalance;
      updated = true;
    }
    else
    {
      m_pendingBalance -= it->pendingBalance - pending;
      updated = true;
    }

    /* Update locked deposit balance, this will cover deposits, as well
       as investments since they are all deposits with different parameters */
    std::vector<TransactionOutputInformation> transfers2;
    container->getOutputs(transfers2, ITransfersContainer::IncludeTypeDeposit | ITransfersContainer::IncludeStateLocked | ITransfersContainer::IncludeStateSoftLocked);

    std::vector<uint32_t> heights2;
    for (auto transfer2 : transfers2)
    {
      Crypto::Hash hash2 = transfer2.transactionHash;
      TransactionInformation info2;
      bool ok2 = container->getTransactionInformation(hash2, info2, NULL, NULL);
      if (ok2)
      {
        heights2.push_back(info2.blockHeight);
        updated = true;
      }
    }
    uint64_t locked = calculateDepositsAmount(transfers2, m_currency, heights2);

    /* This updates the unlocked deposit balance, these are the deposits that have matured
       and can be withdrawn */
    std::vector<TransactionOutputInformation> transfers;
    container->getOutputs(transfers, ITransfersContainer::IncludeTypeDeposit | ITransfersContainer::IncludeStateUnlocked);

    std::vector<uint32_t> heights;
    for (auto transfer : transfers)
    {
      Crypto::Hash hash = transfer.transactionHash;
      TransactionInformation info;
      bool ok = container->getTransactionInformation(hash, info, NULL, NULL);
      assert(ok);
      heights.push_back(info.blockHeight);
    }
    uint64_t unlocked = calculateDepositsAmount(transfers, m_currency, heights);

    /* Now do the same thing for overall deposit balances */
    if (it->lockedDepositBalance < locked)
    {
      m_lockedDepositBalance += locked - it->lockedDepositBalance;
      updated = true;
    }
    else
    {
      m_lockedDepositBalance -= it->lockedDepositBalance - locked;
      updated = true;
    }

    if (it->unlockedDepositBalance < unlocked)
    {
      m_unlockedDepositBalance += unlocked - it->unlockedDepositBalance;
      updated = true;
    }
    else
    {
      m_unlockedDepositBalance -= it->unlockedDepositBalance - unlocked;
      updated = true;
    }

    /* Write any changes to the wallet balances to the container */
    if (updated)
    {
      m_walletsContainer.get<TransfersContainerIndex>().modify(it, [actual, pending, locked, unlocked](WalletRecord &wallet) {
        wallet.actualBalance = actual;
        wallet.pendingBalance = pending;
        wallet.lockedDepositBalance = locked;
        wallet.unlockedDepositBalance = unlocked;
      });

      /* Keep the logging to debugging */
      m_logger(DEBUGGING, BRIGHT_WHITE) << "Wallet balance updated, address "
                                        << m_currency.accountAddressAsString({it->spendPublicKey, m_viewPublicKey})
                                        << ", actual " << m_currency.formatAmount(it->actualBalance) << ", pending "
                                        << m_currency.formatAmount(it->pendingBalance);
      m_logger(DEBUGGING, BRIGHT_WHITE) << "Container balance updated, actual "
                                        << m_currency.formatAmount(m_actualBalance) << ", pending "
                                        << m_currency.formatAmount(m_pendingBalance) << ", locked deposits "
                                        << m_currency.formatAmount(m_lockedDepositBalance) << ",unlocked deposits "
                                        << m_currency.formatAmount(m_unlockedDepositBalance);
    }
  }

  const WalletRecord &WalletGreen::getWalletRecord(const PublicKey &key) const
  {
    auto it = m_walletsContainer.get<KeysIndex>().find(key);
    if (it == m_walletsContainer.get<KeysIndex>().end())
    {
      throw std::system_error(make_error_code(error::WALLET_NOT_FOUND));
    }

    return *it;
  }

  const WalletRecord &WalletGreen::getWalletRecord(const std::string &address) const
  {
    CryptoNote::AccountPublicAddress pubAddr = parseAddress(address);
    return getWalletRecord(pubAddr.spendPublicKey);
  }

  const WalletRecord &WalletGreen::getWalletRecord(CryptoNote::ITransfersContainer *container) const
  {
    auto it = m_walletsContainer.get<TransfersContainerIndex>().find(container);
    if (it == m_walletsContainer.get<TransfersContainerIndex>().end())
    {
      throw std::system_error(make_error_code(error::WALLET_NOT_FOUND));
    }

    return *it;
  }

  CryptoNote::AccountPublicAddress WalletGreen::parseAddress(const std::string &address) const
  {
    CryptoNote::AccountPublicAddress pubAddr;

    if (!m_currency.parseAccountAddressString(address, pubAddr))
    {
      throw std::system_error(make_error_code(error::BAD_ADDRESS));
    }

    return pubAddr;
  }

  void WalletGreen::throwIfStopped() const
  {
    if (m_stopped)
    {
      throw std::system_error(make_error_code(error::OPERATION_CANCELLED));
    }
  }

  void WalletGreen::throwIfTrackingMode() const
  {
    if (getTrackingMode() == WalletTrackingMode::TRACKING)
    {
      throw std::system_error(make_error_code(error::TRACKING_MODE));
    }
  }

  WalletGreen::WalletTrackingMode WalletGreen::getTrackingMode() const
  {
    if (m_walletsContainer.get<RandomAccessIndex>().empty())
    {
      return WalletTrackingMode::NO_ADDRESSES;
    }

    return m_walletsContainer.get<RandomAccessIndex>().begin()->spendSecretKey == NULL_SECRET_KEY ? WalletTrackingMode::TRACKING : WalletTrackingMode::NOT_TRACKING;
  }

  size_t WalletGreen::createFusionTransaction(
      uint64_t threshold, uint64_t mixin,
      const std::vector<std::string> &sourceAddresses,
      const std::string &destinationAddress)
  {

    size_t id = WALLET_INVALID_TRANSACTION_ID;
    Tools::ScopeExit releaseContext([this, &id] {
      m_dispatcher.yield();

      if (id != WALLET_INVALID_TRANSACTION_ID)
      {
        auto &tx = m_transactions[id];
      }
    });

    System::EventLock lk(m_readyEvent);

    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    validateSourceAddresses(sourceAddresses);
    validateChangeDestination(sourceAddresses, destinationAddress, true);

    const size_t MAX_FUSION_OUTPUT_COUNT = 8;

    uint64_t fusionTreshold = m_currency.defaultDustThreshold();

    if (threshold <= fusionTreshold)
    {
      throw std::system_error(make_error_code(error::THRESHOLD_TOO_LOW));
    }

    if (m_walletsContainer.get<RandomAccessIndex>().size() == 0)
    {
      throw std::system_error(make_error_code(error::MINIMUM_ONE_ADDRESS));
    }

    size_t estimatedFusionInputsCount = m_currency.getApproximateMaximumInputCount(m_currency.fusionTxMaxSize(), MAX_FUSION_OUTPUT_COUNT, mixin);
    if (estimatedFusionInputsCount < m_currency.fusionTxMinInputCount())
    {
      throw std::system_error(make_error_code(error::MIXIN_COUNT_TOO_BIG));
    }

    auto fusionInputs = pickRandomFusionInputs(sourceAddresses, threshold, m_currency.fusionTxMinInputCount(), estimatedFusionInputsCount);
    if (fusionInputs.size() < m_currency.fusionTxMinInputCount())
    {
      //nothing to optimize
      throw std::system_error(make_error_code(error::NOTHING_TO_OPTIMIZE));
      return WALLET_INVALID_TRANSACTION_ID;
    }

    typedef CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
    std::vector<outs_for_amount> mixinResult;
    if (mixin != 0)
    {
      requestMixinOuts(fusionInputs, mixin, mixinResult);
    }

    std::vector<InputInfo> keysInfo;
    prepareInputs(fusionInputs, mixinResult, mixin, keysInfo);

    AccountPublicAddress destination = getChangeDestination(destinationAddress, sourceAddresses);

    std::unique_ptr<ITransaction> fusionTransaction;
    size_t transactionSize;
    int round = 0;
    //uint64_t transactionAmount;
    do
    {
      if (round != 0)
      {
        fusionInputs.pop_back();
        keysInfo.pop_back();
      }

      uint64_t inputsAmount = std::accumulate(fusionInputs.begin(), fusionInputs.end(), static_cast<uint64_t>(0), [](uint64_t amount, const OutputToTransfer &input) {
        return amount + input.out.amount;
      });

      //transactionAmount = inputsAmount;

      ReceiverAmounts decomposedOutputs = decomposeFusionOutputs(destination, inputsAmount);
      assert(decomposedOutputs.amounts.size() <= MAX_FUSION_OUTPUT_COUNT);

      Crypto::SecretKey txkey;
      std::vector<WalletMessage> messages;
      fusionTransaction = makeTransaction(std::vector<ReceiverAmounts>{decomposedOutputs}, keysInfo, messages, "", 0, txkey);
      transactionSize = getTransactionSize(*fusionTransaction);

      ++round;
    } while ((transactionSize > m_currency.fusionTxMaxSize()) && (fusionInputs.size() >= m_currency.fusionTxMinInputCount()));

    if (fusionInputs.size() < m_currency.fusionTxMinInputCount())
    {
      throw std::system_error(make_error_code(error::MINIMUM_INPUT_COUNT));
    }

    id = validateSaveAndSendTransaction(*fusionTransaction, {}, true, true);
    return id;
  }

  WalletGreen::ReceiverAmounts WalletGreen::decomposeFusionOutputs(const AccountPublicAddress &address, uint64_t inputsAmount)
  {
    WalletGreen::ReceiverAmounts outputs;
    outputs.receiver = address;

    decomposeAmount(inputsAmount, 0, outputs.amounts);
    std::sort(outputs.amounts.begin(), outputs.amounts.end());

    return outputs;
  }

  bool WalletGreen::isFusionTransaction(size_t transactionId) const
  {
    throwIfNotInitialized();
    throwIfStopped();

    if (m_transactions.size() <= transactionId)
    {
      throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
    }

    auto isFusionIter = m_fusionTxsCache.find(transactionId);
    if (isFusionIter != m_fusionTxsCache.end())
    {
      return isFusionIter->second;
    }

    bool result = isFusionTransaction(m_transactions.get<RandomAccessIndex>()[transactionId]);
    m_fusionTxsCache.emplace(transactionId, result);
    return result;
  }

  bool WalletGreen::isFusionTransaction(const WalletTransaction &walletTx) const
  {
    if (walletTx.fee != 0)
    {
      return false;
    }

    uint64_t inputsSum = 0;
    uint64_t outputsSum = 0;
    std::vector<uint64_t> outputsAmounts;
    std::vector<uint64_t> inputsAmounts;
    TransactionInformation txInfo;
    bool gotTx = false;
    const auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();
    for (const WalletRecord &wallet : walletsIndex)
    {
      for (const TransactionOutputInformation &output : wallet.container->getTransactionOutputs(walletTx.hash, ITransfersContainer::IncludeTypeKey | ITransfersContainer::IncludeStateAll))
      {
        if (outputsAmounts.size() <= output.outputInTransaction)
        {
          outputsAmounts.resize(output.outputInTransaction + 1, 0);
        }

        assert(output.amount != 0);
        assert(outputsAmounts[output.outputInTransaction] == 0);
        outputsAmounts[output.outputInTransaction] = output.amount;
        outputsSum += output.amount;
      }

      for (const TransactionOutputInformation &input : wallet.container->getTransactionInputs(walletTx.hash, ITransfersContainer::IncludeTypeKey))
      {
        inputsSum += input.amount;
        inputsAmounts.push_back(input.amount);
      }

      if (!gotTx)
      {
        gotTx = wallet.container->getTransactionInformation(walletTx.hash, txInfo);
      }
    }

    if (!gotTx)
    {
      return false;
    }

    if (outputsSum != inputsSum || outputsSum != txInfo.totalAmountOut || inputsSum != txInfo.totalAmountIn)
    {
      return false;
    }
    else
    {
      return m_currency.isFusionTransaction(inputsAmounts, outputsAmounts, 0); //size = 0 here because can't get real size of tx in wallet.
    }
  }

  void WalletGreen::validateChangeDestination(const std::vector<std::string> &sourceAddresses, const std::string &changeDestination, bool isFusion) const
  {
    std::string message;
    if (changeDestination.empty())
    {
      if (sourceAddresses.size() > 1 || (sourceAddresses.empty() && m_walletsContainer.size() > 1))
      {
        message = std::string(isFusion ? "Destination" : "Change destination") + " address is necessary";
        m_logger(ERROR, BRIGHT_RED) << message << ". Source addresses size=" << sourceAddresses.size() << ", wallets count=" << m_walletsContainer.size();
        throw std::system_error(make_error_code(isFusion ? error::DESTINATION_ADDRESS_REQUIRED : error::CHANGE_ADDRESS_REQUIRED), message);
      }
    }
    else
    {
      if (!CryptoNote::validateAddress(changeDestination, m_currency))
      {
        message = std::string("Bad ") + (isFusion ? "destination" : "change destination") + " address: " + changeDestination;
        m_logger(ERROR, BRIGHT_RED) << message;
        throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS), message);
      }

      if (!isMyAddress(changeDestination))
      {
        message = std::string(isFusion ? "Destination" : "Change destination") + " address is not found in current container: " + changeDestination;
        m_logger(ERROR, BRIGHT_RED) << message;
        throw std::system_error(make_error_code(isFusion ? error::DESTINATION_ADDRESS_NOT_FOUND : error::CHANGE_ADDRESS_NOT_FOUND), message);
      }
    }
  }

  void WalletGreen::validateSourceAddresses(const std::vector<std::string> &sourceAddresses) const
  {
    validateAddresses(sourceAddresses);

    auto badAddr = std::find_if(sourceAddresses.begin(), sourceAddresses.end(), [this](const std::string &addr) {
      return !isMyAddress(addr);
    });

    if (badAddr != sourceAddresses.end())
    {
      throw std::system_error(make_error_code(error::BAD_ADDRESS), "Source address must belong to current container: " + *badAddr);
    }
  }

  IFusionManager::EstimateResult WalletGreen::estimate(uint64_t threshold, const std::vector<std::string> &sourceAddresses) const
  {
    System::EventLock lk(m_readyEvent);

    throwIfNotInitialized();
    throwIfStopped();

    validateSourceAddresses(sourceAddresses);

    IFusionManager::EstimateResult result{0, 0};
    auto walletOuts = sourceAddresses.empty() ? pickWalletsWithMoney() : pickWallets(sourceAddresses);
    std::array<size_t, std::numeric_limits<uint64_t>::digits10 + 1> bucketSizes;
    bucketSizes.fill(0);
    for (size_t walletIndex = 0; walletIndex < walletOuts.size(); ++walletIndex)
    {
      for (auto &out : walletOuts[walletIndex].outs)
      {
        uint8_t powerOfTen = 0;
        if (m_currency.isAmountApplicableInFusionTransactionInput(out.amount, threshold, powerOfTen, m_node.getLastKnownBlockHeight()))
        {
          assert(powerOfTen < std::numeric_limits<uint64_t>::digits10 + 1);
          bucketSizes[powerOfTen]++;
        }
      }

      result.totalOutputCount += walletOuts[walletIndex].outs.size();
    }

    for (auto bucketSize : bucketSizes)
    {
      if (bucketSize >= m_currency.fusionTxMinInputCount())
      {
        result.fusionReadyCount += bucketSize;
      }
    }

    return result;
  }

  std::vector<WalletGreen::OutputToTransfer> WalletGreen::pickRandomFusionInputs(const std::vector<std::string> &addresses,
                                                                                 uint64_t threshold, size_t minInputCount, size_t maxInputCount)
  {

    std::vector<WalletGreen::OutputToTransfer> allFusionReadyOuts;
    auto walletOuts = addresses.empty() ? pickWalletsWithMoney() : pickWallets(addresses);
    std::array<size_t, std::numeric_limits<uint64_t>::digits10 + 1> bucketSizes;
    bucketSizes.fill(0);
    for (size_t walletIndex = 0; walletIndex < walletOuts.size(); ++walletIndex)
    {
      for (auto &out : walletOuts[walletIndex].outs)
      {
        uint8_t powerOfTen = 0;
        if (m_currency.isAmountApplicableInFusionTransactionInput(out.amount, threshold, powerOfTen, m_node.getLastKnownBlockHeight()))
        {
          allFusionReadyOuts.push_back({std::move(out), walletOuts[walletIndex].wallet});
          assert(powerOfTen < std::numeric_limits<uint64_t>::digits10 + 1);
          bucketSizes[powerOfTen]++;
        }
      }
    }

    //now, pick the bucket
    std::vector<uint8_t> bucketNumbers(bucketSizes.size());
    std::iota(bucketNumbers.begin(), bucketNumbers.end(), 0);
    std::shuffle(bucketNumbers.begin(), bucketNumbers.end(), std::default_random_engine{Crypto::rand<std::default_random_engine::result_type>()});
    size_t bucketNumberIndex = 0;
    for (; bucketNumberIndex < bucketNumbers.size(); ++bucketNumberIndex)
    {
      if (bucketSizes[bucketNumbers[bucketNumberIndex]] >= minInputCount)
      {
        break;
      }
    }

    if (bucketNumberIndex == bucketNumbers.size())
    {
      return {};
    }

    size_t selectedBucket = bucketNumbers[bucketNumberIndex];
    assert(selectedBucket < std::numeric_limits<uint64_t>::digits10 + 1);
    assert(bucketSizes[selectedBucket] >= minInputCount);
    uint64_t lowerBound = 1;
    for (size_t i = 0; i < selectedBucket; ++i)
    {
      lowerBound *= 10;
    }

    uint64_t upperBound = selectedBucket == std::numeric_limits<uint64_t>::digits10 ? UINT64_MAX : lowerBound * 10;
    std::vector<WalletGreen::OutputToTransfer> selectedOuts;
    selectedOuts.reserve(bucketSizes[selectedBucket]);
    for (size_t outIndex = 0; outIndex < allFusionReadyOuts.size(); ++outIndex)
    {
      if (allFusionReadyOuts[outIndex].out.amount >= lowerBound && allFusionReadyOuts[outIndex].out.amount < upperBound)
      {
        selectedOuts.push_back(std::move(allFusionReadyOuts[outIndex]));
      }
    }

    assert(selectedOuts.size() >= minInputCount);

    auto outputsSortingFunction = [](const OutputToTransfer &l, const OutputToTransfer &r) { return l.out.amount < r.out.amount; };
    if (selectedOuts.size() <= maxInputCount)
    {
      std::sort(selectedOuts.begin(), selectedOuts.end(), outputsSortingFunction);
      return selectedOuts;
    }

    ShuffleGenerator<size_t, Crypto::random_engine<size_t>> generator(selectedOuts.size());
    std::vector<WalletGreen::OutputToTransfer> trimmedSelectedOuts;
    trimmedSelectedOuts.reserve(maxInputCount);
    for (size_t i = 0; i < maxInputCount; ++i)
    {
      trimmedSelectedOuts.push_back(std::move(selectedOuts[generator()]));
    }

    std::sort(trimmedSelectedOuts.begin(), trimmedSelectedOuts.end(), outputsSortingFunction);
    return trimmedSelectedOuts;
  }

  std::vector<DepositsInBlockInfo> WalletGreen::getDepositsInBlocks(uint32_t blockIndex, size_t count) const
  {
    if (count == 0)
    {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "blocks count must be greater than zero");
    }

    std::vector<DepositsInBlockInfo> result;

    if (blockIndex >= m_blockchain.size())
    {
      return result;
    }

    auto &blockHeightIndex = m_deposits.get<BlockHeightIndex>();
    uint32_t stopIndex = static_cast<uint32_t>(std::min(m_blockchain.size(), blockIndex + count));

    for (uint32_t height = blockIndex; height < stopIndex; ++height)
    {
      DepositsInBlockInfo info;
      info.blockHash = m_blockchain[height];

      auto lowerBound = blockHeightIndex.lower_bound(height);
      auto upperBound = blockHeightIndex.upper_bound(height);
      for (auto it = lowerBound; it != upperBound; ++it)
      {
        Deposit deposit;
        deposit = *it;
        info.deposits.emplace_back(std::move(deposit));
      }
      result.emplace_back(std::move(info));
    }

    return result;
  }

  std::vector<TransactionsInBlockInfo> WalletGreen::getTransactionsInBlocks(uint32_t blockIndex, size_t count) const
  {
    if (count == 0)
    {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "blocks count must be greater than zero");
    }

    std::vector<TransactionsInBlockInfo> result;

    if (blockIndex >= m_blockchain.size())
    {
      return result;
    }

    auto &blockHeightIndex = m_transactions.get<BlockHeightIndex>();
    uint32_t stopIndex = static_cast<uint32_t>(std::min(m_blockchain.size(), blockIndex + count));

    for (uint32_t height = blockIndex; height < stopIndex; ++height)
    {
      TransactionsInBlockInfo info;
      info.blockHash = m_blockchain[height];

      auto lowerBound = blockHeightIndex.lower_bound(height);
      auto upperBound = blockHeightIndex.upper_bound(height);
      for (auto it = lowerBound; it != upperBound; ++it)
      {
        if (it->state != WalletTransactionState::SUCCEEDED)
        {
          continue;
        }

        WalletTransactionWithTransfers transaction;
        transaction.transaction = *it;
        transaction.transfers = getTransactionTransfers(*it);

        info.transactions.emplace_back(std::move(transaction));
      }

      result.emplace_back(std::move(info));
    }

    return result;
  }

  Crypto::Hash WalletGreen::getBlockHashByIndex(uint32_t blockIndex) const
  {
    assert(blockIndex < m_blockchain.size());
    return m_blockchain.get<BlockHeightIndex>()[blockIndex];
  }

  std::vector<WalletTransfer> WalletGreen::getTransactionTransfers(const WalletTransaction &transaction) const
  {
    auto &transactionIdIndex = m_transactions.get<RandomAccessIndex>();

    auto it = transactionIdIndex.iterator_to(transaction);
    assert(it != transactionIdIndex.end());

    size_t transactionId = std::distance(transactionIdIndex.begin(), it);
    size_t transfersCount = getTransactionTransferCount(transactionId);

    std::vector<WalletTransfer> result;
    result.reserve(transfersCount);

    for (size_t transferId = 0; transferId < transfersCount; ++transferId)
    {
      result.push_back(getTransactionTransfer(transactionId, transferId));
    }

    return result;
  }

  void WalletGreen::filterOutTransactions(WalletTransactions &transactions, WalletTransfers &transfers, std::function<bool(const WalletTransaction &)> &&pred) const
  {
    size_t cancelledTransactions = 0;

    transactions.reserve(m_transactions.size());
    transfers.reserve(m_transfers.size());

    auto &index = m_transactions.get<RandomAccessIndex>();
    size_t transferIdx = 0;
    for (size_t i = 0; i < m_transactions.size(); ++i)
    {
      const WalletTransaction &transaction = index[i];

      if (pred(transaction))
      {
        ++cancelledTransactions;

        while (transferIdx < m_transfers.size() && m_transfers[transferIdx].first == i)
        {
          ++transferIdx;
        }
      }
      else
      {
        transactions.emplace_back(transaction);

        while (transferIdx < m_transfers.size() && m_transfers[transferIdx].first == i)
        {
          transfers.emplace_back(i - cancelledTransactions, m_transfers[transferIdx].second);
          ++transferIdx;
        }
      }
    }
  }

  void WalletGreen::getViewKeyKnownBlocks(const Crypto::PublicKey &viewPublicKey)
  {
    std::vector<Crypto::Hash> blockchain = m_synchronizer.getViewKeyKnownBlocks(m_viewPublicKey);
    m_blockchain.insert(m_blockchain.end(), blockchain.begin(), blockchain.end());
  }

  ///pre: changeDestinationAddress belongs to current container
  ///pre: source address belongs to current container
  CryptoNote::AccountPublicAddress WalletGreen::getChangeDestination(const std::string &changeDestinationAddress, const std::vector<std::string> &sourceAddresses) const
  {
    if (!changeDestinationAddress.empty())
    {
      return parseAccountAddressString(changeDestinationAddress, m_currency);
    }

    if (m_walletsContainer.size() == 1)
    {
      return AccountPublicAddress{m_walletsContainer.get<RandomAccessIndex>()[0].spendPublicKey, m_viewPublicKey};
    }

    assert(sourceAddresses.size() == 1 && isMyAddress(sourceAddresses[0]));
    return parseAccountAddressString(sourceAddresses[0], m_currency);
  }

  bool WalletGreen::isMyAddress(const std::string &addressString) const
  {
    CryptoNote::AccountPublicAddress address = parseAccountAddressString(addressString, m_currency);
    return m_viewPublicKey == address.viewPublicKey && m_walletsContainer.get<KeysIndex>().count(address.spendPublicKey) != 0;
  }

  void WalletGreen::deleteContainerFromUnlockTransactionJobs(const ITransfersContainer *container)
  {
    for (auto it = m_unlockTransactionsJob.begin(); it != m_unlockTransactionsJob.end();)
    {
      if (it->container == container)
      {
        it = m_unlockTransactionsJob.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

  std::vector<size_t> WalletGreen::deleteTransfersForAddress(const std::string &address, std::vector<size_t> &deletedTransactions)
  {
    assert(!address.empty());

    int64_t deletedInputs = 0;
    int64_t deletedOutputs = 0;

    int64_t unknownInputs = 0;

    bool transfersLeft = false;
    size_t firstTransactionTransfer = 0;

    std::vector<size_t> updatedTransactions;

    for (size_t i = 0; i < m_transfers.size(); ++i)
    {
      WalletTransfer &transfer = m_transfers[i].second;

      if (transfer.address == address)
      {
        if (transfer.amount >= 0)
        {
          deletedOutputs += transfer.amount;
        }
        else
        {
          deletedInputs += transfer.amount;
          transfer.address = "";
        }
      }
      else if (transfer.address.empty())
      {
        if (transfer.amount < 0)
        {
          unknownInputs += transfer.amount;
        }
      }
      else if (isMyAddress(transfer.address))
      {
        transfersLeft = true;
      }

      size_t transactionId = m_transfers[i].first;
      if ((i == m_transfers.size() - 1) || (transactionId != m_transfers[i + 1].first))
      {
        //the last transfer for current transaction

        size_t transfersBeforeMerge = m_transfers.size();
        if (deletedInputs != 0)
        {
          adjustTransfer(transactionId, firstTransactionTransfer, "", deletedInputs + unknownInputs);
        }

        assert(transfersBeforeMerge >= m_transfers.size());
        i -= transfersBeforeMerge - m_transfers.size();

        auto &randomIndex = m_transactions.get<RandomAccessIndex>();

        randomIndex.modify(std::next(randomIndex.begin(), transactionId), [transfersLeft, deletedInputs, deletedOutputs](WalletTransaction &transaction) {
          transaction.totalAmount -= deletedInputs + deletedOutputs;

          if (!transfersLeft)
          {
            transaction.state = WalletTransactionState::DELETED;
          }
        });

        if (!transfersLeft)
        {
          deletedTransactions.push_back(transactionId);
        }

        if (deletedInputs != 0 || deletedOutputs != 0)
        {
          updatedTransactions.push_back(transactionId);
        }

        //reset values for next transaction
        deletedInputs = 0;
        deletedOutputs = 0;
        unknownInputs = 0;
        transfersLeft = false;
        firstTransactionTransfer = i + 1;
      }
    }

    return updatedTransactions;
  }

  size_t WalletGreen::getTxSize(const TransactionParameters &sendingTransaction)
  {
    System::EventLock lk(m_readyEvent);

    throwIfNotInitialized();
    throwIfTrackingMode();
    throwIfStopped();

    CryptoNote::AccountPublicAddress changeDestination = getChangeDestination(sendingTransaction.changeDestination, sendingTransaction.sourceAddresses);

    std::vector<WalletOuts> wallets;
    if (!sendingTransaction.sourceAddresses.empty())
    {
      wallets = pickWallets(sendingTransaction.sourceAddresses);
    }
    else
    {
      wallets = pickWalletsWithMoney();
    }

    PreparedTransaction preparedTransaction;
    Crypto::SecretKey txSecretKey;
    prepareTransaction(
        std::move(wallets),
        sendingTransaction.destinations,
        sendingTransaction.messages,
        sendingTransaction.fee,
        sendingTransaction.mixIn,
        sendingTransaction.extra,
        sendingTransaction.unlockTimestamp,
        sendingTransaction.donation,
        changeDestination,
        preparedTransaction,
        txSecretKey);

    BinaryArray transactionData = preparedTransaction.transaction->getTransactionData();
    return transactionData.size();
  }

  void WalletGreen::deleteFromUncommitedTransactions(const std::vector<size_t> &deletedTransactions)
  {
    for (auto transactionId : deletedTransactions)
    {
      m_uncommitedTransactions.erase(transactionId);
    }
  }

  void WalletGreen::clearCacheAndShutdown()
  {
    if (m_walletsContainer.size() != 0)
    {
      m_synchronizer.unsubscribeConsumerNotifications(m_viewPublicKey, this);
    }

    stopBlockchainSynchronizer();
    m_blockchainSynchronizer.removeObserver(this);

    clearCaches(true, true);

    m_walletsContainer.clear();

    shutdown();
  }

  // Burn deposit secret management implementation
  void WalletGreen::addBurnDepositSecret(const std::string& transactionHash, const Crypto::SecretKey& secret, uint64_t amount, const std::vector<uint8_t>& metadata) {
    // Store burn deposit secret locally (never on blockchain)
    WalletGreen::BurnDepositInfo burnInfo(transactionHash, secret, amount, metadata);
    burnInfo.timestamp = static_cast<uint64_t>(std::time(nullptr));

    m_burnDepositSecrets[transactionHash] = burnInfo;

    // TODO: Persist to wallet file for backup
    // This ensures secrets survive wallet restarts
  }

  bool WalletGreen::getBurnDepositSecret(const std::string& transactionHash, Crypto::SecretKey& secret, uint64_t& amount, std::vector<uint8_t>& metadata) {
    auto it = m_burnDepositSecrets.find(transactionHash);
    if (it == m_burnDepositSecrets.end()) {
      return false;  // Secret not found
    }

    const WalletGreen::BurnDepositInfo& burnInfo = it->second;
    secret = burnInfo.secret;
    amount = burnInfo.amount;
    metadata = burnInfo.metadata;

    return true;
  }

  bool WalletGreen::hasBurnDepositSecret(const std::string& transactionHash) {
    return m_burnDepositSecrets.find(transactionHash) != m_burnDepositSecrets.end();
  }

  std::vector<WalletGreen::BurnDepositInfo> WalletGreen::getAllBurnDeposits() {
    std::vector<WalletGreen::BurnDepositInfo> result;
    for (const auto& pair : m_burnDepositSecrets) {
      result.push_back(pair.second);
    }
    return result;
  }

  // ============================================================================
  // Alias methods
  // ============================================================================

  std::error_code WalletGreen::registerAlias(const std::string& alias,
                                              const std::string& ownerAddress,
                                              Crypto::Hash& txHashOut) {
    throwIfNotInitialized();
    throwIfStopped();

    // Parse owner address for canonical identity.
    CryptoNote::AccountPublicAddress masterAddr;
    if (!m_currency.parseAccountAddressString(ownerAddress, masterAddr)) {
      return make_error_code(std::errc::invalid_argument);
    }

    // Build the 0xEA alias registration extra field.
    CryptoNote::TransactionExtraAliasRegistration aliasReg;
    aliasReg.version   = 1;
    aliasReg.alias     = alias;
    aliasReg.aliasHash = Crypto::cn_fast_hash(alias.data(), alias.size());

    // Canonical addressHash from master keys (not base58 string).
    // This is the identity that enforces one-alias-per-address at consensus.
    {
      uint8_t preimage[64];
      memcpy(preimage,      &masterAddr.spendPublicKey, 32);
      memcpy(preimage + 32, &masterAddr.viewPublicKey,  32);
      Crypto::cn_fast_hash(preimage, 64, aliasReg.addressHash);
    }

    // Per-tx rotation: derive a fresh sub-address so an observer scanning
    // blocks cannot link multiple alias registrations by ownerAddress.
    {
      const auto& wallets = m_walletsContainer.get<RandomAccessIndex>();
      if (wallets.empty()) {
        return make_error_code(std::errc::not_connected);
      }
      const WalletRecord& primary = wallets[0];

      // Pick a random non-zero major index (minor=0).
      // Each registration gets a unique sub-address; never (0,0).
      uint32_t major = 0;
      uint32_t minor = 0;
      {
        uint8_t rb[4];
        Crypto::generate_random_bytes(4, rb);
        major = 1 + (static_cast<uint32_t>(rb[0])
                  | (static_cast<uint32_t>(rb[1]) << 8)
                  | (static_cast<uint32_t>(rb[2]) << 16)
                  | (static_cast<uint32_t>(rb[3]) << 24));
        // Failsafe: avoid overflow wrap. Extremely unlikely but safe.
        if (major == 0) major = 1;
      }

      const Crypto::SecretKey* spendSec = (primary.spendSecretKey != NULL_SECRET_KEY)
                                          ? &primary.spendSecretKey : nullptr;

      Crypto::SubAddressKeys subKeys = Crypto::deriveSubAddressKeys(
        m_viewSecretKey, primary.spendPublicKey, spendSec, major, minor);

      CryptoNote::AccountPublicAddress subAddr{subKeys.spendPublicKey, subKeys.viewPublicKey};
      aliasReg.ownerAddress = m_currency.subAddressAsString(subAddr);
    }

    aliasReg.aliasType = 1;      // Regular user alias [a-z0-9&]
    aliasReg.networkId = static_cast<uint32_t>(m_currency.getFuegoNetworkId());

    if (!aliasReg.isValid()) {
      return make_error_code(std::errc::invalid_argument);
    }

    std::vector<uint8_t> extraVec;
    if (!CryptoNote::addAliasToExtra(extraVec, aliasReg)) {
      return make_error_code(std::errc::invalid_argument);
    }

    std::string extra(extraVec.begin(), extraVec.end());

    TransactionParameters params;
    if (!m_currency.isTestnet()) {
      WalletOrder devFundOutput;
      devFundOutput.address = CryptoNote::FUEGO_DEV_FUND_ADDRESS;
      uint64_t randomDust = 0;
      {
        uint8_t randBytes[8] = {};
        Crypto::generate_random_bytes(sizeof(randBytes), randBytes);
        for (int i = 0; i < 8; ++i) {
          randomDust = (randomDust << 8) | randBytes[i];
        }
        randomDust = randomDust % (CryptoNote::parameters::ALIAS_REGISTRATION_FEE_MAX_RANDOM + 1);
      }
      devFundOutput.amount  = CryptoNote::parameters::ALIAS_REGISTRATION_FEE + randomDust;
      params.destinations.push_back(devFundOutput);
    } else {
      WalletOrder selfOutput;
      selfOutput.address = ownerAddress;
      selfOutput.amount  = m_currency.minimumFee();
      params.destinations.push_back(selfOutput);
    }
    params.fee   = m_currency.minimumFee();
    params.mixIn = m_currency.minMixin(CryptoNote::BLOCK_MAJOR_VERSION_10);
    params.extra = extra;

    Crypto::SecretKey txSK;
    size_t txIdx;
    try {
      txIdx = transfer(params, txSK);
    } catch (const std::system_error& e) {
      return e.code();
    } catch (...) {
      return make_error_code(std::errc::io_error);
    }

    WalletTransaction txInfo = getTransaction(txIdx);
    txHashOut = txInfo.hash;
    return {};
  }

  bool WalletGreen::getAliasByAddress(const std::string& address, std::string& aliasOut) {
    // INode does not expose a direct getAliasByAddress method; callers should
    // use the /get_alias_by_address RPC endpoint via NodeRpcProxy directly.
    // This stub returns false to indicate the feature requires RPC access.
    // TODO: extend INode with getAliasByAddress(address, callback) and implement
    //       here once the interface is available.
    (void)address;
    (void)aliasOut;
    return false;
  }

} //namespace CryptoNote
