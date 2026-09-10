// Copyright (c) 2017-2026 Fuego Developers
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

#include "OfferManager.h"
#include "StatusServer.h"
#include "SwapTypes.h"
#include "SwapStateMachine.h"
#include "Spv/SpvHeaderStore.h"
#include "SwapDatabase.h"
#include "SwapTxBuilder.h"
#include "SwapPeerProtocol.h"
#include "SwapP2P.h"
#include "FuegoRpcClient.h"
#include "PriceOracle.h"
#include "../Logging/ILogger.h"
#include "../Logging/LoggerRef.h"
#include "ChainRegistry.h"

namespace CryptoNote {
  class SwapOfferRelay;
}

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <map>
#include <vector>
#include <ctime>

namespace XfgSwap {

// Configuration for counterparty chain RPC endpoints.
// Pass to SwapDaemon constructor to wire per-chain clients.
// Leave host empty ("") for any chain that is not in use.
struct ChainClientConfig {
  // BCH
  std::string bchHost;
  uint16_t    bchPort     = 8332;
  std::string bchRpcUser;
  std::string bchRpcPass;
  std::string bchWif;          // WIF-encoded private key for HTLC signing

  // BCH SPV mode — when bchMode == "spv", use ElectrumSpvClient instead of RPC
  std::string bchMode;                         // "rpc" (default) or "spv"
  std::vector<std::string> bchSpvServers;      // "host:port" strings
  size_t    bchSpvMinServers  = 1;             // min servers for cross-check
  uint64_t  bchSpvCheckpointHeight = 0;        // checkpoint anchor height
  std::string bchSpvCheckpointHash;            // checkpoint hash (display hex)

  // ETH
  std::string ethHost;
  uint16_t    ethPort     = 8545;

  // SOL
  std::string solHost;
  uint16_t    solPort     = 8899;
  std::string solProgramId;  // xfg_htlc program ID (base58)

  // XMR
  std::string xmrDaemonHost;
  uint16_t    xmrDaemonPort = 18081;
  std::string xmrWalletHost;
  uint16_t    xmrWalletPort = 18082;

  // ── Signer credentials ────────────────────────────────────────────────────
  // ETH private key (64 hex chars, 32 bytes) and derived address ("0x...")
  std::string ethPrivKeyHex;
  std::string ethAddress;
  uint64_t    ethChainId = 1;  // EIP-155 chain ID (1=mainnet, 11155111=Sepolia)
  // Optional: path to the pre-compiled HashedTimelock .bin file
  std::string ethHtlcBinPath;
  // Pre-deployed HashedTimelock registry address ("0x...")
  std::string ethHtlcRegistry;
  // Pre-deployed PointTimelock registry address ("0x..."). Enables pure PTLC
  // routing on all EVM chains; empty => BRIDGE (HTLC) — unchanged behavior.
  std::string ethPtlcRegistry;

  // ARB
  std::string arbHost;
  uint16_t    arbPort     = 8547;

  // ARB signer credentials (reuses ETH private key derivation; separate key optional)
  std::string arbPrivKeyHex;
  std::string arbAddress;
  uint64_t    arbChainId = 42161;
  std::string arbHtlcBinPath;

  // BASE (Base L2 — EVM, EIP-1559)
  std::string baseHost;
  uint16_t    basePort     = 8545;
  std::string basePrivKeyHex;
  std::string baseAddress;
  uint64_t    baseChainId  = 8453;
  std::string baseHtlcBinPath;

  // POLYGON (Polygon PoS — EVM, EIP-1559)
  std::string polyHost;
  uint16_t    polyPort     = 8545;
  std::string polyPrivKeyHex;
  std::string polyAddress;
  uint64_t    polyChainId  = 137;
  std::string polyHtlcBinPath;

  // XMR spend/view keys (64 hex chars each)
  std::string xmrSpendKeyHex;
  std::string xmrViewKeyHex;

  // Solana keypair JSON file path (as produced by `solana-keygen new`)
  std::string solKeypairPath;

  // BNB (Binance Smart Chain — EVM)
  std::string bscHost;
  uint16_t    bscPort     = 8545;
  std::string bscPrivKeyHex;
  std::string bscAddress;
  uint64_t    bscChainId  = 56;
  std::string bscHtlcBinPath;

  // DCR (Decred — hybrid PoW/PoS UTXO)
  std::string dcrHost;
  uint16_t    dcrPort     = 9108;
  std::string dcrRpcUser;
  std::string dcrRpcPass;
  std::string dcrWif;

  // DCR SPV mode — when dcrMode == "spv", use NeutrinoSpvClient instead of RPC
  std::string dcrMode;                         // "rpc" (default) or "spv"
  std::vector<std::string> dcrSpvServers;      // "host:port" strings
  size_t    dcrSpvMinServers  = 1;             // min servers for cross-check
  uint64_t  dcrSpvCheckpointHeight = 0;        // checkpoint anchor height
  std::string dcrSpvCheckpointHash;            // checkpoint hash (display hex)

  // BTC
  std::string btcHost;
  uint16_t    btcPort     = 8332;
  std::string btcRpcUser;
  std::string btcRpcPass;
  std::string btcWif;

  // BTC SPV mode — when btcMode == "spv", use ElectrumSpvClient instead of RPC
  std::string btcMode;                         // "rpc" (default) or "spv"
  std::vector<std::string> btcSpvServers;      // "host:port" strings
  size_t    btcSpvMinServers  = 1;             // min servers for cross-check
  uint64_t  btcSpvCheckpointHeight = 0;        // checkpoint anchor height
  std::string btcSpvCheckpointHash;            // checkpoint hash (display hex)

  // LTC
  std::string ltcHost;
  uint16_t    ltcPort     = 9332;
  std::string ltcRpcUser;
  std::string ltcRpcPass;
  std::string ltcWif;

  // LTC SPV mode — when ltcMode == "spv", use ElectrumSpvClient instead of RPC
  std::string ltcMode;                         // "rpc" (default) or "spv"
  std::vector<std::string> ltcSpvServers;      // "host:port" strings
  size_t    ltcSpvMinServers  = 1;             // min servers for cross-check
  uint64_t  ltcSpvCheckpointHeight = 0;        // checkpoint anchor height
  std::string ltcSpvCheckpointHash;            // checkpoint hash (display hex)

  // KMD
  std::string kmdHost;
  uint16_t    kmdPort     = 7771;
  std::string kmdRpcUser;
  std::string kmdRpcPass;
  std::string kmdWif;

  // KMD SPV mode — when kmdMode == "spv", use ElectrumSpvClient instead of RPC
  std::string kmdMode;                         // "rpc" (default) or "spv"
  std::vector<std::string> kmdSpvServers;      // "host:port" strings
  size_t    kmdSpvMinServers  = 1;             // min servers for cross-check
  uint64_t  kmdSpvCheckpointHeight = 0;        // checkpoint anchor height
  std::string kmdSpvCheckpointHash;            // checkpoint hash (display hex)

  // GLEEC (Evmos fork)
  std::string gleecHost;
  uint16_t    gleecPort     = 8545;
  std::string gleecPrivKeyHex;
  std::string gleecAddress;
  uint64_t    gleecChainId  = 11169;
  std::string gleecHtlcBinPath;
  std::string gleecHtlcRegistry;  // pre-deployed HTLC registry on Gleec

  // ROBINHOOD (Robinhood Chain — EVM L1)
  std::string rhHost;
  uint16_t    rhPort     = 8545;
  std::string rhPrivKeyHex;
  std::string rhAddress;
  uint64_t    rhChainId  = 4663;
  std::string rhHtlcBinPath;

  // AVAX (Avalanche C-Chain — EVM, EIP-1559)
  std::string avaxHost;
  uint16_t    avaxPort     = 8545;
  std::string avaxPrivKeyHex;
  std::string avaxAddress;
  uint64_t    avaxChainId  = 43114;
  std::string avaxHtlcBinPath;

  // CRO (Cronos — EVM)
  std::string croHost;
  uint16_t    croPort     = 8545;
  std::string croPrivKeyHex;
  std::string croAddress;
  uint64_t    croChainId  = 25;
  std::string croHtlcBinPath;

  // BOB (Bob — OP Stack BTC rollup, EVM)
  std::string bobHost;
  uint16_t    bobPort     = 8545;
  std::string bobPrivKeyHex;
  std::string bobAddress;
  uint64_t    bobChainId  = 60808;
  std::string bobHtlcBinPath;

  // Sia (SC) — siad / walletd
  std::string siaHost;
  uint16_t    siaPort = 9980;
  std::string siaApiPassword;

  // UNICHAIN (Unichain — OP Stack EVM)
  std::string uniHost;
  uint16_t    uniPort     = 8545;
  std::string uniPrivKeyHex;
  std::string uniAddress;
  uint64_t    uniChainId  = 130;
  std::string uniHtlcBinPath;

  // PLASMA (Plasma — EVM)
  std::string plasmaHost;
  uint16_t    plasmaPort     = 8545;
  std::string plasmaPrivKeyHex;
  std::string plasmaAddress;
  uint64_t    plasmaChainId  = 9745;
  std::string plasmaHtlcBinPath;

  // DOGE (Dogecoin — pre-SegWit UTXO, P2SH + legacy sighash)
  std::string dogeHost;
  uint16_t    dogePort     = 22556;
  std::string dogeRpcUser;
  std::string dogeRpcPass;
  std::string dogeWif;         // WIF-encoded private key (mainnet prefix 0x9E)

  // DASH (Dash — pre-SegWit UTXO, P2SH + legacy sighash)
  std::string dashHost;
  uint16_t    dashPort     = 9998;
  std::string dashRpcUser;
  std::string dashRpcPass;
  std::string dashWif;         // WIF-encoded private key (mainnet prefix 0xCC)
  bool        dashTestnet = false;

  // ZEC (Zcash — transparent-only, v4 tx serialization + legacy sighash)
  std::string zecHost;
  uint16_t    zecPort      = 8232;
  std::string zecRpcUser;
  std::string zecRpcPass;
  std::string zecWif;          // WIF-encoded private key (mainnet prefix 0x80)
  bool        zecTestnet = false;

  // PULSEX (PulseChain — EVM, chain id 369, native PLS 18 decimals)
  std::string pulsexHost;
  uint16_t    pulsexPort   = 8545;
  std::string pulsexPrivKeyHex;
  std::string pulsexAddress;
  uint64_t    pulsexChainId = 369;
  std::string pulsexHtlcBinPath;

  // ZANO (CryptoNote — shared 2-of-2 address via view-key adaptor scheme)
  std::string zanoDaemonHost;
  uint16_t    zanoDaemonPort = 11211;
  std::string zanoWalletHost;
  uint16_t    zanoWalletPort = 0;   // operator passes --rpc-bind-port
  std::string zanoSpendKeyHex;
  std::string zanoViewKeyHex;

  // TON (The Open Network — TVM, account-based, FunC contracts)
  std::string tonHost;
  uint16_t    tonPort       = 2990;
  std::string tonRpcUser;
  std::string tonRpcPass;
  std::string tonWalletKey;           // hex-encoded Ed25519 seed
  std::string tonHtlcAddress;         // deployed HTLC contract address
  int         tonWorkchain   = 0;

  // Monad (EVM L1, OP Stack, chain id 185)
  std::string monadHost;
  uint16_t    monadPort       = 8545;
  std::string monadPrivKeyHex;
  std::string monadAddress;
  uint64_t    monadChainId    = 185;
  std::string monadHtlcBinPath;

  // Optimism (EVM L2, OP Stack, chain id 10)
  std::string opHost;
  uint16_t    opPort       = 8545;
  std::string opPrivKeyHex;
  std::string opAddress;
  uint64_t    opChainId    = 10;
  std::string opHtlcBinPath;

  // DOT (Polkadot Relay — Substrate, SS58 prefix 0)
  std::string dotHost;
  uint16_t    dotPort       = 9933;
  std::string dotAddress;           // SS58 address
  std::string dotSeedPhrase;        // Substrate seed phrase or hex seed

  // XFG wallet key for signing managed offers (hex-encoded 64-char Ed25519 secret key)
  std::string xfgSecretKeyHex;
  std::string xfgViewKeyHex;

  // Fuego wallet RPC config for escrow funding
  std::string xfgWalletRpcHost;
  uint16_t    xfgWalletRpcPort = 0;
  std::string xfgWalletRpcUser;
  std::string xfgWalletRpcPass;
};

class SwapDaemon {
public:
  // Construct with only the Fuegod connection.  Chain clients are disabled;
  // processSwap() will log a warning and skip counterparty-chain steps.
  SwapDaemon(const std::string& fuegodHost, uint16_t fuegodPort,
             const std::string& dataDir, Logging::ILogger& logger);

  // Construct with Fuegod connection and counterparty chain RPC config.
  // For any chain whose host is empty the corresponding client is not created.
  SwapDaemon(const std::string& fuegodHost, uint16_t fuegodPort,
             const std::string& dataDir, Logging::ILogger& logger,
             const ChainClientConfig& chainCfg);

  ~SwapDaemon();

  // Load persisted non-terminal swaps, log recovery summary, and start the
  // background tick thread.  Call once after construction.
  // p2pPort: swap peer protocol listen port (0 = disable P2P).
  // p2pBind: bind address (default loopback).
  void start(uint16_t p2pPort = 18901, const std::string& p2pBind = "127.0.0.1");

  // Stop the background tick thread and P2P.  Safe to call multiple times.
  void stop();

  // Send a signed PeerMessage to the swap's peerEndpoint over SwapP2P.
  // Returns false if P2P is down, peerEndpoint empty, or send fails.
  bool deliverPeerMessage(const PeerMessage& msg);

  // Configure wallet RPC endpoint for escrow funding.
  // Must be called before processSwap() can fund escrow.
  void setWalletRpc(const std::string& host, uint16_t port);

  void setSwapRelay(CryptoNote::SwapOfferRelay* relay) { m_swapRelay = relay; }

  // Forward fuegod swap-control token to the RPC client (X-Swap-Token header).
  void setSwapControlToken(const std::string& token) { m_rpc.setSwapControlToken(token); }

  // Set SOCKS5 proxy for P2P transport (e.g. Tor).
  void setSocks5Proxy(const std::string& proxy);

  // Publicly reachable swap P2P endpoint (host:port) advertised to takers in
  // fill results so they can reach this maker for AFK completion messages.
  void setPublicEndpoint(const std::string& endpoint) { m_publicEndpoint = endpoint; }

  void setMakerKeys(const Crypto::SecretKey& sk, const Crypto::PublicKey& pk);
  bool loadOfferConfig(const std::string& jsonPath);

  OfferManager& offerManager() { return *m_offerManager; }

  bool startStatusServer(uint16_t port);

  std::string buildStatusJson();

  // Start a new swap as initiator (Bob: has XFG, wants counterparty coin).
  bool initiate(SwapParams& params);

  // Accept an incoming swap proposal.
  struct AcceptResult {
    bool success;
    std::string warning;
  };
  AcceptResult accept(const std::string& swapId);
  
  // Handle an incoming swap request from a taker for a soft order
  bool handleSwapRequest(const std::string& offerId, uint64_t amount,
                         const std::string& takerPubKey, const std::string& proofOfFunds);

  // Returns active AFK offers that are still valid (>= 1 hour remaining)
  std::vector<SwapStateMachine> getActiveAfkOffers();

  // Scan active swaps and refund any that have timed out.

  bool checkTimeouts();

  // Advance a specific swap to its next state based on chain observations.
  bool processSwap(const std::string& swapId);
  bool processSwap(SwapStateMachine& sm);  // avoids duplicate DB load in tick loop

  // Print a summary of all swaps.
  void listSwaps();

  // Print detailed info about a specific swap.
  void showSwap(const std::string& swapId);

   // Attempt to refund a specific swap (if timeout has elapsed).
   bool refund(const std::string& swapId);

  // Access the price oracle for configuration.
  PriceOracle& priceOracle();

  // Produce an XMR reserve proof via the configured monero-wallet-rpc
  // (taker side; the maker verifies with check_reserve_proof).
  bool getXmrReserveProof(const std::string& address, const std::string& message,
                          std::string& signature);

  // Access the swap database (for RPC server).
  SwapDatabase& database() { return m_db; }
  const SwapDatabase& database() const { return m_db; }

  // Access a chain client for RPC enrichment (null if chain not configured).
  IChainClient* getChainClient(SwapPair pair) const { return m_chainRegistry.getClient(pair); }

 private:
  // Scan non-terminal swaps and warn about any stuck longer than threshold.
  // Called from checkTimeouts().
  void checkStuckSwaps();

  static constexpr int SWAP_STUCK_THRESHOLD_ESCROW_SECS = 1800;  // 30 min
  static constexpr int SWAP_STUCK_THRESHOLD_KEYS_SECS   = 600;   // 10 min

  // Generate a unique swap ID from the current time and random data.
  std::string generateSwapId();

  // Fund the XFG escrow by sending to the Musig2 joint key address.
  // Computes escrow address from params.escrowPubKey, sends XFG via
  // wallet RPC, and stores the resulting tx hash in params.
  // Returns true on success.
  bool fundEscrow(SwapParams& params);

  // Per-state handlers extracted from processSwap for readability
  bool handlePreSigsReady(SwapStateMachine& sm);
  bool handleSecretRevealed(SwapStateMachine& sm);
  bool handleCtrLocked(SwapStateMachine& sm);
  bool handleEscrowFunded(SwapStateMachine& sm, uint32_t currentHeight);
  bool handleWaitingSpv(SwapStateMachine& sm);
  bool handleSecretConfirmedSpv(SwapStateMachine& sm);
  bool handleAfkAccepted(SwapStateMachine& sm);

  // Shared ring-sig finalization logic for ADAPTOR_SECRET_REVEALED and
  // ADAPTOR_SECRET_CONFIRMED_SPV (both perform the same spend flow).
  bool finalizeEscrowSpend(SwapStateMachine& sm, const std::string& logContext);

  // Verify that the escrow funding tx exists and contains an output
  // with the expected amount to the joint escrow key.
  // Returns true if the escrow is confirmed on chain.
  bool verifyEscrowFunding(const SwapParams& params);
  bool resolveEscrowGlobalIndex(SwapParams& params);

  // v11+ direct escrow spends (TransactionInputSwapEscrow). The claim is
  // the completed MuSig2 adaptor aggregate over the deterministic claim tx
  // prefix; the refund is the maker's plain Schnorr signature. Neither
  // requires peer cooperation after funding.
  bool broadcastEscrowClaimDirect(SwapParams& params);
  bool broadcastEscrowRefundDirect(SwapParams& params);

  // The deterministic claim tx prefix hash — the presig session message
  // for v11+ escrow swaps (identical on both sides).
  Crypto::Hash claimSessionMessage(SwapParams& params);

  // The deterministic claim transaction's hash — used by Alice to watch
  // the fuego chain for Bob's XFG claim (XMR pairs reveal their share only
  // after the claim confirms).
  Crypto::Hash deterministicClaimTxHash(SwapParams& params);

  // XMR leg: generate the per-swap XMR keypair once and exchange key
  // material with the peer (XMR_KEYS). Runs from ADAPTOR_KEYS_EXCHANGED.
  bool handleXmrKeyExchange(SwapStateMachine& sm);

  // XMR leg: reveal our spend share to the peer. Alice reveals after the
  // XFG claim is on-chain; Bob reveals after the timeout. Returns true
  // once sent.
  bool revealXmrShare(SwapStateMachine& sm);

  // Save with conflict-retry. saveSwap() now fails when the on-disk record
  // advanced concurrently (P2P writeback between our load and save). For
  // steps with IRREVERSIBLE external side effects (escrow funding already
  // broadcast, spend/refund tx already broadcast), losing the update would
  // cause a double-fund or a re-broadcast. On conflict this reloads the
  // latest record, re-applies our fields via `apply`, and saves again.
  // apply must be idempotent and must capture its inputs BY VALUE (the
  // caller's SwapParams reference may be invalidated by the reload).
  template <typename F>
  bool saveSwapMerged(SwapStateMachine& sm, F&& apply) {
    for (int attempt = 0; attempt < 5; ++attempt) {
      if (m_db.saveSwap(sm)) return true;
      SwapStateMachine latest;
      if (!m_db.loadSwap(sm.params().swapId, latest)) return false;
      apply(latest);
      sm = std::move(latest);
    }
    return false;
  }

  // Returns the resolved XFG address. If input is an alias (@name or short name),
  // resolves via RPC. If already an address, returns as-is. Returns "" on failure.
  std::string resolveAddressOrAlias(const std::string& input);

  // Build an unsigned escrow-spend tx, run collaborative ring sig rounds
  // with the peer, attach the final signature, and broadcast.
  // txType: "spend" (adapted, Bob claims) or "refund" (cooperative, both sign)
  bool buildAndBroadcastEscrowTx(SwapParams& params,
                                 const Crypto::PublicKey& destinationKey,
                                 const std::string& txType);

  // Handle an incoming peer message for an active swap.
  bool handlePeerMessage(const PeerMessage& msg);

  // Feed TWAP/oracle from a completed swap (local authenticated path only).
  void recordCompletedTrade(const SwapStateMachine& sm);

  // Background tick thread — runs checkTimeouts + processSwap every 30 s
  void tickLoop();

  // Inbound SwapP2P callback: payload is serializePeerMessage() JSON.
  void onP2pMessage(const SwapMessage& msg);

  static constexpr int TICK_INTERVAL_SECS = 30;

   FuegoRpcClient m_rpc;
   SwapDatabase m_db;
   PriceOracle m_oracle;
   Logging::LoggerRef m_logger;
   ChainRegistry m_chainRegistry;
   std::unique_ptr<SwapP2P> m_p2p;

    CryptoNote::SwapOfferRelay* m_swapRelay = nullptr;
    std::unique_ptr<OfferManager> m_offerManager;
    std::unique_ptr<StatusServer> m_statusServer;

    Crypto::SecretKey m_makerSecretKey;
    Crypto::PublicKey m_makerPublicKey;
    Crypto::SecretKey m_makerViewSecretKey;
    bool m_makerKeysSet = false;

    // Publicly reachable swap P2P endpoint advertised in AFK fill results.
    std::string m_publicEndpoint;

    std::string m_xfgWalletRpcHost;
    uint16_t m_xfgWalletRpcPort = 0;
    std::string m_xfgWalletRpcUser;
    std::string m_xfgWalletRpcPass;

   struct TakerRecord {
     std::vector<time_t> requestTimes;
     uint32_t failedSwaps = 0;
   };
   std::mutex m_takerMutex;
   std::map<std::string, TakerRecord> m_takerHistory;
   static constexpr uint32_t MAX_TAKER_REQUESTS_PER_HOUR = 5;
   static constexpr uint32_t TAKER_BAN_THRESHOLD = 3;

   bool isTakerRateLimited(const std::string& takerPubKey);
   void recordTakerFailure(const std::string& takerPubKey);

   // Prune stale taker history entries to free memory.
   void pruneTakerHistory();

   // Derive the treasury vault public key from genesis block hash.
   // Result is cached after first successful derivation.
   bool getTreasuryPubKey(Crypto::PublicKey& key);
   Crypto::PublicKey m_treasuryPubKey;
   bool m_treasuryPubKeyCached = false;

   std::thread           m_tickThread;
   std::atomic<bool>     m_running{false};
   std::mutex            m_tickMutex;
    std::condition_variable m_tickCv;

    // SPV header stores for Neutrino clients (must outlive the chain clients)
    std::map<SwapPair, std::shared_ptr<SpvHeaderStore>> m_spvHeaderStores;
};

// Load a ChainClientConfig from a JSON file.
// Returns true on success; sets errorMsg on failure.
bool loadChainClientConfig(const std::string& path,
                            ChainClientConfig& out,
                            std::string& errorMsg);

} // namespace XfgSwap
