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

#include <string>
#include <cstdint>
#include <vector>
#include <array>

namespace XfgSwap {

enum class EthTxType : uint8_t { Legacy = 0, Eip1559 = 2 };

struct EthTxReceipt {
  std::string txHash;
  std::string contractAddress;
  uint64_t blockNumber;
  bool success;            // status == 1
  uint64_t gasUsed;
};

class EthRpcClient {
public:
  // Construct with JSON-RPC endpoint.
  EthRpcClient(const std::string& host, uint16_t port);

  // Construct with JSON-RPC endpoint + signer credentials.
  // privKeyHex: 64-char hex of the 32-byte secp256k1 private key.
  // signerAddress: "0x..." Ethereum address derived from privKeyHex (caller must
  //   derive and supply; see Secp256k1Signer::derivePublicKey + keccak256(pubkey[1..]).
  // chainId: EIP-155 chain ID (1 = mainnet, 11155111 = Sepolia, etc.).
  // txType: EIP-1559 (default) or Legacy.
  EthRpcClient(const std::string& host, uint16_t port,
               const std::string& privKeyHex,
               const std::string& signerAddress,
               uint64_t chainId,
               EthTxType txType = EthTxType::Eip1559);

  ~EthRpcClient() { closeSocket(); clear(); }

  // Basic queries
  bool getBlockNumber(uint64_t& blockNum);
  bool getBalance(const std::string& address, uint64_t& balanceWei);
  bool getTransactionReceipt(const std::string& txHash, EthTxReceipt& receipt);
  bool getNonce(const std::string& address, uint64_t& nonce);

  // Contract interaction
  // Deploy the HashedTimelock contract (returns tx hash)
  bool deployContract(const std::string& fromAddress,
                      const std::string& bytecode,
                      uint64_t gasLimit,
                      std::string& txHash);

  // Call a contract method (state-changing; signs and broadcasts raw tx)
  bool sendTransaction(const std::string& from, const std::string& to,
                       const std::string& data, uint64_t value,
                       uint64_t gasLimit, std::string& txHash);

  bool callContract(const std::string& to, const std::string& data, std::string& result);

  // Send raw signed transaction
  bool sendRawTransaction(const std::string& signedTxHex, std::string& txHash);

  // ─── HTLC operations (HashedTimelock.sol registry model) ─────────────────
  //
  // The contract is deployed once. Each lock is a payable lock() call that
  // returns contractId = keccak256(sender, recipient, amount, hashLock, timeout).
  // claim/refund take that contractId (NOT the registry address as id).

  // Set the pre-deployed HashedTimelock registry address ("0x...").
  void setHtlcRegistry(const std::string& registryAddress) { m_htlcRegistry = registryAddress; }
  const std::string& htlcRegistry() const { return m_htlcRegistry; }

  // Set the pre-deployed PointTimelock registry address ("0x...").
  // Pure PTLC (EVM side): locks keyed by a secp256k1 point address instead of
  // H(t). Empty => pure PTLC unavailable and the chain stays BRIDGE (HTLC).
  void setPtlcRegistry(const std::string& registryAddress) { m_ptlcRegistry = registryAddress; }
  const std::string& ptlcRegistry() const { return m_ptlcRegistry; }

  // Optional: bytecode for one-time factory deploy (legacy path; lock uses registry).
  void setHtlcBytecode(const std::string& bytecodeHex) { m_htlcBytecode = bytecodeHex; }

  // Compute contractId = keccak256(abi.encodePacked(sender, recipient, value, hashLock, timeout))
  // matching Solidity HashedTimelock.lock().
  static std::string computeContractId(const std::string& sender,
                                       const std::string& recipient,
                                       uint64_t valueWei,
                                       const std::string& hashLockHex,
                                       uint64_t timeoutBlock);

  // Call lock() on the registry; on success sets contractIdHex (64 hex chars).
  bool lockHtlc(const std::string& fromAddress,
                const std::string& recipientAddress,
                const std::string& hashLockHex,
                uint64_t timeoutBlock,
                uint64_t valueWei,
                std::string& contractIdHex);

  // verify via getContract(contractId): amount, recipient, hashLock, not claimed/refunded.
  // AUDIT 6.1: minTimeoutBlock (0 = skip) rejects a counterparty lock whose
  // on-chain timeout is too near — otherwise they can refund before we can
  // safely claim after revealing / locking our side.
  bool verifyLock(const std::string& contractIdHex,
                  uint64_t expectedWei,
                  const std::string& expectedRecipient = "",
                  const std::string& expectedHashLockHex = "",
                  uint64_t minTimeoutBlock = 0);

  // If claimed, returns 64-char hex preimage; empty if not claimed / error.
  std::string getClaimedPreimage(const std::string& contractIdHex);

  // ─── PointTimelock operations (PointTimelock.sol registry model) ──────────
  //
  // Same registry-deployment model as the HTLC path, but locks are keyed by
  // a secp256k1 point address instead of a hash lock. The claim secret is the
  // CryptoNote scalar t in canonical BIG-endian form (byte-reversed CryptoNote
  // LE storage) — see PointTimelock.sol claim() and ContractAbi endianness rule.

  // Compute contractId = keccak256(abi.encodePacked(sender, recipient, value,
  // pointAddress, timeoutBlock)) matching Solidity PointTimelock.lock().
  static std::string computePointContractId(const std::string& sender,
                                            const std::string& recipient,
                                            uint64_t valueWei,
                                            const std::string& pointAddress,
                                            uint64_t timeoutBlock);

  // Call lock() on the PointTimelock registry; on success sets contractIdHex.
  bool lockPoint(const std::string& fromAddress,
                 const std::string& recipientAddress,
                 const std::string& pointAddress,
                 uint64_t timeoutBlock,
                 uint64_t valueWei,
                 std::string& contractIdHex);

  // Verify via getContract(contractId): amount, recipient, pointAddress,
  // not claimed/refunded. Empty expected* args skip that comparison.
  // AUDIT 6.1: minTimeoutBlock (0 = skip) — see verifyLock().
  bool verifyPointLock(const std::string& contractIdHex,
                       uint64_t expectedWei,
                       const std::string& expectedRecipient = "",
                       const std::string& expectedPointAddress = "",
                       uint64_t minTimeoutBlock = 0);

  // If claimed, returns 64-char hex of the canonical big-endian scalar t;
  // empty if not claimed / error.
  std::string getClaimedPointSecret(const std::string& contractIdHex);

  // Claim ETH: claim(contractId, preimage) on the HashedTimelock registry.
  bool claimHtlc(const std::string& fromAddress,
                 const std::string& contractIdHex,
                 const std::string& preimageHex,
                 std::string& claimTxHash);

  // Claim ETH via PointTimelock: claim(contractId, secret) on the
  // PointTimelock registry. secretHex32 is the canonical BIG-endian scalar t
  // (byte-reversed CryptoNote LE storage — see ContractAbi endian rule).
  bool claimPoint(const std::string& fromAddress,
                  const std::string& contractIdHex,
                  const std::string& secretHex32,
                  std::string& claimTxHash);

  // Refund ETH after timeout: refund(contractId) on the registry.
  bool refundHtlc(const std::string& fromAddress,
                   const std::string& contractIdHex,
                   std::string& refundTxHash);

  // Refund ETH after timeout via PointTimelock: refund(contractId) on the
  // PointTimelock registry (same selector as the HTLC path).
  bool refundPoint(const std::string& fromAddress,
                   const std::string& contractIdHex,
                   std::string& refundTxHash);

  // Legacy name kept for callers still wiring bytecode-only deploys.
  bool deployHtlc(const std::string& fromAddress,
                  const std::string& recipientAddress,
                  const std::string& hashLockHex,
                  uint64_t timeoutBlock,
                  uint64_t valueWei,
                  std::string& contractAddressOrId);

  // Estimate gas for a transaction (eth_estimateGas).
  bool estimateGas(const std::string& to, const std::string& data,
                   uint64_t valueWei, uint64_t& gasEstimate);

private:
  std::string httpPost(const std::string& path, const std::string& body);
  std::string jsonRpc(const std::string& method, const std::string& params);

  // Sign an EIP-155 transaction and broadcast it via eth_sendRawTransaction.
  // to: 20-byte address (empty for contract deploy).
  // data: calldata bytes.
  // valueWei: ETH value to send.
  // gasLimit: gas limit.
  // Returns the tx hash on success.
  // Throws std::runtime_error if the signer private key is not configured.
  bool signAndSend(const std::vector<uint8_t>& to,
                   const std::vector<uint8_t>& data,
                   uint64_t valueWei,
                   uint64_t gasLimit,
                   std::string& txHash);

  // Build a signed raw EIP-155 (type-0) transaction.
  std::vector<uint8_t> buildLegacySignedTx(uint64_t nonce,
                                           uint64_t gasPriceWei,
                                           uint64_t gasLimit,
                                           const std::vector<uint8_t>& to,
                                           uint64_t valueWei,
                                           const std::vector<uint8_t>& data);

  // Build a signed raw EIP-1559 (type-2) transaction.
  std::vector<uint8_t> buildEip1559SignedTx(uint64_t nonce,
                                            uint64_t maxPriorityFeePerGas,
                                            uint64_t maxFeePerGas,
                                            uint64_t gasLimit,
                                            const std::vector<uint8_t>& to,
                                            uint64_t valueWei,
                                            const std::vector<uint8_t>& data);

  // Estimate dynamic fees for EIP-1559.
  bool estimateFees(uint64_t& maxPriorityFeePerGas, uint64_t& maxFeePerGas);

  // Query eth_gasPrice for legacy (type-0) transactions.
  // Returns false if the RPC call fails; caller should use m_gasPriceFallback.
  bool queryGasPrice(uint64_t& gasPriceWei);

  std::string m_host;
  uint16_t    m_port;

  // Signing credentials — empty if not configured.
  std::array<uint8_t, 32> m_privKey;   // zeroed if not configured
  std::string              m_signerAddress;
  uint64_t                 m_chainId = 0;
  bool                     m_hasSigner = false;

  // Pre-compiled HTLC contract bytecode (hex, no 0x prefix) — optional.
  std::string m_htlcBytecode;
  // Pre-deployed HashedTimelock registry address ("0x..." + 40 hex).
  std::string m_htlcRegistry;
  // Pre-deployed PointTimelock registry address ("0x..." + 40 hex).
  // Empty => pure PTLC routing disabled (BRIDGE fallback at negotiation).
  std::string m_ptlcRegistry;

  // Transaction type: EIP-1559 (default) or Legacy.
  EthTxType m_txType = EthTxType::Eip1559;

  // Fallback gas price for legacy transactions (wei).
  // Used when eth_gasPrice RPC call fails.
  uint64_t m_gasPriceFallback = 20000000000ULL; // 20 gwei

  // Persistent HTTP connection (keep-alive).  -1 if not connected.
  // Reused across RPC calls, reconnected on failure.
  int m_sock = -1;
  std::string m_sockHost;
  uint16_t    m_sockPort = 0;

  // Internal: connect or reconnect to the RPC host.
  bool connectSocket();
  void closeSocket();
  void clear();
};

} // namespace XfgSwap
