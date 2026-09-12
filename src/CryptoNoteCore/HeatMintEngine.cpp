// Copyright (c) 2017-2026 Fuego Developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See file labeled LICENSE for more details.

#include "HeatMintEngine.h"
#include "CryptoNoteConfig.h"
#include "Common/Int128.h"
#include <cstdio>

namespace CryptoNote {

namespace {

// expectedHeat = xfgBurned × price / COIN, price = HEAT atomics per XFG atomic × COIN.
uint64_t expectedHeatFor(uint64_t xfgBurned, uint64_t price) {
  return static_cast<uint64_t>(((uint128_t)xfgBurned * price) / parameters::COIN);
}

// Scan a mint tx: sum XFG inputs, XFG outputs, HEAT outputs; verify conservation.
// Returns false on structural failure. Shared by legacy and v12 validation paths.
bool scanMintTx(const Transaction& tx, uint64_t fee,
                uint64_t& xfgInputs, uint64_t& xfgOutputs,
                uint64_t& heatOutputs, uint64_t& xfgBurned) {
  xfgInputs = 0;
  xfgOutputs = 0;
  heatOutputs = 0;

  for (const auto& in : tx.inputs) {
    if (in.type() == typeid(KeyInput)) {
      xfgInputs += boost::get<KeyInput>(in).amount;
    } else if (in.type() == typeid(TransactionInputCommitmentSpend)) {
      xfgInputs += boost::get<TransactionInputCommitmentSpend>(in).amount;
    } else if (in.type() == typeid(TransactionInputCommitmentTransfer)) {
      // CommitmentTransfer inputs are not a valid XFG burn source.
      // Allowing them without counting their value would break supply conservation.
      return false;
    }
  }

  for (const auto& out : tx.outputs) {
    if (out.target.type() == typeid(TransactionOutputCommitment)) {
      const auto& commitment = boost::get<TransactionOutputCommitment>(out.target);
      if (commitment.term == parameters::HEAT_TERM) {
        heatOutputs += out.amount;
      } else {
        xfgOutputs += out.amount;
      }
    } else {
      xfgOutputs += out.amount;
    }
  }

  if (heatOutputs == 0) return false;
  if (xfgInputs < xfgOutputs + fee) return false;

  xfgBurned = xfgInputs - xfgOutputs - fee;
  return true;
}

} // anonymous namespace

HeatMintEngine::HeatMintEngine() {
  setbuf(stderr, NULL);
}

bool HeatMintEngine::isHeatMint(const Transaction& tx) const {
  for (const auto& out : tx.outputs) {
    if (out.target.type() == typeid(TransactionOutputCommitment)) {
      const auto& commitment = boost::get<TransactionOutputCommitment>(out.target);
      if (out.amount > 0 && commitment.term == parameters::HEAT_TERM)
        return true;
    }
  }
  return false;
}

bool HeatMintEngine::validateMint(const Transaction& tx,
                                    uint64_t fee,
                                    uint64_t price,
                                    uint64_t& xfgBurned,
                                    uint64_t& heatMinted) const {
  xfgBurned = 0;
  heatMinted = 0;

  if (price == 0) {
#ifdef HEAT_MINT_DEBUG
    fprintf(stderr, "[HeatMint] validateMint FAIL: price is zero\n");
#endif
    return false;
  }

  uint64_t xfgInputs = 0, xfgOutputs = 0, heatOutputs = 0;
  if (!scanMintTx(tx, fee, xfgInputs, xfgOutputs, heatOutputs, xfgBurned)) {
#ifdef HEAT_MINT_DEBUG
    fprintf(stderr, "[HeatMint] validateMint FAIL: structural (inputs=%llu outputs=%llu heat=%llu fee=%llu)\n",
      (unsigned long long)xfgInputs, (unsigned long long)xfgOutputs,
      (unsigned long long)heatOutputs, (unsigned long long)fee);
#endif
    return false;
  }

  uint64_t expectedHeat = expectedHeatFor(xfgBurned, price);

#ifdef HEAT_MINT_DEBUG
  fprintf(stderr, "[HeatMint] validateMint: xfgBurned=%llu expectedHeat=%llu price=%llu heatOutputs=%llu\n",
    (unsigned long long)xfgBurned, (unsigned long long)expectedHeat,
    (unsigned long long)price, (unsigned long long)heatOutputs);
#endif

  if (heatOutputs > expectedHeat) return false;

  heatMinted = heatOutputs;
  return true;
}

bool HeatMintEngine::validateMintAuth(const Transaction& tx,
                                        uint64_t fee,
                                        uint64_t price,
                                        uint64_t xfgBurned,
                                        uint64_t heatMinted) const {
  if (price == 0) return false;
  if (xfgBurned == 0 || heatMinted == 0) return false;

  uint64_t actualXfgBurned = 0, actualHeatMinted = 0;
  if (!validateMint(tx, fee, price, actualXfgBurned, actualHeatMinted)) return false;

  if (actualXfgBurned < xfgBurned) return false;
  if (actualHeatMinted != heatMinted) return false;

  uint64_t expectedHeat = expectedHeatFor(actualXfgBurned, price);
  if (heatMinted > expectedHeat) return false;

  return true;
}

// ── Legacy pre-v12 paths (Q64.64 XFG-per-HEAT) — bit-identical to original ──

bool HeatMintEngine::validateMint(const Transaction& tx,
                                    uint64_t fee,
                                    FixedPoint64 redemptionPrice,
                                    uint64_t& xfgBurned,
                                    uint64_t& heatMinted) const {
  xfgBurned = 0;
  heatMinted = 0;

  if (redemptionPrice.isZero()) {
#ifdef HEAT_MINT_DEBUG
    fprintf(stderr, "[HeatMint] validateMint FAIL: redemptionPrice is zero\n");
#endif
    return false;
  }

  uint64_t xfgInputs = 0, xfgOutputs = 0, heatOutputs = 0;
  if (!scanMintTx(tx, fee, xfgInputs, xfgOutputs, heatOutputs, xfgBurned)) {
    return false;
  }

  FixedPoint64 xfgFp = FixedPoint64::fromUint64(xfgBurned);
  FixedPoint64 heatFp = xfgFp.div(redemptionPrice);
  uint64_t expectedHeat = heatFp.toUint64();

  if (heatOutputs > expectedHeat) return false;

  heatMinted = heatOutputs;
  return true;
}

bool HeatMintEngine::validateMintAuth(const Transaction& tx,
                                        uint64_t fee,
                                        FixedPoint64 redemptionPrice,
                                        uint64_t xfgBurned,
                                        uint64_t heatMinted) const {
  if (redemptionPrice.isZero()) return false;
  if (xfgBurned == 0 || heatMinted == 0) return false;

  uint64_t actualXfgBurned = 0, actualHeatMinted = 0;
  if (!validateMint(tx, fee, redemptionPrice, actualXfgBurned, actualHeatMinted)) return false;

  if (actualXfgBurned < xfgBurned) return false;
  if (actualHeatMinted != heatMinted) return false;

  FixedPoint64 xfgFp = FixedPoint64::fromUint64(actualXfgBurned);
  uint64_t expectedHeat = xfgFp.div(redemptionPrice).toUint64();
  if (heatMinted > expectedHeat) return false;

  return true;
}

} // namespace CryptoNote
