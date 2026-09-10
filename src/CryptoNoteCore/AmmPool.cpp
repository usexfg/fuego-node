// Copyright (c) 2017-2026 Fuego Developers
//
// This file is part of Fuego.
//
// Fuego is free software distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See file labeled LICENSE for more details.

#include "AmmPool.h"
#include "Common/Int128.h"
#include "CryptoNoteConfig.h"
#include "../Serialization/SerializationOverloads.h"

namespace CryptoNote {

namespace {
  const uint64_t FEE_DIVISOR = 10000;

  uint64_t isqrt128(uint128_t n) {
    if (n <= 1) return (uint64_t)n;
    uint128_t x = n;
    uint128_t y = (x + 1) >> 1;
    while (y < x) {
      x = y;
      y = (x + n / x) >> 1;
    }
    return (uint64_t)x;
  }
}

uint64_t ammGetOutputAmount(uint64_t inputAmount,
                             uint64_t reserveIn,
                             uint64_t reserveOut,
                             uint32_t feeBps) {
  if (reserveIn == 0 || reserveOut == 0 || inputAmount == 0)
    return 0;

  uint64_t feeAdj = FEE_DIVISOR - feeBps;
  uint128_t num = (uint128_t)reserveOut * inputAmount * feeAdj;
  uint128_t den = (uint128_t)reserveIn * FEE_DIVISOR + (uint128_t)inputAmount * feeAdj;
  return (uint64_t)(num / den);
}

uint64_t ammGetInputAmount(uint64_t outputAmount,
                            uint64_t reserveIn,
                            uint64_t reserveOut,
                            uint32_t feeBps) {
  if (reserveIn == 0 || reserveOut == 0 || outputAmount >= reserveOut)
    return 0;

  uint64_t feeAdj = FEE_DIVISOR - feeBps;
  uint128_t num = (uint128_t)reserveIn * outputAmount * FEE_DIVISOR;
  uint128_t den = (uint128_t)(reserveOut - outputAmount) * feeAdj;
  return (uint64_t)(num / den);
}

uint64_t ammGetSpotPrice(uint64_t reserveA, uint64_t reserveB) {
  if (reserveA == 0) return 0;
  // Canonical price scale: HEAT atomics per XFG atomic × COIN.
  uint128_t scaled = (uint128_t)reserveB * parameters::COIN;
  return (uint64_t)(scaled / reserveA);
}

uint64_t ammMintLpShares(uint64_t amountA, uint64_t amountB,
                          uint64_t totalShares,
                          uint64_t reserveA, uint64_t reserveB) {
  // No single-sided mints: an imbalanced deposit must first be paired at the
  // pool ratio (validation enforces this); single-sided calls mint nothing.
  if (amountA == 0 || amountB == 0) return 0;

  if (totalShares == 0) {
    uint128_t product = (uint128_t)amountA * amountB;
    uint64_t shares = isqrt128(product);
    const uint64_t MIN_LIQUIDITY = 1000;
    return shares > MIN_LIQUIDITY ? shares - MIN_LIQUIDITY : 0;
  }

  // Invariant guard: a live share supply with an empty reserve is invalid state;
  // refuse to mint rather than divide by zero.
  if (reserveA == 0 || reserveB == 0) return 0;

  uint128_t sharesA = (uint128_t)amountA * totalShares / reserveA;
  uint128_t sharesB = (uint128_t)amountB * totalShares / reserveB;
  return sharesA < sharesB ? (uint64_t)sharesA : (uint64_t)sharesB;
}

void ammGetWithdrawalAmounts(uint64_t lpSharesBurned,
                              uint64_t totalShares,
                              uint64_t reserveA, uint64_t reserveB,
                              uint64_t& amountA, uint64_t& amountB) {
  if (totalShares == 0) {
    amountA = 0; amountB = 0;
    return;
  }
  amountA = (uint64_t)((uint128_t)lpSharesBurned * reserveA / totalShares);
  amountB = (uint64_t)((uint128_t)lpSharesBurned * reserveB / totalShares);
}

bool ammValidateSwap(uint64_t input, uint64_t output,
                     uint64_t reserveIn, uint64_t reserveOut,
                     uint32_t feeBps) {
  if (input == 0 || reserveIn == 0 || reserveOut == 0)
    return false;

  uint64_t expected = ammGetOutputAmount(input, reserveIn, reserveOut, feeBps);
  return output > 0 && output <= expected;
}

bool ammValidateInvariant(uint64_t reserveAIn, uint64_t reserveBIn,
                          uint64_t reserveAOut, uint64_t reserveBOut) {
  uint128_t before = (uint128_t)reserveAIn * reserveBIn;
  uint128_t after  = (uint128_t)reserveAOut * reserveBOut;
  // The fee means the post-swap product must never be below the pre-swap
  // product.  Allow at most 8 atomic HEAT rounding loss (two reserve updates,
  // each losing up to 4 units to integer truncation).  The old 0.1%-based
  // tolerance silently accepted pool-draining regressions on large reserves.
  static const uint64_t MAX_ROUNDING_LOSS = 8;
  return after + MAX_ROUNDING_LOSS >= before;
}

bool ammValidateDepositRatio(uint64_t amountA, uint64_t amountB,
                              uint64_t reserveA, uint64_t reserveB,
                              uint32_t toleranceBps) {
  if (reserveA == 0 || reserveB == 0) {
    return false; // pool requires governance bootstrap — no arbitrary first deposit
  }

  uint128_t expectedRatio = (uint128_t)amountA * reserveB;
  uint128_t actualRatio   = (uint128_t)amountB * reserveA;
  uint128_t delta = (expectedRatio > actualRatio) ?
    (expectedRatio - actualRatio) : (actualRatio - expectedRatio);

  uint128_t maxDelta = expectedRatio * (uint64_t)toleranceBps / FEE_DIVISOR;
  return delta <= maxDelta;
}

void AmmPoolState::serialize(ISerializer& s) {
  s(reserveXfg, "reserveXfg");
  s(reserveHeat, "reserveHeat");
  s(totalLpShares, "totalLpShares");
  s(cdHearthFeeAccumulator, "cdHearthFeeAccumulator");
  s(pendingXfg, "pendingXfg");
  s(pendingHeat, "pendingHeat");

  // Migration: read old accumulator fields if present, discard
  uint64_t legacyFees = 0;
  s(legacyFees, "accumulatedLpFeesHeat");
  s(legacyFees, "accumulatedLpFeesXfg");
  s(legacyFees, "accumulatedLpFees");
}

} // namespace CryptoNote
