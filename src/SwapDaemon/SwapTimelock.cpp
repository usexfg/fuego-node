// Copyright (c) 2017-2026 Fuego Developers

#include "SwapTimelock.h"

namespace XfgSwap {

uint64_t msPerBlock(SwapPair pair) {
  switch (pair) {
    case SwapPair::SOL: return 400;      // ~0.4s/slot
    case SwapPair::ETH: return 12000;    // 12s/block
    case SwapPair::XMR: return 120000;   // 120s/block
    case SwapPair::BCH: return 600000;   // 600s/block
    case SwapPair::BTC: return 600000;   // 600s/block
    case SwapPair::LTC: return 150000;   // ~2.5min/block
    case SwapPair::ARB:  return 250;     // ~0.25s/block
    case SwapPair::BASE: return 2000;    // ~2s/block
    case SwapPair::KMD_SPV: return 60000; // ~60s/block
    case SwapPair::BNB: return 3000;     // ~3s/block
    case SwapPair::DCR: return 300000;   // ~5min/block
    case SwapPair::POLYGON: return 2000; // ~2s/block
    case SwapPair::GLEEC: return 5000;   // ~5s/block (Evmos/Tendermint)
    case SwapPair::ROBINHOOD: return 3000; // ~3s/block
    case SwapPair::AVAX: return 2000;    // ~2s/block
    case SwapPair::CRO: return 6000;     // ~6s/block
    case SwapPair::BOB: return 2000;     // ~2s/block (OP Stack)
    case SwapPair::SIA: return 15000;    // ~15s/block
    case SwapPair::UNICHAIN: return 1000; // ~1s/block (OP Stack)
    case SwapPair::PLASMA: return 2000;  // ~2s/block
    case SwapPair::DOGE: return 60000;   // ~60s/block
    case SwapPair::DASH: return 260000;  // ~2.6min/block
    case SwapPair::ZEC:  return 150000;  // ~2.5min/block
    case SwapPair::PULSEX: return 1000;  // ~1s/block
    case SwapPair::ZANO: return 120000;  // ~2min/block
    case SwapPair::TON: return 5000;     // ~5s/block
    case SwapPair::MONAD: return 500;    // ~0.5s/block
    case SwapPair::OPTIMISM: return 2000; // ~2s/block
    case SwapPair::DOT: return 6000;      // ~6s/block (Polkadot relay)
    default:             return 600000;  // conservative default (safe: overestimates CTR)
  }
}

bool timelockOrderingOk(SwapPair pair,
                        uint64_t xfgCurrentHeight,
                        uint64_t xfgTimeoutHeight,
                        uint64_t ctrCurrentHeight,
                        uint64_t ctrTimeoutHeight,
                        uint64_t marginSec) {
  // Guard underflow
  if (xfgTimeoutHeight <= xfgCurrentHeight ||
      ctrTimeoutHeight <= ctrCurrentHeight) {
    return false;
  }

  uint64_t xfgBlocks   = xfgTimeoutHeight - xfgCurrentHeight;
  uint64_t xfgDeadlineMs = xfgBlocks * 480000ULL; // 480s per XFG block

  uint64_t ctrBlocks   = ctrTimeoutHeight - ctrCurrentHeight;
  uint64_t ctrDeadlineMs = ctrBlocks * msPerBlock(pair);

  uint64_t marginMs = marginSec * 1000ULL;

  return xfgDeadlineMs >= ctrDeadlineMs + marginMs;
}

} // namespace XfgSwap
