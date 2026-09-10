# Source Change Log

Every feature/fix requires a task list with sign-off. Agents record name, date, and status when completing work.

---

## Pool-as-Market-Maker: AMM-Backed Auction

**Branch/Feature**: pool-as-market-maker
**Started**: 2026-09-02
**Agent**: opencode/mimo-v2-free (planning phase)
**Status**: IN PROGRESS

### Task List

| # | Task | Owner | Date | Status |
|---|------|-------|------|--------|
| 1 | Inject pool orders into auction vectors | opencode/mimo-v2-free | 2026-09-02 | DONE |
| 2 | Handle pool fills in settlement loop | opencode/mimo-v2-free | 2026-09-02 | DONE |
| 3 | Add circuit breaker before AMM backstop | opencode/mimo-v2-free | 2026-09-02 | DONE |
| 4 | AMM backstop price guard — verified correct (bids: spot ≤ bid, asks: spot ≥ ask) | opencode/mimo-v2-free | 2026-09-02 | DONE |
| 5 | Fix pre-existing build errors (const qualifier, uint128_t include) | opencode/mimo-v2-free | 2026-09-02 | DONE |
| 6 | Build and verify compilation | opencode/mimo-v2-free | 2026-09-03 | DONE |
| 7 | Run fuego-guardian verification | opencode/mimo-v2-free | 2026-09-03 | DONE |

### Sign-Off

| Gate | Signed By | Date | Result |
|------|-----------|------|--------|
| Build compiles | opencode/mimo-v2-free | 2026-09-03 | PASS |
| All tasks complete | opencode/mimo-v2-free | 2026-09-03 | PASS |

---

## Hearth Audit Remediation: LP Rollback, Pool Self-Trade, Matcher Scale

**Branch/Feature**: hearth-audit-fixes
**Started**: 2026-09-09
**Agent**: claude-code/opus-5
**Status**: COMPLETE

Three defects found by a production audit of the Hearth AMM / call auction.
Findings 01 and 02 were reproduced by execution before any change was made.

### Task List

| # | Task | Owner | Date | Status |
|---|------|-------|------|--------|
| 1 | Reproduce LP apply/undo reserve inflation (finding 01) | claude-code/opus-5 | 2026-09-09 | DONE |
| 2 | Reproduce pool two-sided quote suppression (finding 02) | claude-code/opus-5 | 2026-09-09 | DONE |
| 3 | Add `m_blockLpRemoveAmounts` undo journal (Blockchain.h) | claude-code/opus-5 | 2026-09-09 | DONE |
| 4 | Record actual LP-remove deltas at both apply sites (legacy tag + v11 auth) | claude-code/opus-5 | 2026-09-09 | DONE |
| 5 | Consume journal at both undo sites; clamp fallback so a missing record can never inflate | claude-code/opus-5 | 2026-09-09 | DONE |
| 6 | Exempt `0xF0`-prefixed pool orders from self-trade exclusion in `runAuction` | claude-code/opus-5 | 2026-09-09 | DONE |
| 7 | No version gate: v11 is not live, and the auction only runs at v11+, so the exemption is unconditional | claude-code/opus-5 | 2026-09-09 | DONE |
| 8 | Fix `OrderbookMatcher` VWAP to COIN scale with `uint128_t` accumulator (finding 03) | claude-code/opus-5 | 2026-09-09 | DONE |
| 9 | Add `tests/CoreTests/HearthAmmTests.cpp` — 31 assertions (AMM/LP gap; auction already covered by `OrderbookAuctionTest.cpp`) | claude-code/opus-5 | 2026-09-09 | DONE |
| 10 | Register `test_hearth_amm` target alongside the existing CoreTests | claude-code/opus-5 | 2026-09-09 | DONE |
| 11 | Verify no regression: `test_orderbook_auction` 57/57, `test_orderbook` 44/44, `core_tests` 164/164 | claude-code/opus-5 | 2026-09-09 | DONE |

### Notes

- Finding 01 is applied **unconditionally, without a version gate**. The forward
  path is unchanged; only the undo is corrected. `rebuildCache()` replays every
  block through `pushTransaction` with no pops, so a freshly synced node already
  produces the corrected state — the fix makes reorged nodes agree with it
  rather than diverge.
- Finding 02 needs no version gate. v11 is not live, and `runAuction()` is only
  reached from the `majorVersion >= BLOCK_MAJOR_VERSION_11` branch, so no
  already-accepted block is affected. An `exemptPoolOrders` flag was added first
  and then removed once that was established — it was provably always true.
- `OrderbookMatcher::match()` has no production callers (the live path is
  `runAuction()`), but it is **not** dead code: `OrderbookTest.cpp`,
  `Phase3_OrderbookTest.cpp` and `Phase5_AdversarialTests.cpp` exercise it
  across ~20 cases. Kept and corrected, not deleted.
- Correction to the audit: the claim that the subsystem had no tests was wrong.
  `tests/CoreTests/` is wired in via `src/CMakeLists.txt` and already covers the
  auction (rationing, tie-breaks, self-trade exclusion, fee conservation). The
  real gap was AMM reserve math and LP share accounting, which is what
  `HearthAmmTests.cpp` adds.
- Pre-existing, unrelated: `test_p2p_orderbook` fails 4/61 in
  `SwapOrderbookTests.cpp:425-428` (default-constructed `SwapOrder` field
  defaults). Untouched by this work.

### Sign-Off

| Gate | Signed By | Date | Result |
|------|-----------|------|--------|
| Build compiles (CryptoNoteCore, Daemon, SimpleWallet) | claude-code/opus-5 | 2026-09-09 | PASS |
| Tests pass (test_hearth_amm 31/31; auction 57/57; orderbook 44/44; core 164/164) | claude-code/opus-5 | 2026-09-09 | PASS |
| All tasks complete | claude-code/opus-5 | 2026-09-09 | PASS |

---

## Production-Quality Pass: Auction Scaling, Naming, Latent UB

**Branch/Feature**: hearth-production-quality
**Started**: 2026-09-09
**Agent**: claude-code/opus-5
**Status**: COMPLETE

Remaining audit findings (05, 06) plus defects found while reviewing the
in-flight working tree.

### Task List

| # | Task | Owner | Date | Status |
|---|------|-------|------|--------|
| 1 | Replace quadratic self-trade scan in `runAuction` with keyed lookup (finding 06) | claude-code/opus-5 | 2026-09-09 | DONE |
| 2 | Rename `HEARTH_CD_SHARE_BPS` → `_PCT`: it holds a percentage and is divided by 100 (finding 05) | claude-code/opus-5 | 2026-09-09 | DONE |
| 3 | Fix unbounded growth of `OrderbookIndex` depth maps (drained levels never erased) | claude-code/opus-5 | 2026-09-09 | DONE |
| 4 | Default-initialize `SwapOrder` members — reading them was UB | claude-code/opus-5 | 2026-09-09 | DONE |
| 5 | Pin CD interest compounding in `TreasuryCoreTests` (was uncovered money math) | claude-code/opus-5 | 2026-09-09 | DONE |
| 6 | Restore stray indentation in `Currency::calculateCdInterest` | claude-code/opus-5 | 2026-09-09 | DONE |

### Notes

- Finding 06: the self-trade pass resolved each order's address by linear scan
  over an accumulating vector, making it quadratic in order count on
  attacker-influenceable mempool input. Now a keyed map. Measured at 4000
  orders/side: **93.0 ms → 2.1 ms**, and scaling is linear rather than
  quadratic. Results are unchanged — the container is only ever looked up by
  key, and the existing 57 auction assertions still pass.
- `SwapOrder` had no default member initializers, so `SwapOrder o;` left
  `price`, `amount`, `filled` and `nonce` indeterminate. `PriceLevel::totalDepth()`
  computes `amount - filled`, which would underflow on garbage. This was the
  cause of the 4 pre-existing `test_p2p_orderbook` failures; that suite is now
  61/61.
- CD interest compounding was verified empirically before being pinned: 1000 over
  6 epochs at 10% yields 771 (compounding) rather than 600 (simple). This is a
  behavioural change from the previous simple-interest path and is now asserted
  so it cannot drift silently.

### Sign-Off

| Gate | Signed By | Date | Result |
|------|-----------|------|--------|
| Build compiles (CryptoNoteCore, Daemon, SimpleWallet) | claude-code/opus-5 | 2026-09-09 | PASS |
| Tests pass (hearth 31/31, auction 57/57, orderbook 44/44, p2p 61/61, core 170/170) | claude-code/opus-5 | 2026-09-09 | PASS |
| All tasks complete | claude-code/opus-5 | 2026-09-09 | PASS |
