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

---

## Atomic-Swap Security Fixes: adaptor identity, timeout floor, transfer brick, cross-curve gate

**Branch/Feature**: swap-security-fixes
**Started**: 2026-09-09
**Agent**: claude-code/sonnet-5
**Status**: CODE COMPLETE — full build + test pass PENDING (no C++ build in review env)

Five findings from the module-by-module swap audit
(`docs/review/2026-09-09-swap-security-audit.md`). Fixes are minimal and, where
they change a fund path, fail toward current behaviour rather than stricter.

### Task List

| # | Task | Owner | Date | Status |
|---|------|-------|------|--------|
| 1 | AUDIT 1.2/3.2 — `AdaptorSwap.cpp::adaptor_extract_secret` verifies `t*G == params.adaptorPoint` (and `t != 0`), wipes on mismatch | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 2 | AUDIT 1.2/3.2 — `secp_adaptor_extract` rejects `t == 0`; new 4-arg overload verifies `t*G == T`; header + note | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 3 | AUDIT 3.9 — `SwapDaemon.cpp` gates pure-secp PTLC behind `kCrossCurveDleqAvailable=false` until a real Ed25519↔secp256k1 DLEQ exists (BRIDGE path unaffected) | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 4 | AUDIT 6.1 — `EthRpcClient::verifyLock`/`verifyPointLock` take `minTimeoutBlock` (0 = skip); `EthChainClient::verifyLock` computes it from tip + confirmations + a per-chain ~1h floor via `msPerBlock()` | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 5 | AUDIT 6.2 — `HashedTimelock.sol` + `PointTimelock.sol` pay out with `.call{value:}` + `require(ok)` + `nonReentrant` instead of `.transfer` (2300-gas brick) | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 6 | AUDIT 6.7 — `PtlcTimelockPure.sol` strict mode enforces `(s - s')*G == T` on-chain (new `sPrime` param, `ptlcPointY` stored); also fixed pre-existing compile blockers (`TimeoutNotReached` undeclared, `bytes memory` range-slice); marked `@custom:staged` / not deployable | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 7 | `forge test` — existing PointTimelock suite 12/12 PASS after the 6.2 change | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 8 | `g++ -fsyntax-only` on every touched C++ TU — all parse clean | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 9 | AUDIT 2.1 — `Currency::calculateInterest` simplified to `return 0` (legacy XFG term-deposit interest is intentionally 0; all yield is HEAT CDs; no legacy-bond path). Verified against `getTransactionInputAmount` (input valued at principal → principal-minus-fee withdrawal passes conservation), `Blockchain::validateInput` (maturity + double-spend enforced independently), banking-index emission accounting (`Blockchain.cpp:1044`), and the vestigial legacy-bond removal branch (`Blockchain.cpp:4177`). Wallet callers use it for display only. | claude-code/sonnet-5 | 2026-09-09 | DONE |
| 10 | Full SwapDaemon + CryptoNoteCore build + swap/core test suite | claude-code/opus-5 | 2026-09-10 | DONE — Daemon/SimpleWallet/SwapDaemonLib build clean; 10 C++ suites + forge all green |
| 11 | Regression test: contract-wallet recipient can now claim (6.2); timeout-too-soon lock is rejected (6.1); wrong-`t` extract fails (1.2); matured legacy multisig deposit still withdraws for principal (2.1) | claude-code/opus-5 | 2026-09-10 | DONE — see notes below |

### Notes

- **3.9 is a gate, not a primitive.** A genuine cross-group DLEQ
  (Ed25519↔secp256k1) is a separately-reviewed deliverable; shipping a
  hand-rolled one into a fund path unverified would be worse than the
  documented gap. `FEATURE_PURE_PTLC` now has no effect until
  `kCrossCurveDleqAvailable` flips. `PTLC_HTLC_BRIDGE` (on-chain hashlock) is
  the live PTLC path and is untouched.
- **6.7 is on a staged contract.** `PtlcTimelockPure.sol` targets draft
  EIP-6601 precompiles (not live anywhere) and `supportsPurePtlc()` is false,
  so no swap uses it. The live EVM PTLC contract, `PointTimelock.sol`, already
  proves `t*G == T` via the ecrecover trick — its adaptor identity was never
  the gap.
- **6.1 fails safe.** If the ETH tip RPC is unavailable, `minTimeoutBlock`
  stays 0 and the timeout check is skipped — identical to pre-fix behaviour,
  never stricter by accident. The floor is time-based (~1h) converted through
  `msPerBlock(params.pair)` so it scales across ETH and the fast L2s that
  share the `HashedTimelock` ABI.
- The BTC/BCH/DCR UTXO `verifyLock` paths were reviewed for the same 6.1 gap
  and appear safe *because* they recompute the expected P2SH/P2WSH redeem
  script (timeout included) and match the hash, rather than trusting decoded
  fields — but each chain client's script reconstruction should be confirmed.

### Sign-Off

| Gate | Signed By | Date | Result |
|------|-----------|------|--------|
| Solidity builds (HashedTimelock, PointTimelock) | claude-code/sonnet-5 | 2026-09-09 | PASS |
| forge test (PointTimelock 12/12) | claude-code/sonnet-5 | 2026-09-09 | PASS |
| C++ syntax check (all touched TUs, -fsyntax-only) | claude-code/sonnet-5 | 2026-09-09 | PASS |
| Full C++ build (SwapDaemon) | — | — | NOT RUN (no build env) |
| Swap test suite | — | — | NOT RUN |
| All tasks complete | claude-code/sonnet-5 | 2026-09-09 | PARTIAL (tasks 9–10 pending) |

---

## Swap Audit Regression Coverage

**Agent**: claude-code/opus-5 · **Date**: 2026-09-10 · **Status**: COMPLETE

Closes rows 10 and 11 of the swap security audit, which it could not run itself
("PENDING — run in build env"); it had only done `-fsyntax-only`.

| Finding | Test | Location |
|---------|------|----------|
| 1.2 / 3.2 | Extraction refuses a scalar that does not open the published adaptor point, and rejects a cross-session presig/sig pair; the 3-arg form's weaker `t != 0` contract is pinned alongside it | `src/SwapDaemon/tests/test_swap_audit_regressions.cpp` |
| 6.1 | Timeout floor spans ≥1h of blocks on every supported chain and never falls under the 30-block floor; 1-block, confirmations-only and one-short timeouts are rejected, the exact floor is accepted, and `minTimeoutBlock == 0` still fails open | same file |
| 6.2 | A contract wallet whose `receive()` costs ~20k gas can claim (and refund) — impossible under the old `.transfer` stipend; a reentrant recipient gets exactly one payout | `contracts/point-timelock/test/PointTimelock.t.sol` |
| 2.1 | `calculateInterest` is 0 at every term/height including the old early-deposit window, and a matured term deposit is still valued at exactly its principal, so withdrawal conservation holds | `tests/CoreTests/TreasuryCoreTests.cpp` |

### Sign-Off

| Gate | Signed By | Date | Result |
|------|-----------|------|--------|
| Build compiles (Daemon, SimpleWallet, SwapDaemonLib) | claude-code/opus-5 | 2026-09-10 | PASS |
| C++ suites (10) — hearth 31, auction 57, orderbook 44, p2p 61, core 177, gates 19, audit-regressions 22, + phase3/phase5/adaptor | claude-code/opus-5 | 2026-09-10 | PASS |
| Solidity (forge) — PointTimelock 15/15 | claude-code/opus-5 | 2026-09-10 | PASS |
| All tasks complete | claude-code/opus-5 | 2026-09-10 | PASS |

---

## AUDIT 1.8 — DLEQ Transcript Binding + Inert Small-Order Check

**Agent**: claude-code/opus-5 · **Date**: 2026-09-10 · **Status**: COMPLETE
**Scope note**: this closes 1.8, the documented root of 3.9. **3.9 itself
remains OPEN** — see below.

### Task List

| # | Task | Owner | Date | Status |
|---|------|-------|------|--------|
| 1 | Bind every DLEQ proof to a per-swap 32-byte context hashed into the challenge | claude-code/opus-5 | 2026-09-10 | DONE |
| 2 | Derive that context from `swapId`; refuse an empty id rather than share one context | claude-code/opus-5 | 2026-09-10 | DONE |
| 3 | Validate `base_point`, `A` and `B` prover-side (previously A/B were hashed as opaque bytes) | claude-code/opus-5 | 2026-09-10 | DONE |
| 4 | Reject a zero / out-of-range secret instead of emitting an unverifiable proof | claude-code/opus-5 | 2026-09-10 | DONE |
| 5 | Fix `point_is_valid` in `dleq.cpp` and `adaptor.cpp` — the small-order check was inert | claude-code/opus-5 | 2026-09-10 | DONE |
| 6 | `static_assert` the challenge preimage layout (finding 1.6 class of bug) | claude-code/opus-5 | 2026-09-10 | DONE |
| 7 | Regression tests: cross-swap replay rejected, identity/zero rejected, legitimate flow intact | claude-code/opus-5 | 2026-09-10 | DONE |

### `point_is_valid` was accepting everything

Both `dleq.cpp` and `adaptor.cpp` computed `8*P` and rejected the point only if
the encoding was 32 zero bytes. The Ed25519 neutral element encodes as
`{0x01, 0x00 ... 0x00}`, and **no** valid point encodes to all-zero, so the
comparison could never fire: every decodable point passed, including the
identity and the 8-torsion points. The cofactor check the audit credited these
files with (finding 1.3 cites them as the example MuSig2 should follow) was
doing nothing. Now compares against the neutral encoding.

### Wire compatibility

The challenge preimage gained a 32-byte context, so proofs do not verify across
builds. The swap protocol has no version negotiation, so **both peers must run
the same build**. Acceptable now because the affected path (PTLC_HTLC_BRIDGE) is
Phase 1 and pure PTLC is gated off.

### 3.9 remains OPEN

3.9 needs a genuine Ed25519↔secp256k1 cross-group DLEQ. `crypto/dleq.cpp` is
Chaum-Pedersen on Ed25519 — both `A = x*G` and `B = x*P` are Ed25519 points, so
it cannot bind a secp256k1 point no matter how it is hardened. A real
construction (per-bit Pedersen commitments on both curves plus OR-proofs, à la
Gugger 2020) is a separate, reviewable piece of work.
`kCrossCurveDleqAvailable` stays `false`.

### Sign-Off

| Gate | Signed By | Date | Result |
|------|-----------|------|--------|
| Build compiles (Daemon, SimpleWallet, SwapDaemonLib) | claude-code/opus-5 | 2026-09-10 | PASS |
| 14 suites, 0 failures (audit-regressions 37/37, core 177/177) | claude-code/opus-5 | 2026-09-10 | PASS |
| 3.9 closed | — | — | NO — remains OPEN by design |
