# Fuego Suite — Security Audit (swap system focus)

**Date:** 2026-09-09
**Reviewer:** claude-code/sonnet-5 (module-by-module static review)
**Tree:** `master` @ `37bf331b` + working-tree changes
**Method:** read-only static analysis, module by module. No fuzzing, no dynamic
analysis, no full build. Upstream CryptoNote/Monero primitives (crypto-ops,
slow-hash, keccak/blake/groestl/jh/skein, oaes, Levin) treated as inherited and
not line-audited. Findings are ranked by exploitability, not by blast radius
alone.

Severity: 🔴 HIGH (fund loss / consensus split / key disclosure, plausible
trigger) · 🟠 MEDIUM (fund loss or DoS under a constrained condition, or a
soundness gap mitigated only by discipline) · 🟡 LOW (hardening, hygiene,
latent).

---

## 1. Status summary

### Fixed this session (`swap-security-fixes`, see `CHANGELOG.agent.md`)

| ID | Module | Finding | Fix |
|----|--------|---------|-----|
| 1.2 / 3.2 | crypto / swap | `extract_secret` never checks the recovered `t` opens the published adaptor point `T` | `adaptor_extract_secret` now verifies `t·G == params.adaptorPoint` (Ed25519); `secp_adaptor_extract` rejects `t==0` and gains a 4-arg overload that checks `t·G == T` |
| 3.9 | crypto / swap | No genuine Ed25519↔secp256k1 cross-curve DLEQ; the pure-secp PTLC path binds ETH to an unprovable point | Pure PTLC gated behind `kCrossCurveDleqAvailable=false` in `SwapDaemon.cpp` until a reviewed DLEQ exists; `PTLC_HTLC_BRIDGE` unaffected |
| 6.1 | contracts / swap | `EthRpcClient::verifyLock` ignores the counterparty lock's on-chain `timeoutBlock` → 1-block-timeout grief | `verifyLock`/`verifyPointLock` take `minTimeoutBlock`; `EthChainClient` enforces tip + confirmations + a per-chain ~1h floor; fails safe if tip unavailable |
| 6.2 | contracts | `HashedTimelock` / `PointTimelock` pay out with `.transfer` (2300 gas) → contract-wallet recipients brick both claim **and** refund | `.call{value:}` + `require(ok)` + `nonReentrant`, CEI preserved |
| 6.7 | contracts | staged `PtlcTimelockPure` strict mode doesn't enforce the adaptor identity `(s−s')·G == T` on-chain | strict mode now checks it (new `sPrime` arg, `ptlcPointY` stored); pre-existing compile blockers fixed; marked `@custom:staged`, not deployable |
| 2.1 | consensus | `Currency::calculateInterest` had a dead 128-bit computation behind a hard-coded `0` | simplified to a plain `return 0` — legacy XFG deposit interest is intentionally 0 (all yield is HEAT CDs); verified withdrawal path unaffected |

### Fixed earlier by commit `37bf331b` ("hearth-audit-fixes")

| Module 0 | `OrderbookMatcher` VWAP `>>64` collapsed `P_clear` to 0 | fixed — `uint128_t` accumulator, no shift |
| Module 0 (adjacent) | LP apply/undo reserve inflation on reorg (~654322 XFG atomic units mintable) | fixed — `m_blockLpRemoveAmounts` undo journal |
| Module 0 (adjacent) | pool two-sided quote suppressed by self-trade exclusion | fixed — `0xF0`-prefix exemption |

### Open (not addressed this session)

Everything below marked **OPEN**. Nothing here is a hard blocker discovered
to be currently exploited, but the 🔴/🟠 items in Modules 1–3 and 5 should be
scheduled before mainnet swap volume grows.

---

## 2. Module 1 — Cryptographic primitives (`src/crypto/`)

Live swap crypto: `adaptor.cpp`, `musig2.cpp`, `dleq.cpp`, `secp_adaptor.cpp`,
`pedersen.cpp`, `subaddress.cpp`. Staged / not wired into consensus:
`mlsag.cpp` (only `tests/mlsag_test.cpp`), `tier_proof.cpp` (no callers).

Verified sound: the adaptor / MuSig2 completed-signature format (`c ‖ s`)
correctly matches `crypto_ops::check_signature`'s `s_comm` challenge, so
adapted signatures verify as standard Fuego Schnorr sigs. Key-image torsion is
checked at consensus level (`scalarmultKey(keyImage, L) == I`).

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| 1.1 | 🔴 | **MuSig2 nonce-reuse guard is on the wrong object.** `musig2_partial_sign` guards on `session.nonceSigned`; the secret nonce is a separate `Musig2SecNonce&`. A fresh session + reused/persisted nonce passes the guard and signs again with the same `k` ⇒ private-key disclosure (a reuse of the post-sign zeroed nonce gives `s_i = −c·a_i·x`, `x` falls straight out). Reachable via the swap DB's retry paths. `AdaptorSwap.cpp::adaptor_partial_sign` adds an all-zero-nonce guard at the orchestration layer (partial mitigation) but not for the 9 direct `musig2_partial_sign` call sites. | OPEN — guard must be on the nonce (reject if any `k[j]==0` / already consumed) |
| 1.3 | 🟠 | MuSig2 accepts unvalidated group elements — `musig2_key_agg` (pub0/pub1) and `musig2_session_init` (adaptor point, `R_agg[j]`) only `ge_frombytes_vartime`, no cofactor/`point_is_valid` like `adaptor.cpp`/`dleq.cpp`. Small-order contributions weaken key-agg / make the adaptor lock bypassable. | OPEN |
| 1.4 | 🟠 | `secp256k1` `EC_GROUP` singleton (`secp_group()`) lazily set with no sync — first-use race across RPC/swap threads. `std::call_once`. | OPEN |
| 1.5 | 🟠 | `pedersen_init()` not thread-safe (`s_H_initialized` plain bool) and on the verification path (`pedersen_verify`, `tier_proof`). Function-local `static` / `call_once`. | OPEN |
| 1.6 | 🟠 | `subaddress.cpp` hashes a compiler-dependent struct: `PreImage` relies on `__attribute__((packed))` under `__GNUC__` only. On any other toolchain a pad byte before the `uint32` fields and a changed `sizeof` feed `hash_to_scalar` ⇒ non-deterministic subaddress derivation ⇒ funds sent to a subaddress that can't be re-derived after a compiler change. Serialize to an explicit LE byte buffer. Same path the working-tree alias flow now depends on. | OPEN |
| 1.7 | 🟠 | Alias privacy copy overstates it: `C_ij = A` — every subaddress shares the master view public key. Fresh spend key only; anyone with `A` links all subaddresses + the master. Scope the UX claim to "spend key not reused". | OPEN |
| 1.8 | 🟠 | DLEQ: `generate_dleq_proof` skips `point_is_valid` on `base_point` (verifier checks it); no swap-id / transcript binding ⇒ proof replayable across contexts reusing `(P,A,B)`. **This is the root of finding 3.9.** | OPEN (pure-PTLC path now gated off) |
| 1.9 | 🟡 | `check_adaptor_signature` validates `T` for small order but not `pub`. `extract_adaptor_secret` only checked challenge match + `t≠0` — **partly fixed this session** (orchestration layer now verifies `t·G == T`). | PARTIAL |
| 1.10 | 🟡 | `secp_complete_schnorr_sig` stores x-only `R` while the presig carries compressed `R`; no BIP340 even-y normalization — interop hazard if any external secp verifier consumes these. `bn_to_bytes` silently truncates `>32` bytes. | OPEN |
| 1.11 | 🟡 | (staged) `mlsag.cpp`: `check_mlsag` has no `ring_size` upper bound (CPU-DoS if ever wired); `generate_mlsag` `alloca(ring_size·160)`. | OPEN (staged) |
| 1.12 | 🟡 | (orphaned) `tier_proof.cpp` — no callers. If wired into the deposit path: challenge binds neither `values[]` nor an amount-vs-term domain tag (replay between the two uses), `C` gets no torsion check. | OPEN (orphaned) |
| 1.13 | 🟡 | `mlsag.cpp` and `tier_proof.cpp` look load-bearing but aren't in any consensus path — add an explicit in-tree "staged, not production-audited" marker. | OPEN |

---

## 3. Module 2 — Consensus / blockchain core (`Blockchain.cpp`, `Currency.cpp`)

Verified sound: key-image subgroup check on all three spend paths; the **F-001
fix** (block-level aggregate of `claimedInterest` + BV bonus vs the pre-block
fee pool / `CD_APY_POOL` / `BONUS_VAULT`) is underflow-safe and correct;
miner-tx v10+ enforces `coinbaseTotal == reward` exactly; timestamp rules are
standard.

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| 2.1 | 🟡 | `Currency::calculateInterest` returned a hard-coded `0` behind a dead 128-bit computation. **Confirmed intentional** — legacy XFG term deposits (`MultisignatureOutput`/`Input`) earn no on-chain interest; all yield is HEAT CDs; the legacy-bond migration program no longer exists. Verified that `return 0` does **not** block withdrawal: `getTransactionInputAmount` values a matured legacy input at principal, so a principal-minus-fee withdrawal passes conservation; maturity + double-spend are enforced independently in `Blockchain::validateInput`; the `Blockchain.cpp:1044` banking-index accounting and the vestigial `Blockchain.cpp:4177` legacy-bond branch both behave correctly at 0; wallet callers use it for display only. | **RESOLVED this session** — simplified to a plain `return 0` with a rationale comment |
| 2.2 | 🟠 | Emission underflow guarded only by `assert` (compiled out in `NDEBUG`): `Currency::getBlockReward` does `(m_moneySupply - Osavvirsak) >> factor` / `(m_moneySupply - alreadyGeneratedCoins) >> factor` with the bound checks as `assert`s. If burn re-emission ever lets the subtrahend exceed `m_moneySupply` the result wraps to ~2⁶⁴ and `validate_miner_transaction` would accept the correspondingly huge coinbase. Replace with runtime clamps + `return false`. | OPEN |
| 2.3 | 🟠 | `checkCommitmentSpendInput`'s per-input `baseClaimed > m_feePoolBalance` check is against a pre-connect snapshot; aggregate safety lives **only** in the block-level F-001 loop. Any future path that validates these inputs without that loop reopens F-001. Add a defense-in-depth tx-level aggregate or a hard connect-time invariant assert. | OPEN |
| 2.4 | 🟠 | Two definitions of "valid CD term" in one file: `checkCommitmentTransferInput` hard-codes `newTerm ∈ [1..5]`; `check_tx_outputs` uses `depositMinTerm()..depositMaxTerm()` + a marker whitelist. Pin both to named constants. | OPEN |
| 2.5 | 🟡 | F-001 aggregate gates the full claim (base+bonus) against `m_feePoolBalance` while connect-time only debits base — conservative for safety, but a bonus-heavy claim is wrongly rejected when the fee pool is low (liveness). | OPEN |
| 2.6 | 🟡 | `get_adjusted_time()` = raw `time(NULL)` with `//TODO: add collecting median time`; the block future-time gate depends on unadjusted local clock. | OPEN |
| 2.7 | 🟡 | `check_tx_outputs`: `for (TransactionOutput out : tx.outputs)` copies each output on a hot validation path — `const auto&`. | OPEN |
| 2.8 | 🟡 | `checkCommitmentSpendInput`: `youngestRingMemberHeight` starts at 0, only raised on strict `>`; a ring of all-block-0 members leaves the interest-cap term at 0 (safe, but relies on the index never yielding block 0). | OPEN |

*F-002 (merkle malleability) / F-003 (nullifier chainId) live in the STARK /
HEAT-burn verifier path, not `Blockchain.cpp`. Not in scope for this pass
(you asked to focus on atomic-swap contracts). The **SPV-path** instance of the
same merkle-malleability class is finding 3.1 below.*

---

## 4. Module 3 — Swap daemon (`src/SwapDaemon/`)

Verified sound: `SwapSecretEncryption` (Encrypt-then-MAC, ChaCha8+HMAC-SHA256,
random salt/nonce, CN-hard KDF, constant-time tag compare); `SwapStateMachine`
refuses to persist a record that would drop live secrets; the state-transition
table is a tight linear graph.

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| 3.1 | 🔴 | **SPV Merkle inclusion proof is forgeable.** `SpvMerkle::computeRootHexDisplay(txid, branch, pos)` folds attacker-supplied `branch`/`pos` from the Electrum server and compares to the stored header root. Missing: `pos == 0` post-fold check; a bound on `branch.size()` vs the block's real tree depth (`SpvHeaderStore` doesn't track tx count); **rejection of a 64-byte "transaction"** (indistinguishable from an internal Merkle node — CVE-2012-2459 class). A malicious/eclipsing Electrum server can prove inclusion of a transaction that was never in the block, and the daemon then releases the irreversible XFG claim (`verifyLockSpv`). Only mitigation is `crossCheckTxVerify` (`(N/2)+1` agreement) — **skipped entirely when `m_conns.size() <= 1`** and defeated by an eclipse. | OPEN |
| 3.2 | 🔴 | `adaptor_extract_secret` returned success on `t≠0` only, no `t·G == params.adaptorPoint`. | **FIXED this session** |
| 3.3 | 🟠🔴 | Cross-curve adaptor binding asserted, never proven — `adaptor_generate_adaptor` publishes `secpPubHex = t·G_secp` + a DLEQ that is **same-curve Ed25519**. Nothing proves the secp point shares `t` with the Ed25519 adaptor point. Matters for the BTC Taproot PTLC leg. | **MITIGATED** — pure-secp PTLC gated off (3.9 fix); a real DLEQ still owed |
| 3.4 | 🟠 | `timelockOrderingOk`: hard-coded `480000` ms/XFG-block, unbounded `uint64` multiplies (overflow if a timeout height is attacker-influenced upstream), and `marginSec` fully caller-controlled (a `0` gives zero buffer). Enforce a protocol-min margin inside the function; clamp the block deltas. | OPEN |
| 3.5 | 🟠 | State graph permits `ADAPTOR_SECRET_REVEALED → ADAPTOR_XFG_SPENT`, skipping the SPV wait. The working-tree reorg guard in `finalizeEscrowSpend` only fires on `logContext == "SPV confirmed"` (fragile string-label gate). A claim driven off a 0-conf secret reveal can reach `XFG_SPENT` with no confirmation re-check. Make the SPV-confirmed state a mandatory predecessor, or gate on a typed flag. | OPEN |
| 3.6 | 🟠 | Refund-state transition guard uses one timeout (`xfgTimeoutHeight`) for `AFK_REFUNDED`/`ADAPTOR_REFUNDED`/`XFG_REFUNDED`/**`CTR_REFUNDED`** — the last is a counter-chain refund with its own earlier deadline, so a legitimate CTR refund is blocked in the window between the two (liveness), or `currentHeight` is silently in the wrong chain's units. | OPEN |
| 3.7 | 🟠 | `ElectrumSpvClient::getTipHeight` "median" (`tips[size/2]`) picks the upper element for even counts — one malicious + one honest server still yields the attacker's inflated tip. Needs a quorum minimum and lower-median for even counts. (working-tree change) | OPEN |
| 3.8 | 🟡 | `adaptor_aggregate` signals the zero-`t` error by returning an all-zero `Crypto::Signature` sentinel instead of a bool/optional. | OPEN |
| 3.9 | 🟡 | `adaptor_generate_adaptor` relies on `adaptorSecret` already being a reduced Ed25519 scalar (true via `generate_keys`) — add an `sc_check == 0` assert at generation. | OPEN |
| 3.10 | 🟡 | `SwapStateMachine::transition` writes `m_state`/`m_updatedAt` with no internal lock — safe only if every caller holds a per-swap mutex. | OPEN |
| 3.11 | 🟡 | Confirm `presigSessionHash` ("presig-v1" domain sep) is actually bound into the MuSig2 challenge, or the separation is cosmetic. | OPEN |
| 3.12 | 🟡 | ChaCha**8** (not ChaCha20) for secret-at-rest — inherited, no practical break, below modern margin. | OPEN |

---

## 5. Module 4 — RPC & P2P (`src/Rpc/`, `SwapDaemon/RpcServer.cpp`, `SwapPeerProtocol`, `src/P2p/`)

`src/P2p/` core Levin/NetNode: shallow pass only (20 MB packet cap confirmed).
Verified sound: swap-control endpoints are fail-closed without a token; CORS
opt-in, never wildcard; standalone SwapDaemon RPC binds loopback only; the peer
KEY_EXCHANGE / bound-key + signature model is well-constructed.

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| 4.1 | 🟠 | `restrictRPC()` is called **after** `rpcServer.start()` in `Daemon.cpp`, and `m_restricted_rpc` has no initializer (not in ctor init list). Startup window where the six `if (m_restricted_rpc)` guards branch on an **indeterminate bool** (UB; commonly reads `false` ⇒ restricted endpoints exposed even with `--restricted-rpc`); CORS also unset. `= false` in the header + move `restrictRPC()`/`enableCors()` before `start()`. | OPEN |
| 4.2 | 🟠 | Unbounded ring decode before authentication — `decodeIndices`/`decodePubKeys` loop over an attacker hex string with only a `%8`/`%64` length check, no element cap; the `size()` cross-check is after both vectors are built. `msg.swapId` length-unbounded. Bounded by 20 MB Levin cap (amplification, not unbounded). Cap ring size + swapId before the loops. | OPEN |
| 4.3 | 🟠 | Node-global (not per-IP) rate limiter is itself an amplifier — one bucket for all clients, applied to only two endpoints; the expensive sync endpoints have none. Needs per-peer buckets. | OPEN |
| 4.4 | 🟡 | Bearer/token compare is `std::string ==` — not constant-time (`checkSwapControlAuth`, SwapDaemon `authorize()`). | OPEN |
| 4.5 | 🟡 | Unauthenticated read endpoints disclose swap state, treasury/fee-pool balances, deposit analytics on a non-loopback bind unless behind `--restricted-rpc`. | OPEN |
| 4.6 | 🟡 | `processJsonRpcRequest` logs full request/response bodies at `TRACE`. | OPEN |
| 4.7 | 🟡 | `deserializePeerMessage` relies on exception unwinding for missing/mistyped fields; `ADAPTOR_EXCHANGE.secpPubHex` stored as an unvalidated arbitrary-length string at parse time. | OPEN |
| 4.8 | 🟡 | Working-tree per-swap synchronous external RPC in `handleListSwaps` is loopback-only for the standalone daemon, but `on_list_swaps` is also registered on the core daemon RPC — confirm the remote path before ranking the amplification. | OPEN |

---

## 6. Module 5 — Go components (`dashboard/`, `swapxfg/`, `tui/`)

**No secret custody in Go** — ETH/SOL signing is in the browser wallet
extension, XFG order signing is in `walletd`. Verified sound: SRI hashes on the
bridge CDN scripts; loopback binds; `io.LimitReader` everywhere; `crypto/rand`
for RPC IDs; real CSP + origin-restricted CORS on the dashboard.

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| 5.1 | 🟠 | Dashboard raw reverse-proxy routes bypass the wallet method allowlist — `/json_rpc`, `/wallet_rpc`, `/heat_metrics`, `/amm_pool_info`, `/amm_quote`, `/getswapprice`, `/api/daemon/` are unfiltered proxies straight to daemon/wallet RPC. `/json_rpc` reaches the full core-daemon JSON-RPC surface. Remove them or put them behind the allowlist. | OPEN |
| 5.2 | 🟠 | Fund-moving wallet methods (`place_limit_order`, `cancel_limit_order`, `amm_swap`, `initiate_swap`) require no auth beyond "is a local process" — only a 200 ms/IP limit + browser-only CORS. Any local process executes trades/swaps with the wallet key. Add a per-session token minted at dashboard launch. | OPEN |
| 5.3 | 🟠 | `X-Forwarded-For` is trusted as the rate-limit key on a loopback service with no trusted proxy → unique XFF per request bypasses the limiter, and `rl.buckets` grows one never-evicted entry per value. Ignore XFF; bound/expire the map. | OPEN |
| 5.4 | 🟠 | `validateXMRAddress` is applied to `"xfg"` with Monero's parameters (prefix `4`/`8`, length 95, 64-byte payload). Real XFG addresses will not match → the TUI rejects the user's own payout address, or the check is dead. Needs XFG's actual base58 prefix/length. | OPEN |
| 5.5 | 🟠 | `parseAmountAtomic` converts via `float64` — `amt` up to `1e15` × `decimals` up to `1e18` overflows / loses integer precision; Go's `float64→uint64` for out-of-range is implementation-defined. A large ETH amount produces an atomic value that doesn't match what the user typed, feeding swap/bridge tx construction. Use `big.Int` / fixed-point. | OPEN |
| 5.6 | 🟠 | BCH address validation performs no checksum verification (only prefix + length; CashAddr polymod and legacy base58check not checked). A fat-fingered BCH payout address passes → funds to a wrong/unspendable address. | OPEN |
| 5.7 | 🟡 | Bridge CSP names `https://cdn.ethers.io` while `bridge_eth.go` loads ethers from `https://cdn.jsdelivr.net` — one of the two CSP strings is stale (breaks the page or is dead config). | OPEN |
| 5.8 | 🟡 | `base58Decode` is O(n²) big.Int with no input-length cap (client-side, minor). | OPEN |
| 5.9 | 🟡 | Dashboard WS `CheckOrigin` returns `true` for empty `Origin` (broadcast feed only — low impact). | OPEN |
| 5.10 | 🟡 | `validateSOLAddress` checks base58 + 32-byte length but not ed25519 on-curve. | OPEN |

---

## 7. Module 6 — Atomic-swap contracts (EVM + BTC)

**Wired:** `HashedTimelock.sol` (default HTLC path, live), `PointTimelock.sol`
(PTLC path, live when `eth_ptlc_registry` set — the working-tree
`applyPtlcConfig` wires it for all 12 new chains). **Dead:** `PtlcTimelock.sol`
(28-line stub, doesn't compile — bare internal call to `external lock()`).
**Staged:** `PtlcTimelockPure.sol` (`supportsPurePtlc()==false`, needs
EIP-6601).

Verified sound: the `PointTimelock` `ecrecover` point-check correctly proves
`t·G == pointAddress`. BTC HTLC script is canonical BIP-199.

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| 6.1 | 🔴 | `EthRpcClient::verifyLock` validated amount/recipient/hashlock/claimed but **ignored `info.timeoutBlock`**. A counterparty funding the ETH lock with `timeoutBlock = block.number + 2` passes verification; they refund ~24 s later; the local party has by then revealed `t` / locked their XFG side and loses it. | **FIXED this session** — `minTimeoutBlock` floor enforced, fails safe |
| 6.2 | 🔴 | `HashedTimelock` / `PointTimelock` pay out with `.transfer()` (2300 gas). A Safe / AA / 4337 recipient whose `receive()` costs > 2300 gas makes **both `claim()` and `refund()` revert permanently** — total loss of the locked ETH, no recovery. | **FIXED this session** — `.call{value:}` + `require(ok)` + `nonReentrant`, CEI preserved |
| 6.3 | 🟠 | `contractId` has no nonce/salt and `contracts[id]` is never deleted → an identical swap 5-tuple (or a retry reusing `H(t)`) hits `"Contract already exists"` forever. Add a caller nonce to the preimage. | OPEN |
| 6.4 | 🟠 | Secret encoding differs between live contracts with no on-chain guard: `HashedTimelock.claim` wants raw LE preimage; `PointTimelock.claim` wants byte-reversed BE scalar. Wrong encoding for the negotiated `SwapLockType` ⇒ silent claim failure ⇒ timeout refund. The reversal lives in one boundary fn (`ContractAbi::derivePointAddressFromSecret`) — add a round-trip self-test. | OPEN |
| 6.5 | 🟠 | `PointTimelock.lock` accepts any `pointAddress`; combined with 3.9 the locker can be bound to a point they can't open (griefing, not theft). The receiving daemon must verify the point before locking its side. | OPEN (3.9 gate reduces exposure) |
| 6.6 | 🟡 | Dead `PtlcTimelock.sol` — remove or fix. | OPEN |
| 6.7 | 🟠 | (staged) `PtlcTimelockPure` strict mode verified `s·G == e·P + R` but **not** `(s−s')·G == T`; the `EcrecoverFallback` mode is, by its own NatSpec, not a proof. `constructor(VerifyMode)` makes deploying the unsound mode a one-arg mistake. | **PARTIALLY FIXED this session** — strict mode now enforces the adaptor identity; contract still staged/non-deployable; fallback mode still unsound (do not deploy) |
| 6.8 | 🟡 | (staged) `PtlcTimelockPure.lockWithPoint` only nonzero-checks the group elements; no on-curve validation before the strict precompiles. | OPEN (staged) |

---

## 8. Cross-cutting themes

1. **Adaptor↔point binding was never verified where it mattered** — `extract`
   didn't check `t·G == T` (1.2/3.2, fixed), there is no real cross-curve DLEQ
   (3.9, gated off), and the staged EVM strict path didn't enforce the adaptor
   identity (6.7, fixed on the staged contract). The live `PointTimelock`
   ecrecover check was always sound. **Remaining owed work: a reviewed
   Ed25519↔secp256k1 DLEQ** before pure-secp PTLC can be re-enabled.

2. **SPV trust** — `SpvMerkle` (3.1) has the same merkle-malleability class as
   F-002, independently, on the Bitcoin/BCH/DCR SPV path. The multi-server
   cross-check is skipped at `m_conns.size() <= 1` and defeated by an eclipse.
   This gates irreversible XFG claims.

3. **Timelock discipline is off-chain-only** — `timelockOrderingOk` (3.4)
   computes the *intended* ordering on the honest party's daemon; a malicious
   counterparty ignores it. 6.1 (fixed) plugged the EVM side; confirm the UTXO
   `verifyLock` paths recompute the redeem-script timeout rather than trusting
   decoded/peer-supplied fields.

4. **Thread-safety of lazy singletons** — `secp_group()` (1.4),
   `pedersen_init()` (1.5), `RpcServer::m_restricted_rpc` (4.1) are all
   set-once-without-sync patterns on multi-threaded paths.

5. **`float64` / silent-truncation for money** — `parseAmountAtomic` (5.5),
   `bn_to_bytes` `>32` truncation (1.10), `calculateInterest` returning 0
   (2.1). Amounts and scalars should never round-trip through a lossy type.

---

## 9. Recommended order of work (open items)

1. **3.1** SPV merkle hardening (reject 64-byte tx, `pos==0` post-fold, depth
   bound, hard min server count for SPV-gated claims).
2. **1.1** MuSig2 nonce-reuse guard moved onto the nonce.
3. **3.4 / 3.5 / 3.6** swap timelock + state-machine hardening.
4. **1.3 / 1.6** MuSig2 point validation; portable subaddress preimage.
5. **4.1** `restrictRPC` ordering + init.
6. **5.1 / 5.2** dashboard proxy allowlist + session token.
7. **5.4 / 5.5 / 5.6** TUI address/amount validation.
8. A reviewed **Ed25519↔secp256k1 DLEQ**, then lift the 3.9 gate.
9. **2.2 / 2.4** consensus hardening (emission clamps, term constants). *(2.1
   resolved; 2.3 is defense-in-depth on top of the working F-001 fix.)*

Lower-priority 🟡 items tracked per-module above.
