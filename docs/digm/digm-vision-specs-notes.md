# DIGM Stablecoin: Vision, Specs & Notes

> **Status**: Draft — Internal Planning
> **Date**: 2026-08-26
> **Version**: 0.1

---

## 1. Core Constants

| Parameter | Value |
|-----------|-------|
| DIGM per HEAT | 10 DIGM = 1 HEAT |
| HEAT per DIGM | 0.1 HEAT = 1 DIGM |
| Smallest HEAT unit (minting) | 0.10 HEAT |
| Smallest DIGM unit | 0.01 DIGM |
| Partner share | 20% |
| Protocol (Treasury) share | 80% |

---

## 2. Design Goals

- DIGM is a **non-USD stablecoin** (pegged to HEAT, which targets CPI-adjusted purchasing power)
- DIGM is **outside GENIUS Act P.L. 119-27** scope — USD-denominated payment stablecoins only
- DIGM is **permissionlessly mintable** by anyone via the `DigmMintEngine`
- DIGM is **unfreezable** by design (RingCT)
- DIGM is **self-custodial** — no custodian holds your DIGM
- DIGM earns **yield** via locked positions without an issuer paying it (no "yield to holders" prohibition violation)
- Cross-chain DIGM supply tracked via **partner dashboard signals** from participating parties

---

## 3. The 20/80 Partner Share Model

All DIGM-network fee revenue is distributed:

```
DIGM_NETWORK_FEE_POOL
├── 20% → Partner (wallets / exchanges / merchants / bridges)
└── 80% → Protocol (Vault_CLRV_LP_Manager or Treasury)
```

Partners integrate DIGM and earn a share of network fees. Claimed daily, similar to Paxos Rewards Engine.

---

## 4. Three Collateralization Paths

### Path A: Lock HEAT → Mint DIGM → Re-deposit HEAT (CLRV Model)

**Mechanism**

1. User locks HEAT (min 0.10 HEAT) in `DigmMintEngine`
2. Protocol mints DIGM to user at 10 DIGM per 1 HEAT
3. Locked HEAT is **immediately re-deposited** into:
   - **Hearth Reserves** (operational liquidity)
   - **CLRV_HEAT_CD** — a new CD class, Collateral Reserve CD, owned by protocol
   - **CLRSVP_HEAT_LP** — a new LP reserve position in **Vault_CLRV_LP_Manager**

**Code implications**

- Existing `HEAT_CD` stays unchanged (user-facing, legacy deposits)
- New `CLRV_HEAT_CD` class: same machinery, isolated to protocol-owned deposits
- New `CLRSVP_HEAT_LP`: mirrors `LP_RESERVE_HEAT` but routes to `Vault_CLRV_LP_Manager`
- `Vault_CLRV_LP_Manager` is a **new isolated Treasury sub-manager**, separate from normal Treasury/Hearth operations
- The two CD types will share ~90% of the same code path (epoch tracking, yield accrual, withdrawal解锁)
- The isolation prevents CLRV deposits from mixing with user-held CD accounting

**Pros**

- HEAT never leaves circulation — strong collateral narrative
- Existing HEAT_CD code reused with minimal duplication
- Protocol always holds reserves ≥ circulating DIGM
- Clean audit trail: every DIGM minted backed by locked HEAT

**Cons**

- Near-duplicate code paths for two CD classes
- HEAT in Hearth Reserves is productive but CLRV_HEAT_CD yield must be tracked separately
- Dynamic allocation between Hearth Reserves and CLRV_HEAT_CD requires governance or algorithmic rules

---

### Path B: Burn HEAT for DIGM (XFG Burn Extension)

**Mechanism**

1. User burns HEAT → protocol mints DIGM at 10 DIGM per 1 HEAT
2. DIGM can be **burned back** to claim HEAT (no 1:1 — see note)
3. No HEAT/DIGM AMM pool needed — DIGM supply is purely burn-derived

**Note on reverse burn**: When DIGM burns back to HEAT, options:
- **Option B1**: 1 DIGM → 0.1 HEAT (pure 1:1 unwinding, no protocol take)
- **Option B2**: Protocol keeps 50% of returned HEAT (weaken collateral narrative — not recommended)
- **Option B3**: No reverse burn — DIGM is one-way from HEAT (breaks redemption promise)

**Code implications**

- Extends existing XFG burn framework → HEAT burn endpoint
- `DigmMintEngine` gains a `burnHEAT()` entry that calls `createDigmFromBurn()`
- DIGM reverse burn (DIGM → HEAT) tracked via `burnDigmToClaimHeat()`
- Heavy bookkeeping: `totalHeatBurned`, `totalDigmMinted`, `totalDigmBurned`, `totalHeatReturned`
- No AMM pool needed for HEAT/DIGM — simplifies AMM design significantly

**Pros**

- Clean supply model: 0 DIGM exists until HEAT is burned
- No AMM pool needed — eliminates DEX complexity
- Simple reserve proof: just `totalHeatBurned × 10 = circulating DIGM`
- No duplicate CD code

**Cons**

- HEAT supply permanently reduced → collateral base shrinks
- Political/UX problem: "I locked my HEAT and it's gone"
- DIGM supply is inelastic — cannot expand unless people burn HEAT
- If HEAT price rises, burning HEAT for DIGM becomes expensive ( DIGM becomes "expensive" relative to HEAT in a way that breaks the peg narrative)
- Reverse burn mechanics contentious (who gets what back?)

---

### Path C: HEAT Stays, DIGM Burns to Redeem HEAT (Reserve Collateral Model)

**Mechanism**

1. HEAT is **never burned, never converted**
2. DIGM is **issued in bundles/tracts** based on SWF epoch conversions
3. SWF converts XFG → HEAT each epoch (each 8th epoch)
4. Treasury examines cross-chain DIGM supplies during the 9th epoch
5. 10th epoch: Treasury mints DIGM = SWF-epoch-converted HEAT × 10
6. DIGM holders can **burn DIGM** to claim equivalent HEAT (DIGM destroyed permanently)
7. HEAT reserve pool is the **collateral backstop** — always sufficient

**Cross-chain distribution**

- Each target chain gets a pro-rata share based on:
  - Volume of DIGM swaps on that chain (from partner dashboard signals)
  - Liquidity depth on that chain's DIGM pool
  - Partner signal inputs (opt-in dashboard UI — see §4 below)
- Treasury algorithm calculates per-chain issuance for epoch N+1

**Partner Dashboard Signals**

Partners (wallets/exchanges/bridges) using DIGM can submit lightweight signals:
- Preferred chain for next issuance
- Current local demand (inflows/outflows)
- Liquidity conditions
- One-click "signal" button in DIGM Partner Dashboard

Treasury aggregates these signals with on-chain metrics to route next issuance.

**Code implications**

- `DigmMintEngine` gets `issueDigmFromReserve(heatAmount, chainId)` — protocol-only, no user-facing burn
- New `redeemDigmForHeat(digmAmount)` — user burns DIGM, receives HEAT from reserve
- `Vault_CLRV_LP_Manager` holds HEAT reserve that backs circulating DIGM
- No AMM pool dependency for HEAT/DIGM direct redemption
- `SWF` epoch tracker added: `getConversionAmount(epoch)` → HEAT converted → × 10 = DIGM issuance

**Pros**

- HEAT supply never decreases — collateral base stays intact
- DIGM supply expands with SWF epoch conversions organically
- Most intuitive UX: "my DIGM is backed by HEAT locked by the protocol"
- Cleanest reserve proof: Vault holds HEAT, circulating DIGM ≤ vault HEAT × 10
- No reverse-burn complexity — DIGM burns to claim HEAT, HEAT never moves

**Cons**

- DIGM supply is epoch-locked — cannot mint arbitrarily, only when SWF converts XFG
- Treasury must manage HEAT reserve actively
- Cross-chain distribution requires on-chain tracking per chain
- Partner dashboard signals add a soft-governance layer (Sybil risk)

---

## 5. Path Comparison

| Dimension | Path A (Lock+Redeem) | Path B (Burn HEAT) | Path C (Reserve Collateral) |
|-----------|----------------------|--------------------|----------------------------|
| HEAT supply impact | No burn | Permanent reduction | No change |
| DIGM supply model | Immediate mint on lock | Only on burn | Epoch-based bundles |
| Collateral narrative | Strong (locked HEAT) | Weak (HEAT gone) | Strong (HEAT reserve) |
| AMM pool needed | Yes HEAT/DIGM | No | No |
| Code duplication | High (CLRV vs CD) | Low | Low |
| Reverse burn complexity | N/A | Contested | Simple |
| Supply elasticity | Immediate | Elastic on demand | Epoch-locked |
| Partner dashboard signals | No | No | Yes |
| Protocol HEAT management | Re-deposit dynamic | N/A | Active reserve mgmt |

**Recommendation**: Path C is strongest on collateral narrative, code simplicity, and regulatory optics. Path A is viable if code duplication is acceptable and dynamic re-deposit allocation is governed. Path B is weakest on narrative and supply mechanics.

---

## 6. Smallest Unit Constraints

| Asset | Smallest Mintable Unit |
|-------|----------------------|
| HEAT | 0.10 HEAT |
| DIGM | 0.01 DIGM (implicit from 10 DIGM = 1 HEAT) |

- HEAT amounts below 0.10 cannot be used to mint DIGM — dust prevention
- DIGM below 0.01 not representable (2 decimal places)

---

## 7. Open Questions

- [ ] Path C: How does Treasury handle HEAT reserve if DIGM demand exceeds SWF conversion supply?
- [ ] Path C: What is the minimum HEAT reserve ratio? (e.g., 110% to allow for redemption headroom?)
- [ ] Partner dashboard signal aggregation: weighted by volume? one-signal-one-vote? stake-weighted?
- [ ] Cross-chain DIGM: which chains first? Base (STARK_TARGET_CHAIN_BASE=8453) was already noted in SwapDaemonMain.cpp
- [ ] Path A dynamic allocation: governance param or algorithmic (e.g., based on DIGM circulating supply ratio)?
- [ ] Path C epoch mechanics: does SWF conversion amount drive DIGM issuance exactly, or is there a multiplier?

---

## 8. Next Steps

1. **Decision**: Pick Path A, B, or C as primary (hybrid A+C also possible — lock HEAT, use Path C mechanics for expansion)
2. **Spec the epoch pipeline**: SWF epoch N → HEAT conversion → Treasury analysis → DIGM issuance
3. **Define Vault_CLRV_LP_Manager** interface and isolation boundaries
4. **Partner dashboard spec**: signal schema, aggregation algorithm, UI
5. **Cross-chain routing**: Base first (STARK bridge already flagged), then options

---

*Last updated: 2026-08-26*
