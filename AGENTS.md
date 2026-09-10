# AGENTS.md — Fuego Suite

## Project Identity

- **Name**: Fuego (XFG) / Fuego Suite
- **Repository**: `github.com/usexfg/fuego-suite`
- **Language**: C++17 (daemon), Go (TUI), Rust (adaptor sigs, swap daemon)
- **Build**: CMake 3.16+, Make, Go 1.24+
- **Protocol**: CryptoNote (RingCT, ring signatures, subaddresses)

## Architecture

```
fuego-suite/
├── src/CryptoNoteCore/     # Consensus, blockchain, HEAT mint, Hearth orderbook
├── src/crypto/             # MLSAG, Pedersen, MuSig2, DLEQ, adaptor sigs
├── src/P2p/                # P2P networking, Levin protocol
├── src/Rpc/                # JSON-RPC server
├── src/Wallet*/            # CLI wallet (fire_wallet)
├── src/SwapDaemon/         # Cross-chain atomic swap daemon
├── src/SimpleWallet/       # Wallet launcher + swapxfg TUI launcher
├── tui/                    # Go TUI (fuego_suite terminal UI)
├── fuego-swapd-adaptor/    # Rust — adaptor signature lib (Schnorr+MuSig2+DLEQ)
├── contracts/              # Solidity/Rust HTLC contracts
├── mcp/                    # MCP server for AI-agent integration
├── docs/                   # Documentation (Mintlify MDX)
└── graphify-out/           # Knowledge graph (auto-generated)
```

## Key Subsystems

### Hearth Exchange (on-chain AMM + limit-order overlay, v12+)
- Constant-product AMM (XFG/HEAT) with a **limit-order overlay**: orders are tx-extra-backed `TransactionExtraLimitDeposit` commitments (no gossip, no unbacked orders)
- Orders execute **at block time against the pool at the live spot price** (`ammGetSpotPrice`, HEAT/XFG × COIN); partial fills credit `proceedsXfg/proceedsHeat`, claimable via `TransactionExtraLimitWithdraw`
- Expiry is height-based; expired orders keep deposit + proceeds claimable (auto-return)
- **Balanced LP deposits only** — single-sided deposits mint no shares (no dilution); shares are fair pro-rata at the pool ratio
- Taker pays the 1% fee; **70%** is debited into the HEAT-denominated `cdHearthFeeAccumulator` → minted into `CD_APY_POOL` at the epoch boundary, **30%** is the maker rebate (auction makers, or LPs on pool fills); consumed XFG burned 50/50 (EF/SWF)
- `PoolOrderOrchestrator` still generates the displayed depth band (adaptive spread 30–300 bps, volatility fed by the pool spot price at v12) — informational depth, not in-band matched
- The in-band CLOB matcher, `MIN_DISTINCT_PARTIES`, and gossiped orders are **retired**
- Bootstrap window: 144 blocks of AMM-only operation after upgrade
- **Treasury LP Manager**: the protocol's own ratio-paired LP position from the 20% treasury share + mint premiums + donations (both legs, no cross-conversion); compounds and drives bootstrap repayment (two-leg owned-reserves check)

### HEAT Flatcoin (colored coin)
- Not fiat based, peg targets purchasing power only; adjusts for inflation/CPI
- Mint by burning XFG at hearth pool price with 0% launch premium (hardcoded, PI controller removed)
- Launch ratio: 1 HEAT = 10 XFG (10:1 XFG per HEAT)
- Peg reference: $1.58 USD (HEAT_PEG_USD)  adjusted for inflation starting Q1|2009 1 USD 
- Certificates of Deposit (CD): V12 activation, epoch-term-locked HEAT earning protocol revenue yield
- **TREASURY ROUTING (69/11/20)**: 69% CD Yield Pool / 11% Bonus Vault / 20% Treasury Reserve
- **BONUS VAULT**: 11% of swap fees fund tier-based loyalty bonuses (2.5× for 72 epochs, 2× for 36, 1.5× for 18, 1.25× for 6)
- **DEPOSIT MODEL**: See `DEPOSIT_ARCHITECTURE.md` for full details. Key points:
  - "HEAT" has TWO meanings in code: current flatcoin (dynamic TWAP pricing) vs legacy Embers_Heat (fixed 10M:1 ratio)
  - **Two-step process**: burn XFG → mint HEAT → deposit HEAT as CD (you CANNOT deposit a deposit)
  - Legacy 10M:1 `convertXfgToHeat()`/`convertHeatToXfg()` removed from the codebase — do not reintroduce
  - `mintHeatV10()` uses Hearth pool TWAP — this is ACTUAL mint pricing (canonical scale HEAT/XFG × COIN)
  - **DEPRECATED (DO NOT REINTRODUCE)**: COLD deposits (0xCD tag), Embers_Heat deposits, XFG deposits
  - **GUARDRAILS**: APY from protocol fees (not inflation), deposit secret stored locally, different term lengths don't hurt privacy

### Protocol Earnings (ONLY TWO — DO NOT ADD MORE)
1. **Hearth swap fee — 1% taker fee** (`HEARTH_FEE_BPS = 100`), on-chain Hearth fills. Split **70% → CD yield / 30% → maker rebate** (auction makers; the pool/LPs when it is the counterparty).
2. **Atomic swap fee — 1% + 1% = 2% per cross-chain swap** (`SWAP_FEE_RATE_BPS = 100` initiation + claim), via SwapXFG TUI or DeXFG tab in Fuego-Wallet GUI. Split **69% CD Yield / 11% Bonus Vault / 20% Treasury**.

NOT protocol earnings:
- **Mint premium**: none — `HEAT_MINT_PREMIUM_BPS = 0`, goes nowhere. Do not document as revenue.
- **CD creation fee**: 0.1% of CD amount → burned and credited (HEAT) to the **Treasury LP Manager** via the `TreasuryFund` tag (v12+). NOT protocol revenue, NOT CD yield. Pre-v12 it was a donation to @fuegoxfg (development fund).

### Hearth Exchange — Data Flow Per Block (v12+)
1. `PoolOrderOrchestrator`: record pool spot price (volatility feed), decide regeneration, compute adaptive spread
2. `generatePoolOrders()` — displayed depth band from AMM reserves (informational)
3. OOB executor: fill resting `m_limitDeposits` whose limit is crossed by the live spot price (1% taker fee, proceeds credited, height-based expiry)
4. Treasury LP Manager epoch work (fee share routing, conversions, ratio-paired LP provisioning, burns, bootstrap check)
5. Write P_clear + depth stats to block header

### Cryptographic Primitives
- Ring signatures: MLSAG with OSPEAD decoy selection
- Commitments: Pedersen (RingCT)
- Key aggregation: MuSig2
- Adaptor signatures: Schnorr + discrete log tweak for atomic swaps
- DLEQ proofs for commitment verification
- Hash functions: CryptoNight, Keccak, Blake, Skein, JH, Groestl
- Curve: secp256k1 (via libsecp256k1)

## Naming Conventions

| Convention | Usage |
|-----------|-------|
| `snake_case` | Variables, functions, file names |
| `PascalCase` | Class/struct names |
| `camelCase` | Method names |
| `UPPER_SNAKE` | Constants, macros, enums |
| `m_` prefix | Class member variables |
| `COMMAND_RPC_*` | RPC request/response structs |

## Build Notes

- C++17 required, C99 for C files
- Boost 1.86+ (uses `io_context`, `executor_work_guard` — no legacy `io_service`)
- OpenSSL 3.x/4.x
- External dependency: `secp256k1` (submodule at `external/secp256k1` or system package)
- CMake flag: `-DUSE_VENDORED_SECP256K1=OFF` to link against system secp256k1
- No KDF/MM2/AtomicDEX integration (removed)
- TUI disabled in CMake (`add_subdirectory(tui)` commented out), built separately via `make build-tui`
- **Deposit architecture**: See `DEPOSIT_ARCHITECTURE.md` for current vs deprecated deposit systems

## CI/CD

- GitHub Actions: macOS, Ubuntu 22/24, Windows, AppImage, Docker, Termux, Raspberry Pi
- No longer building `swapxfgui` or `mm2_xfg` (removed)

## RPC Endpoints

| Path | Auth | Purpose |
|------|------|---------|
| `/json_rpc` | varies | JSON-RPC methods (balance, transfers, etc.) |
| `/heat_metrics` | open | HEAT supply, redemption price, treasury |
| `/amm_quote` | open | Quote a swap amount |
| `/amm_pool_info` | open | Pool reserves, spot price |
| `/addswapfee` | restricted | Fee configuration |

## Known Issues

- **Block-serving RPC hang (pre-existing, not DIGM-related).** Every binary tested — including the month-old Jul-10 daemon on 18180 while idle and fully synced — hangs on `queryblockslite.bin` / `queryblocks.bin` / `getblocks.bin`. This blocks live sync/send e2e testing only; verification is done against the C++ production code directly (unit/integration harnesses), not live RPC.

## Graphify

- Graph: `graphify-out/` — 21,757 nodes, 35,228 edges, 2,183 communities
- Update after code changes: `graphify update .`
- Navigation: read `graphify-out/GRAPH_REPORT.md` first
- Query: `graphify query "<question>"`, `graphify path "<A>" "<B>"`

## Claude Code automations (project)

| Kind | Path |
|------|------|
| Entry | `CLAUDE.md` |
| Settings / hooks | `.claude/settings.json`, `.claude/hooks/` |
| Skills | `.claude/skills/fuego-build`, `.claude/skills/crypto-change-gate` |
| Agents | `.claude/agents/build-doctor.md`, `.claude/agents/crypto-security-reviewer.md` |
| MCP | `.mcp.json` (`fuego-mcp`, `github`) |

Hooks block edits to `.env` / wallets / keys. Build ground truth is `make -j$(nproc)`.

## Source Change Log (mandatory)

Every feature or fix that touches source code requires a `CHANGELOG.agent.md` file at the repo root. Each entry contains:
- **Feature name** and start date
- **Task list** with numbered tasks, owner (agent/model name), date, and status (TODO / IN PROGRESS / DONE)
- **Sign-off table** marking gate completion (build compiles, tests pass, all tasks done)

Agents sign off with their name and date when completing tasks. No source changes land without a corresponding task list entry. The log persists across sessions so any agent can pick up where another left off.

## OKOC Skill Chain

When working in this repo, the default skill chain auto-loads:
1. `okoc` — behavioral baseline
2. `graphify` — codebase navigation
3. `fuego-guardian` — recursive multi-agent code verification (auto on C++/crypto changes)
4. `007` — security audit (auto on sensitive operations)
5. `prompt-library` — persona generation
6. `code-reviewer` — code quality
