<img title="The Long Night Is Coming, and the DEBT comes with it" src="https://github.com/usexfg/fuego-data/blob/master/fuego-images/fuegoline.gif?raw=true"><img/>

### Fuego is a sovereign privacy blockchain banking network & cryptocurrency built and maintained by advocates of freedom thru sound money and free open-source software.

Based on the CryptoNote protocol.

#### Resources

-   [Website](https://usexfg.org)
-   Explorer: <https://explore-xfg.loudmining.com>
-   Explorer: <http://fuego.spaceportx.net>
-   [Discord](https://discord.gg/5UJcJJg)
-   [Twitter](https://twitter.com/useXFG)
-   [Medium](https://medium.com/@usexfg)
-   [Bitcoin Talk](https://bitcointalk.org/index.php?topic=2712001)

### Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Core** | CryptoNote | Ring-signature privacy at protocol level |
| **Core** | Dynamic Ring Size | 32, 16, or min 8 decoys per transaction, adaptive to pool depth |
| **Core** | Sub-addresses | Multiple addresses from single seed; integrated (v1) wallets |
| **Core** | Fire Aliases | 8 characters ONLY, on-chain '@' aliases for fire addresses; (@fuegoxfg for development) integrated with ecosystem wallets |
| **Assets** | ΗΞΔŦ flatcoin | XFG-colored coin pegged to purchasing power by rate of inflation on 1 USD since Q1|2009 value ⩰ $1.58 | Burn XFG to mint at pool price |
| **Assets** | Hearth Floor | Block-discrete on-chain exchange with adaptive-spread AMM pool band; batch-clears at VWAP |
| **Assets** | Certificates of Deposit | HEAT-denominated time-locked deposits earning yield from protocol fees |
| **Swaps** | Atomic Swaps | Cross-chain XFG swaps via COMIT protocol with PTLC/HTLC adaptor signatures |
| **Swaps** | ЅШ𑫛𑫒**❋**XFG | Integrated TUI, Go-based swap engine with inter-chain fee routing |
| **Network** | I2P / Tor  | Pluggable transport-layer privacy |
| **Wallet** | `fire_wallet`| Full-featured CLI: send, receive, deposits, HEAT mint/swap, pool operations |
| **Wallet** | TUI(suite) | Go-based terminal UI for atomic swaps, CD operations, HEAT mint |
| **GUI Wallet/SDK** | Fuego Valise | Cross-platform GUI (Flutter/Rust) — [fuego-valise](https://github.com/usexfg/fuego-valise) Fuego SDK |
| **Tools** | RPC API | JSON-RPC: heat_metrics, amm_quote, amm_pool_info, swap fees, CD queries |
| **Dev Tools** | MCP Server | AI-agent integration for swap/mint automation |
| **Dev Tools** | Fuego-Skills | AI-agent tools for codebase analytics, knowledge graph, and specialization |

_____________________________

<sup>"Working software is the primary measure of progress." [‣](http://agilemanifesto.org/)</sup>

##### Build Status :

[![Build check](https://github.com/usexfg/fuego-suite/actions/workflows/check.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/check.yml)
[![macOS](https://github.com/usexfg/fuego-suite/actions/workflows/macOS.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/macOS.yml)
[![AppImage Linux](https://github.com/usexfg/fuego-suite/actions/workflows/appimage.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/appimage.yml)
[![Ubuntu 24.04](https://github.com/usexfg/fuego-suite/actions/workflows/ubuntu24.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/ubuntu24.yml)
[![Ubuntu 22.04](https://github.com/usexfg/fuego-suite/actions/workflows/ubuntu22.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/ubuntu22.yml)
[![Windows](https://github.com/usexfg/fuego-suite/actions/workflows/windows.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/windows.yml)
[![Docker Images](https://github.com/usexfg/fuego-suite/actions/workflows/docker.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/docker.yml)
[![Android (Termux)](https://github.com/usexfg/fuego-suite/actions/workflows/termux.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/termux.yml)
[![Raspberry Pi (ARM64)](https://github.com/usexfg/fuego-suite/actions/workflows/raspberry-pi.yml/badge.svg)](https://github.com/usexfg/fuego-suite/actions/workflows/raspberry-pi.yml)

### Build Requirements

**Boost Version**: Fuego supports Boost 1.86+ (uses `io_context` — no legacy `io_service` dependency)

- **macOS**: `brew install boost` (1.90+)
- **Linux**: Uses system packages (1.74+ on Ubuntu 22.04, 1.83+ on Ubuntu 24.04)
- **Windows**: Uses vcpkg packages (1.84+)

**OpenSSL**: Supports OpenSSL 3.x and 4.x

**secp256k1**: External dependency — use system package or bundled submodule
- macOS: `brew install secp256k1`
- Linux: `apt install libsecp256k1-dev` or use the submodule at `external/secp256k1`
- CMake flag: `-DUSE_VENDORED_SECP256K1=OFF` to link against system secp256k1

### Linux (Ubuntu/Debian)

#### 1. Install Dependencies

```bash
sudo apt install build-essential git cmake libboost-all-dev libjsoncpp-dev libssl-dev libsecp256k1-dev
```

#### 2. Clone and Build

```bash
git clone --recursive https://github.com/usexfg/fuego-suite
cd fuego-suite && git submodule init && git submodule update
mkdir build && cd build
cmake .. -DUSE_VENDORED_SECP256K1=OFF
make -j$(nproc)
```

Binaries will be in `build/release/src/`. The Go TUI builds automatically if Go 1.24+ is installed.

#### 3. Start the Daemon

```bash
./build/release/src/fuegod
```

### macOS

#### 1. Install Dependencies

Install [Xcode](https://developer.apple.com/xcode/) and [Homebrew](https://brew.sh/), then:

```bash
xcode-select --install
brew install git cmake boost openssl secp256k1 jsoncpp
```

#### 2. Build

```bash
git clone https://github.com/usexfg/fuego-suite
cd fuego-suite
mkdir build && cd build
cmake .. -DUSE_VENDORED_SECP256K1=OFF
make
```

Binaries will be in `build/src/`.

### Windows

#### 1. Prerequisites

- [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16)
- [CMake](https://cmake.org/download/)
- [Boost 1.73.0 MSVC 14.2](https://sourceforge.net/projects/boost/files/boost-binaries/1.73.0/boost_1_73_0-msvc-14.2-64.exe/download)

When installing Visual Studio, include **Desktop development with C++** and **MSVC v142 - VS 2019 C++ x64/x86 build tools**.

#### 2. Build

From `x64 Native Tools Command Prompt for VS 2019`:

```bash
git clone https://github.com/usexfg/fuego-suite
cd fuego-suite
mkdir build && cd build
cmake .. -G "Visual Studio 16 2019" -A x64 -DBOOST_LIBRARYDIR="c:\local\boost_1_73_0\lib64-msvc-14.2"
msbuild fuegoX.sln /p:Configuration=Release /m
```

Binaries will be in `src/Release/`.

### Docker

```bash
docker build -t fuego .
docker run -p 11898:11898 -p 11899:11899 fuego
```

### Build Variants

| Command | Description |
|---------|-------------|
| `make` | Release build + TUI |
| `make build-release` | CMake release build |
| `make build-debug` | Debug build with symbols |
| `make build-static` | Static-linked build |
| `make build-tui` | Go TUI only |
| `make test-release` | Build and run tests |
| `make -j$(nproc)` | Parallel build (all cores) |

For Clang: `export CC=clang CXX=clang++` before `make`.

### Terminal User Interface (TUI)

Go-based TUI for swaps, wallet management, and CD operations. Requires Go 1.24+.

```bash
make build-tui
./tui/build/fuego-tui
```

Navigate with arrow keys or j/k, select with Enter, quit with q or Ctrl+C.

### ΗΞΔŦ Flatcoin & Hearth Exchange

ΗΞΔŦ is Fuego's flatcoin — a stable asset pegged to purchasing power. It is **not** pegged to a fiat currency; it is pegged to inflation rate over time beginning Jan 2009 ⩰ $1.58 ||  XFG/ΗΞΔŦ ratio at launch mints 10:1 (1 XFG ⩰ $0.15)

| Operation | CLI Command | Description |
|-----------|------------|-------------|
| Mint ΗΞΔŦ | `mint_heat <xfg_amount>` | Burn XFG to create ΗΞΔŦ at Hearth price |
| Swap | `swap <dir> <in> <out> <min>` | Swap XFG↔ΗΞΔŦ on Hearth at bid/ask spread |
| MM Pool Info | `pool_info` | Show exchange depth, MM pool orders, spread |
| ΗΞΔŦ Metrics | `heat_info` | Show ΗΞΔŦ supply, redemption price, treasury, CD yield |
| ΗΞΔŦ Balance | `balance` | Shows ΗΞΔŦ balance alongside XFG |

**Daemon RPC endpoints**: `/heat_metrics`, `/amm_quote`, `/amm_pool_info`, `/addswapfee`

**Key Properties**:
- Launch ratio 10:1 (1 ΗΞΔŦ = 10 XFG) at genesis
- Peg target $1.58 USD; mint premium hardcoded to **0 bps** (`HEAT_MINT_PREMIUM_BPS = 0`) — no premium, PI controller removed
- Protocol buys or mints ΗΞΔŦ for CD yield payments (structural demand, protocol pays 0% fee)
- On-chain exchange replaces constant-product AMM; MM pool orders regenerate each block ±10% depth
- Pool reserves tracked (as a whole) on-chain with unspendable pool keys

### Protocol Earnings 

There are exactly **two** protocol earnings streams

| # | Stream | Rate | Split |
|---|--------|------|-------|
| 1 | **Hearth swap fee** — on-chain Hearth DEX fills | **1%** per trade (`HEARTH_FEE_BPS = 100`) | → CD yield / LP per Hearth routing |
| 2 | **Atomic swap fee** — cross-chain swaps (SwapXFG TUI or DeXFG tab in Fuego-Wallet GUI) | **1% + 1% = 2%** per swap (`SWAP_FEE_RATE_BPS = 100` initiation + claim) | **69% CD Yield / 11% Bonus Vault / 20% Treasury** |

NOT protocol earnings:
- **Mint premium** — none (0 bps, `HEAT_MINT_PREMIUM_BPS = 0`), goes nowhere.
- **CD creation fee** — 0.1% of CD amount, donated to **@fuegoxfg** (Fuego Development Fund). Not protocol revenue, not CD yield, not treasury.

### Certificates of Deposit (CD) — V12 activation

Epoch (900 blocks) term-locked ΗΞΔŦ deposits earning real yield thru protocol revenue, not inflation. Each CD requires an upfront banking fee of a mere 0.1% of CD amount (fee also in ΗΞΔŦ) paid at time of CD creation (no fees at claim) and sent to **@fuegoxfg** as a donation to Fuego Development Fund.

| Command | Description |
|---------|-------------|
| `heat_deposit <amount> <term_epochs>` | Lock ΗΞΔŦ for epoch-based yield |
| `heat_withdraw <deposit_id>` | Redeem matured CD with accrued interest |
| `heat_list` | List active ΗΞΔŦ CDs and balance |

### Atomic Swaps (swapxfg)

Cross-chain XFG atomic swaps via COMIT protocol with DLEQ adaptor signatures. Fee routing bridges SwapDaemon into on-chain CD yield and treasury.

### Documentation

Comprehensive docs at [docs.usexfg.org](https://docs.usexfg.org) and in `docs/`:
- `getting-started/` — Onboarding
- `features/` — Feature guides
- `api-reference/` — RPC API
- `design/` + `developer/` — Architecture & protocols
- `security/` — Audits & hardening
- `HEAT_STABLECOIN_VISION.md` — ΗΞΔŦ economic design
- `ATOMIC_SWAP_PLAN.md` — Swap protocol plan
- `PRIVACY_ROADMAP.md` — Privacy milestones

### Advanced

- **Parallel build**: `make -j$(nproc)`
- **Debug build**: `make build-debug`
- **Tests**: `make test-release`
- **Static binary**: `make build-static`

---

For the most user-friendly graphic interface experience, see [Fuego Desktop Wallet](https://github.com/usexfg/fuego-valise).

_____________________________
<sup>Made with ❤️‍🔥 for Fuego Mob</sup>


Join Fuego's worldwide community [Discord](https://discordapp.com/invite/5UJcJJg), [Reddit](https://reddit.com/r/Fango), or [Twitter](https://twitter.com/usexfg).
