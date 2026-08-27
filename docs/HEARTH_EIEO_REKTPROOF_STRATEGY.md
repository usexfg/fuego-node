# Hearth EIEO + RektProof — Market Structuring Guide

> User-built example: how one participant structures Hearth order flow using EIEO basics + RektProof multi-bias.
> No copy of proprietary EIEO PDFs. No claim of synthetic volume. Only own wallet, hard limits, `dry-run` default.
> Hearth is a CLOB with pool-injected liquidity, batch-matched per block at `P_clear` (`MIN_DISTINCT_PARTIES=2`, adaptive spread 30-300bps). This bot acts as a participant, not the exchange.

## 1. What we take from EIEO (basics only — own wording)

- **POI (point of interest)**: prior supply/demand, equal highs/lows, or a base that contained `BB`/`DC`. Hearth: prior CLOB levels from `OrderbookMempool` + `PoolOrderOrchestrator` spread.
- **Sweep**: wick beyond a POI high/low that takes buy/sell stops. Hearth: `Htlc`/`AmmPool` `spot_price` wick beyond `orderbook` `bids/asks` level on 1m/5m `candles` from `dashboard/static/js/hearth.js`.
- **BB (broken base)**: `sweep of liquidity at POI` → `break and close beyond the low that swept the high` → `Broken Base Range = lowThatSweptHigh .. newLocalHigh`. Confirmed on **close** beyond that low. `PoolOrderOrchestrator` still injects pool depth; BB is read-only participant signal.
- **DC (double confirmation)**: `sweep of a high that sits INSIDE a BB range` → `break below that swept low` → `DC Range = that low .. new local high`. Entry `limit at DC Range Low`, stop just above `DC Range High`. Never trade a third confirmation (chop).
- **RS vs FS (real vs fake sweep)**: subjective. Heuristic for bot: `FS` after obvious `DC` distribution or during trend with obvious objectives still ahead → ignore single sweep. `RS` is second sweep following distribution. Bot tags both and prefers `DC` over single `BB`.

## 2. What we take from RektProof (public timeline, own summary)

From `threadreaderapp.com` threads `1247567599`, `1291615193`, `1412955497`:

- **Multi-bias per timeframe** — have a game plan per `HTF / Mid / LTF`, not one-sided. Hearth: keep three concurrent biases.
  - `HTF Resistance`: `Weekly S/R` + `Daily/H12 Supply` distribution → look for range + distribution.
  - `Mid directional`: `Daily demand` with `H12-H4` breaker retest → trend continuation.
  - `LTF scalp`: `key level` + `ltf range` + `sweep` → swing-point scalp both sides.
- **Ranges + deviations**: mark `swing low/high` range, wait for `sweep/deviation` of `range high/low` → close back inside → `MSB` → retest `SD`.
- **Supply/demand as confirmation**, not blind limits: wait for `BB/DC` **at** the level before entering.
- **Inside/outside objectives (IRO/ORO)**: `IRO` inside prior distribution, `ORO` beyond `equal highs/lows` just outside. Hearth: `IRO` = prior `VMR`/`Battlematch` `heat_metrics` pool price; `ORO` = `equal lows` just below `DC Range Low`.

## 3. How this structures Hearth while it gains users

- **We are a participant** providing real two-sided `limit_deposit` commitments (no unbacked orders, no gossip) up to `max_orders 10` per block, spread `30-300bps` matching `PoolOrderOrchestrator`. We do **not** claim exchange volume.
- **We piggy-back order flow**: at `HTF Supply` wait for `BB` retest → `DC` inside `BB` → limit at `DC Range Low`. On trend: after `KSRP` above `key swing high` + distribution, wait for `FVG`/`breaker` and `DC` with obvious `ORO` ahead. This is participation, not manipulation: `MIN_DISTINCT_PARTIES=2` forces counterparty.
- **We do not rug**: `max_position_xfg` cap, `max_hold_blocks 144` (bootstrap window), stop above `DC Range High`, `max_spread_bps 300`, `consecutive_errors 3 → halt`, `dry_run` default `true` — user must `--execute`.

## 4. Bot wiring (real)

`scripts/hearth_mm_bot_safe.py` already exposes:

- `--pair XFG/HEAT` `--spread-bps 30..300` `--max-orders 1..10` `--swap-interval-sec ≥30` `--wallet-url --daemon-url --dashboard-url --wallet-address`
- `--lp-mode none/add/remove/claim` (`Hearth LP` `hearth_add/exit` via wallet `fuego_rpc_service`)
- `--strategy-file docs/strategies/eieo_heartbeat.json` → loads `buy_threshold_bps/sell_threshold_bps/max_hold_blocks/max_position_xfg/exit_on_loss_bps` plus `eieo: {poi_timeframes, sweep_lookback, bb_confirm_closes, dc_prefer_over_bb, fvg_filter, session_utc}`

New EIEO-aware fields (add to that JSON, safe defaults if missing):

```json
{
  "name": "hearth-eieo-rektproof-user",
  "version": 1,
  "author_note": "User-built from own EIEO study + RektProof multi-bias; not a copy service",
  "pair": "XFG/HEAT",
  "spread_bps": 50,
  "max_orders": 2,
  "swap_interval_sec": 60,
  "lp_mode": "none",
  "buy_threshold_bps": 150,
  "sell_threshold_bps": 300,
  "max_hold_blocks": 144,
  "max_position_xfg": 100,
  "exit_on_loss_bps": 500,
  "eieo": {
    "poi_timeframes": ["H12","H4","M15"],
    "sweep_lookback": 20,
    "bb_confirm_closes": 1,
    "dc_prefer_over_bb": true,
    "fs_filter": true,
    "fvg_filter": true,
    "session_utc": ["08:00-11:00","12:00-14:00","17:00-19:00","23:00-01:00"],
    "timeframe_bias": {"htf":"supply","mid":"trend","ltf":"range"}
  },
  "rektproof": {
    "htf_resistance": "Weekly S/R + Daily/H12 Supply",
    "mid_bias": "Daily demand breaker retest",
    "ltf_scalp": "LTF range sweep + MSB",
    "objectives": ["IRO: prior distribution","ORO: equal lows/highs outside"]
  },
  "dry_run_default": true,
  "source_reference": "https://www.eieostrategy.com/indicator",
  "source_twitter": "https://www.Twitter.com/_SMFX_"
}
```

Bot reads `eieo.*` and `rektproof.*` only as parameters — no proprietary PDF text is copied.

## 5. Safety rails (Hearth + network)

- `OrderbookMempool::expireOrders` respected; `generatePoolOrders()` spread caps 300bps — bot never undercuts below 30bps.
- `MIN_DISTINCT_PARTIES=2` prevents self-match wash.
- `max_position_xfg` + `max_orders` + `swap_interval_sec` throttle RPC: single-thread `urllib.request` 5s/10s timeout, skip on any `HTTPError`, stop after 3 consecutive errors — no overload, no strain on `fuegod`/`xfg-swapd`/`dashboard`.
- Only `wallet_address` configured by user; no external peer relay; no secp point reuse across swaps (`presigSessionHash(T)`).
- `dry_run true` unless `--execute`; logs state only, never claims synthetic volume.

## 6. How to run

```bash
python3 scripts/hearth_mm_bot_safe.py --dry-run --pair XFG/HEAT --lp-mode none --max-orders 2 --strategy-file docs/strategies/eieo_heartbeat.json
python3 scripts/hearth_mm_bot_safe.py --execute --pair XFG/HEAT --lp-mode add --wallet-address fire... --wallet-url http://127.0.0.1:18183/json_rpc --daemon-url http://127.0.0.1:18180/json_rpc
```

No proprietary distribution. User builds file, owns file.
