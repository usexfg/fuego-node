# Hearth Market Liquidity Guide

> User guide for operating liquidity management on Fuego Hearth (XFG/HEAT AMM + limit-deposit overlay).

## 1. Liquidity Management Overview

Hearth combines a constant-product AMM with a limit order overlay.
Participants can provide liquidity directly or place limit-deposit commitments.

## 2. Using `scripts/hearth_market_maker.py`

`scripts/hearth_market_maker.py` provides a Python script to interact with your local node and wallet daemon:

```bash
# Dry-run mode (default)
python3 scripts/hearth_market_maker.py --dry-run --pair XFG/HEAT --lp-mode none --max-orders 2 --strategy-file docs/strategies/market_maker_config.json

# Execution mode against local daemon
python3 scripts/hearth_market_maker.py --execute --pair XFG/HEAT --lp-mode add --wallet-address fire... --wallet-url http://127.0.0.1:18183/json_rpc --daemon-url http://127.0.0.1:18180/json_rpc
```

## 3. Safety Rails

- `--dry-run` is default; `--execute` must be explicitly passed.
- `--max-orders` capped between 1 and 10 per cycle.
- `--swap-interval-sec` minimum 30 seconds to prevent RPC spam.
- Skips gracefully on any RPC failure.
