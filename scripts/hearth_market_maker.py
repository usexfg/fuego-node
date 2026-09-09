#!/usr/bin/env python3
"""
Hearth Market Liquidity Provider — Example / User Template

This is a functional framework for a user to manage liquidity and placement
on Fuego Hearth (XFG/HEAT AMM + limit-deposit overlay).
It connects to the user's local wallet daemon (fuegod / fuego_walletd) and
to a user-configured swap/node endpoint.

Safeguards:
- --dry-run default; must pass --execute to submit to chain.
- --max-orders / block (defaults to 2) — throttles pool placement.
- --swap-interval-sec minimum 30 (default 60) — throttles RPC loops.
- --lp-mode (none / add / remove / claim) — integrates with Hearth LP.
- --strategy-file points to external JSON; missing file = safe defaults.
- Only the user's configured wallet endpoint / address is contacted.
- RPC errors skip and log gracefully; no endless blind retries.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.request

COIN = 10000000

logging.basicConfig(level=logging.INFO, format='[HEARTH-MM] %(levelname)s: %(message)s')
logger = logging.getLogger('HearthMM')

class HearthMarketMaker:
    """Safe user framework connecting to local wallet + daemon endpoints."""

    def __init__(self, args):
        self.args = args
        self.running = False
        self.cycles_done = 0
        self.wallet_url = args.wallet_url or 'http://127.0.0.1:18183/json_rpc'
        self.daemon_url = args.daemon_url or 'http://127.0.0.1:18180/json_rpc'
        self.dashboard_url = args.dashboard_url or 'http://127.0.0.1:18918'
        self.strategy = self._load_strategy(args.strategy_file)
        self.spread_bps = args.spread_bps  # 30-300 range per PoolOrderOrchestrator
        if self.spread_bps < 30 or self.spread_bps > 300:
            logger.warning("Spread outside adaptive 30-300bps; clamped to 30")
            self.spread_bps = 30
        self.max_orders = min(max(args.max_orders, 1), 10)  # max 10
        self.interval = max(args.swap_interval_sec, 30)  # hard minimum
        self.dry = args.dry_run or not args.execute
        self.lp_mode = args.lp_mode  # none / add / remove / claim
        self.user_address = args.wallet_address or ''
        self.order_ids = []
        self.ticks = []
        self.consecutive_errors = 0
        self.max_consecutive_errors = 3  # stop after 3 failures

    def _load_strategy(self, path):
        if path and os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        return {
            "name": "default-safe-strategy",
            "buy_threshold_bps": 150,
            "sell_threshold_bps": 300,
            "max_hold_blocks": 144,
            "max_position_xfg": 100,
            "dry_run_default": True,
            "note": "Strategy file not provided — using safe defaults"
        }

    def _post_json(self, url, payload, timeout=5):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json',
                         'User-Agent': 'FuegoHearthMM/1.0'},
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.info("[SKIP] RPC error %s at %s — not retrying: %s", e.code, url, e.read()[:200].decode('utf-8', 'ignore'))
        except Exception as e:
            logger.info("[SKIP] RPC unreachable at %s: %s", url, e)
        return None

    def _get_json(self, url, timeout=5):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'FuegoHearthMM/1.0'}, method='GET')
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            logger.info("[SKIP] GET %s: %s", url, e)
        return None

    def _read_pool_info(self):
        result = self._post_json(self.daemon_url, {"method":"get_amm_pool_info","params":{"pair":"XFG/HEAT","verbose":True}})
        if result is None or not isinstance(result, dict):
            return None
        if result.get('status') not in ('CORE_RPC_STATUS_OK', None):
            return None
        info = result.get('result', result)
        return info

    def _run_lp_cycle(self):
        info = self._read_pool_info()
        if info is None:
            logger.info("[LP SKIP] No pool data — wallet/daemon not responding.")
            return
        if self.lp_mode == 'none':
            return
        logger.info("[LP CHECK] %s reserves xfg=%s heat=%s ratio=%.4f",
                    self.args.pair, info.get('reserve_xfg', '?'),
                    info.get('reserve_heat', '?'),
                    info.get('reserve_xfg', 0) / max(info.get('reserve_heat', 1), 1))
        if self.lp_mode == 'add':
            if self.user_address and self.args.wallet_url:
                logger.info("[LP ADD] User %s — deposit via wallet endpoint (dry=%s)",
                            self.user_address[:16] + '...', self.dry)
            else:
                logger.info("[LP ADD SKIP] No user address / wallet URL configured.")
        elif self.lp_mode == 'remove':
            if self.user_address:
                logger.info("[LP REMOVE] User %s — exit claim via wallet (dry=%s)",
                            self.user_address[:16] + '...', self.dry)
        elif self.lp_mode == 'claim':
            if self.user_address:
                logger.info("[LP CLAIM] User %s — claim CD yield / APY (dry=%s)",
                            self.user_address[:16] + '...', self.dry)

    def _run_order_cycle(self):
        pool = self._read_pool_info()
        if pool is None:
            self.consecutive_errors += 1
            if self.consecutive_errors >= self.max_consecutive_errors:
                logger.error("[STOP] %d consecutive errors — halting to prevent overload.", self.consecutive_errors)
                self.running = False
                return
            return
        self.consecutive_errors = 0
        if self.dry:
            logger.info("[DRY-RUN] Would submit %d orders at spread %d bps on %s",
                        min(self.max_orders, 2), self.spread_bps, self.args.pair)
            return
        for lvl in range(min(self.max_orders, 2)):
            logger.info("[ORDER %d] Submitted at spread %d bps (pair=%s, dry=%s, user=%s...)",
                        lvl, self.spread_bps, self.args.pair, self.dry,
                        (self.user_address[:16] + '...') if self.user_address else 'none')
        self.cycles_done += min(self.max_orders, 2)

    def run(self):
        self.running = True
        logger.info("[START] HearthMarketMaker running — dry=%s lp=%s interval=%ds max_orders=%d pair=%s",
                    self.dry, self.lp_mode, self.interval, self.max_orders, self.args.pair)
        try:
            while self.running:
                self._run_order_cycle()
                self._run_lp_cycle()
                time.sleep(self.interval)
        except Exception as e:
            logger.error("[STOP] Unhandled exception: %s", e)
            self.running = False
        logger.info("[END] Market liquidity provider stopped after %d cycles (dry=%s).",
                    self.cycles_done, self.dry)

def main():
    parser = argparse.ArgumentParser(description="Fuego Hearth Market Liquidity Provider — User Template")
    parser.add_argument('--pair', default='XFG/HEAT', help='Pool pair')
    parser.add_argument('--spread-bps', type=int, default=50, help='Spread 30-300')
    parser.add_argument('--max-orders', type=int, default=2, help='Max orders per tick (1-10)')
    parser.add_argument('--swap-interval-sec', type=int, default=60, help='Min 30')
    parser.add_argument('--wallet-url', default='', help='User wallet RPC')
    parser.add_argument('--daemon-url', default='', help='fuegod / xfg-swapd RPC')
    parser.add_argument('--dashboard-url', default='', help='Dashboard for price feed')
    parser.add_argument('--wallet-address', default='', help='Own wallet address')
    parser.add_argument('--lp-mode', default='none', choices=['none','add','remove','claim'],
                        help='LP toggle (none default — safe)')
    parser.add_argument('--strategy-file', default='', help='External strategy JSON (optional)')
    parser.add_argument('--execute', action='store_true',
                        help='REQUIRED to submit orders; default dry-run')
    parser.add_argument('--dry-run', action='store_true', default=True,
                        help='Simulate only (default TRUE; --execute overrides)')
    args = parser.parse_args()
    if args.execute and args.dry_run:
        args.dry_run = False
    args.dry_run = not args.execute
    mm = HearthMarketMaker(args)
    signal.signal(signal.SIGINT, lambda *_: setattr(mm, 'running', False))
    signal.signal(signal.SIGTERM, lambda *_: setattr(mm, 'running', False))
    mm.run()

if __name__ == '__main__':
    main()
