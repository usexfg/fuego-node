# HEARTH MM Strategy — EIEO Reference Framework

> User-provided framework. **Not a copy of proprietary strategy content.**
> The proprietary EIEO materials (Introduction / Syllabus / Pattern Recognition /
> Steps / Videos) remain under copyright by the original author (SMFX / _SMFX_ /
> @ProjectEffingo / https://www.eieostrategy.com/indicator). Do NOT distribute,
> reproduce, or claim ownership of those works.

This document only describes the **JSON schema** that `scripts/hearth_mm_bot_safe.py`
loads via `--strategy-file`. The user builds and owns their own strategy file.
No content from the copyrighted PDFs is reproduced here.

---

## Field Spec (user provides this JSON; bot applies safe defaults if missing)

```json
{
  "name": "EIEO-example-user-built",
  "version": 1,
  "author_note": "Built by user from their own EIEO study; not a service.",
  "buy_threshold_bps": 150,
  "sell_threshold_bps": 300,
  "max_hold_blocks": 144,
  "max_position_xfg": 100,
  "max_spread_bps": 300,
  "min_spread_bps": 30,
  "dry_run_default": true,
  "exit_on_loss_bps": 500,
  "volume_target_hint": 0,
  "source_reference": "https://www.eieostrategy.com/indicator",
  "source_twitter": "https://www.Twitter.com/_SMFX_"
}
```

## How the bot uses it (from docs/PTLC_FLUTTER_PLAN.md F4 + scripts/hearth_mm_bot_safe.py)

```
if strategy_file exists:
   load JSON → set bot params (spread, thresholds, max_hold)
else:
   use safe defaults (tight spread, quick exit, conservative position)
# Always: dry-run by default; never claim synthetic volume; only own wallet
```

## What this is NOT
- Not a copy-trading service.
- Not generated market data.
- Not an external-order relay (only user's configured wallet endpoint).
- Not a replacement for the user's own study of Intro/Syllabus/Pattern/Steps.

The user should watch from the beginning at https://www.Youtube.com/SMFXAnalytics
and use https://www.Twitter.com/_SMFX_ for updates — then encode their own
findings into this JSON.

---

*This framework is the user's own example. All proprietary EIEO content stays
with SMFX / @ProjectEffingo / eieostrategy.com.*
