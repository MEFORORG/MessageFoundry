# HANDOFF (bench → dev) — P0 pre-flight questions before the harness patch

**Date:** 2026-07-12 · **From:** AWS bench (relay via operator) · **Re:** `HANDOFF_P0_inline_fusion_measurement.md`
**Purpose:** four specifics I can't resolve from the pinned mirror alone, before I write the recorder patch and commit
a ~multi-hour run on a build-gating experiment. Everything else in the doc I'll follow as written.

## Bench-side pre-flight status (all green)
- **P0 build = public mirror `28f860e`** (you published it 17:41; supersedes `98bec81` for P0). Confirmed present on it:
  `committed_txns` in `messagefoundry/store/sqlserver.py` **and** `harness/load/enginepoll.py` (polled from `/stats`,
  getattr-safe, summed across shards, cumulative → run total = last−first); fusion gate at
  `messagefoundry/pipeline/wiring_runner.py:3712` (`if inline and len(names) == 1:`).
- **Feature ON** (`IsTempdbMetadataMemoryOptimized=1`, `tempdb_xtp` pool @25%), **engine box m7i.4xlarge** (the "downsized
  to 2x" note was stale — it's already 4x), store i4i.2xlarge (`n_sched=8`).
- **Disarmed-arm trap verified avoided:** `names = route_only(...)`; at `H=D=1` the router selects 1 handler →
  `len(names)==1` → the gate fires. At the default `H=8` it never fires (confirmed).

## My planned approach (please sanity-check against the doc's intent)
- **Shape `H=D=1`** via `MEFOR_SHARDCERT_HANDLERS/DELIVERING/DESTS=1`; **arm E** = `HANDLERS∈{1,2,4,8}, DELIVERING=1,
  DESTS=1, TRANSFORM=cheap`.
- **Staged decisive-first:** arms **A, B (primary), E (dominates)** at ≥3 replicates → early verdict; then C/D if still live.
- **Recorder patch (~20 lines):** capture the enginepoll `committed_txns` delta across the soak, divide by delivered
  messages, add `committed_txns_per_msg` to the report JSON beside the modelled `3+2H+2D` self-report (`shardcert.py:2358`).

## The four questions (where your private-worktree + author context is authoritative)
1. **`inline` toggle.** What is the exact mechanism to set `inline` **ON** (arms B/D) vs **OFF** (arms A/C) for a
   shardcert run at H=D=1 — an env var, a graph-config flag, an inbound param? And does the shardcert certification
   graph satisfy the **graph-level `_inline_ok` gates** (no live lookup, `ack_after=ingest`, not LOOPBACK) so `inline`
   actually engages? (I see the per-message gate but not the harness knob that sets the inbound opt-in.)
2. **`batch_handoff_statements` toggle.** How does a shardcert run set it **OFF** (A/B) vs **ON** (C/D)? `PipelineSettings`
   defaults it True; the API param defaults False — which path does the shardcert serve use, and how do I force each per arm?
3. **`committed_txns` recorder + `inline_fallbacks`.** (a) Does shardcert already snapshot enginepoll at soak start/end,
   or do I add the T0/T1 capture? Confirm the exact report site. (b) `inline_fallbacks` isn't in the mirror — where does
   the fused path fall back to split, and is there a **harness-observable** way to count fallbacks (zero engine code), or
   does it need one additive engine counter? What did you intend by "add it alongside the txn recorder"?
4. **Run structure / scale.** Does each P0 arm need a **rate ladder** (to yield the "last 100%-delivered rung AND the
   collapse rung", §7) like the C5 runs, or a **single fixed-rate 900 s soak** at H=D=1? What rate(s)/rungs? This sets
   the whole scale (my current estimate: ~24 soaks ≈ ~9 h serial; I'd like to confirm before committing).

**Bench is HOLDING** the patch + all arms until these are answered — to avoid a void/wrong run on a build-gating call.
Manipulation check (`committed_txns/msg` drop ≥0.9 A→B; `inline_fallbacks==0` in B/D), FIFO/loss gates, and the §7
decision bands will be applied exactly as written. Read-only DMV/public catalog names; no secrets/IPs/PHI.
