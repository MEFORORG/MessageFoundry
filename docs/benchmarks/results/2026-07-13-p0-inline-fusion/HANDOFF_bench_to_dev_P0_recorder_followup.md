# HANDOFF (bench → dev) — P0 follow-up: the exact `committed_txns` recorder diff (one precise question)

**Date:** 2026-07-12 · **From:** AWS bench (relay via operator) · **Re:** your P0 answers (Q3a)
Everything else from your answers is applied/understood — this is the only open item, and it's the manipulation-check
instrument, so I want your exact diff rather than a guess. All on mirror `28f860e`.

## Done / understood
- **Q1 inline knob: APPLIED** — `graph.py` now has `import os` + `inline=os.environ.get("MEFOR_SHARDCERT_INLINE","")…`
  on the `inbound()` at :145. Good.
- **Q2 batch:** `MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS=false` per-arm (A/B), unset for C/D. No code change. Understood.
- **Q3b:** dropping `inline_fallbacks` entirely (homogeneous all-or-nothing; `committed_txns/msg` is the sole arming proof). Understood.
- **Q4 run structure:** calibrate `R_sustain` on A (short 300 s probes, start well above C5), then A/B @ `R_sustain` ×3 +
  E ×2/H; C/D + `R_collapse` conditional. Understood.

## The one open item — Q3a: which report, which build site, exact lines
Your "record beside the `3+2H+2D` self-report (~shardcert.py:2358)" pointed at a **@property**, but I found the wiring
spans two report classes and I want to patch the right one:

- **`ShardCertReport`** (single-box, dataclass ~:843 build) — `final = poller.final` is right there (:817), one clean
  build site. But this is the *single-box* report.
- **`ShardCertDriveReport`** (dataclass @2313; `to_json_dict` @2448; `"kind": "shardcert_drive"`) — the **two-box drive**
  report, built at :1052 / :1094 / :2751. P0 runs the **two-box ladder** (C5/C6/C7 used it; its top-level JSON was
  `"kind": "shardcert_ladder_two_box"`, aggregating per-soak drive reports). So I believe the recorder belongs on the
  **two-box** soak report, not the single-box one.

**Please confirm the target and give the exact diff:**
1. Which report class does P0's decisive two-box soak actually emit — `ShardCertDriveReport`, or does the two-box
   ladder produce/aggregate a different record I should target? (I want `committed_txns/msg` in the JSON the go/no-go reads.)
2. At the correct build site, is `poller.baseline`/`poller.final` (or an equivalent EngineSample pair) in scope so I can
   set `committed_txns_run = final.committed_txns - baseline.committed_txns`? If the two-box drive doesn't carry the
   engine poller (it reads `/stats` remotely), where does the summed `committed_txns` arrive?
3. The exact lines: the new field (default `None`, older-engine-safe), the `committed_txns_per_msg` property (÷ `acked`,
   the ingress-message count — confirm that's the right denominator vs `sink_received`), the build-site population, and
   the `to_json_dict` entry.

If a **standalone `/stats` committed_txns poll** (like the C6 store sampler, but hitting the engine shard `/stats` at
soak start/end) is what you'd actually do instead, say so and point me at how to enumerate the shard `/stats` URLs in
the two-box run — I'll take whichever you consider correct.

Bench is holding the recorder + all arms on this. Inline knob applied, batch/shape/run-structure ready to go the moment
this is nailed. Read-only DMV/public catalog names; no secrets/IPs/PHI.
