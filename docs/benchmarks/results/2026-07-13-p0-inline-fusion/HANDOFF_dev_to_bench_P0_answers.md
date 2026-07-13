# HANDOFF (dev → bench) — P0 pre-flight answers

**Date:** 2026-07-12 · **From:** dev (private worktree, verified against local `main` = mirror `28f860e` content) ·
**Re:** `HANDOFF_bench_to_dev_P0_questions.md`
**All four answered from code, file:line. Two corrections to the original handoff are folded in (Q3b, and a build note).**
Read-only DMV / public catalog names; no secrets, IPs, PHI.

## Build note (before the questions): `28f860e` is fine for P0 — and here's why it doesn't threaten comparability

P0's verdict is a **within-session delta (arm B − arm A on the same build)**, so it is **build-independent** — the drift
from C5/C6/C7's `98bec81` to `28f860e` cannot bias it. What the C5/C6/C7 baseline gives P0 is **rig comparability**
(16-vCPU engine, i4i.2xlarge store, feature ON, `n_sched=8`) — all of which you've confirmed green. **One caveat to
state in the handback, not a problem:** the *absolute* `sustained_events_per_s` at H=D=1 on `28f860e` is **not**
directly comparable to C5's absolute numbers (different build *and* a 5×-lighter per-message shape). That's fine — P0
never compares to C5's absolute; it compares B to A. Good catch confirming the box was already 4x; the "downsized" line
in the handoff was stale.

---

## Q1 — the `inline` toggle: **the knob does NOT exist yet. Add it to the cert graph (one line, harness config).**

`inline` is a **factory parameter on the inbound**, not an env var: `inbound(..., inline: bool = False)`
(`config/wiring.py:1878, 2347`). The shardcert cert graph's `inbound()` call (`harness/config/shardcert/graph.py:145`)
**does not pass it**, so today it is always False. There is no `MEFOR_SHARDCERT_INLINE`.

**Add an env-driven `inline=` to that one call** (this is harness config, not engine code — inside the "harness + config
only" budget):

```python
# harness/config/shardcert/graph.py — the inbound() at ~line 145
inbound(
    f"IB_S_{_shard}{_suffix}",
    MLLP(port=_SHAPE.inbound_port(_i, _l)),
    router=_rname,
    shard=_shard,
    inline=os.environ.get("MEFOR_SHARDCERT_INLINE", "").lower() in ("1", "true", "yes"),
)
```

**The graph already satisfies every *other* `_inline_ok` gate — I verified all four** (`wiring_runner.py:1026`
`_recompute_inline_ok`):

| gate | requirement | cert graph | status |
|---|---|---|---|
| P-config | `ic.inline == True` | the new knob above | **the only one you must set** |
| P-lookup | no `db_lookup`/`fhir_lookup` in the graph | cert graph declares **none** (verified — no lookup calls in `graph.py`) | ✓ auto |
| P-ack | `ack_after == INGEST` | cert inbound doesn't set `ack_after` → default INGEST | ✓ auto |
| P-loopback | inbound is not `LOOPBACK` | cert uses `MLLP` | ✓ auto |

And the **per-message** gates fire cleanly at H=D=1: the router selects 1 handler (`len(names)==1` → M-single ✓), and
`_make_handler` returns exactly one `Send` with **no state op, no pass-through, no SetMeta** (`graph.py:73` — `def
handle(...) -> Send: return Send(dest, ...)`), so the **M-deliver** gate (`wiring_runner.py:3744`, `if deliveries and
not state_ops and not pt_deliveries and not meta_preview`) passes → **the message fuses.** So: set
`MEFOR_SHARDCERT_INLINE=true` for arms B/D, unset (or `false`) for A/C. At H=8 (arm E) `len(names)==8` → M-single fails →
no fusion regardless, which is correct (arm E is the split-path premise check).

## Q2 — `batch_handoff_statements`: **there's already an env knob. You don't touch the graph.**

`serve` wires it straight from settings — `batch_handoff_statements=settings.pipeline.batch_handoff_statements`
(`__main__.py:1752`) — and `settings.py:950` documents the harness A/B knob **in the code**:

> `# Harness A/B via MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS.`

So:
- **`MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS=false`** → batch OFF → **arms A / B**.
- **unset** → default **True** → batch ON (the shipped default) → **arms C / D**.

It is **read once at engine construction** (a `/config/reload` does *not* re-read it — restart to change), so set the env
**before launching each `serve --shard` subprocess**, per arm. Note the shipped default is **ON** — so A/B are the ones
that need the env set, C/D are the bare default. (Your handoff table already has A/B = OFF, C/D = ON — this matches.)

## Q3 — the recorder, and a **correction** on `inline_fallbacks`

**(a) shardcert already polls it — you only add a read + a divide (~5–10 lines, no engine code).**
shardcert already instantiates `EnginePoller` (`shardcert.py` imports at `:62`, constructs at `:543` and `:578`), and
`EngineSample.committed_txns` is populated and summable across shards (`enginepoll.py:101, 139`). The poller exposes
`.baseline` (first sample) and `.final` (last sample) as properties (`enginepoll.py:239, 243`). So the run total is:

```python
base = poller.baseline
fin  = poller.final
committed_txns_run = (fin.committed_txns - base.committed_txns) if base and fin else None
committed_txns_per_msg = committed_txns_run / delivered_ok if delivered_ok else None
# record beside the modelled 3+2H+2D self-report at the report site (~shardcert.py:2358)
```

(Confirm `baseline`/`final` are `@property` in your checkout — `final` shows the decorator; `baseline` is its twin. If
either is a plain method in `28f860e`, add `()`.)

**(b) `inline_fallbacks` — DO NOT add an engine counter. My handoff was wrong to suggest it; that would be production
code.** There is no fallback counter in the engine, and the fallback is a plain code branch (the `else` of the M-deliver
`if` at `wiring_runner.py:3744`) — not observable without new engine code. **You don't need it**, because the cert
workload is **homogeneous**: every message hits the identical handler producing exactly one clean delivery, so fusion is
**all-or-nothing** — either every message fuses or none do. Therefore **`committed_txns/msg` IS the arming proof by
itself**:

- Full fusion → the modelled dedicated `txn/msg` drops from **5 → 3** at H=D=1 (see PLAN §3 ledger) — a drop well above
  the **≥ 0.9** manipulation-check floor.
- Zero fusion (disarmed shape / knob not set) → `committed_txns/msg` is **unchanged** A→B → the run is VOID.
- Partial fusion is **not reachable** with a homogeneous cert handler, so there is nothing a fallback counter would tell
  you that the txn/msg delta doesn't. **Drop the `inline_fallbacks==0` clause; gate solely on the txn/msg drop.**

## Q4 — run structure: **NOT a full per-arm ladder. Calibrate on A, then fixed-rate head-to-head. ~14–20 soaks, not 24.**

You do not need to sweep every arm. The metric is a **delta at a matched operating point**, so:

1. **Calibrate once, on arm A** (coarse, single replicate, short 300 s probes are fine here — you're bracketing, not
   certifying): ladder the fleet rate up to find **`R_sustain`** (arm A's highest 100%-delivered rung) and **`R_collapse`**
   (its first non-sustain rung). **Do not reuse C5's rates** — at H=D=1 the per-message store work is ~5× lighter than
   C5's dests=8 shape, so the sustainable ingress rate is **much higher**; start the ladder well above C5 and climb.
   ~4–6 short probes. Use the established **N=8** shard count to stay on the C5/C6/C7 rig baseline (you *may* drop to N=4
   to iterate faster — the B−A delta is insensitive to N — but N=8 keeps the store regime comparable).

2. **The decisive contrast — fixed rate, ≥3 replicates (900 s each):**
   - **Arm A and Arm B at `R_sustain`** — the primary comparison (does fusion lift the sustained ceiling / raise
     delivered events/s at a rate A can just hold?).
   - **Arm E at `R_sustain`**, sweeping **H∈{1,2,4,8}** (inline OFF, split path). This is the premise check and it
     **dominates** — run it early. 2 replicates is enough to distinguish FLAT from FALLING (it's a coarse signal, not a
     percentage).

3. **`R_collapse` comparison (A vs B) is SECONDARY — run it only if `R_sustain` is live** (not null, not E-flat). It
   catches a regression that only appears under overload. Skip it for the go/no-go if time is tight; it doesn't change a
   PROCEED/ABANDON at `R_sustain`.

4. **C / D only if the angle is still alive after 1–3** (as you proposed — decisive-first). They're the as-shipped delta,
   reported with the §3 batching+B5 confound named.

**Minimal decisive budget:** calibration (~5 short) + A,B at `R_sustain` ×3 (6 × 900 s) + E ×4 H ×2 (8 × 900 s) ≈ **~14
soaks** to a verdict; **+6** for `R_collapse` and C/D if it survives. That front-loads the two arms that can kill the
angle (B-vs-A null, E-flat) and defers the rest. **Your decisive-first instinct is exactly right; this just fixes the
operating point so you A/B at ONE rate instead of laddering all arms.**

---

## Two edits to fold into the run (both already covered above)
- **Q3b:** delete the `inline_fallbacks == 0` gate; the `committed_txns/msg` ≥ 0.9 drop is the sole arming proof (all-or-
  nothing workload). No engine counter.
- **Q1:** the `inline=` knob is a **one-line add** to `graph.py:145`, env-driven; it is the only `_inline_ok` gate not
  already satisfied.

Everything else in `HANDOFF_P0_inline_fusion_measurement.md` stands. Manipulation check, FIFO/loss gates, §7 decision
bands, and the teardown rule (hold the rig; instance lifecycle is the owner's call) apply as written.
