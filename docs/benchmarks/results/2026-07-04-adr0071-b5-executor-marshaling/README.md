# ADR 0071 (B5) — executor-marshaling wall: profile + micro-bench (2026-07-04)

Evidence for [ADR 0071](../../../adr/0071-cut-executor-round-trips-b5.md) — "cutting per-message
executor round-trips." Synthetic HL7 only, no PHI.

## Files

- `PROFILE_FINDINGS.md`, `engine_flame.svg`, `profile_run.json` — the py-spy profile of a single
  pooled **SQL Server** engine at its ~107 msg/s ceiling. Names the wall as **per-completion
  executor→loop marshaling + the Windows Proactor self-pipe (`_write_to_self`) wakeup** on the
  off-loop hops/message, with **CPU idle (2/8 cores) and the store idle** — neither is the ceiling.
  *Caveat:* py-spy 0.4.2 partial 3.14 support — the flame resolves fully but `--gil` could not be
  captured; GIL-boundedness is inferred (single-loop-thread chain + per-thread CPU).

- `b5_microbench.py` — the **SQLite / Windows-Proactor** mechanism micro-bench. **It now lives here**
  (it was operator-local for the ADR-evidence PR; it lands with the B5 build here, lint/format-clean).
  It is **mechanism-only** (self-contained; does **not** import `messagefoundry`; CPU analogs of
  `route_only`/`transform_one` with **real committed SQLite** writes), pins `ProactorEventLoop`
  (SKIPs off-Windows, returning 2), counts `call_soon_threadsafe` crossings + `_write_to_self` writes,
  asserts a **commits/msg identity guard**, and sweeps concurrency `B5_C ∈ {1,64,256,1024}`. See
  **Running it** below for the recipe; the reproduced §8 numbers are in **Verified results**.

## Running it

Windows / Proactor only (a selector or non-Windows loop is **not** evidence — the script SKIPs and
returns exit 2 there). Synthetic HL7, no PHI. From the repo root:

```
python docs/benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/b5_microbench.py
```

Env knobs (all optional; defaults reproduce the full §8 run in a few minutes):

| var | default | meaning |
|---|---|---|
| `B5_WARMUP` | `1500` | messages discarded before the measured window |
| `B5_MEASURED` | `6000` | measured messages per arm/trial |
| `B5_C` | `1,64,256,1024` | concurrency sweep (the wall is a concurrency phenomenon) |
| `B5_TRIALS` | `3` | independent trials per arm (median + spread reported) |
| `B5_POOL` | `8` | dedicated fusing-executor size == sync connection pool |

A quick smoke run (a few seconds): `B5_WARMUP=100 B5_MEASURED=400 B5_C=1 B5_TRIALS=1 python …`.
The **A0/A1 crossing-count control** is also a **living gate** on the Windows CI `test` legs —
[`tests/test_adr0071_crossing_count.py`](../../../../tests/test_adr0071_crossing_count.py) reuses this
same script (no duplicated arm logic) at a scaled-down config and asserts the stable quantities
(commits/msg identity + the ≥40% A0→A1 crossings/msg drop), never throughput.

## Verified results (reproduced across 3 independent runs — implementer, adversarial validator, confirm)

| metric | result | reading |
|---|---|---|
| crossings/msg, driver-constant A0→A1 | **4.00 → 2.00 (−50%)** | fusion halves executor→loop completions |
| crossings/msg, async per-statement B0→B1 | **12.00 → 2.00 (−83%)** | the informative number — a per-statement async driver (aioodbc/aiosqlite) spends ~10 marshaling crossings/msg that fusion eliminates |
| commits/msg (identity guard) | **2.000 every arm** | **no covert transaction fusion** — direct support for "fuses hops, not transactions" (ADR 0069's fence is not hit) |
| `_write_to_self` vs crossings | **1:1** | confirms the marshaling→self-pipe chain (arithmetically forced, *not* independent corroboration) |
| co-tenant validate p99 | **flat (~0.18 ms)** | dedicated executor does not starve the listener path |
| throughput (SQLite) | **sign-unstable across runs** | **NOT a valid payoff signal** — SQLite is write-lock-bound, not the profiled idle-store marshaling regime |

## What this proves — and what it does NOT

**Proven:** the crossing-count reduction and the commits/msg identity (fusion cuts marshaling
completions without changing durable work).

**Not proven here:** the **throughput lift**. SQLite structurally cannot enter the profiled
idle-store, marshaling-bound regime (its write-lock is the wall), so its throughput is not a valid
proxy — the validator's independent re-run flipped the throughput sign while crossings stayed
byte-stable. The throughput GO/NO-GO is the **SQL Server aioodbc B0 vs dedicated-sync-pyodbc B1**
leg at C ≥ 256, run on the **AWS bench rig** (ADR §6.4(b) + the SS handoff) — **out of scope for this
PR**, which lands only the mechanism artifact + the living crossing-count gate. The real-path
invariants (poison-guard, crash-replay, non-regression) are the ADR §6 gates on the flagged fused
path — not covered by this self-contained bench.
