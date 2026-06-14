# Load testing

A headless, asyncio load engine (`harness/load/`) that drives the MessageFoundry engine under **heavy
MLLP traffic** and measures it: maximum sustainable throughput, latency under load, and — critically —
**no message loss**. It is a separate layer of the test harness; the PySide6 GUI's single-thread
sender (one fresh socket per message, RTT-bound) cannot saturate the engine, so load generation is
asyncio and CLI-driven. It reuses the engine's own MLLP framing primitives and HTTP API client and
never touches the store.

> **Synthetic only.** Every profile and the load config graph are generic and synthetic — no real
> partner, site code, host, IP, or message volume. A real-numbers profile (if you build one) lives
> only in the git-ignored `migration-local/` tree and is run with `--load <path>`. Generated traffic
> is synthetic HL7 (the `messagefoundry` generators). Reports carry **metrics and metadata only** —
> never message bodies or control-id lists.

## How it works

```
corpus.next() → (control_id, payload)        [governor admits per the phase's loop model]
  → ConnectionPool.submit → persistent, pipelined MLLP connection (records send time, frames, drains)
  → [ENGINE: commits to ingress + ACKs on receipt]   → reader times the ACK (intake latency), classifies AA/NAK
  → [ENGINE: route → transform → deliver to the sink] → CorrelationSink times each arrival end-to-end
  → [EnginePoller @1 Hz, in parallel]: /stats /connections /status → throughput, backlog, DB growth, drain
```

Three measurement channels answer three different questions:

- **Sender** → offered-vs-achieved rate, **ACK (intake) latency** percentiles, NAK/error/timeout rates.
- **Correlation sink** → **true end-to-end (intake→delivery) latency** percentiles — *without touching
  the DB*. The engine ACKs on receipt (before routing/transform/delivery), so ACK latency ≠ pipeline
  latency; the sink is the only DB-free source of true end-to-end timing. With fan-out, one sent
  message is delivered to many sink connections (all carrying the same control id), and each arrival
  is timed.
- **Engine poller** → engine-side throughput (Δdone/Δt), queue depth/backlog over time, dead-letter
  accumulation, DB/WAL growth, and post-load **drain time** (wall time for the backlog to reach zero
  after offered load stops).

## Running

The runner assumes an **already-running engine** (the harness never imports it — the `--db` backend
choice is the whole point). Serve the synthetic high-fan-out system-under-test, then run a profile:

```bash
# 1) Serve the load config (its own ports, separate from harness/config). Tune via env (below).
MEFOR_LOAD_FANOUT=20 MEFOR_LOAD_TRANSFORM=edit MEFOR_LOAD_SINK_PORT=2700 \
  python -m messagefoundry serve --config harness/config/load --db ./load.db

# 2) Drive it. --sink-port must match MEFOR_LOAD_SINK_PORT above.
python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T> \
  --sink-port 2700 --report-json out/load/run.json --report-csv out/load/run.csv
```

`python -m harness --list-profiles` lists the built-ins. `--load` accepts a built-in name **or** a
path to a `.toml`. (If the engine enforces auth, pass `--token`; or serve with
`MEFOR_AUTH_ENABLED=false` on a trusted dev box.)

### Engine load-config knobs (env, read at serve time)

| Env var | Default | Meaning |
|---|---|---|
| `MEFOR_LOAD_FANOUT` | 20 | sink destinations per ADT message (write-amplification) |
| `MEFOR_LOAD_RESULTS_FANOUT` | 4 | destinations per results/other message |
| `MEFOR_LOAD_TRANSFORM` | `edit` | `cheap` (pass-through) / `edit` (field rewrites) / `slow` (CPU spin) |
| `MEFOR_LOAD_TRANSFORM_MS` | 1.0 | CPU spin per transform when `slow` (finds the transform-cost ceiling) |
| `MEFOR_LOAD_SINK_HOST` / `_SINK_PORT` / `_SINK_PORTS` | 127.0.0.1 / 2700 / 1 | where every destination delivers |
| `MEFOR_LOAD_ADT_PORT` / `_RESULTS_PORT` / `_OTHER_PORT` | 2600 / 2601 / 2602 | inbound hub ports |

`slow` is a deliberate busy-loop (not a sleep): it models CPU-bound transform contention on the single
event loop, which is how you find the per-core transform ceiling (the research finding that
transformation, not framing, dominates throughput).

## Profiles

A profile (`harness/load/profiles/*.toml`, parsed by `harness/load/profile.py`) defines targets, the
message-type mix, a sequence of phases, and the SLO thresholds. A malformed/typo'd key fails loud
before any traffic is sent. Built-ins:

| Profile | Purpose | When |
|---|---|---|
| `smoke` | Tiny zero-loss wiring check (not a perf measurement) | CI gate |
| `fanout-baseline` | ADT-dominant mixed feed at high fan-out; characterizes a realistic mix | On-demand |
| `soak` | Long steady-state; watches DB/WAL growth + dead-letter accumulation | On-demand |

Phases are `warmup` / `ramp` / `sustained` / `spike` / `soak`; only **`sustained`/`soak`** phases are
*measured* (SLOs evaluated against them — warmup/ramp/spike are transient). Loop models per phase:
**`open`** holds an offered rate (`rate_start`→`rate_end`, msg/s; interpolated for a ramp) to measure
latency at a fixed load; **`closed`** holds a fixed `concurrency` in flight to find maximum sustainable
throughput (a local backlog can't inflate the achieved number). A schematic:

```toml
[load]
name = "example"
pool_size = 64
[[load.target]]
port = 2600
types = ["ADT"]
[load.mix]            # weighted; "ADT" (any trigger) or "ADT^A01"
ADT = 55.0
ORU = 18.0
[load.slo]            # measured-phase + run-level thresholds → the exit code
min_sustained_msg_s = 200.0
max_e2e_p99_ms = 5000.0
max_error_rate = 0.001
max_drain_seconds = 60.0
zero_loss = true
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 800.0
duration_s = 180.0
concurrency = 64
```

## The report

Console: a per-phase table (offered/achieved, ACK + e2e p50/p99, NAK, deferred; warmup/ramp flagged
excluded), an engine-side line (peak backlog/queue-depth, drain seconds, DB growth), a no-loss line,
and a per-SLO pass/fail block ending in `RESULT: PASS|FAIL → exit N`.

`--report-json` / `--report-csv` write a machine-readable artifact (git-ignored `out/load/`) for trend
tracking. `--baseline run.json --tolerance 0.1` flags regressions (throughput below
`baseline*(1−tol)`, p99 above `baseline*(1+tol)`, or any worsening of loss).

**No-loss reconciliation** (the headline check) asserts, within a small in-flight tolerance:

- `sent == engine_read` — every message the harness sent was received (ACK-on-receipt), and
- `sink_received == engine_written` — every delivery the engine made arrived at the sink, and
- backlog drained to zero.

This is **fan-out-agnostic** (it never assumes 1:1), so it holds for any fan-out factor. At-least-once
re-deliveries are reported as a derived count (`sink_received − engine_written`).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | all SLOs met |
| 1 | ran, but an SLO was violated or message loss / a baseline regression was detected |
| 2 | setup error (bad profile, engine unreachable at preflight, sink bind failed, `--load`+`--scenario`) |
| 3 | aborted mid-flight (interrupt) |

## Comparing store backends (single-node ceiling vs scale-out)

The harness is **store-agnostic** — it speaks only MLLP + the HTTP API, so it drives whatever backend
the engine was served with. Run the same profile against each backend (swap `--db`) and compare with
`--baseline`:

```bash
# SQLite (single-writer WAL ceiling — the baseline to beat)
python -m messagefoundry serve --config harness/config/load --db ./load.db
python -m harness --load fanout-baseline --engine ... --db-backend sqlite --report-json out/load/sqlite.json

# Postgres (Track B scale-out — full staged-pipeline parity)
python -m messagefoundry serve --config harness/config/load --db "postgresql://..."
python -m harness --load fanout-baseline --engine ... --db-backend postgres \
  --baseline out/load/sqlite.json --report-json out/load/postgres.json
```

> ⚠️ **SQL Server is a pending target.** The SQL Server backend does **not** implement the staged
> ingress pipeline yet (`supports_ingest_stage = False`), so the engine refuses to start the staged
> runner on it (gated on BACKLOG #1). The harness is store-agnostic and will drive SQL Server
> unchanged the moment that backend lands — load-testing it is one of the motivations for that work.

To scale a single Python sender past what one process can offer, shard across processes (partition the
control-id prefix per process; merge the per-process JSON histograms by summing buckets). Not built in
v1 — documented as the escape hatch.

## CI

- **PR gate:** the in-process load integration test (`tests/test_load_runner.py`) serves the engine,
  runs a tiny load, and asserts no-loss + exit 0 — it runs in the normal `test` job on every PR/OS.
- **On-demand:** the `load-test` CI job (push-to-main + `workflow_dispatch`, Linux 1×) serves the load
  config with auth off and drives the `smoke` profile through the real CLI, uploading the report.
  Heavier `fanout-baseline` / `soak` runs and the backend comparison are run manually / locally.

## Notes

- The sink and sender run in **one event loop**, so send and receive timestamps share one monotonic
  clock (no skew). Latencies are recorded in nanoseconds (`perf_counter_ns`) into fixed-relative-error
  histograms (≈1% quantile error, memory bounded regardless of message count).
- The report flags when the harness itself was the limit (the local pool saturated while engine
  backlog stayed low) so engine numbers are never silently the harness's own ceiling.
- The `zero_loss` gate is **exact** by default (no message may be lost). At-least-once re-deliveries
  (`sink_received > engine_written`) are reported as a count and are *not* treated as loss.

## Known limitations

- **Drain/no-loss see only the outbound stage.** The engine API exposes outbound-stage depth, not the
  ingress/routed stages. Drain detection also requires the engine's `read`/`written` counters to stop
  moving, which catches a *progressing* router/transform worker — but a fully **stalled** worker
  (hung, or rows stranded after a crash) leaves those counters flat with the outbound backlog at zero,
  which the harness can't distinguish from "drained". In normal runs the workers progress, so the
  no-loss check is sound; the robust fix is a stage-aware in-pipeline gauge from the engine (tracked
  in [BACKLOG.md](BACKLOG.md)). Run the engine at `DEBUG` and watch for `ERROR`/dead-letter dispositions
  if you suspect a stalled stage.
