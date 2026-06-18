# MessageFoundry — Throughput Baseline & Tuning Reference

**Status: published (2026-06-16) — measured on CI Linux + Docker PG/SQL Server containers (see the
[`throughput-baseline`](../../.github/workflows/benchmark.yml) workflow + [Results](#results)).** This is
the published throughput baseline for v0.1 (Gate #3).
It exists to answer two different questions with two different rigor levels — see *Two-tier gate* below.

> **Read this first:** the numbers here are **"as measured on the reference config below"**, not a
> guarantee for your hardware. MessageFoundry's durable-write path (fsync-bound SQLite WAL; a
> per-commit network round-trip on PostgreSQL / SQL Server) makes throughput **hardware-dependent** —
> the same engine varies by an order of magnitude across hosts. Every integration engine hits this same
> durable-write wall; there is **no trustworthy public per-node benchmark** for the commercial engines
> to compare against (cited Rhapsody/Mirth figures are marketing, not reproducible). So we publish a
> transparent **method** you can re-run on **your** hardware (see *Validate on your hardware*), not a
> headline number.

---

## Two-tier gate

| Tier | What it measures | Hardware-dependent? | Release rule |
|---|---|---|---|
| **Conformance** | zero message loss · bounded whole-pipeline drain (`in_pipeline → 0`) · error rate < 0.1% · low ACK-on-receipt p99 | **No** — these are correctness invariants | **Hard blocker** — a miss blocks the tag, no override |
| **Performance** | sustained msg/s · ACK p99 · end-to-end p99, **on the reference config** | **Yes** | Reported "as measured on config X". Must clear the reference floor (below) **or** carry an owner-signed note recording the value + reason — **never** silently lowered |

**Reference performance floor (the named reference config must clear this):** **≥ 200 msg/s sustained ·
ACK-on-receipt p99 ≤ 50 ms · end-to-end p99 ≤ 5 s · error rate < 0.1% · zero loss.** This is a *sanity
floor* proving the engine isn't pathologically slow — it is far below real hospital peak, not a market
claim.

---

## Reference configuration

Measured on **accessible infrastructure** (no dedicated benchmark host — see the v0.1 plan, Q1): SQLite
on the project's dev box / CI Linux runner; PostgreSQL 16 and SQL Server 2022 in **Docker containers**
(CI-identical). Each committed result is stamped with the exact environment so it is reproducible.

Measured **2026-06-16** via the on-demand [`throughput-baseline`](../../.github/workflows/benchmark.yml)
workflow. Raw metrics-only reports: [`results/2026-06-16-ci-linux/`](results/2026-06-16-ci-linux/).

| Field | Value |
|---|---|
| Host | GitHub-hosted `ubuntu-latest` runner (Azure VM, 4 vCPU / 16 GB) |
| OS / kernel | Ubuntu 24.04 / Linux `6.17.0-1018-azure` |
| Python | 3.13.13 |
| SQLite version / journal mode | 3.45.1 (`synchronous=NORMAL`, WAL) |
| PostgreSQL version / container | 16.14 — `postgres:16` Docker **service container, co-located on the runner** |
| SQL Server version / container | 2022 — `mssql/server:2022-latest` **service container, co-located** (RCSI on) |
| Fan-out | 2 outbound deliveries per inbound (`MEFOR_LOAD_FANOUT=2`) |
| Engine commit | `63cd59f` |

> ⚠️ **The DB is co-located with the engine on one 4-vCPU runner** — not a dedicated, low-latency database
> server. So these are a deliberately-conservative **sanity floor**, far below a real deployment (a
> properly-provisioned DB on a fast link). The binding constraint here is the **delivery path** — the MLLP
> connector opens a fresh TCP connection per delivery and each stage is a server-DB round-trip
> ([#291](https://github.com/MEFORORG/MessageFoundry/issues/291) tracks a pooled connector) — so the
> numbers below are well under the reference floor. Per Q1/Q3 that is **expected and recorded, not a
> blocker**: the deploying org provisions the hardware, and the **conformance** tier (the hard gate) holds
> everywhere.

---

## Method

1. **Stand up the system under test:** serve `harness/config/load` (the synthetic high-fan-out graph)
   against the engine on the chosen backend.
2. **Drive load with the harness:**
   - `python -m harness --load reference --engine <URL> --token <T>` — **the published sustainable-ceiling
     finder.** Open-loop *rate* steps (30 → 50 → 70 msg/s) with a low cooldown so the pipeline drains. The
     sustainable rate is the highest step where **achieved ≈ offered with bounded e2e p99**; above it, e2e
     climbs sharply (the delivery path can't keep up). This is the profile the Results below are measured on.
   - `python -m harness --load closed-loop --engine <URL> --token <T>` — a closed-loop *concurrency* sweep.
     **Caveat:** the engine ACKs **on receipt** (before delivery), so an ACK-gated concurrency sweep lets
     intake outrun the **delivery** path and just floods an undrainable backlog — it measures the *intake*
     ceiling, not a sustainable end-to-end rate. Use `reference` (rate-stepped) for the published ceiling;
     `closed-loop` characterizes peak intake / backpressure behavior.
3. **Verify drain + no loss:** the harness's `await_drain` requires the engine's `/stats` **`in_pipeline`**
   gauge (NOT-DONE rows across ingress + routed + outbound) to reach **zero** — so a stalled
   router/transform cannot be mistaken for a drained pipeline.
4. **Commit metrics-only artifacts** to `docs/benchmarks/results/` (JSON/CSV + the environment stamp).
   **No message bodies, no control-ids** — the artifacts pass the publish forbidden-content guard.

---

## Per-backend recommended settings

Tuning that materially affects throughput. Full reference: [`../CONFIGURATION.md`](../CONFIGURATION.md).

| Backend | Recommended | Why |
|---|---|---|
| **SQLite** | `synchronous=NORMAL`, WAL (default) | The single-writer fsync is the wall; `NORMAL`+WAL is the safe throughput sweet spot for a single node. |
| **PostgreSQL** | `[store].pool_size ≥ 3` (≥ 2 required in cluster mode); server on a low-latency link | Each stage handoff is a committed round-trip; a pool of 1 serializes the background workers against intake. |
| **SQL Server** | `[store].pool_size ≥ 3`; **RCSI on** (auto-enabled at open); a real `command_timeout` | RCSI removes reader/writer blocking on the finalizer; the pool feeds the per-stage workers concurrently. |

**Cross-cutting:** intake throughput scales with **per-inbound** parallelism and (future) **multi-process**
deployment, not by relaxing FIFO order — see [`../THROUGHPUT-IMPROVEMENTS.md`](../THROUGHPUT-IMPROVEMENTS.md).
A single strictly-ordered feed is capped at one core in every engine; the order-preserving escape hatch
is per-key lanes (0.2), not unordered delivery.

---

## Results

Measured on the reference config above (CI Linux, **co-located DB containers**, fan-out 2) via the
`reference` rate-stepped profile. Raw reports: [`results/2026-06-16-ci-linux/`](results/2026-06-16-ci-linux/).

### Single-node throughput (reference sustainable ceiling)

The **sustainable** rate = the highest rate step that held `achieved ≈ offered` with bounded e2e p99; the
"saturates above" column is the next step where e2e p99 jumps (the delivery path falls behind).

| Backend | Sustainable msg/s | ACK p99 | e2e p99 | Saturates above | Error | Zero loss | Conformance | Perf vs floor |
|---|---|---|---|---|---|---|---|---|
| SQLite | **≥ 70** (not saturated at the top step) | 13 ms | 44 ms | — | 0 | ✅ | ✅ PASS | below floor (host-bound) |
| PostgreSQL | **~50** | 18 ms | 121 ms | 70 (e2e → 15 s) | 0 | ✅ | ✅ PASS | below floor (host-bound) |
| SQL Server | **~30** | 173 ms | 3.9 s | 50 (e2e → 35 s) | 0 | ✅ | ✅ PASS | below floor (host-bound) |

All three **passed the conformance tier** (zero message loss, `in_pipeline → 0` drain, error rate 0, no
dead-letters). The **performance** numbers are far below the ≥ 200 msg/s reference floor — **recorded, with
the architectural reason, per Q3** (never silently lowered): on a single 4-vCPU runner with the DB
**co-located** in a container, the delivery path (a fresh TCP connection per delivery + a server-DB
round-trip per stage) is the binding constraint, not the engine's CPU. A properly-provisioned DB on a fast
link, and the pooled-connector improvement ([#291](https://github.com/MEFORORG/MessageFoundry/issues/291)),
both lift this materially. SQLite (local file, no network) is fastest and did not even reach its knee here.

### Active-passive failover (kill primary mid-load)

The `failover` profile (two nodes share the DB; the harness SIGKILLs the primary mid-load). All conformance
columns pass on both backends; recovery **time** is reported (host-/timing-variable).

| Backend | Recovery time | Dropped (acked) | Duplicated | Ordering preserved | Zero loss |
|---|---|---|---|---|---|
| PostgreSQL | ~60 s ⚠️ | 0 | 0 | ✅ (0 inversions / 2 lanes) | ✅ |
| SQL Server | ~7 s | 0 | 1 (0.04%) | ✅ (0 inversions / 2 lanes) | ✅ |

Both **lost nothing acknowledged, drained fully (`in_pipeline = 0`), preserved per-lane FIFO, and stayed
single-leader.** ⚠️ **PostgreSQL functional recovery (~60 s) is much slower than SQL Server (~7 s)** even
though promotion is fast on both (~6.5 s) — the survivor resumes delivery slowly, consistent with the
Postgres path waiting on the leader lease-reclaim sweep (the rows aren't lease-expired the instant of
promotion). It is lossless and order-preserving, so it's reported, not a correctness gate — tracked as
[#293](https://github.com/MEFORORG/MessageFoundry/issues/293) (an on-promotion immediate reclaim of the
*in-flight* head, independent of lease expiry). SQL Server's `reset_stale_inflight`-on-promotion path
recovers promptly.

---

## Validate on your hardware

The published numbers are a reference point, not a promise. To establish **your** baseline:

1. Deploy on your target server-DB ([`../DEPLOY-SERVER-DB.md`](../DEPLOY-SERVER-DB.md)).
2. Run `python -m harness --load reference --engine <your URL> --token <T>` against a synthetic SUT (or
   the on-demand [`throughput-baseline`](../../.github/workflows/benchmark.yml) workflow on your infra).
3. Read the achieved ceiling from the report; confirm the **conformance tier** (zero loss, drain,
   error rate) holds — that part is hardware-independent and must pass everywhere.
4. Size for headroom: provision so your peak is a comfortable fraction of the measured ceiling.

---

*Companion: [`../LOAD-TESTING.md`](../LOAD-TESTING.md) (harness guide), the `reference` / `fanout-baseline`
/ `closed-loop` / `failover` profiles under `harness/load/profiles/`, the on-demand
[`throughput-baseline`](../../.github/workflows/benchmark.yml) workflow, and the v0.1 plan's two-tier
Gate #3 ([`../releases/v0.1-EXECUTION-PLAN.md`](../releases/v0.1-EXECUTION-PLAN.md) §Q3).*
