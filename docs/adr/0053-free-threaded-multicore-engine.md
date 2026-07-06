# 0053 — Free-threaded (cp314t) multi-core engine as the committed unified-store scale path (supersedes 0040)

- **Status:** **Accepted** (2026-06-29) — the *commitment* is ratified; the cp314t feasibility + scaling
  spike is **Phase 1 of execution** (see Acceptance Criteria), with ADR 0037 sharding + cross-shard
  observability as the documented **fallback** if the spike fails. **Supersedes
  [0040](0040-free-threaded-engine-support.md).**
- **Date:** 2026-06-29
- **Related:** **supersedes** [0040](0040-free-threaded-engine-support.md) (free-threading declined-by-design) ·
  **driven by** [0052](0052-enterprise-scale-target.md) (the committed enterprise target) · **refines**
  [0051](0051-corepoint-throughput-parity-strategy.md) (brings the free-threading element *forward* of 0051's
  enterprise-hardware measurement gate; complements — does not replace — its durable-write levers) ·
  **fallback** [0037](0037-multi-process-sharding-l3.md) + cross-shard observability · [0039](0039-database-tier-sharding-l5.md) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability invariant — pure routers/transforms) ·
  [design/freethread.md](../design/freethread.md) (the 0040 assessment — still-valid input)

---

## Context

ADR 0052 commits the enterprise target (up to 45M msgs/day, 1,500 connections, remote DB) **on a unified
store**. Per [CLAUDE.md](../../CLAUDE.md) §2 the engine is a single asyncio event loop, so all Python runs on
one core. There are two routes to many cores:

- **across processes — sharding (ADR 0037):** N engine subprocesses, each its **own** SQLite db + API port.
  Scales throughput (measured η≈0.88 → ~733 msg/s at K=8 on consumer hardware) but **fragments the store** —
  K databases → fragmented search, reporting, and audit, the exact reporting/logging pain the funding-tier
  (large-IDN) customers cannot accept.
- **within one process — free-threading (cp314t no-GIL):** the router/transform/delivery workers run as real
  OS threads inside **one** process sharing **one** store, **one** API port. This is the unified-store path —
  and the direct analog of how Corepoint reaches 45M/day with **one** internally-multi-threaded engine on a
  shared DB.

Free-threading fits *specifically because* the hot path is already pure. Per the reliability invariant
([CLAUDE.md](../../CLAUDE.md) §2, verbatim):

> At-least-once now relies on a re-run re-deriving identical output, so **routers and transforms must be
> pure** (message in → message out, no external side effects); outbound connections must still be
> **idempotent**.

A pure hot path is the ideal no-GIL workload: no shared mutable state to coordinate.

**Why this supersedes ADR 0040.** 0040 declined free-threading as *measure-first / deferred-until-proven*
(single-thread perf tax, unproven C-extension thread-safety, no measured win, L3 sharding stays the multi-core
path). Two things changed:

1. **ADR 0052 makes the enterprise unified-store target *committed*.** Sharding answers it only with a
   fragmented store, so the unified-store path is now a **requirement**, not one option among equals.
2. **The early-phase timing argument.** A foundational concurrency-model change is cheapest **before**
   anything depends on the single-event-loop assumption — and today almost nothing does. Every week of
   deferral raises the cost. The gate is therefore **technical risk** (cheap to test now), **not** calendar
   effort and **not** a signed deal.

**Reconciliation with ADR 0051 (Proposed, measure-first).** 0051 defers free-threading behind an
enterprise-hardware measurement gate, on the (correct) thesis that **DB durable-write I/O**, not CPU, is the
single-process bottleneck (the box sits ~85% idle; the wall is commit-serialization on the single writer).
Free-threading does **not** contradict that — it is the **CPU-parallelism half, necessary but not
sufficient**: multi-core compute on a *unified* store only scales if the durable-write path also accepts
**concurrent commits**, which the SQLite single-writer lock does **not**, but the server backends **do**
(Postgres per-message advisory locks; SQL Server RCSI + `sp_getapplock` — both lift the global writer lock).
So the enterprise unified-store path = **free-threading (this ADR) + a concurrent-commit server DB + ADR
0051's durable-write/group-commit levers.** This ADR brings the **free-threading element** forward of 0051's
gate on the timing argument; 0051's measure-first stance for the durable-write/storage levers and
sharding-as-fallback **stands**, and 0051's "no language rewrite, no broker" principle is preserved
(free-threading is the same Python, a no-GIL build — not a rewrite).

## Decision

**Adopt free-threading (cp314t) as the committed path to multi-core execution on a single unified store**, to
meet the ADR 0052 enterprise target without fragmenting the store. **Phase 1 is a feasibility + scaling
spike, started now**, with explicit go/no-go and ADR 0037 sharding (+ cross-shard observability) as the
documented fallback.

- **Phase 1 — the spike (days; gated on the cp314t question, *not* on enterprise hardware):** on a `cp314t`
  interpreter — (a) confirm the **engine-path compiled deps are thread-safe under true parallelism**:
  pydantic-core, cryptography, argon2-cffi/cffi 2.0, and the server-DB drivers **asyncpg + pyodbc** (`[sftp]`
  paramiko and `[console]` Qt are out of scope — separate concerns/process); (b) **measure multi-core
  scaling** of the router/transform workers as real threads on the load harness against a concurrent-commit
  server DB — actual speedup vs the single-loop baseline, **not** merely "doesn't crash"; (c) confirm **no
  reliability-invariant regression**.
- **Phase 2 — the re-arch (only on a green spike):** run the per-inbound router/transform + per-outbound
  delivery workers as real OS threads; convert the adoption-time hardening items ADR 0040 already identified
  (the per-engine stat dicts in `pipeline/engine.py`; any cross-connection shared state from `asyncio.Lock` →
  `threading.Lock`); pair with ADR 0051's concurrent-commit / group-commit durable-write work on the server
  backends. This touches the reliability core, so it carries the heaviest verification (failover + load
  harness + adversarial review).
- **Go/no-go:** IF the spike shows no measured multi-core scaling win **OR** any engine-path compiled dep
  fails under parallelism, THEN fall back to ADR 0037 sharding + cross-shard observability (the
  fragmented-store path) and free-threading returns to deferred.

**Must not break:** the reliability invariant (per-channel FIFO, at-least-once, pure routers/transforms),
count-and-log (single-finalizer disposition authority), and unified-store observability. **SQLite stays
single-writer** (its global lock is correct for one file); the unified-store multi-core target is
**server-DB-first**.

## Acceptance Criteria

- **AC-1** — WHEN the engine runs under `cp314t`, THE SYSTEM SHALL report `sys._is_gil_enabled() is False`
  and pass the engine-core pure-path test subset.
  → `.github/workflows/freethread-smoke.yml` (the ADR 0040 canary) + the engine-core test subset
- **AC-2** — WHILE the router/transform/delivery workers run as real parallel threads, THE SYSTEM SHALL
  preserve per-channel FIFO, at-least-once delivery, and single-finalizer disposition (no message lost,
  duplicated, or reordered within a lane).
  → `tests/` invariant + staged-pipeline suites · `harness/load/failover.py`
- **AC-3** — WHEN the router/transform workers run as parallel threads on a concurrent-commit server DB under
  load, THE SYSTEM SHALL show measured multi-core throughput scaling above the single-loop baseline.
  → `harness/load/` throughput profile (Phase-1 spike artifact under `docs/benchmarks/`)
- **AC-4 (go/no-go)** — IF Phase 1 shows no scaling win OR a compiled-dep thread-safety failure, THEN the
  decision SHALL fall back to ADR 0037 sharding + cross-shard observability.
  → recorded under "To resolve on acceptance"

## Options considered

1. **Commit to free-threading now; spike-gated Phase 1 + sharding fallback (this).** **CHOSEN** — the
   unified-store enterprise target (0052) needs multi-core **without** a fragmented store; the timing argument
   makes it cheapest now; the cheap feasibility spike de-risks it **without deferring the decision**.
2. **Keep ADR 0040's decline / measure-first behind the enterprise-hardware gate (status quo).** Rejected —
   gates a foundational concurrency change on a late, expensive parity run and a sales event; cost only grows
   with deferral; the cheap feasibility spike is the *right* measurement for this specific decision.
3. **Reach 45M/day via sharding only (ADR 0037/0039).** Rejected **as the primary path** — it scales
   throughput but fragments the store (the funding-tier reporting/audit pain). **Kept as the fallback.**
4. **Native-language rewrite of the hot path.** Rejected — out of scope; ADR 0051 already declines a language
   rewrite. Free-threading keeps Python and the whole ecosystem.

## Consequences

**Positive** — a path to many-cores-on-one-unified-store, preserving unified search/reporting/audit at the
enterprise tier; reuses the already-pure hot path (the ideal no-GIL workload); the store is **already most of
the way there** (server backends lift the single-writer lock); the change is made at the cheapest possible
time (fewest downstream dependencies on the single-loop assumption).

**Negative / risks** — cp314t is a distinct ABI with install friction (the cffi 2.0 chain); a published wheel
proves *compilation*, not *thread-safety* (the spike's job); the no-GIL build carries a **single-thread perf
tax**, so a single busy connection can be *slower* — the win must be **measured** (AC-3); it touches the
**reliability core**, demanding the heaviest verification; free-threading is **necessary-not-sufficient** — it
needs ADR 0051's concurrent-commit / group-commit durable-write work to actually feed many cores on one
store.

**Out of scope** — SQLite multi-core on one file (stays single-writer); `[sftp]` / `[console]` under no-GIL;
the durable-write / group-commit levers themselves (ADR 0051); the 1,500-connection axis (ADR 0052).

## Phase-1 results (2026-06-29, run on the 265KF — WS1/WS2 GREEN, WS3 conditional GO)

**WS1 (env / install / GIL-off) ✓ and WS2 (compiled-dep thread-safety) ✓ — both GREEN.**

- A free-threaded **win_amd64** build installs (`cpython-3.14.6+freethreaded`) — the previously-unverified
  Windows gap is **closed**.
- The 4 core compiled deps at the locked versions (cryptography 49.0.0, argon2-cffi-bindings 25.1.0,
  cffi 2.0.0, pydantic-core 2.46.4) install **wheels-only (0 sdist builds)**, **declare free-threading**
  (GIL stays off), and the MessageFoundry engine itself imports GIL-off.
- WS2 stress (cp314t, `PYTHON_GIL=0`, barrier-synced for max contention): cryptography/AES-GCM **800k ops**,
  pydantic-core **800k validations**, argon2/cffi — all **0 errors, GIL off**. The whole compiled surface
  is free-threading-safe.
- **SQL Server (D2) driver decision — `pyodbc` + `PYTHON_GIL=0`:** pyodbc ships a cp314t wheel but
  *re-enables the GIL on import* (no free-threading declaration). Running with **`PYTHON_GIL=0`** (proven)
  keeps the GIL off; under it pyodbc ran every store pattern (incl transaction-scoped `sp_getapplock`),
  a 16-connection × 250 transactional-write stress (**4,000 concurrent writes, 0 errors, no cross-thread
  bleed**), and scaled **7.5× on 8 cores** in the query+CPU micro-benchmark. **No `sqlserver.py` rewrite
  needed.** Alternatives evaluated: `python-tds` (pure-Python, FT-native, scales 7.4× but fails
  `sp_getapplock` result-nav + needs a backend rewrite → documented fallback only); `pymssql` /
  Microsoft `mssql-python` don't install on cp314t. asyncpg (Postgres) is FT-native.
- **Only Windows wheel gap: `watchfiles`** (a `uvicorn[standard]` dev-`--reload` extra) — use plain
  `uvicorn`. uvloop is win32-excluded already.

**Operational requirement on adoption:** run the free-threaded engine process with **`PYTHON_GIL=0`**
(or `-Xgil=0`) and plain `uvicorn` (drop the watchfiles reload extra) on cp314t.

## WS3 (multi-core scaling) — CONDITIONAL GO: the cap is python-hl7, not free-threading

The first WS3 pass on the real pipeline *looked* like a scaling NO-GO (~2–3.5× on 8 cores, below the
S(8)≥5 bar). **Isolation proved that conclusion wrong** — the ceiling is the **HL7 parsing library**, not
free-threading and not the workload:

| workload (free-threaded, 8 P-cores) | single-thread | S(8) |
|---|---|---|
| arithmetic / `alloc_list` / `alloc_str` / `alloc_dict` (built-in types) | — | **5.7–7.6×** ✅ |
| **`parse_builtins`** — full HL7 parse into dict/list/str | **158k msg/s** | **6.44×** ✅ |
| **python-hl7** (today's `Peek` hot path) | 11k msg/s | **2.02×** ❌ |
| **hl7apy** (opt-in strict validate) | 0.24k msg/s | **2.04×** ❌ |

Root cause: both libraries build **user-defined-class object trees** (`Container(collections.abc.Sequence)`
etc.); free-threaded CPython penalizes heavy operations on **shared class/type objects** (reference-count +
type-machinery contention), which **built-in immortal types (str/list/dict) sidestep**. It is **not**
allocation in general (pure dict/list/str allocation scales 5.7–7.6×), **not** GC (`gc.disable()` → no
change: 2.49→2.52×), and **not** fixable by switching to hl7apy (same wall, ~46× slower single-thread).

**Therefore WS3 is a CONDITIONAL GO:** free-threading delivers near-linear multi-core scaling for this
engine **iff the hot-path parse (the python-hl7 `Peek`) is replaced by a low-allocation built-ins HL7
parser** — which is *independently* a ~14× single-thread win that also raises sharded (ADR 0037)
throughput. That parser is the **gating dependency** and the highest-leverage perf work on the board
(BACKLOG #88). Building it is real work (tolerant parsing, MSH-2 encoding chars, escapes, backing the
`Peek` + transform `Message` API); a dedicated parser ADR should precede the build.

## WS4 (reliability invariants under real threads) — GO + a strategic reframe

The parser (BACKLOG #88 / [ADR 0054](0054-low-allocation-builtins-hl7-parser.md), merged) is **done** and
scales **6.93× / 31.5× single-thread** in production. WS4 then asked the last question: can the reliability
invariants (per-channel FIFO, at-least-once, single-finalizer) survive the staged-pipeline workers running
as real OS threads? **Yes — at ~0 reliability cost, via the DB-owner-loop model.**

- **H1a (recommended) — a store-owned event loop.** A dedicated loop owns the single writer connection +
  `self._lock`; every store call marshals onto it via `run_coroutine_threadsafe` — **generalizing the
  pattern already at `wiring_runner._run_lookup`**. Keeps the single-writer model byte-for-byte (so the
  handoff atomicity, `reset_stale_inflight`, the read-through caches, and the WAL read-pool all hold), and
  costs **~0** (measured 679 vs 684 handoffs/s — the SQLite commit **fsync** is the wall, not the lock).
  The **naive** "one loop per worker" model is **infeasible**: a shared `asyncio.Lock` *raises*
  `RuntimeError: bound to a different event loop` (3/4 threads crashed), and cross-loop `Event.set()`
  wakeups are lost. **REJECT H1b** (threading.Lock + per-loop writer-conn pool): 1.6× faster but dismantles
  the single-writer model = a reliability-core rewrite.
- **H2/H3/H4 — cheap lockless fixes:** immutable-swap the `_state_cache`/`_reference_cache` (build-then-flip,
  as `_reference_cache` already does); make the reload-rebinds-a-fresh-`Registry` contract enforceable
  (`MappingProxyType` the per-name dicts); route cross-thread wakes via `loop.call_soon_threadsafe`.
- **All three invariants are PRESERVED under H1a** — by the same mechanisms, relocated onto the owned loop.
  FIFO constraint: **never two claimers per lane** (SQLite has no row-leasing); the only safe parallelism is
  **across lanes + the off-loop pure-transform fan-out**.

**THE STRATEGIC REFRAME (forced by the data):** GIL-on vs GIL-off measured **identical on every store /
handoff experiment** — the write-path ceiling is the **SQLite single-writer commit fsync, which
free-threading does not move.** So **free-threading buys nothing on store throughput.** Its *only* win is
parallelizing the off-loop **pure router/transform CPU** work — exactly where the ADR 0054 parser's 6.93×
lands. That helps the **single-hot-feed CPU-bound transform gap** (the one real throughput gap), **not**
multi-feed throughput (already served by across-lane concurrency) and **not** store write-throughput.
**Therefore free-threading (this ADR) and sharding ([ADR 0037](0037-multi-process-sharding-l3.md)) are
COMPLEMENTARY, not either/or — they address different walls.** This **corrects** this ADR's original
"unified-store enterprise-scale path" thesis and [ADR 0052](0052-enterprise-scale-target.md)'s "0053 primary
/ sharding fallback" framing: free-threading is the **single-feed transform-CPU** tool; **sharding +
durable-write levers remain the store-scale path** for the enterprise 45M/day target.

**VERDICT — SCOPED GO.** Free-threading is a GO, **scoped to "parallelize the pure off-loop router/transform
path under the H1a reliability model"** — reliability cost ~0, the parser is done. The final commit is gated
on **(a)** building H1a + H2/H3/H4 (BACKLOG #90) and **(b)** a clean **GIL-on-vs-FT A/B on a real hot feed**
(BACKLOG #91) — the parser's 6.93× is a microbench; the engine-level speedup is unproven (both spike venvs
were cp314t, no clean GIL-on control). Do **not** pitch free-threading as a store-throughput win — it is not.

## To resolve on acceptance

- [x] Phase-1: engine-path compiled-dep thread-safety under true parallelism — **DONE (WS1 + WS2 ✓; the
  core deps + the engine are FT-safe; pyodbc is safe under `PYTHON_GIL=0`).**
- [x] **WS3** — multi-core scaling — **DIAGNOSED: CONDITIONAL GO.** The ~2× cap is python-hl7's object
  model, not free-threading; a built-ins parser scales 6.44× + ~14× faster single-thread (see WS3 section).
- [x] **Gating dependency — the built-ins HL7 parser — DONE** ([ADR 0054](0054-low-allocation-builtins-hl7-parser.md),
  #655 merged): 6.93× multi-core / 31.5× single-thread in production.
- [x] **WS4** — reliability invariants under real threads — **DONE: SCOPED GO.** Preserved at ~0 cost via the
  H1a DB-owner-loop model (+ H2/H3/H4 lockless fixes); free-threading **reframed** as the single-feed
  transform-CPU tool (it does **not** move the store fsync wall), **complementary** to ADR 0037 sharding.
- [ ] **Build H1a + H2/H3/H4 — the DB-owner-loop reliability re-arch (BACKLOG #90).** The committed scope of
  this ADR.
- [ ] **GIL-on-vs-FT A/B on a real hot feed (BACKLOG #91)** — the final commit gate; the parser's 6.93× is a
  microbench, the engine-level transform speedup is unproven (both spike venvs were cp314t).
- [ ] Final commit recorded here once #90 lands and #91 confirms an engine-level win on a real single hot feed.
