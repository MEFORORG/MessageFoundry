# Free-threading (cp314t) — Phase-1 feasibility + scaling spike (ADR 0053)

Execution plan for **Phase 1** of [ADR 0053](../adr/0053-free-threaded-multicore-engine.md) (free-threaded
cp314t multi-core engine, the committed unified-store scale path). This is a **GO/NO-GO gate, not an
adoption**: it ships **zero production `.py` changes**, produces verdicts + a hazard/locking-design list +
proof harnesses, and leaves the engine on the GIL build. Everything here **extends** the existing weekly
[`freethread-smoke.yml`](../../.github/workflows/freethread-smoke.yml) canary — new legs stay
`continue-on-error` and **must not** join the 7 required checks. Companion to the readiness assessment in
[`freethread.md`](freethread.md).

> **Why the canary isn't enough:** today it installs `-e .[dev]`, asserts `sys._is_gil_enabled() is False`,
> and runs a *pure* test subset on **ubuntu-latest only** — it exercises **no compiled wheel at runtime and
> never touches Windows** (the actual deploy target). "Canary green" does **not** prove cp314t works for the
> engine.

## Locked decisions (owner, 2026-06-29)

| # | Decision | Value | Consequence |
|---|---|---|---|
| D1 | GO/NO-GO thresholds | **GO:** S(4)≥3.0 (eff≥0.75) **and** S(8)≥5.0, S(1)≥0.7, e2e p99 regression ≤20%, zero loss at every K. **NO-GO:** S(4)<2.0 or efficiency<0.5 | The quantitative gate for WS3 |
| D2 | Primary server DB | **SQL Server** (aioodbc pool + RCSI + `sp_getapplock` finalizer) | WS3/WS4 run on SQL Server; **pyodbc/aioodbc thread-safety (WS2) is now primary-backend-critical**, not optional. asyncpg/Postgres becomes the optional secondary. |
| D3 | Scaling host | **the 265KF dev box** (8 P-cores + 12 E-cores; SQL Server already on Docker there) | K∈{1,2,4,8} pinned to the **8 P-cores** (exclude E-cores — heterogeneous cores skew S(K)). Consumer **floor**, not enterprise HW: pin + repeat, don't extrapolate. |
| D4 | WS4 threading topology | **per-worker-loop + pooled per-connection** for SQL Server; **dedicated DB-owner loop + `run_coroutine_threadsafe`** for the shared SQLite writer. **No** blind whole-loop `threading.Lock`. | Shapes every H1–H4 hazard fix; finalize at WS4 step 1 |

**Synergy from D2+D3:** SQL Server + the 265KF means the spike's **primary path is Windows**, so the
previously-unverified `win_amd64` cp314t story is exercised in the *main* run, not a side-leg.

**Residuals resolved (do-what-is-best):** new legs stay `continue-on-error` / out of branch protection;
Phase 1 ships **zero production `.py`** (the H1–H4 locking fixes land in Phase 2 on a green spike); the
asyncpg leg is optional/skip-on-absent-DSN since SQL Server is primary.

## Workstreams

### WS1 — Environment & dependency install (cp314t; Windows-primary, Linux-secondary) · ~1–1.5d
- Provision cp314t: CI `actions/setup-python` `3.14t` + `freethreaded:true` (as `freethread-smoke.yml:53-60`);
  on the 265KF, `uv python install 3.14t` (or the python.org "free-threaded" Windows option) → isolated venv.
- Install the engine path only: `pip install -e ".[dev]"` **+ `[sqlserver]`** (the primary backend). Exclude
  `[console]`/Qt (separate process) and `[sftp]`/paramiko (cp314t-unverified). **Do not** use
  `--require-hashes requirements.lock` (it's a GIL-build uv export with no cp314t hashes) — editable resolution;
  treat the lock as the version-pin reference only.
- Verify **0 from-sdist compiles**: every compiled dist resolves a `cp314t`/`*-freethreaded`/`abi3` wheel —
  pydantic-core 2.46.4, cryptography 49.0.0, argon2-cffi-bindings 25.1.0, cffi 2.0.0, pyodbc 5.3.0, plus
  uvicorn[standard]'s `httptools`/`watchfiles`(Rust)/`websockets` (uvloop is win32-excluded by the lock marker).
- Prove GIL-off **after** importing the engine + compiled deps:
  `import messagefoundry.pipeline.engine; from argon2 import PasswordHasher; ...; assert sys._is_gil_enabled() is False`
  (an extension lacking `Py_mod_gil` silently re-enables the GIL at import).
- **Net-new vs the canary:** a compiled-dep *runtime* smoke (actually call argon2 hash, AES-256-GCM
  encrypt/decrypt, pydantic-core `model_validate`) on **windows-2025 + the 265KF**, not just Linux.

**✅ Success:** 0 sdist builds, GIL off post-import, compiled-dep runtime smoke green on Windows (primary)
and Linux.

### WS2 — Compiled-dependency thread-safety under TRUE parallelism · ~2–2.5d
A cp314t wheel proves *compilation*, not thread-safety. `tests/freethread/test_compiled_threadsafety.py`,
`skipif(sys._is_gil_enabled())` (no-op on GIL build). Each test: one shared object the engine shares,
N=`os.cpu_count()*4` threads × ≥10k iters, assert zero exceptions + GIL still off + per-dep correctness.

- **cryptography / AES-GCM** (highest value — hot path, every PHI value): one shared cipher mirroring
  `store/crypto.py`; each thread round-trips its own unique plaintext, asserts `decrypt==plaintext`, no
  `InvalidTag` (catches cross-thread nonce/buffer bleed).
- **argon2-cffi + cffi 2.0** (most-exposed — already runs parallel via `auth/service.py` `to_thread`): shared
  module-level `_hasher`; each thread's hash verifies only against its own password.
- **pydantic-core** (load/reload + API body validation): pre-built validator; each thread validates a
  valid + invalid payload, asserts correct accept/reject, no cross-thread field bleed.
- **pyodbc/aioodbc** (primary backend, D2): per-worker-thread event loop, each opening its own **pooled**
  connection (mirror `sqlserver.py` `_acquire` — sharing one conn would be a false FAIL) looping a
  representative parameterized query, behind a live-DB gate. asyncpg optional/secondary.
- Wire a non-blocking `continue-on-error` stress leg for the 3 core deps; DB legs behind a service-container
  gate. Emit a per-dep verdict table.

**✅ Success:** all **3 core deps** PASS clean (N≥cpu×4 × ≥10k iters, zero exceptions/corruption, GIL stays
off) + the pyodbc verdict. A FAIL on any core dep ends the path on thread-safety grounds, independent of perf.

### WS3 — Multi-core scaling micro-benchmark (SQL Server, net of single-thread tax) · ~2–3d
- **CPU-bound, write-light** profile (model on `harness/load/profiles/closed-loop.toml`): N≥16 inbound
  connections, each Router+Handler doing heavy *pure* work (`validation.strict` so `hl7apy` validate runs,
  and/or a measurable transform), **FANOUT~1** so the durable-write path is **not** what's measured.
  Parallelism scales with **connection count** (each transform worker is strictly FIFO — one in-flight per
  connection).
- **SQL Server only** (concurrent commits via aioodbc pool + RCSI + `sp_getapplock`). **Never SQLite**
  (`store.py` global `self._lock` would cap scaling regardless of cores). Size the DB pool ≥ K.
- **Baseline** = GIL build (cp314 GIL on): steady-state throughput `T_gil` + e2e p99 via the closed-loop
  governor + no-loss reconciliation (`harness/load/`).
- **Sweep** on cp314t (assert GIL off at the start of every run): K∈{1,2,4,8} by bounding the `to_thread`
  default executor `max_workers` to K **and** CPU-pinning the process to **K P-cores** of the 265KF. K=1
  isolates the single-thread tax. Keep busy connections N ≥ K.
- Compute **S(K)=T_ft(K)/T_gil** on the *same* backend/pool/corpus/host, efficiency S(K)/K, tax S(1).
  Metrics-only report (no PHI); feed the ADR 0040 revisit gate. **Manual run — not a CI check.**

**✅ Success / ❌ fail:** per D1.

### WS4 — Reliability-invariant preservation under parallel workers · ~3–4d (highest risk — touches the core)
- **Topology first (D4):** one event loop per worker thread; the store/engine objects are shared across loops.
- **The 4 hazards as a concrete lock-change list:**
  - **H1** `store.py` `self._lock` is an `asyncio.Lock` → **no** cross-thread exclusion; two threads could
    interleave BEGIN/commit on a shared writer, corrupting the claim→produce-next→complete handoff at-least-once
    rests on. → DB-owner loop + `run_coroutine_threadsafe` marshaling (mirrors `db_lookup`, `wiring_runner.py:447`);
    for SQL Server, per-loop pooled connections.
  - **H2** read-through caches published **outside** the lock (post-commit) while readers hold
    `MappingProxyType` windows → concurrent dict read/write race. → immutable-swap or a real `threading.Lock`.
  - **H3** `engine.py` per-engine stat dicts + `RegistryRunner` hot-path per-name dicts mutated by reload while
    delivery threads read them.
  - **H4** cross-loop `asyncio.Event.set()` / `asyncio.Lock` — a wake from another thread is silently lost until
    the poll interval. → route via `loop.call_soon_threadsafe`.
- **Free-threaded steady-state proof harness:** extend `harness/load/failover.py`'s invariant accounting
  (acked ⊆ delivered, `in_pipeline==0`, `dead==0`, `lane_inversions==0`, `dup_rate≤cap`) into a non-failover
  cp314t run, ≥2 inbounds + ≥2 outbound lanes saturating ≥2 P-cores; SLOs must be **identical** to the GIL run.
- **New parallel tests** (`skipif` GIL on): K threads each with own loop hammering
  `claim_next_fifo`/`transform_handoff`/`mark_done`/`_maybe_finalize_message` on a shared WAL DB → every
  message reaches exactly one terminal disposition, no INFLIGHT strand, no duplicate outbound rows. Plus a
  **finalizer-single-authority** race test (N sibling handlers driven from N threads → finalizes exactly once,
  never a torn `ROUTED→PROCESSED` while a sibling routed row is in flight).
- Run the existing staged-pipeline/cluster/transform-state suites under cp314t, GIL asserted off,
  `continue-on-error`.

**✅ Success:** a cp314t steady-state run (≥2 inbounds, ≥2 lanes, ≥100k msgs, ≥2 P-cores) reports invariant
SLOs identical to the GIL baseline; the parallel store-race + finalizer tests pass; the suites are green under
3.14t; and a concrete, bounded H1–H4 lock-change design exists. ❌ = any loss/inversion, finalizer double-fire,
concurrent-dict `RuntimeError`, or SLO divergence.

## GO / NO-GO

**OVERALL GO** = WS1 green **+** all 3 WS2 core deps PASS (+ pyodbc) **+** WS3 meets D1 **+** WS4 invariants hold
with a tractable hardening list. Any one failing flips to **NO-GO**.

**NO-GO → fallback:** [ADR 0037](../adr/0037-multi-process-sharding-l3.md) process sharding + the
(still-unbuilt) cross-shard observability layer remains the recommended multi-core path; ADR 0040 stays
Rejected/Deferred; ADR 0053 records the measured NO-GO (curve + verdict table) as evidence. **Triggers:**
(1) any core dep fails thread-safety; (2) S(4)<2.0 or eff<0.5; (3) invariants can't hold without loop-blocking
serialization worse than the GIL; (4) a core compiled wheel has no `win_amd64` cp314t artifact (soft — revisit
when it ships).

## False-signal guards (the point of a trust gate)

**False GREEN** — *canary≠engine* (WS1 runtime smoke + Windows leg are mandatory) · *silent GIL re-enable*
(re-assert `_is_gil_enabled() is False` after every compiled import **and** at the end of each parallel
section) · *flaky race passes* (stress tests are **detectors** — a FAIL is conclusive, a PASS only suggestive;
≥10k iters, oversubscribed, repeated) · *benchmark over-read as e2e safety* (WS3 dispatches off one loop, so it
does **not** exercise the shared-state hazards — gate adoption on WS4, never WS3 alone) · *write-light masks a
write-bound reality* (note the result doesn't generalize to write-amplification-bound workloads).

**False RED** — *single busy connection* (FIFO-capped at 1 core → cp314t looks slower; require N busy
connections ≥ K) · *SQLite as test DB* (single-writer lock fakes a flat curve → SQL Server only, pool ≥ K) ·
*GIL-build tests* (prove nothing about parallelism → run on genuine 3.14t) · *unbounded executor / apples-to-
oranges* (same backend/pool/corpus/host; bound `max_workers`=K + CPU-pin) · *mis-modeled driver usage* (pyodbc
per-thread connection-per-acquire, never a shared conn).

## Effort & sequencing

**7–10 engineer-days.** WS1 (~1–1.5d) → WS2 (~2–2.5d) are prerequisites; WS3 (~2–3d) and WS4 (~3–4d, highest
risk) parallelize once the env is up but compete for the SQL Server instance + the 265KF P-cores. Zero
production `.py` ships — the cost is environmental (the 3.14t runner, the P-core host, the Dockerized SQL
Server) and analytical, not code volume.

## Phase-1 results (2026-06-29, 265KF) · WS1/WS2 GREEN, WS3 conditional GO

| Gate | Result |
|---|---|
| **WS1** env/install | ✅ cp314t **win_amd64** build installs; 4 core deps **wheels-only (0 sdist builds)** + declare FT; engine imports **GIL-off**. Only Win gap = `watchfiles` (dev-reload-only → plain `uvicorn`). |
| **WS2** compiled-dep thread-safety (`PYTHON_GIL=0`, barrier-synced) | ✅ AES-GCM 800k ops · pydantic-core 800k validations · argon2/cffi — **all 0 errors, GIL off**. |
| **SQL Server head-to-head** (live SQL 2022) | ✅ **`pyodbc` + `PYTHON_GIL=0`**: all store patterns incl `sp_getapplock`; **4,000 concurrent transactional writes, 0 errors**; **7.5× on 8 cores**. No `sqlserver.py` rewrite. |

**Driver verdict:** keep pyodbc + SQL Server; **set `PYTHON_GIL=0`** (pyodbc re-enables the GIL on import
otherwise). `python-tds` (pure-Python, FT-native, 7.4×) is a fallback only — it fails `sp_getapplock`
result-nav and needs a backend rewrite; `pymssql`/`mssql-python` don't install on cp314t; asyncpg (PG) is
FT-native. **Adoption requires `PYTHON_GIL=0` + plain `uvicorn`.**

**WS3 (multi-core scaling) — CONDITIONAL GO.** A first pass on the real pipeline looked like a NO-GO (~2×
on 8 cores), but isolation showed the cap is **python-hl7 specifically**, not free-threading: pure
built-in-type work scales 5.7–7.6×, and a **full HL7 parse into dict/list/str scales 6.44× and is ~14×
faster single-thread** (158k vs 11k msg/s), while python-hl7 (2.02×) and hl7apy (2.04×) both stall on their
`Container(collections.abc.Sequence)` object trees (shared class/type contention under free-threading; not
allocation, not GC). **So free-threading is viable IFF the hot-path parse is replaced by a low-allocation
built-ins HL7 parser** ([BACKLOG #88](../BACKLOG.md)) — itself the highest-leverage perf win (helps
single-process + sharding too; a parser ADR should precede the build). **WS4** (invariant preservation under
threads) is re-enabled by the conditional GO and runs *after* the parser, *if* free-threading is chosen over
ADR 0037 sharding. Full detail: ADR 0053 "WS3 (multi-core scaling)".
