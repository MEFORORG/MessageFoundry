# Free-threaded (no-GIL / PEP 703, cp314t) readiness — engine

Status: exploratory assessment + low-risk scaffold (no behaviour change; not adopted).

This is an **optional lever**, not a committed direction. Nothing here changes how the engine
runs today: it still runs on a single CPython process with the GIL. This doc records (1) why
free-threading *might* help, with honest caveats, (2) the dependency-wheel readiness for cp314t,
(3) a GIL-assumption audit of the engine packages, and (4) a recommended path plus a concrete,
**non-blocking** CI scaffold that smoke-tests under `3.14t` without ever gating a merge.

It is a sibling to [`multiproc.md`](multiproc.md) (L3 per-connection multi-process sharding): both
target "use more than one CPU core". Free-threading is the *within-one-process* alternative to that
*across-processes* approach — see §1.

---

## 1. Why no-GIL might help here (and the honest caveats)

### The shape of the problem

The engine is **GIL-bound and single-process** by design (CLAUDE.md §2): concurrency is **asyncio**
on **one event loop** — one listener + a router worker + a transform worker per inbound connection,
one delivery worker per outbound — supervised by `RegistryRunner`. asyncio gives *concurrency*
(overlapping I/O waits), not *parallelism*: all that Python bytecode — `python-hl7` peek, routing
predicates, `Message` transforms, `hl7apy` strict validation — executes on a **single core** because
the GIL serializes it. At high inbound volume the CPU-bound router/transform path is the ceiling
(the load numbers in memory: the WIN2025 ~50 msg/s floor and the E≈400 enterprise estimate are
single-core Python ceilings).

There are two ways to use more than one core:

* **L3 multiprocessing** ([`multiproc.md`](multiproc.md)) — run N engine subprocesses, each owning a
  disjoint subset of inbound connections, each with its **own** SQLite WAL file and API port. This is
  **built/designed** and is the safe, boring answer: process isolation means no shared-memory data
  races are even possible, at the cost of one db-file + port per shard and a fan-out console.

* **Free-threading (this doc)** — run the existing asyncio workers as **real OS threads inside one
  process** on a `cp314t` (no-GIL) interpreter, so router/transform across connections run *truly in
  parallel* on multiple cores **while sharing one store, one API port, one process**. No per-shard
  db/port sprawl; the graph stays one object.

Free-threading is attractive *specifically* because the engine's hot path is **pure** (CLAUDE.md
reliability invariant: routers and transforms must be pure, message-in → message-out, no side
effects) — pure CPU-bound work over independent messages is the *ideal* free-threading workload, with
no shared mutable state to coordinate.

### Honest caveats (do not gloss these)

1. **Free-threaded perf today is not free.** The no-GIL build removes the GIL but adds per-object
   locking / biased-reference-counting overhead; single-threaded code on `3.14t` runs **measurably
   slower** than the GIL build (the well-documented free-threading single-thread tax). Free-threading
   only wins when you actually saturate ≥2 cores with parallel Python; a single busy connection is
   *slower*, not faster. This must be **measured on our load harness**, never assumed.

2. **C-extension thread-safety is the real risk, not the pure path.** Our pure Python is safe; the
   compiled dependencies (pydantic-core, cryptography, the DB drivers, argon2) must be *both*
   `cp314t`-built *and* actually thread-safe under true parallelism. A wheel existing means it
   **compiles** for `3.14t` — it does not prove the extension is free-threading-correct under
   concurrent calls. Treat every compiled dep as "smoke-test before trusting."

3. **Ecosystem maturity / install friction.** `cp314t` is a **distinct ABI** from `cp314`. A dep
   without a `cp314t` wheel either falls back to an sdist build (needs a toolchain) or fails. As of
   mid-2026 the core compiled deps ship `cp314t` wheels (§2), but the install story still needs
   `--prerelease=allow`-style handling for the `cffi 2.0` chain and is more fragile than the GIL build.

4. **It does not replace L3.** Free-threading scales *one box's cores*; it does **not** give the
   process isolation, independent failure domains, or per-shard stores that `multiproc.md` does. The
   two are complementary, not either/or. Free-threading is the lower-ceiling, lower-ops-cost option for
   a single beefy host; sharding is the higher-isolation option. **Sharding remains the default
   recommendation** until free-threading is measured to win on our workload.

---

## 2. Dependency wheel readiness (cp314t)

Verified against the versions our `requirements.lock` currently resolves (June 2026). "cp314t wheel"
means a free-threaded wheel is published on PyPI for that line; "pure-Python" means it is
ABI-independent and works on any interpreter (no compiled extension, so no `cp314t`-specific concern).

| Dependency (locked version) | Kind | cp314t status |
|---|---|---|
| `pydantic` 2.13.4 | pure-Python | OK — pure wrapper over pydantic-core |
| `pydantic-core` 2.46.4 | **compiled (Rust/PyO3)** | **cp314t wheels published** (the 2.4x line ships cp314 + cp314t, incl. win_amd64) |
| `cryptography` 49.0.0 | **compiled (Rust)** | **cp314t wheels published** (ships the additional cp314t set alongside cp314) |
| `argon2-cffi` 25.x | pure-Python | OK — pure wrapper; the C is in argon2-cffi-bindings |
| `argon2-cffi-bindings` 25.1.0 | **compiled (CFFI)** | **cp314t wheels published** (25.1.0 added free-threading; **requires cffi 2.0**) |
| `cffi` 2.0.0 | **compiled** | **cp314t supported** (2.0 is the free-threaded-capable line; not back-ported to 3.13t) |
| `aiosqlite` 0.22.1 | pure-Python | OK — pure asyncio wrapper over stdlib `sqlite3` (the C is CPython's, built into the interpreter) |
| `hl7` (python-hl7) 0.4.5 | pure-Python | OK |
| `hl7apy` 1.3.5 | pure-Python | OK |
| `fastapi` 0.138.0 | pure-Python | OK (depends on starlette + pydantic) |
| `starlette` 1.3.1 | pure-Python | OK |
| `uvicorn` 0.49.0 | pure-Python | OK — `[standard]` pulls optional compiled extras (`httptools`, `uvloop`); see note |
| `httpx` 0.28.1 | pure-Python | OK (depends on anyio + httpcore + certifi) |
| `anyio` 4.14.0 | pure-Python | OK |
| `ldap3` 2.9.1 | pure-Python | OK |
| `pyspnego` 0.12.1 | pure-Python | OK (Windows SSPI is via stdlib `ctypes`, no wheel concern) |
| `tomlkit` 0.15.0 | pure-Python | OK |
| `defusedxml` 0.7.1 | pure-Python | OK |
| `prometheus-client` 0.25.0 | pure-Python | OK |
| **Optional extras** | | |
| `asyncpg` 0.31.0 (`[postgres]`) | **compiled (Cython)** | **cp314t wheels published** (0.31 ships cp314t) |
| `pyodbc` 5.3.0 (`[sqlserver]`, via `aioodbc`) | **compiled (C++)** | **cp314t wheels published** (5.3 ships cp314t) |
| `aioodbc` 0.5.0 (`[sqlserver]`) | pure-Python | OK — async wrapper over pyodbc |
| `pydicom` 3.0.2 / `pynetdicom` 3.0.4 (`[dicom]`) | pure-Python | OK (headers/SR only — no numpy in our extra) |
| `paramiko` 5.0.0 (`[sftp]`) | pure-Python | depends on cryptography (above) + pure `bcrypt`/`pynacl` — **verify pynacl/bcrypt cp314t** before trusting `[sftp]` under no-GIL |
| `PySide6` 6.x (`[console]`) | **compiled (Qt)** | **out of scope** — the console is a *separate* process and never runs in the engine; do not block engine free-threading on Qt |

**Notes / gaps:**

* The **core engine install** (`pip install -e .`, SQLite store) depends on exactly **two**
  free-threaded-relevant compiled wheels: **pydantic-core** and **cryptography** (plus the
  **argon2-cffi-bindings + cffi 2.0** auth chain). All publish `cp314t` wheels today. That is the
  minimal surface to smoke first.
* `uvicorn[standard]`'s optional `httptools`/`uvloop` are compiled; if either lacks a `cp314t` wheel
  the standard extra may fall back to the pure-Python asyncio loop + h11 parser (functional, slightly
  slower). Confirm in the smoke leg; uvloop in particular has historically lagged on new ABIs.
* `[sftp]` (paramiko) drags `pynacl`/`bcrypt` (compiled) — **not yet verified** for `cp314t`. Flag, do
  not assume.
* "Wheel exists" ≠ "thread-safe under parallelism" (caveat §1.2). The wheels unblock *installation*
  on `3.14t`; the smoke leg (§4) is what surfaces a runtime thread-safety break.

---

## 3. GIL-assumption audit (engine packages)

Scope: `pipeline/ transports/ parsing/ store/ config/` (the engine; the GUI console and its Qt
threads are out of scope — the console is a separate process). The question for each spot: *would this
race if the same process ran Python bytecode on two cores at once?*

**Headline: the engine's concurrency model is single-event-loop asyncio, and it holds up well.** The
worker model is cooperative tasks on **one** loop, not a thread pool sharing mutable state — so most
"shared state" is only ever touched by one loop and is not exposed to true parallelism *as written
today*. The audit below lists the spots that *would* matter the moment workers became real parallel
threads, so a future free-threading adoption knows exactly what to harden.

### Module-level registries — populated at import, read-only at runtime → SAFE

* `messagefoundry/transports/base.py:244-245` — `_SOURCES` / `_DESTINATIONS` dicts, mutated only by
  `register_source` / `register_destination`. Every call site is at **module import time** (bottom of
  each `transports/*.py`, e.g. `mllp.py:699-700`, `file.py:553-554`, `dicom.py:584-585`). After import
  they are **read-only** (`build_source`/`build_destination` only read). Read-only-after-import dicts
  are safe under free-threading — no runtime mutation, no race. **No change needed.**
* Other module-level constants found by the audit (`mllp.py:_CODES`, `file.py:_RESERVED`,
  `parsing/x12/message.py:_ENVELOPE_SEGMENTS`, `parsing/dicom/peek.py:_PEEK_TAGS`,
  `auth_routes.py:_VALID_ROLE_IDS`, `store/store.py:_MESSAGE_MIGRATIONS`, etc.) are **immutable
  literals built once at import** and never reassigned. Safe.

### The one runtime-mutated module global — already lock-guarded → SAFE (by an existing lock)

* `messagefoundry/config/wiring.py:2204` — `_load_lock = threading.Lock()`, guarding the
  module-global load state (`_active`, plus `sys.meta_path` / `sys.modules` mutations) in `_loading()`
  (`wiring.py:2207-2229`). This is the **only** engine module-global mutated *at runtime* (a config
  reload runs in a worker thread via `asyncio.to_thread(load_config, ...)`, `engine.py:690`). It is a
  real `threading.Lock` (not asyncio), so it is **correct independently of the GIL** — it already
  serializes the reload against a concurrent validate/load. **This is a positive readiness signal:**
  the one genuinely thread-shared mutation was already written for thread-safety, not GIL-atomicity.
  (`sys.meta_path`/`sys.modules` are process-global CPython state; this lock is what keeps a reload
  from corrupting them, GIL or not.)

### Per-engine mutable state — single-loop today, would need locks under true threading → FLAG

* `messagefoundry/pipeline/engine.py:216-219` — `_inbound_stat_offsets` / `_outbound_stat_offsets`
  dicts (console stats-reset baselines), mutated by `reset_stats()`. Today only ever touched on the
  one event loop, so safe **as currently run**. If router/transform workers became real parallel
  threads each updating engine state, these (and the cumulative counters they offset) become
  read-modify-write on shared dicts and **would need a lock**. Not a bug today; a hardening item for
  adoption.
* `engine.py` uses `asyncio.Lock` (`_graph_lock`, `:207`) and `store/store.py:790` / `sqlserver.py`
  use `asyncio.Lock` — these serialize *coroutines on one loop*. An `asyncio.Lock` does **not**
  provide mutual exclusion across OS threads. Under a future multi-loop / multi-thread worker model
  these would have to be reconsidered (per-loop locks are fine if each connection's workers stay on
  one loop; cross-connection shared state would need `threading.Lock`).

### Real OS threads that exist *today* (via `asyncio.to_thread`) → already parallel, already fine

The default-executor `to_thread` calls (auth/argon2 `service.py`, alert sinks, DICOM/FHIR/file blocking
I/O, `load_config`) already run on real OS threads concurrently with the loop. They were written to be
**self-contained** (no shared-mutable-state mutation back into engine objects without a lock), which is
exactly the discipline free-threading needs — so they are a **non-issue** and a good sign the codebase
already respects the boundary.

### Store / parsing → SAFE

* The store is **SQLite/WAL accessed through aiosqlite on the event loop** (or per-shard files in L3).
  Each connection's worker serializes through `asyncio.Lock` + single-connection access today; the
  reliability invariant (single committed transaction per stage handoff, per-row leases) is a
  **database-level** guarantee, not a GIL guarantee — it survives true parallelism. WAL gives
  concurrent readers + one writer at the SQLite level regardless of the interpreter.
* `parsing/` is **pure and side-effect-free** (CLAUDE.md §4 carve-out) — no module state, no I/O.
  Inherently free-threading-safe; the per-message `Message`/`RawMessage`/peek objects are not shared
  across workers.

### Verdict

**No GIL-dependent correctness bug found in the engine as it runs today** (single event loop). The
one runtime-shared module global is already `threading.Lock`-guarded. The concrete spots that would
need attention *if and only if* workers became real parallel threads are: the per-engine stat dicts /
counters (`engine.py:216-219`) and the `asyncio.Lock`→`threading.Lock` question for any
**cross-connection** shared state. Those are **adoption-time hardening items**, not bugs to fix now.

---

## 4. Recommended path + low-risk scaffold

### Recommendation

1. **Do not adopt free-threading now.** Keep the GIL build as the shipped, supported interpreter.
   **L3 sharding ([`multiproc.md`](multiproc.md)) stays the recommended multi-core path** — it is
   built, isolation-safe, and free of the single-thread perf tax and C-extension-thread-safety risk.
2. **Treat free-threading as a measured experiment**, gated on data from our own load harness, not on
   "wheels exist." The deciding question is whether parallel router/transform on `3.14t` beats N
   shards on the *same* box for *our* HL7 workload — unknown until measured.
3. **Land a non-blocking CI canary** (below) so we get an early, continuous signal on whether the
   engine even **installs and imports + smoke-tests** under `3.14t`, and catch the day a dependency's
   `cp314t` wheel regresses — without that signal ever blocking a merge.

### The scaffold: a separate, allow-failure CI workflow

Added as a **new** workflow file, `.github/workflows/freethread-smoke.yml`, deliberately **not** part
of `ci.yml`:

* It is **not** in `ci.yml`'s `ci-gate` `needs:` list, so it is **not** the required "CI gate"
  context and **cannot** block a PR.
* Every job step that could fail under an immature `3.14t` is wrapped in `continue-on-error: true`,
  and the job itself is `continue-on-error: true`, so a red canary reports a red **informational**
  check, never a failed required one.
* It must **not** be added to branch protection's required checks (see §"required checks" in memory —
  the 7 required contexts are the `test` matrix + bandit + pip-audit + cla). **Do not** add this
  context there.

What it does (kept minimal — install + import + the fastest pure-Python test subset):

* `actions/setup-python` with `python-version: "3.14t"` + `freethreaded: true` +
  `allow-prereleases: true` (setup-python provisions the free-threaded build; `3.14t` is available).
* Install the **core** engine only (`pip install -e ".[dev]"` — no Qt/SQL/DICOM extras), so the smoke
  exercises the minimal compiled surface (pydantic-core, cryptography, argon2 chain).
* Assert `sys._is_gil_enabled() is False` (prove we are actually on the no-GIL interpreter, not a
  silent GIL re-enable from an incompatible extension importing).
* Run a **pure, fast** test subset (parsing + config wiring) under `3.14t`.

If `setup-python` ever cannot provision `3.14t` on the runner, the `continue-on-error` job simply goes
red as information; it never wedges a merge. (Were that to become permanent, the fallback is to
document it and drop the leg rather than ship a broken required check — but as of mid-2026
`setup-python` does provision `3.14t`.)

### Deferred / out of scope for the scaffold

* Any `.py` production change (none made here).
* A free-threaded **load** comparison (the real perf question) — that belongs in the load harness +
  `docs/LOAD-TESTING.md`, run manually, not in a per-PR canary.
* `[sftp]`/`[console]` under no-GIL (paramiko's pynacl/bcrypt, Qt) — verify only if/when those paths
  are in scope for a free-threaded deployment.
