# 0040 — Free-threaded (no-GIL / cp314t) engine support (L6) — evaluated, not adopted now

- **Status:** **Rejected for now (declined-by-design, 2026-06-27)** — *evaluated and not adopted*. This
  is a deliberate **deferral with a revisit gate**, not a permanent close: the GIL build stays the
  shipped, supported interpreter; L3 sharding (ADR 0037) remains the recommended multi-core path. The
  only thing built is a **weekly, non-blocking cp314t CI canary** (an early-warning signal). Revisit
  **only** if a measured load comparison on the harness shows free-threading wins on our workload.
  Assessment landed in PR #589.
- **Date:** 2026-06-27
- **Related:** [docs/design/freethread.md](../design/freethread.md) (full assessment) · ADR 0037 (L3
  multi-process sharding — the across-processes alternative this is weighed against) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (asyncio concurrency model), reliability invariant (pure
  routers/transforms)

---

## Context

The engine is **GIL-bound and single-process** by design (CLAUDE.md §2): concurrency is **asyncio** on
**one event loop**, so all Python bytecode (peek, routing, transforms, strict validation) runs on a
**single core**. Free-threading (PEP 703, the `cp314t` no-GIL build) is the *within-one-process*
alternative to L3's *across-processes* sharding: run the asyncio workers as real OS threads inside one
process so router/transform across connections run truly in parallel while sharing one store, one API
port, one process. It is attractive *specifically because* the hot path is **pure** (the reliability
invariant: routers and transforms are pure, message-in → message-out) — the ideal free-threading
workload, no shared mutable state to coordinate.

But the honest caveats forbid adopting it on "wheels exist" alone: (1) the no-GIL build adds a
**single-thread perf tax** — single-busy-connection work is *slower*, not faster, so a win must be
**measured on our load harness**, never assumed; (2) a published `cp314t` wheel proves a C extension
*compiles*, **not** that it is thread-safe under true parallelism; (3) `cp314t` is a distinct ABI with
more fragile install friction; and (4) it does **not** replace L3 (no process isolation, no independent
failure domains, no per-shard stores).

## Decision

**Do not adopt free-threading now. Keep the GIL build as the shipped interpreter; L3 sharding (ADR 0037)
stays the recommended multi-core path. Land only a non-blocking cp314t CI canary as an early-warning
signal, and treat free-threading as a measured experiment gated on harness data.**

- **Dependency-wheel readiness — ready, but narrow.** The **core engine install** (SQLite store) has
  exactly **two** free-threaded-relevant compiled wheels — **pydantic-core** and **cryptography** —
  plus the **argon2-cffi-bindings + cffi 2.0** auth chain. **All publish `cp314t` wheels today** (incl.
  win_amd64). Everything else on the core path is pure-Python (python-hl7, hl7apy, fastapi/starlette,
  uvicorn, httpx/anyio, aiosqlite, ldap3, tomlkit, defusedxml, prometheus-client). Optional extras
  asyncpg / pyodbc also ship cp314t; **`[sftp]` (paramiko → pynacl/bcrypt) is unverified** and `[console]`
  (Qt) is out of scope (separate process). A wheel unblocks *installation*, not thread-safety.
- **GIL-assumption audit — no correctness bug today.** Across `pipeline/ transports/ parsing/ store/
  config/`: module-level registries are populated at import and read-only at runtime (safe); the one
  runtime-mutated module global (`config/wiring.py` load state) is already guarded by a real
  `threading.Lock` (safe independent of the GIL); the store is SQLite/WAL via aiosqlite (a database-level
  guarantee, survives parallelism); `parsing/` is pure. The spots that *would* need locks **only if**
  workers became real parallel threads (the per-engine stat dicts in `engine.py`; the
  `asyncio.Lock`→`threading.Lock` question for any cross-connection shared state) are **adoption-time
  hardening items, not bugs to fix now**.
- **The canary, deliberately non-blocking.** A separate `freethread-smoke.yml` workflow (weekly):
  `setup-python` `3.14t` + `freethreaded`, install the **core** engine only, assert
  `sys._is_gil_enabled() is False`, and run a fast pure-Python test subset. It is **not** in the
  `ci-gate` `needs:` list, every step and the job are `continue-on-error: true`, and it **must not** be
  added to branch protection's required checks — so a red canary is informational, never blocks a merge.

This changes **no** production behaviour and breaks **no** invariant — nothing about how the engine runs
today is altered.

## Options considered

1. **Decline now; keep the GIL build + L3 sharding; land a non-blocking canary; revisit on measured
   data (this).** **CHOSEN.** L3 is built, isolation-safe, and free of the single-thread perf tax and the
   C-extension-thread-safety risk; the canary gives an early signal (catch the day a `cp314t` wheel
   regresses) at zero merge-gating cost.
2. **Adopt free-threading now (run workers as real parallel threads on `cp314t`).** **Rejected** — the
   single-thread perf tax and unproven C-extension thread-safety make it a measured-experiment question,
   not a default; it does not provide L3's process isolation / per-shard stores.
3. **Do nothing (no canary).** **Rejected** — then a future evaluation starts blind and a wheel/ABI
   regression goes unnoticed; the cheap, non-blocking canary keeps a continuous readiness signal.

## Consequences

**Positive** — the supported runtime and all invariants are unchanged; the multi-core story stays the
proven L3 path; the canary surfaces install/import/thread regressions early without ever gating a PR;
the readiness assessment (narrow compiled surface, no GIL-correctness bug today) is recorded for a future
revisit.

**Negative / risks** — the single-busy-connection perf tax and per-thread C-extension thread-safety
remain **unmeasured** for our workload (the deciding data is deferred to the load harness); `cp314t`
install friction (the cffi 2.0 chain) is real; a permanently-unprovisionable `3.14t` runner would make
the canary red as information (then documented/dropped, not shipped as a broken required check).

**Out of scope / deferred** — any `.py` production change (none made); a free-threaded **load**
comparison on the harness (the real perf question, run manually); `[sftp]`/`[console]` under no-GIL; and
the adoption-time hardening items (engine stat dicts, cross-connection lock types) — addressed *only if*
a measured win justifies adopting free-threading.
