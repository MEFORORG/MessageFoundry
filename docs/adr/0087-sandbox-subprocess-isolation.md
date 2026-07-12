# 0087 — Router/Handler subprocess isolation

- **Status:** Accepted  <!-- opt-in subprocess isolation built (#197, 2026-07-10) -->
- **Date:** 2026-07-10
- **Related:** [ADR 0009](0009-run-scoped-context-providers.md) (RunContext providers) · [ADR 0010](0010-live-db-lookup-in-handlers.md) / [ADR 0043](0043-fhir-lookup.md) (`db_lookup`/`fhir_lookup`) · [ADR 0072](0072-traced-dry-run.md) (tracer seam it composes with) · [ADR 0036](0036-config-source-trust.md) / [ADR 0041](0041-load-path-attestation-and-change-attribution.md) (config-source trust) · CLAUDE.md §2 (reliability/purity, count-and-log) · CLAUDE.md §4 (layering) · BACKLOG #197 · ASVS 15.2.5 / `docs/security/ASVS-L3-REMEDIATION-PLAN.md` WP-L3-17

---

## Context

Routers and Handlers are admin-authored Python the engine executes **in its own address space**.
CLAUDE.md §2 states the trust posture plainly: these capabilities *"run in the same process and OS
account as the in-memory store key and the audit chain"*, and the reliability invariant requires
*"routers and transforms must be pure (message in → message out, no external side effects)"* — with
one carve-out, a *"live, read-only lookup … `db_lookup` … or a FHIR read/search via `fhir_lookup`
… run off the event loop"*.

ASVS 15.2.5 ("additional protections/sandbox around dangerous functionality") reads this in-process
model as a **Fail** on a strict interpretation; the remediation plan carried it as WP-L3-17, the
*heaviest* documented residual — a built encapsulation OR-list (fail-closed `[egress]`, read-only
off-loop `db_lookup`, parser caps, one-way import boundary) conditionally satisfies 15.2.5 but there
is **no hard boundary** between admin code and the DEK / audit chain / sockets.

The forcing constraints on any fix:

- **Byte-identical, zero-overhead default.** The overwhelming majority of deployments run trusted
  admin code and cannot pay an isolation tax. The default MUST be indistinguishable from today.
- **Throughput.** A per-message `fork`/spawn would destroy the throughput target — isolation must
  reuse a long-lived worker.
- **Reliability / purity (CLAUDE.md §2).** At-least-once re-runs a router/transform and *"relies on
  a re-run re-deriving identical output"*; isolation must not change the result or the disposition,
  and any isolation fault must go to `ERROR`/dead-letter **post-ACK** — *"never accept-and-drop,
  never crash the connection"* (count-and-log invariant).
- **Layering (CLAUDE.md §4).** Isolation is a `pipeline/` concern — *no `api/`/`console/` imports*.
- **No new dependency without cause (CLAUDE.md §5).** Prefer stdlib.

## Decision

Add an **opt-in `[sandbox]` section** that, when `mode=subprocess`, runs each inbound's
Router/Handler in a **persistent per-inbound worker subprocess**; `mode=off` (the default) runs them
in-process, byte-identically and with zero overhead.

- **Approach (B) SUBPROCESS, stdlib-only.** `pipeline/sandbox.py` (`SandboxPolicy`, `SandboxSession`,
  `run_sandboxed`, `SandboxError`) + `pipeline/_sandbox_worker.py` (the child, launched
  `python -m messagefoundry.pipeline._sandbox_worker`). No new dependency. **RestrictedPython is
  rejected** — it is not hard isolation (it restricts an AST but shares the address space) and would
  add a dependency.
- **Persistent per-inbound worker, never a per-message fork.** The child is spawned lazily on first
  dispatch, reused across messages, and reaped at `stop()`. It loads **its own** `Registry` from the
  same `config_dir` (the unchanged safe-source loader) and looks the Router/Handler up **by name** —
  the "fn-selector"; the parent marshals `(phase, name, payload, run_context)` over a length-prefixed
  pickle pipe and gets back the **raw** return value.
- **The boundary is the win.** The child constructs only the message *graph* — never the store, DEK,
  crypto, or sockets — so admin code physically cannot reach the parent's secrets/audit chain across
  the process boundary. Defence-in-depth on top: a **forbidden-import guard** (a `sys.meta_path`
  finder that denies `socket`/`ssl`/store/crypto/transports/api, with those already-cached modules
  purged so a cached import re-triggers it), a **parent-enforced wall-clock cap** (the authoritative
  bound on every platform — the parent kills a worker that overruns it) plus a POSIX
  `RLIMIT_CPU`/`RLIMIT_AS` backstop inside the child where `resource` exists (a no-op on Windows).
- **Interposition at the `route_only`/`transform_one` seam.** A `sandbox`/`run_context` pair threads
  through those two functions; `sandbox=None`/`mode=off` is the existing in-process line verbatim (so
  it **composes** with the ADR 0072 `tracer`). The live `wiring_runner` dispatch sites build the
  per-phase `RunContext` on the loop (as today) and pass it — `loop.run_in_executor`/`to_thread` do
  not copy contextvars across a process, so the RunContext is **re-marshalled** and the child
  re-establishes `run_contexts(rc, phase)` itself.
- **Engine-side validation stays engine-side.** The worker returns only the raw Router/Handler
  result; the fail-closed unknown-handler / unknown-outbound validation in `route_only`/
  `transform_one` runs in the **parent**, so a compromised worker cannot smuggle an unknown
  destination past the graph.
- **`db_lookup`/`fhir_lookup` in the sandbox = FORBIDDEN, fail-closed (this PR).** They bridge back
  onto the engine event loop via `run_coroutine_threadsafe`, which a subprocess boundary breaks. A
  sandboxed Handler that calls one gets a clear `SandboxError` → `ERROR`/dead-letter. A Handler that
  needs live enrichment runs with `mode=off` (per-policy). Forward-over-IPC is a documented
  next-phase residual.
- **Isolation denial routing.** A forbidden import/op, a resource-cap overrun, a worker crash, or an
  unmarshallable payload/run-context raises `SandboxError`, which the router/transform worker routes
  to `ERROR`/dead-letter **post-ACK** via the existing `_apply_router_internal_error` /
  `_apply_transform_internal_error` paths — no NAK, never accept-and-drop, never a crashed
  connection.
- **Load-time top-level exec is NOT sandboxed** in this PR. `_exec_module` runs admin config under
  the unchanged `_assert_safe_config_source` DACL gate (ADR 0036); sandboxing import-time exec is a
  chicken-and-egg (the worker itself must load the graph) and out of scope. `_assert_safe_config_source`
  is **not weakened**.

## Acceptance Criteria

- **AC-1** — WHERE `[sandbox].mode=off` (the default), THE SYSTEM SHALL run a Router and a Handler
  in-process and return a result byte-identical to a direct call, spawning no subprocess.
  → `tests/test_sandbox.py::test_mode_off_session_is_byte_identical_and_never_spawns`
- **AC-2** — WHERE `[sandbox].mode=subprocess`, THE SYSTEM SHALL return a Router/Handler result
  byte-identical to the in-process path for a benign function.
  → `tests/test_sandbox.py::test_subprocess_parity_router_and_handler`
- **AC-3** — WHEN a sandboxed Handler performs a forbidden op (imports `socket`), THE SYSTEM SHALL
  deny it with `SandboxError` and keep the persistent worker usable for the next message.
  → `tests/test_sandbox.py::test_forbidden_import_is_denied_and_worker_survives`
- **AC-4** — IF a sandboxed Router/Handler exceeds its wall cap (a busy-loop), THEN THE SYSTEM SHALL
  cap and terminate it (not wedge intake) and transparently respawn for the next message.
  → `tests/test_sandbox.py::test_busy_loop_is_wall_capped_and_recovers`
- **AC-5** — IF a sandboxed Handler calls `db_lookup`/`fhir_lookup`, THEN THE SYSTEM SHALL fail
  closed with `SandboxError`.
  → `tests/test_sandbox.py::test_db_lookup_in_sandbox_fails_closed`
- **AC-6** — WHEN a Router/Handler runs in the worker, THE SYSTEM SHALL activate the marshalled
  `RunContext` in the child (e.g. `current_environment()` resolves).
  → `tests/test_sandbox.py::test_run_context_reaches_the_worker`
- **AC-7** — WHERE `[sandbox].mode=subprocess` and the engine passes its **real** `RunContext` (the
  store's live `MappingProxyType` `reference_view`/`state_view`), THE SYSTEM SHALL snapshot those
  views to picklable dicts and process the message (route + deliver) rather than fail marshalling —
  i.e. the control processes real traffic against the default SQLite store, not just an empty
  `RunContext`.
  → `tests/test_sandbox.py::test_subprocess_marshals_live_store_run_context`,
  `tests/test_sandbox.py::test_picklable_run_context_snapshots_mappingproxy_views`

## Options considered

1. **Persistent per-inbound subprocess worker, stdlib-only — CHOSEN.** Real address-space boundary;
   reuse amortizes spawn cost; no new dependency; `mode=off` stays byte-identical.
2. **RestrictedPython / AST restriction — Rejected.** Not hard isolation (shared heap, key, audit
   chain); adds a dependency; a determined admin bypasses it.
3. **Per-message `fork`/spawn — Rejected.** Destroys the throughput target; not viable on Windows
   (spawn, not fork).
4. **Container/OS sandbox (seccomp/AppContainer) — Deferred.** Environment-delegated, platform-specific;
   the subprocess boundary + host controls are the pragmatic first step. Still tracked as the
   fuller-closure host control.

## Consequences

**Positive** — Genuine hard isolation of admin code from the DEK/audit-chain/sockets when enabled;
closes the heaviest WP-L3-17 (15.2.5) residual as a **residual-closure**. Default-off means zero
overhead and byte-identical behaviour for existing deployments; the whole existing test suite is
unaffected (sandbox is `None`/off everywhere).

**Negative / risks** — When enabled, each message pays a pickle round-trip to the worker and the
per-inbound worker serializes that inbound's Router/Handler calls (matching the per-inbound worker
cadence). A Handler needing live enrichment cannot use the sandbox this PR. The engine builds the
`RunContext` `reference_view`/`state_view` as live `types.MappingProxyType` windows onto the store
caches, which are **not** picklable; `run_sandboxed` therefore snapshots them to plain point-in-time
`dict`s (`_picklable_run_context`) before the frame crosses the pipe — the read-only content a
router/transform would have seen at that instant (re-run stability makes a point-in-time copy the
contract anyway), so `mode=subprocess` processes real messages against the default SQLite store.
Snapshotting copies the reference/state caches per dispatch, an accepted cost of the opt-in isolation
mode. Any residually-unpicklable view (a future exotic value) still fails closed (`SandboxError`),
never silently degrading.

**Out of scope / honest residuals** —
- **DEK-in-worker:** the child never constructs the store/DEK, so there is no DEK in the worker to
  strip; if a future change loads store state at registry-build time, that must stay out of the
  child.
- **`db_lookup`/`fhir_lookup` forward-over-IPC** — deferred; sandboxed live-enrichment Handlers run
  with `mode=off`.
- **Load-time top-level config exec** — not sandboxed; unchanged `_assert_safe_config_source` gate.
- **Combining `mode=subprocess` with the ADR 0071 B5 SS-only thread-hop fusion** — the fused SS path
  is orthogonal/default-off and not wired to the session in this PR; sandbox is honored on the
  standard async dispatch.
- **Least-privilege service account as the default** — remains environment-delegated (host control).
