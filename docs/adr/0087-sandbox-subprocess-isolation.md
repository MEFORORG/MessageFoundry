# 0087 — Router/Handler subprocess isolation

- **Status:** Accepted; **Amended (2026-08-04)** — the transform-result parity rule changed shape. The child now materialises a container return with `_partition`'s **own** rule instead of reproducing its exact input container, so a tuple/set/generator **delivers** in both modes (BACKLOG #341). AC-11 and the "Result parity" bullet below are rewritten accordingly; the isolation boundary and the codec grammar are untouched.  <!-- opt-in subprocess isolation built (#197, 2026-07-10) -->
- **Date:** 2026-07-10
- **Related:** [ADR 0009](0009-run-scoped-context-providers.md) (RunContext providers) · [ADR 0010](0010-handler-callable-db-lookup.md) / [ADR 0043](0043-fhir-read-lookup.md) (`db_lookup`/`fhir_lookup`) · [ADR 0072](0072-traced-dryrun-mode.md) (tracer seam it composes with) · [ADR 0036](0036-windows-config-source-trust.md) / [ADR 0041](0041-load-path-attestation-and-change-attribution.md) (config-source trust) · CLAUDE.md §2 (reliability/purity, count-and-log) · CLAUDE.md §4 (layering) · BACKLOG #197 · ASVS 15.2.5 / `docs/security/ASVS-L3-REMEDIATION-PLAN.md` WP-L3-17

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
  the "fn-selector"; the parent marshals `(id, phase, name, payload, run_context)` over a
  length-prefixed **non-executing** pipe codec and gets back a *description* of the return value.
- **The IPC codec is part of the boundary, not plumbing (amended — see "IPC codec" below).** Both
  legs speak **MFW2** (`pipeline/_sandbox_codec.py`): a segmented, closed-tag JSON wire whose decode
  path is `json.loads` + `bytes.decode` and a literal tag match. Nothing is pickled in either
  direction, in either process.
- **The boundary is the win.** The child constructs only the message *graph* — never the store, DEK,
  crypto, or sockets — so admin code physically cannot reach the parent's secrets/audit chain across
  the process boundary. Defence-in-depth on top: a **forbidden-import guard** (a `sys.meta_path`
  finder that denies `socket`/`ssl`/store/crypto/transports/api, with those already-cached modules
  purged so a cached import re-triggers it), a **parent-enforced wall-clock cap** (the authoritative
  bound on every platform — the parent kills a worker that overruns it) plus a POSIX
  `RLIMIT_CPU`/`RLIMIT_AS` backstop inside the child where `resource` exists (a no-op on Windows).
  The import guard is **defence-in-depth only** and must never be cited as a compensating control: a
  module imported before the finder goes up keeps a live reference (`urllib.request.socket` is the
  real socket module inside a sandboxed Handler), so the address-space boundary and the codec are the
  load-bearing controls.
- **Interposition at the `route_only`/`transform_one` seam.** A `sandbox`/`run_context` pair threads
  through those two functions; `sandbox=None`/`mode=off` is the existing in-process line verbatim (so
  it **composes** with the ADR 0072 `tracer`). The live `wiring_runner` dispatch sites build the
  per-phase `RunContext` on the loop (as today) and pass it — `loop.run_in_executor`/`to_thread` do
  not copy contextvars across a process, so the RunContext is **re-marshalled** and the child
  re-establishes `run_contexts(rc, phase)` itself.
- **Engine-side validation stays engine-side.** The worker describes only the *shape* of the
  Router/Handler result; the fail-closed unknown-handler / unknown-outbound validation in
  `route_only`/`transform_one` runs in the **parent**, so a compromised worker cannot smuggle an
  unknown destination past the graph. That claim is only load-bearing because the codec builds
  nothing but plain data *before* that validation runs — under the original pickle pipe the name
  validation ran long after `pickle.loads` had already executed whatever the child sent.
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

### IPC codec (amendment — MFW2, replaces the pickle pipe)

The original decision marshalled both directions with `pickle`, justified as "a private pipe between
the engine and its own spawned worker — never external/untrusted data". **That premise was false in
the child→parent direction**, and CLAUDE.md §11 forbids a compensating control resting on a false
premise. Two facts make it false:

1. The child runs exactly the code this ADR exists to distrust. A Handler returning an object with a
   custom `__reduce__` executed arbitrary code **in the engine parent**, because the parent's reader
   thread called `pickle.loads` on the response frame *before* any envelope inspection. That is a
   complete bypass of the address-space boundary, inside this ADR's own threat model.
2. `subprocess`/`os`/`ctypes` are importable inside the sandbox, and a **grandchild** the Handler
   spawns inherits fd 1 (the response pipe) and survives `proc.kill()`. It can write a frame at any
   later moment.

So **both legs are untrusted by contract** and both speak the same schema — one review, one fuzz
target, no `pickle` import left to mis-suppress:

- **Wire.** Outer `>I length || body` (64 MiB cap, unchanged). The body is *segmented*:
  `>I header_len || header_json || ( >I blob_len || blob_bytes )*`, so a large message payload never
  round-trips through JSON string escaping. Bounds: header ≤ 64 MiB, ≤ 65536 segments, value nesting
  ≤ 256 — each an independent fail-closed rejection. The header bound is deliberately the frame bound
  and nothing tighter: a request header carries the whole `reference_view`, so a 16 MiB header cap was
  in practice a ~700k-entry ceiling on reference tables that dead-lettered **every** message on a
  bigger graph while `mode=off` served it, and the outer framing already refuses an over-cap frame
  before a byte is parsed. A fail-closed cap must be sized against real traffic or it is an outage.
- **Closed grammar.** Containers are tagged (`{"l":…}` list, `{"p":…}` tuple, `{"d":[[k,v],…]}` dict,
  `{"b":…}` bytes, `{"f":…}` non-finite float, `{"D"/"E"/"T":…}` datetime/date/time), so a bare array
  is illegal at value level and nothing needs escaping. Decoding is `json.loads` + `bytes.decode` +
  a literal tag match calling ordinary constructors — it cannot name a type, import a module, or
  reach `__reduce__`. An ADR 0028 `mfb64:v1:` body is already an ASCII `str` and rides as one; it is
  explicitly **not** re-wrapped through the bytes tag.
- **Segment discipline.** References are strictly sequential and exactly-once (a cursor; decode
  succeeds only if every segment was consumed), so the one silent failure mode of an indirection
  table — cross-wiring one `Send`'s PHI body onto another `Send`'s destination — is unreachable by
  construction, not merely untested.
- **A frame answers a request, or the worker dies.** Every dispatch mints a fresh
  `secrets.token_hex(16)` id and a response must echo the whole `(id, phase, name)` triple; *and* the
  parent treats a frame queued **before** a dispatch — or left over **after** its answer — as fatal.
  Both halves are needed, and a first attempt at this shipped only the weaker one: a derivable id
  (a per-spawn nonce plus a counter, both visible to the child) let the code running dispatch *N*
  compute *N+1*'s id and pre-stage its answer, so a benign sibling Handler's delivery was silently
  replaced by attacker-chosen content on a message it never saw — for `phase="accepts"`, a
  routing-verdict flip with no `ERROR` and no disposition anomaly. A random per-dispatch id is not
  derivable, and the worker only learns it from the request frame, which the parent writes only after
  proving nothing is already queued. A **dead peer** is deliberately not the same event: EOF is a
  parent-private sentinel with no wire form, so a worker cannot manufacture one and it proves nothing
  about trust. It reaps the worker without failing a call that already holds a correlation-proven
  answer — treating it as a forgery would fail closed on a signal that carries no information.
  **What this is not.** It does not confine one Handler from another *inside* a worker: code running a
  dispatch is handed that dispatch's id, and it could equally rebind a sibling in the child's own
  registry. `mode=off` draws no such line either — see the residuals.
- **Result parity.** The child materialises a router result with `_handler_names`' own logic (so a
  documented-supported **generator Router**, which is unpicklable, now works under `mode=subprocess`)
  and — since the 2026-08-04 amendment — a transform result with `_partition`'s own logic, the shared
  `wiring.handler_result_items` rule. A **container** return (list, tuple, set, generator) is described
  element-wise, so both modes deliver the **same `Send`s, into the same three partitions**; anything
  that rule does not recognise as a container stays a single item, and an item `_partition` would ignore
  is **described rather than omitted**, so it still drops and a `Send` **subclass** still delivers,
  byte-identically to `mode=off`. The materialization runs inside the child's `with run_contexts(...)`,
  so a **generator Handler's** lazily-executed body sees the same run-scoped providers (`code_set`,
  `state_get`, …) it sees under `mode=off` — materialising it later, at describe time, would make those
  raise under `mode=subprocess` only.
  - **CAUTION — parity is over the delivered set, not the order, for an unordered container.** An *ordered*
    container (list, tuple, generator) delivers in its own order under either mode. A **`set`** has no
    defined iteration order — `Send` is a frozen dataclass hashed on its fields and `str` hashing is
    seeded per process — so the child, being a **different process**, materialises it in a different
    order than the parent would (measured: a six-element set iterated in a different order in **all
    four** independent process pairs probed). Fan-out order from a
    `set` is therefore unspecified in *both* modes and is **not** a mode-parity obligation; only the
    multiset is. This is a property of `set`, not of the sandbox: the same non-reproducibility appears
    across a crash re-run at `mode=off`. See `wiring.handler_result_items` for the full statement and
    `docs/CONNECTIONS.md` for the author-facing steer toward ordered containers.
  - **Residual (mode-independent, recorded in [ADR 0072](0072-traced-dryrun-mode.md) §6 gate 1 —
    do not restate it here):** a generator Handler is not execution-traced and its per-invocation
    `sends` are empty. It reproduces at `mode=off`, so it is not a sandbox residual; it is noted here
    only because this bullet is where a reader meets generator Handlers.
- **`Send` carries encoded text, never a live `Message`.** The sole parent-side consumer already
  reduces it to a `str`, so the parent's `Send(...)` rebuild is a provable no-op for ADR 0104's
  copy-on-Send choke point instead of taking a second snapshot.
- **`code_sets` are hoisted off the per-dispatch frame** (they were ~430 KB / ~4.6 ms per message on a
  realistic crosswalk) and travel **once per spawn in the `boot` frame** instead. The engine's tables
  are the source of truth on both sides, so the child cannot diverge from `mode=off`. A first attempt
  let the child re-read `codesets/` itself and pinned a SHA-256 digest to *detect* the divergence —
  which converted a fail-open hazard into a worse fail-closed one: after any routine respawn (a
  wall-cap kill, a crash) following an unreloaded `codesets/` edit, every message on that inbound
  dead-lettered permanently, burning a full config load per attempt. Sending the tables removes the
  hazard rather than detecting it.
- **A lookup table travels in one of two forms, and they decode identically.** A crosswalk is
  overwhelmingly `str -> short str`; those tables ride as a single plain JSON object so the C
  encoder/decoder does the walk, and anything else falls back to the tagged per-entry form. The
  compact form is an *encoding*, not a grammar relaxation — the decoder still proves every value is a
  `str`. Without it the per-entry Python walk over `reference_view` made `mode=subprocess` ~5×
  slower per message than the pickle it replaced on a 20k-entry table. With it, that table costs
  ~1.4× the pickle round-trip (4.5 ms vs 3.3 ms of marshalling; ~6.2 ms end-to-end per dispatch,
  ~0.19 ms with no reference view) — the standing, measured price of a non-executing wire, and well
  inside the ~60 msg/s per-interface end-to-end bound the pipeline already has.
- **`CapturedResponse` relocated** to the store-free `config/response.py` (re-exported from
  `store/store.py`). It is what `response_view` carries, and `messagefoundry.store` is on the
  forbidden-import list — so `mode=subprocess` plus a LOOPBACK inbound with a correlated reply was
  **100% non-functional** before this amendment.
- **Framing vs decoding are separated.** The parent's daemon reader thread does framing only; a
  rejection there would have been a silent reader death and a wall-cap *hang*, not a fail-closed
  error. Decoding happens on the dispatch thread inside its existing `try`. `SandboxCodecError`
  subclasses `SandboxError`, so the documented "raises `SandboxError`" contract still holds.

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
  views to marshallable dicts and process the message (route + deliver) rather than fail marshalling —
  i.e. the control processes real traffic against the default SQLite store, not just an empty
  `RunContext`.
  → `tests/test_sandbox.py::test_subprocess_marshals_live_store_run_context`,
  `tests/test_sandbox.py::test_run_context_codec_snapshots_mappingproxy_views`

### Acceptance Criteria — IPC codec amendment (MFW2)

- **AC-8** — IF a sandboxed Handler returns an object carrying a hostile `__reduce__`, THEN THE
  SYSTEM SHALL NOT execute it in the engine parent, and SHALL resolve the message byte-identically to
  `mode=off`.
  → `tests/test_sandbox.py::test_a_handler_returning_a_reduce_gadget_does_not_execute_in_the_engine`,
  `tests/test_sandbox_codec.py::test_a_reduce_gadget_never_reaches_the_parent`
- **AC-9** — WHERE a frame is malformed, over a cap, out of the closed value grammar, or out of
  segment sequence, THE SYSTEM SHALL reject it with a `SandboxError` (never a cross-wired value,
  never a hang, never a non-`SandboxError` escape).
  → `tests/test_sandbox_codec.py::test_hostile_frames_fail_closed`,
  `tests/test_sandbox_codec.py::test_blob_reference_discipline_is_exactly_once_and_sequential`
- **AC-10** — WHEN a worker writes an extra/forged response frame — whether *before* its own answer or
  staged *between* dispatches — THE SYSTEM SHALL NOT consume it as a later dispatch's answer; it SHALL
  drop that worker and fail the call closed, and the later dispatch SHALL resolve identically to
  `mode=off`. Request ids SHALL be unpredictable and never reused. A **dead peer** (EOF) is NOT a
  frame — it has no wire form, so a worker cannot manufacture one — and SHALL drop the worker without
  failing a call that already has a correlation-proven answer.
  → `tests/test_sandbox.py::test_a_desynced_or_forged_response_is_rejected`,
  `tests/test_sandbox.py::test_a_frame_staged_between_dispatches_can_never_answer_the_next_one`,
  `tests/test_sandbox.py::test_a_dead_peer_is_not_treated_as_a_forged_frame`,
  `tests/test_sandbox.py::test_request_ids_are_unpredictable_and_never_reused`,
  `tests/test_sandbox_codec.py::test_hostile_frames_fail_closed[name_mismatch]`
- **AC-11** — WHERE `[sandbox].mode=subprocess`, THE SYSTEM SHALL route a **generator** Router
  identically to `mode=off` (it previously dead-lettered every message), and SHALL preserve
  `_partition` parity for **every** return shape — where, since the 2026-08-04 amendment, a
  tuple/set/generator of `Send`s **delivers** in both modes (BACKLOG #341), a `Send` subclass still
  delivers, and a non-iterable unrecognized value (a bare `int`, a `__reduce__` gadget) still drops.
  Parity is over the **multiset** of items in each of the three partitions, plus their **order for an
  ordered container**; a `set` return has no defined iteration order in either mode, so its fan-out
  order is explicitly **not** covered by this SHALL (see the Result-parity bullet).
  WHERE the Handler is a **generator**, its body SHALL execute inside the child's run context, so a
  run-scoped accessor within it resolves as it does under `mode=off` rather than raising.
  → `tests/test_sandbox.py::test_generator_router_routes_under_mode_subprocess`,
  `tests/test_sandbox_codec.py::test_partition_parity_table`,
  `tests/test_sandbox.py::test_a_generator_handler_delivers_under_mode_subprocess`,
  `tests/test_sandbox.py::test_a_generator_handlers_body_runs_inside_the_childs_run_context`,
  `tests/test_sandbox_codec.py::test_handler_result_items_treats_a_str_as_a_single_value`
- **AC-12** — WHERE the engine publishes code-set tables, THE SYSTEM SHALL serve **those** tables to a
  sandboxed Router/Handler — including after a transparent respawn that follows a `codesets/` edit
  made without a `/config/reload` — and the per-dispatch frame SHALL carry no code-set bytes.
  → `tests/test_sandbox.py::test_an_unreloaded_codeset_edit_does_not_brick_the_inbound`,
  `tests/test_sandbox.py::test_the_engines_code_sets_win_over_the_childs_own_load`,
  `tests/test_sandbox.py::test_code_sets_reach_the_child_without_travelling_per_dispatch`,
  `tests/test_sandbox.py::test_code_sets_are_loaded_by_the_child_and_resolve`,
  `tests/test_sandbox_codec.py::test_code_sets_round_trip_through_the_boot_frame`
- **AC-13** — WHERE a sandboxed Handler reads a captured reply (`response_get`), THE SYSTEM SHALL
  deliver the same result as `mode=off` (previously the child died on the forbidden
  `messagefoundry.store` import, making the feature combination non-functional).
  → `tests/test_sandbox.py::test_response_view_reaches_a_sandboxed_handler`
- **AC-14** — WHERE a value crosses the boundary that `mode=off` accepts — a large `reference_view`,
  a deeply nested `SetState` value — THE SYSTEM SHALL marshal it rather than dead-letter it, so no
  codec bound is a mode-dependent behaviour change.
  → `tests/test_sandbox_codec.py::test_the_header_cap_is_the_frame_cap_and_nothing_tighter`,
  `tests/test_sandbox_codec.py::test_a_large_reference_view_round_trips`,
  `tests/test_sandbox_codec.py::test_a_deeply_nested_value_is_not_a_mode_dependent_dead_letter`
- **AC-15** — WHERE a Router *mutates* its payload (a contract violation — Routers must be pure), THE
  SYSTEM's routing decision under `mode=subprocess` MAY differ from `mode=off`, and that difference
  SHALL be pinned by a test rather than left to drift. This is the one place `[sandbox].mode` is not
  transparent; it is a residual, not a guarantee — see "Out of scope / honest residuals".
  → `tests/test_sandbox.py::test_a_mutating_router_is_the_one_documented_mode_divergence`

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
closes the heaviest WP-L3-17 (15.2.5) residual as a **residual-closure**. That closure is only as
good as the pipe: as originally shipped, the parent's `pickle.loads` of the child's frame let admin
code cross the boundary it claims to enforce, so the MFW2 amendment is what makes the claim true
rather than an enhancement on top of it. Default-off means zero overhead and byte-identical behaviour
for existing deployments; the whole existing test suite is unaffected (sandbox is `None`/off
everywhere).

**Negative / risks** — When enabled, each message pays a codec round-trip to the worker and the
per-inbound worker serializes that inbound's Router/Handler calls (matching the per-inbound worker
cadence). A Handler needing live enrichment cannot use the sandbox this PR. The engine builds the
`RunContext` `reference_view`/`state_view` as live `types.MappingProxyType` windows onto the store
caches; `enc_run_context` snapshots them to plain point-in-time rows **by construction** as it walks
them onto the wire — the read-only content a router/transform would have seen at that instant (re-run
stability makes a point-in-time copy the contract anyway), so `mode=subprocess` processes real
messages against the default SQLite store. Snapshotting copies the reference/state caches per
dispatch, an accepted cost of the opt-in isolation mode (`code_sets`, the largest of the three, is
hoisted out of the per-dispatch frame entirely). A value outside the closed grammar fails closed
(`SandboxError`), never silently degrading — and the reverse is also true, so a Handler returning an
exotic object now reports a *codec* rejection rather than the pickle error text it used to.

**Out of scope / honest residuals** —
- **DEK-in-worker:** the child never constructs the store/DEK, so there is no DEK in the worker to
  strip; if a future change loads store state at registry-build time, that must stay out of the
  child.
- **The boundary confines the address space, not the machine.** `os`/`subprocess`/`ctypes`/`sqlite3`/
  `http.client` are importable inside the sandbox, so a Handler can still read and write files, open
  network connections, and spawn processes **as the service account**. The forbidden-import guard
  narrows the obvious paths but is bypassable (a module imported before it goes up keeps a live
  reference) and carries no compensating-control weight. Least-privilege for the service account
  remains the host control that bounds this. ADR 0147 tracks the fuller closure.
- **A grandchild the Handler spawns inherits fd 1** and outlives `proc.kill()`. It can write frames
  into the parent's reader at any later moment. What makes that harmless is the *codec* (nothing it
  writes can construct an arbitrary object) plus the request-answer binding (nothing it writes can be
  taken as an answer, and its mere presence kills the worker) — not the process teardown. On POSIX,
  `/proc/<pid>/fd/1` is additionally openable by any same-UID process subject to
  `ptrace_scope`/`hidepid`. What it **can** still do is force a kill-and-respawn, i.e. dead-letter
  messages on that inbound: a compromised worker can deny its own feed.
- **One Handler is not confined from another inside a worker.** All of an inbound's Routers/Handlers
  share one child and one `Registry`, so admin code can rebind a sibling in-process. This seam does
  not change that — `mode=off` shares an address space too — and any claim that the pipe protects
  handler-to-handler integrity is false. The boundary drawn here is between admin code and the
  **engine**. Per-Handler confinement would need a worker per Handler.
- **The child's stderr is inherited by the engine** (`stderr=None`), unframed and unparsed: a
  sandboxed Handler that prints writes straight into the engine's log. That is a log-injection /
  PHI-to-log surface, not a frame surface.
- **ADR 0072 tracing does not compose with `mode=subprocess`.** In `_accepted`/`route_only`/
  `transform_one` the sandbox branch precedes the tracer branch, so a traced dry-run produces no
  Router/Handler trace when the sandbox is on. It composes with `mode=off` as stated above.
- **A *mutating* Router is the one place `mode` is not transparent.** Every dispatch marshals the
  payload, so the child rebuilds its own object; in-process, one object is *shared*. A Router that
  mutates its payload — which CLAUDE.md §2 forbids (routers/transforms must be pure) and
  `HandlerAccepts` restates for predicates — therefore reaches an `accepts=` predicate under
  `mode=off` and not under `mode=subprocess`, so the two modes can **route differently**; on a non-HL7
  `route_message` (dry-run / `check` / Test Bench, where one writable `RawMessage` is shared with the
  handlers too) it can also change the delivered bytes. This predates the codec — the original pickle
  pipe copied the payload per dispatch identically — and closing it would mean returning the payload
  from every router/predicate dispatch, roughly doubling the wire cost of the routing stage to
  reproduce a documented authoring hazard. Pinned by AC-15 so it cannot drift silently. If a graph
  needs a Router-derived fact at the predicate, pass it through the message, not through mutation.
- **A Handler's own exception reaches the operator wrapped.** In-process a Handler raise propagates as
  itself; under `mode=subprocess` it is reported across the pipe and re-raised as `SandboxError`
  carrying `"<Type>: <message>"`. The **disposition is identical** (both land in the router/transform
  worker's `except Exception` → `ERROR`/dead-letter); only the `last_error` text differs, and no
  traceback crosses.
- **Run-scoped sinks do not cross back.** The `#162` unmapped-capture buffer drains inside the child
  against a sink the child never installs. No production sink exists today, so nothing is lost — but
  any future run-scoped sink (capture, metrics, audit) will silently no-op under `mode=subprocess`
  until the codec grows a side-channel for it.
- **`db_lookup`/`fhir_lookup` forward-over-IPC** — deferred; sandboxed live-enrichment Handlers run
  with `mode=off`.
- **Load-time top-level config exec** — not sandboxed; unchanged `_assert_safe_config_source` gate.
- **`mode=subprocess` and the ADR 0071 B5 SS-only thread-hop fusion are mutually exclusive, and the
  sandbox wins.** The fused twins call `route_only`/`transform_one` with no `sandbox=`, so fusion
  would run the Router, the Handler *and* the `accepts=` predicate in the engine process — silently
  outside the guard the operator turned on. `_open_fused_pool` therefore **disables fusion** with a
  loud warning when both are configured. That is fail-closed, not free: a graph tuned for fusion loses
  it the moment the sandbox goes on (an IPC round-trip inside a fused hop would have negated the
  fusion anyway).
- **Least-privilege service account as the default** — remains environment-delegated (host control).
