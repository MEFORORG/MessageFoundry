# ADR 0009 — Run-scoped context providers

- **Status:** Accepted (2026-06-14). A no-functional-change refactor that introduces a shared seam; it
  ships in its own PR ahead of the run-scoped accessors that build on it (the "Wave 0 foundation" of the
  multi-session engine build plan).
- **Built:** Implemented. New [`config/run_context.py`](../../messagefoundry/config/run_context.py)
  (the provider registry + `RunContext` + `run_contexts`), with the four existing activations
  (`code_sets`, `reference`, `state`, `environment`) pre-registered as built-in providers. The router
  worker, transform worker ([`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py))
  and the dry-run path ([`pipeline/dryrun.py`](../../messagefoundry/pipeline/dryrun.py)) now activate
  run-scoped state through `run_contexts(...)` instead of hand-written `with (activated(...), …)` tuples.
  Behaviour is byte-identical, proven by the existing suite.
- **Related:** [ADR 0001](0001-staged-pipeline-architecture.md) (the at-least-once / pure-re-run
  invariant every provider must preserve), [ADR 0005](0005-transform-accessible-state.md) and
  [ADR 0006](0006-external-data-lookups.md) (the `state`/`reference` read-side accessors this generalizes),
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability invariant) and §4 (one-way dependency direction).

## Context

Routers and Handlers read engine-published state at call time through **synchronous accessors**:
`code_set()` (config bundle), `reference()` (synced external snapshots, ADR 0006), `state_get()`
(committed cross-message state, ADR 0005), `current_environment()` (the deployment environment name).
Each resolves against a `ContextVar` the engine **activates** for the duration of one router/transform
run, via a small `activated(view)` context manager in that accessor's module.

Three call sites activate these, each with its own hand-written `with` tuple:

- the **router worker** — `code_sets`, `reference`, `environment` (router phase);
- the **transform worker** — `code_sets`, `reference`, `state`, `environment` (transform phase; `state`
  is transform-only);
- **`dryrun.route_message`** — `code_sets`, `reference`, `state` (runs router + transform in one block;
  it has no live environment).

This shape has two problems. First, **every new run-scoped accessor must edit all three tuples** — and
the planned engine work adds several (a live `db_lookup`, a re-run-stable ingest-time clock, …), so each
would collide with the others in exactly these hot lines. Second, the call sites are spread across the
`pipeline/` layer while the accessors live in `config/`, so a new `config/`-layer accessor that needs to
self-register can't reach into `pipeline/` without inverting the one-way dependency (CLAUDE.md §4).

## Decision

Introduce a single **provider registry** in `config/run_context.py`:

- A **provider** is `Callable[[RunContext], AbstractContextManager]` registered once at import via
  `register_run_context(name, provider, *, phases)`, tagged with the phase(s) it applies to (`"router"`,
  `"transform"`). `RunContext` is a small frozen dataclass carrying the per-run views (`code_sets`,
  `reference_view`, `state_view`, `active_environment`); a provider reads only the fields it needs.
- `run_contexts(context, *, phase)` enters every provider registered for `phase`, in **registration
  order**, through one `contextlib.ExitStack`. The three call sites each call it (the engine builds a
  `RunContext` from its live store/registry per run; dry-run builds one from its simulated views). No
  call site enumerates providers anymore.
- The four existing activations are **pre-registered** in `run_context.py` so the seam is byte-identical:
  registration order `code_sets → reference → state → environment` reproduces the old nesting, `state` is
  tagged transform-only, and the others apply in both phases.

The registry lives in **`config/`** (not `pipeline/`) so a `config/`-layer accessor (e.g.
`config.db_lookup`) registers a provider without importing `pipeline/`. Providers register at **engine
module import** (once per process); user config modules never register, so a config reload never
re-appends. Registration is **idempotent by name** (re-import replaces in place).

Two rules are load-bearing and documented here:

1. **Registration order = nesting order.** Because `run_contexts` enters providers in registration order
   via one `ExitStack`, the order in which provider-adding modules are imported determines the runtime
   context-manager nesting. A provider that must nest *inside* another (e.g. an ingest-time provider
   inside `db_lookup`'s executor scope) must be imported after it. Multi-session merge order is set to
   honor this (see the build plan).
2. **Re-run stability.** At-least-once re-runs a router/transform and relies on identical output
   (ADR 0001 / CLAUDE.md §2). Every provider's published view must therefore be re-run-stable. The four
   built-ins are (code sets, reference snapshots, committed state, the deployment environment name). A
   future accessor that exposes **live, non-deterministic** data — a synchronous `db_lookup` that queries
   a database on each pass — is the **deliberate exception**: it is allowed under an explicit owner
   decision (a re-run may re-query and differ, accepted by design), and it must **refuse to run where
   determinism is assumed** — i.e. it raises in the dry-run path rather than fabricating a result. Each
   new provider documents its stability story against this rule.

## Consequences

- **Adding a run-scoped accessor is now additive:** create the accessor module, call
  `register_run_context(...)` once at its import, and it participates in both the live engine and dry-run
  with no edit to `wiring_runner.py` or `dryrun.py`. This is what lets the run-scoped features (db_lookup,
  ingest-time clock, …) be built in parallel worktree sessions without colliding.
- **Byte-identical today:** with only the four built-ins registered, `run_contexts` reproduces the prior
  `with`-tuple behavior exactly (same providers, same order, same per-phase set; dry-run activates
  `environment` to `None`, which is the value `current_environment()` already returned when dry-run left
  it unset). The existing test suite is the proof obligation.
- **Cost:** one indirection (a registry + an `ExitStack`) on the per-run path — negligible against the
  routing/transform work it brackets.
- **Failure mode to respect:** a provider that captures a *stale* or non-re-run-stable view would
  silently break at-least-once determinism. The re-run-stability rule above, plus the dry-run-raises
  exception for live providers, is the guard; reviewers check every new provider against it.
