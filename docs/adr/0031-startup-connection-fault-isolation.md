# ADR 0031 — Startup connection fault isolation (a failed connection must not crash the engine)

- **Status:** **Accepted (2026-06-21, owner go).** Built in the same change. `0031` is the next free
  ADR number (0023/0027/0029 stay reserved; 0024/0025/0026/0028/0030 are taken — see
  [README.md](README.md)).
- **Built:** yes — [`RegistryRunner.start`](../../messagefoundry/pipeline/wiring_runner.py) now
  isolates a per-connection build/bind failure instead of aborting the whole startup; the failure is
  recorded, alerted, and surfaced on `GET /connections` + `/connections/{name}/metadata` and in the
  console connections table.
- **Decision in one line:** at **engine startup**, a single Connection that fails to build/bind
  (unresolvable `env()`/cert, an egress-allowlist refusal, a port already in use, a cleartext-exposure
  refusal, a capture/backend mismatch) is **isolated** — logged loudly, recorded as `failed` with its
  reason, and alerted — and the engine **brings up the rest of the graph and serves the API**; a
  failed *outbound* still gets its delivery worker (with no connector) so rows routed to it are
  **retried, never dropped**, and a reload/restart that builds it self-heals the lane; a failed
  *inbound* simply isn't listening. **Reload stays fail-fast** (its pre-quiesce `build_check` still
  rejects broken config before touching a healthy running graph) — only *startup* degrades.
- **Related:**
  - [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline + supervision model whose
    "a crash in one is isolated" principle this extends to the one remaining un-isolated path —
    startup wiring) and its **reliability** / **count-and-log** invariants ([CLAUDE.md](../../CLAUDE.md)
    §2) this change is careful to preserve;
  - [ADR 0013](0013-query-response-orchestration.md) §"fail closed at start" (the capturing-outbound /
    backend check — relaxed from *crash the engine* to *degrade this lane*, while still never silently
    dropping replies);
  - [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §0 + [ADR 0025](0025-dicom-codec-store-connectors.md)
    §9 (the MLLP/DIMSE cleartext-exposure gate — a refused listener now degrades rather than crashing,
    and **never binds insecurely**);
  - [ADR 0014](0014-alerting-rules-engine.md) + the `AlertSink` protocol
    ([pipeline/alerts.py](../../messagefoundry/pipeline/alerts.py)) — a startup failure reuses the
    existing `connection_stopped` signal (its meaning, "this connection is down until an operator
    intervenes", fits exactly), so no new sink method is added;
  - the `messagefoundry check` / dry-run gate (`build_check_registry` in
    [pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)) — the *pre-deploy*
    place to catch broken config; this ADR is the *runtime safety net* for failures that survive to
    start time (a cert missing on the box, a port conflict, an env not set), not a license to ship
    config that `check` would reject.

## Context

Before this change, [`RegistryRunner.start`](../../messagefoundry/pipeline/wiring_runner.py) built
every Connection inside one `try` block: it constructed all outbound connectors, built the live-lookup
executor, then bound every inbound listener. **Any** single failure — one outbound whose `env()` or
client cert couldn't resolve, one inbound whose port was taken — hit the `except`, tore down the
*partial* start, and re-raised. That exception propagated up through `Engine.start()` → the ASGI
lifespan → uvicorn's "Application startup failed. Exiting." So **one misconfigured or unreachable
connection took down the API and every healthy feed with it.**

That is the opposite of the engine's own design philosophy. The whole point of the staged pipeline
(ADR 0001) and the `RegistryRunner` supervisor is fault isolation: "one listener + a router worker + a
transform worker per inbound … supervised by the `RegistryRunner` so a crash in one is isolated"
([CLAUDE.md](../../CLAUDE.md) §2); "each outbound connection drains independently (a slow/failing one
never blocks siblings)". Every *runtime* failure path is already isolated — a bad message dead-letters,
a slow transform can't block routing, a failing delivery retries without stalling siblings. The single
remaining place where one component could take down the whole engine was **startup wiring**, and a
healthcare integration hub fronting many feeds should not refuse to start its other 20 feeds because
feed #21's downstream cert is missing this morning.

The real-world trigger: a sample graph included a WS-* SOAP outbound to an immunization registry whose
mutual-TLS client cert / WS-Security credentials come from `MEFOR_VALUE_REGISTRY_*` env vars
(deliberately not in the versioned env file). On a box where those aren't set, the SOAP connector's
constructor raises while loading the cert chain — and the entire engine refused to start, taking the
ADT, X12, eligibility, and FHIR feeds with it.

## Decision

### §1 Per-connection isolation at startup

`start()` builds each Connection independently. The outbound build + the inbound bind are each wrapped
so a failure of one is caught, **recorded** (`self._failed[name] = reason`), **logged** at ERROR with
the cause, and **alerted** (`AlertSink.connection_stopped(name, detail="failed to start: …")`) — then
startup **continues**. The outer `except` that unwinds + re-raises is retained as a backstop for
genuinely fatal, *graph-wide* startup errors (the store, the lookup executor) — those are not a single
connection and should still abort.

The end-of-start log distinguishes the two outcomes: a clean start logs `wiring started: N inbound, M
outbound`, a degraded start logs a WARNING `wiring started DEGRADED: … K failed to start … <names +
reasons>`.

### §2 A failed outbound retries; it never drops

A failed *outbound* is recorded in `_failed` **and still gets its delivery worker spawned — but with
no connector in `_destinations`.** The worker's existing "no connector for a claimed row" branch then
`mark_failed`s any row routed to that lane (with the connection's retry/backoff policy) and raises the
queue-buildup alert, exactly as it already does during a brief mid-reconcile window. Consequences:

- **The reliability + count-and-log invariants hold.** A message a router/handler sends to a failed
  outbound is enqueued, retried, and surfaced (disposition + `queue_buildup` alert + a growing
  backlog) — it is **never silently dropped or accepted-and-lost** ([CLAUDE.md](../../CLAUDE.md) §2).
  The ADR 0013 promise ("never silently drop replies") is preserved: a capturing outbound on an
  unsupported backend degrades its lane (rows retry) rather than dropping anything.
- **It self-heals.** Because the worker reads its connector live per item, a later reload/restart that
  builds the connector drains the accumulated backlog with no message loss.

### §3 A failed inbound simply isn't listening

A failed *inbound* is recorded in `_failed`; it is **not** in `_sources`, so `inbound_running()` is
False and it accepts nothing. Its router + transform workers are still spawned (they are
registry-tied, not source-tied), so any **crash-recovered** ingress/routed backlog from a prior run
still drains even though the listener is down. A cleartext-exposure refusal degrades the same way and
**never results in an insecure bind** — the gate still refused; the engine just doesn't also die.

### §4 Recovery is operator-driven; reload stays fail-fast

- **Engine restart** re-runs `start()`, which now isolates per connection and builds the previously
  failed one successfully once its cause is fixed. This is the primary recovery path.
- **An inbound** can also be recovered live with `POST /connections/{name}/start` (binds it; clears the
  failure marker on success).
- **A reload** recovers a failed *outbound* in place: `reload()`'s pre-quiesce `build_check` first
  re-validates the **whole** new registry — so it still **fail-fast rejects** a reload while a
  connection is *still* broken (you cannot push broken config onto a healthy running graph) — and once
  the cause is fixed, `_reconcile_outbounds` rebuilds the failed lane's connector in place and clears
  the marker.

The asymmetry is deliberate: **startup degrades** (a restart must never be held hostage by one
connection that's broken on the box right now), but **reload is fail-fast** (an operator editing a
running production engine gets the config validated before anything is quiesced).

### §5 Surfacing

`RegistryRunner` exposes `connection_failed(name) -> str | None` and `degraded_connections() ->
dict[str, str]`. `GET /connections` reports `status: "failed"` + an `error` reason on the affected
source/destination rows, and **emits a standalone row for a degraded outbound that has no traffic edge
yet** (so a failed-at-start outbound is never invisible just because nothing has been routed to it).
`GET /connections/{name}/metadata` carries the same `error`. The console connections table renders a
`failed` status in red with the reason on hover.

## Consequences

- **The engine starts in the presence of a broken connection** and serves the API, so operators can
  see the degraded state (log WARNING + `connection_stopped` alert + `failed` rows) and fix it without
  the all-or-nothing "the whole engine is down" failure mode.
- **A degraded outbound accrues a retrying backlog** rather than dropping traffic; the existing
  buildup alerting makes that visible. This is the intended trade (retry + alert > drop, and >
  crash-everything).
- **`messagefoundry check` is unchanged and still the right gate** for config errors pre-deploy — it
  builds every connector and fails on a bad one. This ADR does not weaken that; it adds resilience for
  failures that only manifest at runtime on a specific box.
- **No new dependency, no new AlertSink method, no schema change beyond an additive optional `error`
  field** on the two connection API models. The change is additive and the byte-for-byte behavior of a
  fully-valid graph is unchanged (no `_failed` entries → identical log line, identical rows).

## Options considered

1. **Crash the engine on any connection failure (status quo).** Simple, fail-loud — but a single
   misconfigured/unreachable feed denies service to every other feed. Rejected: contradicts the
   engine's own isolation philosophy and is the wrong posture for a multi-feed clinical hub.
2. **Isolate, retry failed-outbound rows, operator-driven recovery (chosen).** Preserves the
   reliability/count-and-log invariants, reuses existing retry/backoff/alert machinery (no new code
   paths for delivery), self-heals on reload/restart.
3. **Isolate, but immediately dead-letter messages routed to a failed outbound.** Rejected: a
   transient cause (a cert momentarily absent, an env not yet exported) would dead-letter live traffic
   that a simple retry would have delivered after a fix. Retry-and-alert is the safer default.
4. **Auto-retry the *build* of a failed connection on a background timer.** More machinery and timing
   semantics for marginal benefit; the reload/restart paths already rebuild. Deferred — can be added
   later without changing this contract.
