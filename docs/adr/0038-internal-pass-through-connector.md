# 0038 — Internal pass-through (PT) connector (L4) — engine-internal re-ingress for 1:N routing

- **Status:** **Accepted (implemented, 2026-06-27).** Built across PR #585 (the `PT` connector +
  the `pt_deliveries` branch of `transform_handoff`, SQLite), PR #587 (the fail-fast PT-backend guard at
  start + reload + dry-run), and PR #590 (re-ingress parity on Postgres + SQL Server).
- **Date:** 2026-06-27
- **Related:** [ADR 0013](0013-query-response-orchestration.md) (query/response orchestration) +
  [0013-increment-2-reingress-design](0013-increment-2-reingress-design.md) — PT **generalizes** the
  re-ingress primitive · ADR 0001 (staged pipeline — the `transform_handoff` transaction) ·
  [`transports/passthrough.py`](../../messagefoundry/transports/passthrough.py) ·
  [CLAUDE.md](../../CLAUDE.md) §1 (count-and-log, single-finalizer), reliability invariant (at-least-once,
  pure routers/transforms)

---

## Context

A logical feed sometimes needs to **fan out and re-route deeper without an external hop** — one feed's
output routed through a *second* router/handler graph, internally. ADR 0013 Increment 2 built a
re-ingress primitive, but only for **query→response capture**: a `Loopback()` inbound fed by a capturing
outbound's *partner reply* (1:1). There was no first-class way for an ordinary Handler to push its
**transformed** message back into the pipeline on a named internal channel that carries its **own**
Router (1:N internal routing).

Whatever does this must not break the staged-pipeline invariants. Per CLAUDE.md, every handoff is

> a **single committed transaction** (claim → produce-next-stage rows → complete-this-stage), so a
> message is never lost or partially handed off …

and the store **finalizer is its single authority**, and *every received message is persisted before
the ACK* (count-and-log). It also must not re-introduce the **double-injection trap** ADR 0013 names:
re-ingressing through the source/listener seam via a bare `enqueue_ingress` would inject a message twice
on a re-run.

## Decision

**Add an internal pass-through (PT) inbound: a Handler may `Send` into a PT inbound (naming it like any
outbound), and the engine re-ingresses that body as a new, independent, content-addressed child message
on the PT inbound's channel — produced inside the *parent's* `transform_handoff` transaction — where the
PT inbound's own Router decides where it goes next.**

- **Inert connector, handoff does the work.** [`PassThroughSource`](../../messagefoundry/transports/passthrough.py)
  is a deliberately inert inbound: no socket, no poll; its `start()` records the handler and returns and
  the handler is **never invoked** (a unit test pins this). The re-ingress is the `pt_deliveries` branch
  of `transform_handoff`, which produces each PT child's INGRESS row (`source_type="passthrough"`, its
  own content-addressed id, status `RECEIVED`) **plus** the parent's terminal OUTBOUND marker in the
  **same transaction** that consumes the parent's routed row. A crash/re-run is therefore an idempotent
  no-op (content-addressed id; the consumed row is gone), and the PT child re-enters via the queue's
  router worker — **not** the listener seam — so the double-injection trap (ADR 0013) is avoided.
- **All invariants preserved.** Count-and-log holds (the child is persisted `RECEIVED` before any work);
  at-least-once holds (single-transaction handoff); the single-finalizer holds (the parent's marker
  finalizes the parent, the child is an *independent* message finalized on its own); per the reliability
  invariant the body is the *transformed* (pure) message.
- **Correlation-depth loop cap.** Each child carries `correlation_depth` (parent + 1); a breach of
  `correlation_depth_cap` (default 8) produces **no child**, dead-letters the parent's marker (`ERROR`),
  and is logged — bounding internal PT (and re-ingress) loops.
- **Allow-listed to capable backends.** PT re-ingress is opt-in per backend via `supports_pt_reingress`
  (SQLite, Postgres, SQL Server today). The engine **fails fast at startup/reload/dry-run**
  (`check_pt_backend_supported`) if the wired graph contains a PT inbound on a backend that doesn't
  implement the branch — *before any inbound listener binds* — so the runtime `NotImplementedError`
  (after a message is already ACKed) can never surface. A graph with no PT inbound, or on SQLite, is
  byte-identical to before.

## Acceptance Criteria

- **AC-1** — WHEN a Handler `Send`s into a PT inbound, THE SYSTEM SHALL re-ingress the body as a new,
  independent, content-addressed child message on the PT inbound's channel, produced inside the parent's
  `transform_handoff` transaction (atomic with consuming the parent's routed row).
  → `tests/test_passthrough.py`
- **AC-2** — THE PT CONNECTOR SHALL never invoke its inbound handler (no socket/poll seam); re-ingress
  is the engine-internal handoff only.
  → `tests/test_passthrough.py`
- **AC-3** — WHILE re-ingressing, THE SYSTEM SHALL preserve count-and-log (the child persists `RECEIVED`
  before work), at-least-once (single committed transaction), and the single-finalizer (parent and child
  finalize independently).
  → `tests/test_passthrough.py`
- **AC-4** — IF a PT re-ingress would exceed `correlation_depth_cap`, THEN THE SYSTEM SHALL produce no
  child, dead-letter the parent's marker (`ERROR`), and log the breach.
  → `tests/test_passthrough.py`
- **AC-5** — IF the wired graph contains a PT inbound on a backend that does not implement PT re-ingress,
  THEN THE SYSTEM SHALL refuse to start/reload (and fail `dryrun`) before any inbound listener binds.
  → `tests/test_passthrough.py` · `tests/test_dryrun.py`
- **AC-6** — THE PT re-ingress branch SHALL behave identically on the SQLite, Postgres and SQL Server
  stores (the allow-listed backends).
  → `tests/test_postgres_store.py` · `tests/test_sqlserver_store.py`

## Options considered

1. **A PT inbound re-ingressed inside `transform_handoff`, with a depth cap, allow-listed by backend
   (this).** **CHOSEN.** Reuses ADR 0013's atomic content-addressed re-ingress shape, keeps every
   staged-pipeline invariant, and is fail-fast on an unsupported backend.
2. **Re-ingress through the source/listener seam (a bare `enqueue_ingress`).** **Rejected** — the
   double-injection trap (ADR 0013): a re-run injects the message twice; not atomic with consuming the
   parent's row.
3. **A one-off `Loopback()` per fan-out (the ADR 0013 Increment 2 shape).** **Rejected as the general
   mechanism** — it is 1:1 query→response capture of a *partner reply*, not 1:N internal routing of the
   *transformed* message, and has no first-class Router on the internal channel.

## Consequences

**Positive** — one logical feed can fan out and re-route internally with no external hop; the new path
inherits all reliability invariants for free (atomic, at-least-once, count-and-log, single-finalizer);
the depth cap bounds internal loops; unsupported backends are caught before any message is accepted.

**Negative / risks** — a deep PT/re-ingress chain consumes commits (each hop is a real ingress); the
`correlation_depth_cap` is a global bound, not per-path; PT is unavailable on a backend that hasn't
implemented `supports_pt_reingress` (refused at startup, by design).

**Out of scope** — per-message-key routing of the child (the child re-enters its channel's normal
Router); cross-backend PT (a message's stages live on one store — see ADR 0039's non-goals); any change
to the ADR 0013 query/response capture path (untouched; PT generalizes, does not replace it).
