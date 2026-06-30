# ADR 0044 — Operator alert state (resolvable alert instances)

- **Status:** Accepted (2026-06-27, built — 0.2.10)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-27
- **Related:** BACKLOG #56 · **refines** [ADR 0014](0014-alerting-rules-engine.md) (the rules engine + the
  pure `AlertRuleSet` + the `NotifierAlertSink._emit` per-`(type, connection)` throttle key this de-dupes
  on) · [ADR 0001](0001-staged-pipeline-architecture.md) (the count-and-log / at-least-once invariants —
  alert state must stay a **side observer**, never gate a disposition) ·
  [ADR 0027](0027-per-connection-retention.md) (the additive-table-across-three-backends + single-pass-audit
  discipline this matches; alert-state pruning rides the **same** purge pass) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (engine concurrency = asyncio; one-way dependency; no PHI in logs/alerts),
  §9 ([PHI.md](../PHI.md) — metadata-only) ·
  [`pipeline/alerts.py`](../../messagefoundry/pipeline/alerts.py) (`AlertSink` Protocol + `LoggingAlertSink`) ·
  [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py) (`NotifierAlertSink._emit`, the
  `(event['type'], event['connection'])` key, `AlertRuleSet`) ·
  [`store/base.py`](../../messagefoundry/store/base.py) (`QueueStore` Protocol — the `record_connection_event`
  metadata-only observer pattern) · [`store/store.py`](../../messagefoundry/store/store.py)
  (`_SCHEMA` `connection_event` table + `_migrate`) · [`store/sqlserver.py`](../../messagefoundry/store/sqlserver.py)
  (the SQL Server backend the table must mirror) · [`api/models.py`](../../messagefoundry/api/models.py)
  `ConnectionRow.alerts_active` (line 250 — **stubbed `0` today**) · [`auth/permissions.py`](../../messagefoundry/auth/permissions.py)
  (`Permission.MONITORING_DIAGNOSE`) · BACKLOG #22 (the deferred console Alerts page this rides)

---

## Context

MessageFoundry **fires** alerts but does not **track** them. The `AlertSink`
([`pipeline/alerts.py`](../../messagefoundry/pipeline/alerts.py)) is a fire-and-forget event channel: the
`NotifierAlertSink` ([`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py)) takes each
event — `connection_stopped`, `queue_buildup`, `message_stall`, `connection_error`, `storage_threshold`,
`cert_expiry`, `integrity_drift` — refines it through the ADR 0014 `AlertRuleSet`, throttles a repeat to one
notification per cooldown keyed on `f"{event['type']}:{event['connection']}"` (`_emit`, alert_sinks.py:446),
and fans it to the webhook/email transports. Once enqueued, **the event is gone**: there is no record an
alert ever fired, no concept of an alert that is still *open* vs one an operator has *acknowledged* or that
has *resolved*, and no way to ask "what is wrong right now". The notifier's only memory is the in-memory
`_last_sent` throttle map, which is per-node, reset on restart, and carries a timestamp — not a state.

This shows directly in the API: `ConnectionRow.alerts_active` ([`api/models.py:250`](../../messagefoundry/api/models.py))
is documented as `# stubbed 0 until the alerts feature exists` and the dashboard sets it to a literal `0` at
every fill site ([`api/app.py`](../../messagefoundry/api/app.py) — three `alerts_active=0` rows). The console
renders that stub ([`console/connections.py`](../../messagefoundry/console/connections.py) `_fmt_count(row.alerts_active)`),
so an operator's connections dashboard always shows zero active alerts no matter how many lanes are stopped.

The Mirth/Corepoint operator model is an **alert dashboard**: an alert is an *instance* with a lifecycle
(open → acknowledged → resolved), a first-seen/last-seen window, and an occurrence count — so an operator
triages a list of open conditions, acks the ones they're working, and watches them auto-resolve. ADR 0014
gave the **routing** layer (severity, suppression, per-rule cooldown); it explicitly left **state** out
(the throttle is in-memory, advisory, "lost on restart/failover … acceptable for advisory alerting; durable
state is future work" — ADR 0014 §4 / Consequences). #56 is that durable-state follow-up.

Two [CLAUDE.md](../../CLAUDE.md) invariants bound the design and **must not** be relaxed:

- **Alert state is a side observer, never a disposition gate (§2, ADR 0001).** Exactly as
  `record_connection_event` is "a **pure observer** … touching no `queue` row and calling no finalizer, so it
  can never pin a message's disposition or inflate received counts" ([`store/base.py:527-538`](../../messagefoundry/store/base.py)),
  an alert-instance write must be invisible to `_maybe_finalize_message`. An alert is operational metadata
  about a *connection*, not about a *message*.
- **Metadata only — no new at-rest PHI tier (§9, [PHI.md](../PHI.md)).** Every alert event already carries
  "the connection name + queue shape only — **no PHI**" ([`alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py)
  module docstring); the alert-instance row stores only those same metadata fields (type, connection, severity,
  a `safe_text`-scrubbed reason), so it introduces **no** new PHI classification — like `connection_event`,
  it sits in the existing metadata tier.

## Decision

**Add a durable `alert_instance` store table that records each alert as a resolvable instance
(open / acknowledged / resolved + first_seen / last_seen + count), de-duped on ADR 0014's existing
`(event_type, connection)` throttle key; expose it through `GET /alerts/active` + ack/resolve endpoints gated
by `MONITORING_DIAGNOSE`; wire the stubbed `ConnectionRow.alerts_active` to the real open count; and surface
it as a console Alerts tab riding #22.** The table is additive on all three backends and pruned by the
existing retention pass — it does **not** change the `AlertSink` fire-and-forget contract or the in-memory
throttle.

### D1 — A new `alert_instance` table, an upsert keyed on the throttle key

Add an `alert_instance` table to `_SCHEMA` ([`store/store.py`](../../messagefoundry/store/store.py)),
shaped like the `connection_event` table (metadata-only, encrypted `reason` at rest via the existing
`_CIPHER_COLUMNS` mechanism), keyed on the **same identity ADR 0014 already throttles by** — the
`(event_type, connection)` pair from `_emit`'s `key = f"{event['type']}:{event['connection']}"`
([`alert_sinks.py:446`](../../messagefoundry/pipeline/alert_sinks.py)). One open instance per key:

| Column | Notes |
|---|---|
| `id` | `INTEGER PRIMARY KEY AUTOINCREMENT` (SQLite) / backend-native identity |
| `event_type` | the `AlertSink` event name (bounded enum — must be in `_ALERT_EVENT_TYPES`, [`config/settings.py:1034`](../../messagefoundry/config/settings.py)) |
| `connection` | inbound/outbound connection name (or the cert/db/`engine-integrity` label that already stands in for `connection` in `_emit`) — **config metadata, never payload** |
| `severity` | the effective ADR 0014 severity (`info`/`warning`/`critical`) — last write wins |
| `status` | `open` \| `acknowledged` \| `resolved` |
| `first_seen` / `last_seen` | REAL epochs — the open window |
| `count` | occurrences folded into this open instance (incremented on re-fire) |
| `reason` | `safe_text`-scrubbed diagnostic, **encrypted at rest** (same as `connection_event.reason`); no message body ever |
| `acked_by` / `acked_at` | the operator who acknowledged + when (NULL until acked) |
| `resolved_at` | when it resolved (NULL while open/acknowledged) |

The write is an **upsert**: when an event fires, if an `open`/`acknowledged` instance for that key exists,
bump `last_seen` + `count` (+ refresh `severity`/`reason`); otherwise insert a new `open` row. An
acknowledged instance that re-fires stays `acknowledged` (the operator already owns it) — it does not pop
back to `open`. This is the **identical de-dup grain** the throttle already uses, so an alert dashboard and
the notification throttle agree by construction.

### D2 — The upsert is a side observer on the `_emit` path (ADR 0001 invariant)

The instance upsert hangs off `NotifierAlertSink._emit` — the one chokepoint every event already flows
through — fired through the same fail-soft, off-loop discipline as the notification: it **never** raises into
the caller (the emit methods run "inline on a delivery worker" and "must never raise", [`alerts.py`](../../messagefoundry/pipeline/alerts.py)
docstring), and it touches **no** `queue` row and calls **no** finalizer (the `record_connection_event`
observer contract, [`store/base.py:532-538`](../../messagefoundry/store/base.py)). A new `QueueStore`
Protocol method (`upsert_alert_instance(...)` + the read/ack/resolve accessors) sits beside
`record_connection_event` — metadata-only, its own short transaction, invisible to `_maybe_finalize_message`.
Because it observes `_emit` (not the per-rule routing), an instance is recorded **even when a rule suppresses
the *notification*** (`transports = []`) — the dashboard still shows the open condition the operator chose
not to be paged about. (To-resolve, below: whether a suppressed event records an instance or is fully muted.)

Auto-resolution closes the loop without a human: a `connection_restored` / `connection_started` transition
(the inverse of the firing event) **resolves** the matching open instance. The MVP keys auto-resolution off
the existing inverse signals the engine already emits (the `connection_event` lifecycle kinds); a generic
"hasn't re-fired in N cooldowns ⇒ stale" sweep is **deferred** (it needs a timer and a policy — out of scope
here, like ADR 0014's deferred durable cross-node dedup).

### D3 — `GET /alerts/active` + ack/resolve, RBAC `MONITORING_DIAGNOSE`

Three additive API routes ([`api/app.py`](../../messagefoundry/api/app.py)), an `AlertInstance`/`AlertInstanceList`
Pydantic model ([`api/models.py`](../../messagefoundry/api/models.py)):

- `GET /alerts/active` — list open + acknowledged instances (newest `last_seen` first), per-channel-RBAC
  scoped exactly as `list_connection_events` scopes (`allowed_channels`: inbound-direction instances filtered
  to the allow-set, shared-outbound topology excluded — [`store/base.py:555-560`](../../messagefoundry/store/base.py)).
- `POST /alerts/{id}/ack` — set `status='acknowledged'`, record `acked_by`/`acked_at` (the requesting
  operator's actor), write an `audit_log` row (action `alert_ack`, **no message content** — the
  metadata-only audit discipline, never PHI).
- `POST /alerts/{id}/resolve` — set `status='resolved'`, `resolved_at`, audit (`alert_resolve`).

Reading is **diagnostic state**, and ack/resolve **mutate** operator-facing state, so all three gate on
`Permission.MONITORING_DIAGNOSE` ([`auth/permissions.py:26`](../../messagefoundry/auth/permissions.py)) —
the same diagnose-tier permission `GET /events`-adjacent diagnostic routes use (app.py:1048/1798), not the
read-only `MONITORING_READ` the dashboard uses. (To-resolve: confirm GET-active on DIAGNOSE vs READ.)

### D4 — Wire the stubbed `ConnectionRow.alerts_active` to the real open count

Replace the literal `alerts_active=0` at all three fill sites in `_connection_rows`
([`api/app.py`](../../messagefoundry/api/app.py)) with the **open** (not acknowledged, not resolved)
instance count for that connection — a single grouped `COUNT(*) WHERE status='open' GROUP BY connection`
read on the lockfree read path, joined to the row by connection name. The model field's comment
([`api/models.py:250`](../../messagefoundry/api/models.py)) updates from "stubbed 0 until the alerts feature
exists" to its real meaning. The console dashboard (`_fmt_count(row.alerts_active)`,
[`console/connections.py`](../../messagefoundry/console/connections.py)) then renders a true count with **no
console change**. Acknowledged instances are **excluded** from `alerts_active` (an operator working an alert
clears the red badge) but remain visible on the Alerts page — the standard ack semantics.

### D5 — A console Alerts tab (rides #22), additive store-table parity, pruned by the retention pass

- **Console (BACKLOG #22).** A thin Alerts page in the PySide6 console — a table over `GET /alerts/active`
  with Acknowledge / Resolve actions calling the D3 routes through the API client. It imports **only** the
  `api/` Pydantic models + the HTTP client (the §10 console rule), never the engine; it ships **with** #22
  (the deferred Alerts/Event-Log console work), not as a separate page.
- **Three-backend parity.** `alert_instance` lands additively on **SQLite + Postgres + SQL Server**
  ([`store/store.py`](../../messagefoundry/store/store.py) `_SCHEMA` + `_migrate`, [`store/sqlserver.py`](../../messagefoundry/store/sqlserver.py),
  and the Postgres backend) with a schema/accessor parity test — the same additive-table discipline ADR 0027
  set for its per-connection purge. **This is the coordination point:** the table add **must** be sequenced
  with the parallel **pool-prewarm store sibling** (sole store-writer) and the **#57 roles migration** so the
  three `_SCHEMA`/`_migrate` edits rebase cleanly and don't clobber each other.
- **Retention.** Resolved instances are pruned by the **existing** single `RetentionRunner.run_once` pass
  (the same pass that already interleaves body-purge + the #46 `connection_event` purge, ADR 0027) under a
  short window analogous to `connection_event_retention_hours` — metadata-only, one audit row, never an
  open/acknowledged instance.

## Acceptance Criteria

> EARS form; each linked (`→`) to its test/fixture. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHEN an alert event fires through `NotifierAlertSink._emit` and no open/acknowledged instance
  exists for its `(event_type, connection)` key, THE SYSTEM SHALL insert one `open` `alert_instance` with
  `count=1` and `first_seen == last_seen`.
  → `tests/test_alert_state.py::test_first_fire_opens_instance`
- **AC-2** — WHEN the same `(event_type, connection)` re-fires, THE SYSTEM SHALL fold it into the existing
  open instance (increment `count`, advance `last_seen`) rather than create a second row.
  → `tests/test_alert_state.py::test_refire_dedupes_on_throttle_key`
- **AC-3** — WHEN a rule suppresses the notification (`transports = []`), THE SYSTEM SHALL still record/update
  the instance, so a suppressed-but-active condition is visible on the Alerts page.
  → `tests/test_alert_state.py::test_suppressed_notification_still_recorded`
- **AC-4** — WHEN an operator ack's an instance, THE SYSTEM SHALL set `status='acknowledged'` + `acked_by`/`acked_at`,
  write exactly one `alert_ack` audit row with no message content, and exclude it from `alerts_active`.
  → `tests/test_alert_state.py::test_ack_transitions_and_audits`
- **AC-5** — WHEN the inverse lifecycle signal arrives (e.g. `connection_restored`), THE SYSTEM SHALL resolve
  the matching open/acknowledged instance (`status='resolved'`, `resolved_at`).
  → `tests/test_alert_state.py::test_auto_resolves_on_inverse_signal`
- **AC-6** — THE SYSTEM SHALL populate `ConnectionRow.alerts_active` with the **open** instance count for that
  connection (acknowledged/resolved excluded), replacing the stubbed `0`.
  → `tests/test_connection_rows.py::test_alerts_active_reflects_open_count`
- **AC-7** — `GET /alerts/active` / ack / resolve SHALL require `Permission.MONITORING_DIAGNOSE` and apply the
  same per-channel RBAC scoping as `list_connection_events`.
  → `tests/test_api_alerts.py::test_alerts_routes_rbac_and_scope`
- **AC-8** — THE SYSTEM SHALL create + operate the `alert_instance` table identically on SQLite, Postgres, and
  SQL Server (schema/accessor parity), and resolved instances SHALL be pruned by the existing retention pass.
  → `tests/test_alert_state.py::test_three_backend_parity`
- **AC-9** — An `alert_instance` write SHALL touch no `queue` row, call no finalizer, and never raise into the
  `_emit` caller (a store error is swallowed/logged, never wedging a delivery worker).
  → `tests/test_alert_state.py::test_instance_write_is_side_observer`

## Options considered

1. **A durable `alert_instance` table, upserted on the existing `(event_type, connection)` throttle key,
   read/acked/resolved over the API — CHOSEN.** Reuses ADR 0014's de-dup grain so the dashboard and the
   notification throttle agree; mirrors the `connection_event` metadata-only side-observer table + the ADR
   0027 additive-three-backend + single-pass-prune discipline; wires the already-present `alerts_active` stub.
   Minimal new surface, no `AlertSink` contract change.
2. **A new `[alerts].rules`-style settings overlay / in-memory-only state.** Rejected: state must be
   **durable** (survive restart/failover — the explicit ADR 0014 gap) and queryable across nodes; an
   in-memory map is exactly what we already have and is insufficient. A settings overlay is config, not state.
3. **Derive "active alerts" on the fly from the `connection_event` log (no new table).** Rejected: the event
   log is an append-only history with no `open/acknowledged/resolved` lifecycle, no ack actor, and no
   per-key fold — reconstructing instance state from raw events per request is expensive and can't store an
   acknowledgement. A first-class instance table is the right model.
4. **A second alert-state runner/sink wrapping `NotifierAlertSink`.** Rejected (same shape as ADR 0014 §2): a
   wrapping sink can't see the post-rule decision cleanly and would split state-writing from the one `_emit`
   chokepoint; the upsert belongs *on* the emit path where the throttle key is already computed.
5. **Status quo (`alerts_active` stays `0`, fire-and-forget only).** Rejected: the dashboard permanently lies
   ("0 active" with lanes stopped), and operators have no triage surface — the explicit Mirth/Corepoint gap #56 names.

## Consequences

**Positive** — Operators get a real alert dashboard: a list of open conditions with ack/resolve, a true
`alerts_active` count on the connections page (the stub becomes real), and an audit trail of who ack'd what.
It reuses ADR 0014's de-dup grain (the throttle and the dashboard agree), the `connection_event` side-observer
+ metadata-only + encrypted-`reason` pattern, the ADR 0027 additive-three-backend + single-prune-pass
discipline, and the existing `MONITORING_DIAGNOSE` + per-channel-RBAC scoping — **no new mental model, no new
PHI tier, no `AlertSink` contract change.**

**Negative / risks** — A new table on three backends is a parity surface that must stay in lock-step (AC-8 +
the parity test) and **must be land-ordered** with the pool-prewarm store sibling (sole store-writer) and the
#57 roles migration so the `_SCHEMA`/`_migrate` edits don't collide. The instance upsert adds one short write
per `_emit` (bounded by the throttle — re-fires within a cooldown are a single `count`/`last_seen` bump, not a
new row). Auto-resolution in the MVP relies on the engine emitting an inverse lifecycle signal; conditions
with no clean inverse (e.g. a transient `queue_buildup` that simply drains) need the deferred staleness sweep
to clear, so an operator may have to resolve some manually until that lands. In a multi-node cluster each node
upserts what it observes — same per-node-observation reality ADR 0014 §4 documents; durable cross-node dedup
of shared-resource events stays the deferred future work ADR 0014 already named.

**Out of scope / stays as-is** — The `AlertSink` fire-and-forget contract + the in-memory `_last_sent`
throttle (unchanged; the instance table is *additive* state beside them, not a replacement). Timed multi-stage
escalation chains (still deferred, ADR 0014 §3). The cross-node durable dedup of shared-resource events
(ADR 0014 §4). A generic "stale ⇒ auto-resolve after N cooldowns" sweep (deferred — needs a timer + policy).

## To resolve on acceptance

- [ ] **Suppressed-event recording.** Confirm a rule-suppressed event (`transports = []`) still records an
  instance (D2 — dashboard shows the condition even when un-paged), **or** a suppression also mutes the state
  write. (Recommend: record it — suppression is a *notification* choice, not "this isn't happening".)
- [ ] **GET-active permission.** Confirm `GET /alerts/active` on `MONITORING_DIAGNOSE` (the ack/resolve tier)
  vs `MONITORING_READ` (the dashboard read tier) — the reads are diagnostic state, so DIAGNOSE is proposed,
  but a read-only dashboard could justify READ for the list and DIAGNOSE only for the mutations.
- [ ] **Land-order with the store siblings.** Confirm the `alert_instance` `_SCHEMA`/`_migrate` add rebases
  cleanly onto the **pool-prewarm store refactor** (sole store-writer) **and** the **#57 roles migration** —
  coordinate the merge order so the three additive store edits don't clobber one another.
- [ ] **Auto-resolution coverage.** Confirm which events have a clean inverse the MVP auto-resolves on
  (`connection_restored`/`connection_started`) and which (`queue_buildup`/`storage_threshold`/`message_stall`)
  rely on the deferred staleness sweep or manual resolve until it lands.
- [ ] **Resolved-instance retention window.** Confirm the prune window for resolved instances (a
  `connection_event_retention_hours` analog) and that it rides the **existing** `RetentionRunner.run_once`
  pass + one audit row (never an open/acknowledged instance).
- [ ] **Console scope.** Confirm the Alerts tab ships **with** #22 (deferred Alerts/Event-Log console work),
  not as a standalone page, and consumes only `api/` models + the HTTP client.
