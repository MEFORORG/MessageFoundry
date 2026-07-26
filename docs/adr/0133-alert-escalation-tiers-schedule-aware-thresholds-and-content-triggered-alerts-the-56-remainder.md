# ADR 0133 — Alert escalation tiers, schedule-aware thresholds, and content-triggered alerts (the #56 remainder)

- **Status:** Accepted (2026-07-18, built) — DEMAND-GATE-BACKLOG Wave 4 (lane `dg-s1b`).  <!-- Proposed → Accepted → Superseded by NNNN / Rejected -->
- **Date:** 2026-07-18
- **Related:** BACKLOG #81 (the confirmed remainder of #56) · **refines** [ADR 0014](0014-alerting-rules-engine.md)
  (the rules engine + the pure `AlertRuleSet.decide` + the per-`(type, connection)` throttle this escalation
  and content path ride) · **builds on** [ADR 0044](0044-operator-alert-state.md) (the resolvable
  `alert_instance` state; this adds the `escalation_tier` column beside the #143 `suspended_until` one) ·
  [ADR 0001](0001-staged-pipeline-architecture.md) (the at-least-once / **routers-and-transforms-must-be-pure**
  invariant the content-trigger carve-out below reconciles) · [ADR 0095](0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  (the `Schedule` / `ActiveWindow` model #147 built, **reused** verbatim for schedule-aware rules) ·
  [CLAUDE.md](../../CLAUDE.md) §2/§9 (PHI-free alerts, no new PHI tier) ·
  [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py) ·
  [`config/settings.py`](../../messagefoundry/config/settings.py) ·
  [`store/store.py`](../../messagefoundry/store/store.py) (+ `sqlserver.py` / `postgres.py`).

---

## Context

#56 (ADR 0044) shipped the **resolvable-state** half of the alert model: instances with an
open → acknowledged → resolved lifecycle, a first/last-seen window, and a `count`. #143 (the ADR 0044
amendment, this wave) added **windowed suspend/mute**. The **confirmed remainder of #56** — BACKLOG #81 —
is three Corepoint alert-parity features that layer *on top of* the shipped state and rules:

1. **Escalation tiers.** A single alert has one severity/route for its whole life. An operator can't say
   "warn on the first few occurrences, then page critically once it has fired N times" — a *progressive*
   response to a persistent condition.
2. **Schedule-aware thresholds (day/time).** A rule applies uniformly around the clock. An operator can't
   say "page critically for `OB_*` stops during business hours; off-hours just email" without an external
   scheduler flipping config.
3. **Content-triggered ("Action-Point") alerts.** Every alert today keys on *queue/transport shape*
   (`queue_buildup`, `connection_error`, …). There is no alert keyed on **message content** — e.g. "a STAT
   order arrived on this feed". Corepoint's "Action Point" alerts fill exactly this.

Two invariants bound the design and **must not** be relaxed:

- **Alerts are PHI-free (CLAUDE.md §9, ADR 0044).** Every emitted event carries "the connection name +
  queue shape only — no PHI". A content-triggered event is the risky one: it is *born from inspecting a
  message body*, so it must carry **only** the connection + a rule id + a boolean/label — **never the
  matched field value**.
- **Routers and transforms must be pure (ADR 0001).** A Handler that emits a content-triggered alert
  performs a **side effect**; under at-least-once a stage re-run **re-emits** it. This must be reconciled
  (below), not silently broken.

## Decision

**Add three additive, occurrence/severity-driven capabilities to the ADR 0014 rules layer + the ADR 0044
state, all off by default and byte-identical when unconfigured.** Escalation and schedule-awareness are
pure config on `AlertRule` evaluated synchronously on the existing emit path; content-triggers add one new
PHI-free `content_match` event type + an emit method. One durable column (`alert_instance.escalation_tier`)
is added beside the #143 `suspended_until` (STORE-SERIALIZED, three backends, ADR 0064 hash bump).

### D1 — Escalation tiers are OCCURRENCE-driven, evaluated synchronously (NOT a timed chain)

`AlertRule.escalate: list[EscalationTier]` where each tier is `{after_count, severity?, transports?,
recipients?}`. The notifier keeps an **in-memory per-`(type, connection)` occurrence counter**
(`_occurrences`, mirroring the store's `count` — both increment once per emit) and, in `_emit`, selects the
**highest tier whose `after_count <= occurrences`** and applies its overrides over the base rule decision.
So a condition that keeps firing climbs: warn → page → critical-page as its occurrence count crosses each
tier's threshold. The counter resets on auto-resolve (the inverse-event observer) and on operator
resolve/resume (the API clears it), so a resolved-then-reopened key restarts at the base tier.

**This is explicitly NOT the timed multi-stage escalation ADR 0014 §3 declined** ("email now, page after
15 min" — a scheduler/timer over one condition). Escalation here keys on the **occurrence count** (a
severity/occurrence signal), not elapsed time. There is **no timer and no sweep** — the tier is recomputed
purely from the in-memory count on each emit. Should a future increment ever add a **timed re-evaluation
sweep**, it MUST be **leader-gated** (single-writer in a cluster, like the `RetentionRunner` purge pass) so
N nodes can't each re-escalate the same shared condition; this ADR builds no such sweep.

The highest tier reached is persisted to `alert_instance.escalation_tier` (monotonic within an open
instance: `MAX`/`GREATEST`/`CASE` on the upsert), so the dashboard shows the escalation level and it
survives a restart. Like ADR 0014's in-memory throttle, the occurrence counter is per-node/advisory — the
durable `count` + `escalation_tier` are the cross-restart record.

### D2 — Schedule-aware rules reuse the #147 `Schedule` model

`AlertRule.schedule: Schedule | None` — the **same** `Schedule`/`ActiveWindow` (day-set + local
time-of-day window + IANA timezone + `invert`) #147/ADR 0095 built for connection scheduling. `decide` is
made schedule-aware: it takes the emit's `now` (wall clock), and a rule with a `schedule` **matches only
when `schedule.is_active(now)`** (or, with `invert=True`, only *outside* its windows). Different thresholds
by time are expressed as two rules with different schedules — consistent with ADR 0014's "first match wins,
AND-combined, two rules for OR". Reusing the built, tested model adds no new time-window code and no new
dependency (`zoneinfo` is stdlib).

### D3 — Content-triggered alerts: a PHI-free `content_match` event, reconciled with purity via the throttle/dedup

Add `content_match` to `_ALERT_EVENT_TYPES` and a `NotifierAlertSink.content_match(connection, *, label,
rule_id=None)` emit method. The event carries **only** `{type: "content_match", connection, label}` — a
connection name + an **operator-config label/rule id** (e.g. `"STAT order"`), and **NEVER the matched field
value**. A code-first Handler (the "Action Point") that inspects a message and decides to alert calls this
via the alert sink the engine already threads into its runners; matching is **match-only, off the routing
hot path** (a Handler, not the router). `AlertRule.content_label: str | None` lets a rule route by that
label (e.g. page for `label="STAT"`, email otherwise). The event flows through the **same** `AlertRuleSet` /
throttle / ADR 0044 state machinery — no new transport, no new PHI tier.

**Purity carve-out reconciliation (load-bearing).** A Handler emitting `content_match` is a **side effect**,
and under at-least-once a transform re-run **re-emits** it — which would violate "transforms must be pure".
This is reconciled by **the existing `(event_type, connection)` throttle + dedup**, exactly as every other
alert already relies on: a re-emit of `content_match` for the same `(connection)` **folds into the same
`alert_instance`** (the ADR 0044 upsert de-dups on the `(event_type, connection)` key — a re-run bumps
`count`/`last_seen`, never a second row) and is **collapsed to at most one notification per `realert_seconds`
cooldown** by the in-memory throttle. So a re-run's re-emit is **idempotent w.r.t. the durable instance and
bounded w.r.t. notification** — the observable alert state is identical whether the transform ran once or
re-ran. (The alternative the plan offered — routing content-triggers entirely *off* the transform path — is
not needed once the throttle/dedup makes the re-emit idempotent; it stays available as a future option for a
Handler that wants a *notification per distinct match* rather than per condition.)

### D4 — Store: one additive `escalation_tier` column across three backends (ADR 0064 hash bump)

`alert_instance.escalation_tier` (INTEGER, `DEFAULT 0`) lands **additively** on SQLite (a migration
`ALTER TABLE ADD COLUMN`), Postgres (`ADD COLUMN IF NOT EXISTS` in the hash-gated `_SCHEMA`), and SQL Server
(a `COL_LENGTH`-gated idempotent `ADD` beside the CREATE, mirroring `suspended_until`). Adding the column to
the server backends' `_SCHEMA` **bumps the ADR 0064 `_schema_hash()`** automatically, forcing one idempotent
schema run; the parity test pins the column set across all three. It is the **second store slot** this wave
(after S3a's `processed_files`, with #143's `suspended_until`), so it is store-serialized. Metadata-only —
no new PHI tier.

## Acceptance Criteria

- **AC-1** — WHEN a rule with `escalate` tiers is matched and the instance's occurrence count reaches a
  tier's `after_count`, THE SYSTEM SHALL apply that tier's severity/transports/recipients (the highest
  satisfied tier wins), persisting the tier to `alert_instance.escalation_tier`.
  → `tests/test_alert_escalation.py::test_escalates_by_occurrence_count`
- **AC-2** — WHEN a rule carries a `schedule`, THE SYSTEM SHALL match it only when `schedule.is_active(now)`
  (inside its windows, or outside when `invert`), so an out-of-window rule does not apply.
  → `tests/test_alert_escalation.py::test_schedule_aware_decide`
- **AC-3** — WHEN a Handler emits a `content_match`, THE SYSTEM SHALL emit a PHI-free event
  (connection + label + rule id only, **never** a matched field value) that flows through the rules /
  throttle / state machinery.
  → `tests/test_alert_escalation.py::test_content_match_event_is_phi_free`
- **AC-4** — WHEN the same `content_match (connection)` is re-emitted (a transform re-run), THE SYSTEM SHALL
  fold it into the one open instance (throttle/dedup) rather than open a second — the purity/at-least-once
  reconciliation.
  → `tests/test_alert_escalation.py::test_content_match_reemit_is_idempotent`
- **AC-5** — THE SYSTEM SHALL create + operate the `escalation_tier` column identically on SQLite, Postgres,
  and SQL Server (schema/accessor parity), with the ADR 0064 schema hash bumped.
  → `tests/test_alert_state.py::test_three_backend_parity_columns`

## Options considered

1. **Occurrence-driven escalation + schedule-as-match-gate + a PHI-free content event through the existing
   rules/throttle/state — CHOSEN.** Additive, synchronous, no timer, reuses the #147 `Schedule` and the ADR
   0044 de-dup grain; the throttle/dedup makes the content re-emit idempotent (purity preserved).
2. **Timed multi-stage escalation chains (warn now → page in 15 min).** Rejected — the ADR 0014 §3 decline
   stands (needs a scheduler/timer; a cluster-wide timed sweep would need leader-gating and durable
   last-escalated state). Occurrence-driven covers the real "persistent condition" need without it.
3. **A rule-embedded content expression the engine evaluates against every message.** Rejected — that puts
   content matching on the routing/transform hot path and risks an injection/PHI surface; content matching
   stays **code-first in a Handler** (the differentiator), the rule only routes the resulting label.
4. **Carry the matched value in the `content_match` event for context.** Rejected — a direct PHI leak; the
   event is connection + label + rule id only, and the durable `reason` is the (non-PHI) label at most.

## Consequences

**Positive** — Operators get progressive (occurrence-driven) escalation, time-of-day-aware routing, and
content/Action-Point alerts, all through the **one** rules/throttle/state path — no new mental model, no new
transport, no new PHI tier. Content re-emits are idempotent by construction (the throttle/dedup), so the
at-least-once/purity invariant holds.

**Negative / risks** — One more additive column on three backends (a parity surface kept in lock-step by the
column test + the ADR 0064 hash). The occurrence counter + escalation are per-node/advisory (same posture as
the ADR 0014 throttle); the durable `count`/`escalation_tier` are the cross-restart record. A content-alert
Handler must honor the PHI-free contract (label, never the value) — enforced by the sink's method signature
(no value parameter) and the closed event shape, documented here.

**Out of scope / stays as-is** — Timed multi-stage escalation chains (ADR 0014 §3 decline stands; any future
timed re-eval sweep MUST be leader-gated). Cross-node durable dedup of shared-resource events (ADR 0014 §4).
A declarative content-match expression language (content matching stays code-first in a Handler).
