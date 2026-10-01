# ADR 0133 — Alert escalation tiers, schedule-aware thresholds, and content-triggered alerts (the #56 remainder)

- **Status:** Accepted (2026-07-18) — DEMAND-GATE-BACKLOG Wave 4 (lane `dg-s1b`) — **PARTIALLY BUILT; corrected 2026-09-09**, see **Built** below. **D3 RETRACTED 2026-09-30 by owner ruling, not planned** (BACKLOG #1504); D1, D2 and D4 keep the build state the **Built** bullet records. See **Retraction of D3** below.  <!-- Proposed → Accepted → Superseded by NNNN / Rejected -->
- **Retraction of D3 (2026-09-30).** The batch 183 Manager's record of the ruling, verbatim:
  *"Owner ruling 2026-09-30, given to the batch 183 Manager in session: ADR 0133 D3 is retracted and
  not planned, and the unreachable content_match plumbing is removed with it, in one engine PR."*
  That PR is BACKLOG #1504. **What it removed:** at least `content_match` in `_ALERT_EVENT_TYPES`,
  `AlertRule.content_label` and its filter in `AlertRuleSet`, and `NotifierAlertSink.content_match`.
  It also removed the `label` fallback for an instance's `reason`, and `content_label` on the rules
  API and in the alert-rule editor's field list. Three D3 tests went too. A rule naming
  `event_type = "content_match"` or setting `content_label` is now refused at load, like any
  unknown event type or key. **Why it is retracted rather than finished.** Two grounds, and this
  bullet is where they are stated. First, nothing could fire it: a Handler is called with its
  payload alone. Second, finishing it would break purity. A Handler that emits an alert performs an
  external side effect, which the purity invariant (CLAUDE.md section 2) forbids. An at-least-once
  re-run would emit it again, and D3's throttle only bounded that re-emit. The 2026-09-09 notes below
  record the tree before the removal, so read their D3 facts as history.
- **Built (re-verified against the tree 2026-09-09):** **D1, D2 and D4 are BUILT. D3 is NOT BUILT as a
  reachable capability** — it is plumbing nothing outside the tests can fire *(that plumbing was removed 2026-09-30)*. The words that stood on the
  Status line — *"Accepted (2026-07-18, built)"* — claimed all four decisions shipped. They are corrected
  here rather than deleted, because that is the sentence a reader would otherwise carry forward, and an
  unqualified "built" over a D3 with zero non-test callers over-claims what the tree delivers.
  - **BUILT — D1 escalation tiers.** `EscalationTier` and `AlertRule.escalate` (`config/settings.py`); the
    `_occurrences` counter and highest-satisfied-tier selection in `NotifierAlertSink._emit`
    (`pipeline/alert_sinks.py`); the tier persisted through `upsert_alert_instance` (`store/base.py`) and
    read back on `AlertInstance.escalation_tier` (`store/store.py`).
  - **NOT BUILT — D1's operator-visible half.** D1 says the persisted tier is there so "the dashboard shows
    the escalation level". It does not. `escalation_tier` appears nowhere under `messagefoundry/api/` or
    `messagefoundry_webconsole/`, and `AlertInstanceInfo` (`api/models.py`) carries no such field, so
    `GET /alerts/active` never returns it. The #143 `suspended_until` beside it does appear in both. The
    rules API's `escalate_tiers` (`AlertRuleInfo`, `api/models.py`) is not this half: it reports how many
    tiers a RULE configures, not which tier an instance reached.
  - **BUILT — D2 schedule-aware rules.** `AlertRule.schedule` (`config/settings.py`), gated inside
    `AlertRuleSet.decide` on `rule.schedule.is_active(...)` (`pipeline/alert_sinks.py`), reusing the ADR 0095
    `Schedule`/`ActiveWindow` verbatim.
  - **BUILT — D4's column on all three backends.** `alert_instance.escalation_tier` on SQLite (`ALTER TABLE
    ADD COLUMN`, `store/store.py`), Postgres (`ADD COLUMN IF NOT EXISTS`, `store/postgres.py`) and SQL Server
    (`COL_LENGTH`-gated `ADD`, `store/sqlserver.py`), kept monotonic by `MAX`/`GREATEST`/`CASE`.
  - **REMOVED 2026-09-30 (BACKLOG #1504); this bullet is history.** It read *"BUILT — D3's config
    and notifier half only"*, and described the tree as of 2026-09-09.
    `content_match` is in `_ALERT_EVENT_TYPES`
    (`config/settings.py`); `AlertRule.content_label` filters on it in `AlertRuleSet.decide`; and
    `NotifierAlertSink.content_match(connection, *, label, rule_id=None)` exists with the PHI-free shape this
    ADR specifies — no value parameter.
  - **RETRACTED 2026-09-30, not planned; this bullet is history.** It read *"NOT BUILT — D3's
    reachability, which is the capability itself"*. `content_match` is absent from the
    `AlertSink` Protocol and from `LoggingAlertSink`, both in `pipeline/alerts.py`, while the engine holds
    its sink as `self._alert_sink: AlertSink` (`pipeline/wiring_runner.py`). So the type the engine programs
    against does not carry the method, and a deployment configuring no `[alerts]` transport gets
    `LoggingAlertSink`, which cannot record the event at all. `messagefoundry/__init__.py` exports no alert
    symbol of any kind, and a Handler is called as `HandlerFn = Callable[[Payload], HandlerResult]`
    (`config/wiring.py`) — one payload argument, no sink. `.content_match(` has **zero** non-test callers.
  - **D3's sentence "calls this via the alert sink the engine already threads into its runners" is FALSE as
    written**, and is kept below so the correction sits beside the claim. The engine threads a sink into its
    runners. It threads nothing into a Handler, and the threaded type lacks the method.
  - **Every test this ADR names EXISTS** *(true on 2026-09-09; see the correction at the end of this bullet)*. `test_escalates_by_occurrence_count`, `test_schedule_aware_decide`,
    `test_content_match_event_is_phi_free` and `test_content_match_reemit_is_idempotent` are all in
    `tests/test_alert_escalation.py`, and `test_three_backend_parity_columns` is in
    `tests/test_alert_state.py`. The defect is what AC-3 and AC-4 assert, not a missing test — see the note
    under the Acceptance Criteria. **CORRECTED 2026-09-30:** the two `content_match` tests were removed
    with D3 (BACKLOG #1504). In their place, the same file pins that the event type and the
    `content_label` key are refused and the emit method is absent.
  - **This is build state, not live impact.** There are zero deployments (CLAUDE.md section 0), so nothing
    is exposed and no operator depends on this. **CORRECTED 2026-09-30:** this bullet ended *"The
    remainder is BACKLOG #81, which already records it."* D3 is no longer a remainder of anything. It is
    retracted and not planned, so the only NOT BUILT part this ADR still records is D1's
    operator-visible half. Narrowing #81 to match is a ledger edit in the maintainer-internal
    repository, not in this one.
- **Date:** 2026-07-18
- **Related:** BACKLOG #81 (the confirmed remainder of #56) · **refines** [ADR 0014](0014-alerting-rules-engine.md)
  (the rules engine + the pure `AlertRuleSet.decide` + the per-`(type, connection)` throttle this escalation
  and content path ride) · **builds on** [ADR 0044](0044-operator-alert-state.md) (the resolvable
  `alert_instance` state; this adds the `escalation_tier` column beside the #143 `suspended_until` one) ·
  [ADR 0001](0001-staged-pipeline-architecture.md) (the at-least-once / **routers-and-transforms-must-be-pure**
  invariant the content-trigger carve-out below claimed to reconcile; it did not, and D3 is retracted) · [ADR 0095](0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
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
  (below), not silently broken. **CORRECTED 2026-09-30:** it was not reconciled, and D3 is retracted
  (see the D3 section).

## Decision

**Add three additive, occurrence/severity-driven capabilities to the ADR 0014 rules layer + the ADR 0044
state, all off by default and byte-identical when unconfigured.** Escalation and schedule-awareness are
pure config on `AlertRule` evaluated synchronously on the existing emit path; content-triggers add one new
PHI-free `content_match` event type + an emit method (**retracted 2026-09-30 and removed; see D3**). One durable column (`alert_instance.escalation_tier`)
is added beside the #143 `suspended_until` (STORE-SERIALIZED, three backends, ADR 0064 hash bump).
**CORRECTED 2026-09-30:** two capabilities remain, escalation and schedule-awareness. The third,
content triggers, is retracted (see D3).

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

> **RETRACTED 2026-09-30 by owner ruling, not planned (BACKLOG #1504).** The ruling, what was
> removed and why are in the **Retraction of D3** bullet at the top of this ADR. The original text
> is kept below, unchanged, as the record of what was decided.

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
- **AC-3 and AC-4 — WITHDRAWN 2026-09-30 with D3 (BACKLOG #1504).** Their text is kept below as
  history, in a quote so that `adr-analyze` does not count them as live criteria. The tests they
  named were removed with D3.

  > **AC-3** — WHEN a Handler emits a `content_match`, THE SYSTEM SHALL emit a PHI-free event
  > (connection + label + rule id only, **never** a matched field value) that flows through the rules /
  > throttle / state machinery.
  > → `tests/test_alert_escalation.py::test_content_match_event_is_phi_free` (removed)
  >
  > **AC-4** — WHEN the same `content_match (connection)` is re-emitted (a transform re-run), THE SYSTEM SHALL
  > fold it into the one open instance (throttle/dedup) rather than open a second — the purity/at-least-once
  > reconciliation.
  > → `tests/test_alert_escalation.py::test_content_match_reemit_is_idempotent` (removed)

- **NOTE added 2026-09-09 — AC-1, AC-2 and AC-5 are MET. AC-3 and AC-4 are NOT MET, and the tests they name
  DO exist.** **CORRECTED 2026-09-30:** AC-3 and AC-4 are WITHDRAWN with D3, and the two tests this
  note names were removed with it (BACKLOG #1504). The rest of this note is the 2026-09-09 record.
  Both tests are real, and both call `NotifierAlertSink.content_match` **directly**. Neither
  exercises the "WHEN a Handler emits a `content_match`" premise, because no Handler can emit one:
  `content_match` is on neither the `AlertSink` Protocol nor `LoggingAlertSink` (`pipeline/alerts.py`), no
  alert emitter is exported from `messagefoundry/__init__.py`, and a Handler is called with the payload
  alone (`HandlerFn = Callable[[Payload], HandlerResult]`, `config/wiring.py`). What the two tests verify is
  the event shape and the dedup grain. What stays unverified — and is unbuildable at this build state — is
  the trigger the criteria open with. See the **Built** bullet at the top.
- **AC-5** — THE SYSTEM SHALL create + operate the `escalation_tier` column identically on SQLite, Postgres,
  and SQL Server (schema/accessor parity), with the ADR 0064 schema hash bumped.
  → `tests/test_alert_state.py::test_three_backend_parity_columns`

## Options considered

1. **Occurrence-driven escalation + schedule-as-match-gate + a PHI-free content event through the existing
   rules/throttle/state — CHOSEN.** Additive, synchronous, no timer, reuses the #147 `Schedule` and the ADR
   0044 de-dup grain; the throttle/dedup makes the content re-emit idempotent (purity preserved).
   **CORRECTED 2026-09-30:** the content half of this option is retracted; see **Retraction of D3**.
2. **Timed multi-stage escalation chains (warn now → page in 15 min).** Rejected — the ADR 0014 §3 decline
   stands (needs a scheduler/timer; a cluster-wide timed sweep would need leader-gating and durable
   last-escalated state). Occurrence-driven covers the real "persistent condition" need without it.
3. **A rule-embedded content expression the engine evaluates against every message.** Rejected — that puts
   content matching on the routing/transform hot path and risks an injection/PHI surface; content matching
   stays **code-first in a Handler** (the differentiator), the rule only routes the resulting label.
4. **Carry the matched value in the `content_match` event for context.** Rejected — a direct PHI leak; the
   event is connection + label + rule id only, and the durable `reason` is the (non-PHI) label at most.

**CORRECTED 2026-09-30:** options 3 and 4 describe the retracted D3 design. No `content_match` event,
`content_label` routing or `label`-derived `reason` exists any more; see **Retraction of D3**.

## Consequences

**Positive** — Operators get progressive (occurrence-driven) escalation, time-of-day-aware routing, and
content/Action-Point alerts, all through the **one** rules/throttle/state path — no new mental model, no new
transport, no new PHI tier. Content re-emits are idempotent by construction (the throttle/dedup), so the
at-least-once/purity invariant holds. **CORRECTED 2026-09-30:** the content/Action-Point half of
this paragraph did not hold and D3 is retracted; see **Retraction of D3**. Operators get the
escalation and schedule-aware halves only.

**Negative / risks** — One more additive column on three backends (a parity surface kept in lock-step by the
column test + the ADR 0064 hash). The occurrence counter + escalation are per-node/advisory (same posture as
the ADR 0014 throttle); the durable `count`/`escalation_tier` are the cross-restart record. A content-alert
Handler must honor the PHI-free contract (label, never the value) — enforced by the sink's method signature
(no value parameter) and the closed event shape, documented here. **CORRECTED 2026-09-30:** that sink
method was removed with D3, so this risk no longer applies.

**Out of scope / stays as-is** — Timed multi-stage escalation chains (ADR 0014 §3 decline stands; any future
timed re-eval sweep MUST be leader-gated). Cross-node durable dedup of shared-resource events (ADR 0014 §4).
A declarative content-match expression language (content matching stays code-first in a Handler).
**CORRECTED 2026-09-30:** with D3 retracted, the engine offers no content-triggered alert at all,
code-first or declarative.
