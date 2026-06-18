# ADR 0014 — Alerting rules engine

- **Status:** Proposed (2026-06-14) — the configurable rules layer over the built alert notifier.
- **Built:** Yes — additive. A typed `AlertRule` model + `[alerts].rules` in
  [`config/settings.py`](../../messagefoundry/config/settings.py), and an `AlertRuleSet` the
  `NotifierAlertSink` consults in [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py).
  No `AlertSink`-protocol change, no fire-site change, no engine/runner change.
- **Related:** [`pipeline/alerts.py`](../../messagefoundry/pipeline/alerts.py) (the AlertSink contract +
  `LoggingAlertSink`), [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py) (the
  notifier + webhook/email transports), the BACKLOG "alerting framework" item (the notifier is built;
  this is the rules follow-up), Track B leader-gating ([`pipeline/cluster.py`](../../messagefoundry/pipeline/cluster.py)).

## Context

MessageFoundry already raises three operational alert events through a single `AlertSink`
([`alerts.py`](../../messagefoundry/pipeline/alerts.py)) — `connection_stopped` (a lane halted by the
`STOP` internal-error policy), `queue_buildup` (a backlog over the per-outbound `BuildupThreshold`),
and `storage_threshold` (the store file over its limit). With `[alerts]` configured, a
`NotifierAlertSink` fans **every** event out to **every** configured transport (webhook + email),
throttled per `(event_type, connection)` by a single global `realert_seconds`.

That is all-or-nothing: an operator can't say "page on a stopped connection but only email on a slow
lane", "treat a 50-deep backlog as INFO and a 5,000-deep one as CRITICAL", "stay quiet about a known-
bursty test feed", or "re-alert a critical sooner than the 5-minute default". The notifier needs
**rules**.

## Decision

### §1 — A rule is config, evaluated by a pure `AlertRuleSet`

Add an `AlertRule` (typed Pydantic — **never `eval`/code**) to `[alerts].rules`, and a pure
`AlertRuleSet.decide(event) -> RuleDecision` that the notifier consults. Keeping the matcher a pure,
synchronous function makes it cheap (it runs inline on the worker, same as the existing throttle) and
unit-testable without the async notifier.

```
AlertRule:
  event_type: "any" | "connection_stopped" | "queue_buildup" | "storage_threshold"   (default "any")
  connection: glob over the connection name                                            (default "*")
  min_depth: int | None            # queue_buildup only — match only at/over this pending depth
  min_oldest_seconds: float | None # queue_buildup only — match only at/over this oldest-message age
  severity: "info" | "warning" | "critical"                                            (default "warning")
  transports: list["webhook"|"email"] | None   # None = all configured; [] = SUPPRESS  (default None)
  cooldown_seconds: float | None   # override the global realert for matching events

RuleDecision: severity, transports (None=all / ()=suppress / subset), cooldown_seconds
```

**All conditions on a rule are AND-combined** — every populated field must hold for the rule to match
(so `event_type` *and* `connection` *and* any threshold all narrow it; setting both `min_depth` and
`min_oldest_seconds` requires both). To alert on *either* of two thresholds, write two rules.
**First matching rule wins** (order is the operator's priority). An event matching **no** rule keeps
today's behaviour: notify **all** transports at `warning` with the global cooldown — so adding a rule
never silently silences an event you didn't name.

### §2 — Rules live in the notifier, not a new sink

The notifier owns the transports and the throttle, which is exactly what a rule routes and overrides,
so the rules layer belongs there (not a separate wrapping sink that couldn't reach the transports).
`NotifierAlertSink._emit` consults the `AlertRuleSet`: a `()`-transports decision **suppresses** (drop,
no enqueue); otherwise it applies the rule's `cooldown_seconds` to the throttle and tags the event with
`severity` (carried into the webhook JSON / email subject) and the transport subset. `_run` then sends
only to the named transports. With **no rules** configured the decision is always the default, so
behaviour is byte-identical to today. The `AlertSink` protocol and every fire site are unchanged.

### §3 — Severity travels in the payload; routing is per-rule

`severity` is added to the event dict so a downstream webhook target (PagerDuty/Slack/Teams) and the
email subject can route/triage by it. Transport routing is the per-rule `transports` subset (e.g.
`["webhook"]` to page only, `["email"]` to email only, `[]` to suppress) — escalation as a *static
routing decision*. **Timed multi-stage escalation chains** ("email now, page after 15 min") are
deliberately **out of scope** (they need a scheduler/timers); rules give the routing primitive they'd
build on.

### §4 — Leader-gating: not added (per-node events must not be suppressed)

A tempting cluster optimisation is to fire alerts only on the leader, to dedup. It is **wrong here**:
`connection_stopped` is a **per-node** observation — a lane halts on a *specific* node, and an operator
must see *that* node's failure even if it is a follower. Blanket leader-gating the notifier would
silence real follower events. So:

- `connection_stopped` / `queue_buildup` stay **per-node** (each node's notifier alerts on what it
  observes; the per-node `(event,connection)` throttle bounds repeats to one per cooldown per node).
- `storage_threshold` is already **cluster-once** — its fire site (the retention runner) is leader-
  gated, so only the leader observes it.
- Single-node (`NullCoordinator`) is unaffected — there is one node.

The residual is a **duplicate `queue_buildup`** in a multi-node cluster (each node draining the shared
outbound observes the same depth and alerts once per cooldown). That is bounded and acceptable for v1;
true cluster-wide dedup of shared-resource events needs **durable** last-fired state (a small cluster
table) — documented future work, not built here. The in-memory throttle/cooldown is likewise per-node
and reset on restart (advisory alerting, acceptable).

## Options considered

1. **Rules in the notifier, pure `AlertRuleSet` matcher (chosen).** Additive, cohesive (routing lives
   with the transports), unit-testable, backward-identical when empty.
2. **A separate `RuleAlertSink` wrapping the notifier.** Rejected — it couldn't select *which*
   transport fires (the notifier owns them), so per-rule routing would leak back into the notifier
   anyway; two objects for one concern.
3. **Arbitrary expression / callable conditions.** Rejected — a code-injection surface (ASVS) and a
   re-run/safety hazard. Whitelisted comparison fields cover the real needs.
4. **Leader-gate the notifier for cluster dedup.** Rejected — suppresses legitimate per-node
   `connection_stopped` (see §4).

## Consequences

**Positive**
- Operators tune severity, routing, thresholds, cooldown, and suppression per connection — the gap
  between "the framework can alert" and "alert *usefully*".
- Severity in the payload lets existing webhook targets (PagerDuty/Slack) route without engine changes.
- Fully additive: no protocol/fire-site/engine change; empty rules = today's behaviour.

**Negative / risks**
- Duplicate `queue_buildup` across nodes in a cluster (bounded by the per-node throttle; durable dedup
  deferred).
- Cooldown/suppression state is in-memory and per-node (lost on restart/failover) — acceptable for
  advisory alerting; durable state is future work.
- Timed escalation chains are not built (only static per-rule routing).

## To resolve on acceptance

1. Confirm rules live in the notifier (not a separate sink). *(Recommended.)*
2. Confirm no leader-gating in v1 (per-node `connection_stopped`); document the duplicate-`queue_buildup`
   limitation. *(Recommended.)*
3. Confirm the MVP omits timed multi-stage escalation chains. *(Recommended.)*
