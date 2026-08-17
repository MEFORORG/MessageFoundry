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

## Amendment (2026-07-12) — a `saturation` alert on the backlog DERIVATIVE (BACKLOG #93)

**Status:** Built — additive. A new `saturation` event type + `AlertSink.saturation_rising` emit
method, a per-`(stage, lane)` `SaturationDetector` and emit site on the `RegistryRunner`, and a
`SaturationThreshold` / `[delivery].saturation_sustain_samples` config knob. Fully off by default
(deny-by-default); empty config = today's behaviour byte-for-byte.

**Context — the gap.** Every operational alert this ADR governs (`queue_buildup`, `message_stall`, and
the ceilings in `AlertRule.min_depth` / `min_oldest_seconds`) keys on an **absolute snapshot**: a
pending-depth ceiling or an oldest-message-age ceiling. On that axis a **bursty-but-DRAINING** lane (a
spike the worker is clearing) and a genuinely **OVERLOADED** one look identical until a ceiling trips —
and by then the operator is already behind. Nothing fires on the **rate of change**: the system
*becoming* overloaded is invisible.

**Decision — a derivative dimension, not an escalation chain.** Add `saturation` as a first-class alert
event keyed on the queue **derivative**: a lane's pending depth **rising sustained** across a small
bounded sampling window. By conservation of the queue, sustained rising depth over the window is
exactly *arrivals > departures* (**ingest > drain**) held over it — so a lane that spikes then drains
(depth falls back) never fires, while one whose depth climbs monotonically does. That "does **not**
fire on a bursty-but-draining lane" is the defining property, enforced by `SaturationDetector` (a
`deque(maxlen=sustain_samples+1)` of `(ts, depth)`; fires only when the newest depth strictly exceeds
the oldest **and** no step in the window decreased). The detector is pure/synchronous and unit-tested
directly. It rides the existing per-lane buildup tick (`_maybe_alert_buildup` → `_maybe_alert_saturation`),
so it adds **no new sampler** — and returns before any store read when disabled (zero cost when off).

**Coverage (inherited from the buildup tick).** The sampler covers exactly where that tick runs today:
**ingress and routed** are sampled on the regular per-batch interval (full coverage), and the **outbound**
stage is sampled on its **delivery-failure / retry** paths. So the realistic saturation cases — a
failing/retrying outbound, a slow router, a slow transform — all page; but a **healthy-but-behind**
outbound (delivering successfully while its backlog climbs monotonically) is **not** sampled. That
outbound blind spot is inherited from the pre-existing buildup architecture, not introduced by this
amendment; closing it with a periodic owned-outbound depth sweep is a scoped follow-up (BACKLOG #93 residual).

The alert flows through the **same** ADR 0014 machinery unchanged: `AlertRuleSet.decide` (a rule may
set its severity, route it to a transport subset, or **suppress** it for a known-bursty feed via
`connection` glob + `transports=[]`), the per-`(type, connection)` `realert_seconds` throttle, and the
ADR 0044 resolvable alert-state observer. No new transport, no fire-site fan-out.

**This is NOT the declined timed multi-stage escalation (§ "To resolve" #3).** That decline stands:
`saturation` is a single, throttled, edge-ish notification on a *different input signal* (a rate), not
a time-ordered escalation chain (warn→page→exec) over one condition. It adds an axis (derivative vs
absolute), not the sequenced-severity machinery §3 rejected.

**Deny-by-default & scope.** `saturation_sustain_samples` defaults `None` (**off**) because the
signal's coverage overlaps `queue_buildup`'s age dimension; an operator opts in globally via
`[delivery]`. `sustain_samples` has a floor of 2 (fewer can't distinguish a burst from sustained
growth). Global-only for now; a per-connection `saturation=` override is a documented follow-up (a
per-connection `AlertRule` can already suppress it per lane in the interim). Detector history is
in-memory/per-node and dropped on connection teardown/reload (same posture as the other alert state).

**Consequences.** Operators get an early "this lane is *becoming* overloaded" page before a ceiling
trips, without false-paging a draining burst. Costs: another in-memory per-lane structure (bounded to
`sustain_samples+1` samples) and, when enabled, one extra cheap `pending_depth` COUNT+MIN per tick.

## Amendment (2026-07-17) — maker-checker instructed at exposure (ASVS 2.3.5, ADR 0115 / WP #243)

**Status:** Doc-only — no default changed. The `[approvals]` maker-checker layer stays **off by
default** (`[approvals].enabled = false`, `expiry_hours = 72`, default gated `operations =
["connection_purge", "dead_letter_replay"]`; `config_reload` is opt-in). This records the runbook
instruction that lifts ASVS 2.3.5 to Pass for the **documented multi-operator exposed deployment**
without touching the single-operator loopback default.

Per ADR 0115, 2.3.5 is a control whose secure setting is deployment-specific: a single-operator
loopback install has no second operator to be the checker, so a global flip would break it. The
deliverable is therefore the **instruction**, now in
`docs/security/OFF-LOOPBACK-DEPLOYMENT.md` §"Dual-control
approvals at exposure": set `[approvals].enabled = true` (optionally tune `operations` /
`expiry_hours`) on any multi-operator, network-exposed console.

The existing `serve` posture is unchanged: an exposed PHI instance with `[approvals].enabled` off
**warns** (advisory, non-fatal — the reviewed single-operator default); a production-refuse arm
remains an unbuilt owner fork. This ADR does not re-score; ADR 0115 governs the sweep.

## Amendment (2026-07-17) — chapter-16 logging controls instructed at exposure (ASVS 16.2.2 / 16.3.2 / 16.4.2, ADR 0115 / WP #244)

**Status:** Doc-only — no default changed. This records the WP #244 runbook instructions that lift three
ASVS chapter-16 logging controls to Pass for the **documented exposed (off-loopback) deployment** without
touching the loopback defaults. Each control is **instructed, not global-flipped** (ADR 0115): its secure
setting is deployment-specific, so a `true` default would break an unconfigured or peerless loopback
install. All three shipped defaults are unchanged and byte-identical.

- **16.2.2 — startup time-sync gate.** Built and tested (ADR 0080: `serve` runs a bounded SNTP probe
  before intake; `tests/test_logging.py`). The runbook
  (`docs/security/OFF-LOOPBACK-DEPLOYMENT.md` §"Time
  synchronization") instructs `[logging].require_time_sync = true` + `ntp_peer = <mgmt-NTP>` (and
  `time_sync_fail_closed = true` where a wrong clock is worse than a missed start). `require_time_sync`
  stays `false` by default — a `true` default requires `ntp_peer` at config load and would refuse to
  start every peerless deployment. **Residual (accepted):** the probe is unauthenticated SNTP
  (RFC 4330), not NTS — a coarse drift check for a trusted management network.
- **16.3.2 — all-authz audit verbosity.** The `[diagnostics].audit_all_authz` gate is **built in this
  WP** (`api/security.py`). The runbook (§"Authorization audit verbosity") instructs
  `audit_all_authz = true` for the full authorization trail off-loopback. PHI-view grants stay
  excluded even under `true` (the PHI-access audit path already records them). **The default has since
  flipped ON** ([ADR 0168](0168-default-the-authorization-grant-audit-on-the-console-cannot-flood-it.md),
  BACKLOG #1277), so the "default off is byte-identical" this bullet used to end on no longer holds —
  the runbook instruction is now what a stock engine already does.
- **16.4.2 — tamper-evident audit chain.** Two levers, both instructed (§"Tamper-evident audit chain"):
  (A) `[integrity].audit_verify_on_start = true` re-walks the chain at startup — **alert-only, never
  crashes** (a broken chain WARNs + fires `integrity_drift`); (B) keying the chain against forgery
  **cannot be a config flip** — its HMAC key is HKDF-derived from the store DEK, so the runbook instructs
  `[ai].data_class = "phi"` + a store key + the one-time `messagefoundry rekey_audit_chain` migration,
  after which keying is automatic. **Residual (accepted):** lever (B) depends on store encryption being
  on (off by default), so 16.4.2 is **Partial** until the WP #243 needle-mover turns encryption on —
  tamper-evident today, forgery-evident once keyed. **A second residual on lever (A), added 2026-08-04
  ([BACKLOG #328](../BACKLOG.md)):** it is a *bare* walk — it passes no anchor — so it cannot see a
  truncated tail (the surviving prefix still chains cleanly), whatever the keying state. The operator
  lever for that is `messagefoundry audit-verify --expected-anchor`, run against a quiesced chain; there
  is no startup setting that consumes an anchor. Do not read (A) as covering deletion of the newest rows.

Each control is **A → Partial (accepted) / B → Pass** — none reaches an unconditional loopback
(Posture-A) Pass; the exposed-deployment Pass is the instructed configuration above. This ADR does not
re-score; ADR 0115 governs the sweep.

## Amendment (2026-07-17) — per-rule alert recipients (BACKLOG #146)

**Status:** Built — additive. A new `recipients` field on the typed `AlertRule`, carried through
`AlertRuleSet.decide` → `_RuleDecision.recipients` → the notifier, and consumed by `EmailTransport`.
Off by default (`recipients = None` → the global `[alerts].email_to`); empty config = byte-identical.

**Context — the gap.** §1's `AlertRule` routes an event to a *transport subset* (`transports`), but the
email transport always sends to the single global `[alerts].email_to`. An operator can't say "page the
on-call for `OB_*` connection stops, but email the interface team for the ACME feed" — every email goes
to one list. That is the Corepoint per-route-recipient parity feature (the workaround — one global list
plus downstream mail rules — is real but clumsy).

**Decision — a per-rule EMAIL recipient override.** Add `recipients: list[str] | None` to `AlertRule`
(pure data, `extra="forbid"` still holds). `AlertRuleSet.decide` carries it into `_RuleDecision`; when a
matching rule sets it, `NotifierAlertSink._emit` tags the event with an **internal** `_recipients` key
that `_handle` **pops before the fan-out loop** and hands to each transport's `send(event, recipients=…)`.
`EmailTransport` sends to the override (falling back to its own global recipients when `None`); the
webhook **ignores** it. `recipients = None` (the default) is byte-identical to before.

**PHI / secret posture.** Recipient addresses are **operator config, not PHI** — but they are still an
**internal routing key that never crosses the webhook wire**: `_handle` pops `_recipients` before any
`send`, and `WebhookTransport._post` additionally strips **every** `_`-prefixed key from the serialized
JSON (defense in depth), so a webhook payload can never carry recipient addresses. The read-only
`GET /alerts/rules` view reports a `recipient_count` (an integer), never the addresses — parity with the
existing `email_recipient_count` secret-guard. An **empty** `recipients = []` is rejected at config-load
(a recipient override that sends to nobody is a config error; suppress a notification with `transports=[]`
instead, not an empty recipient list).

**Scope.** Email-only (the webhook has no per-recipient concept); a rule that sets `recipients` while
routing only to the webhook is harmless (the override is simply never consumed). This does **not** change
§4 (per-node `connection_stopped` is unchanged) or add escalation chains (§3 decline stands).

## Amendment (2026-07-17) — HA leadership + DR transition alert events (BACKLOG #145)

**Status:** Built — additive. New `AlertSink` methods (`leadership_acquired` / `leadership_lost` /
`dr_activated` / `dr_released`), new event types + one auto-resolve pair, and new **fire sites** in
`pipeline/cluster.py` + `pipeline/cluster_sqlserver.py` (leadership transitions) and `pipeline/dr.py`
(activate/release). Off unless clustered / a DR box (single-node `NullCoordinator` never transitions, so
byte-identical).

**This amendment RETIRES the original "no protocol/fire-site/engine change" self-scope.** The base ADR
(and the #146/#93 amendments) were **fully additive to the rules layer only** — the `AlertSink` protocol,
the fire sites, and the engine were untouched. #145 is the first change that **adds `AlertSink` protocol
methods and new emit sites in the engine** (the cluster coordinators + the DR coordinator). That is a
deliberate, scoped widening: the Consequences bullet "no protocol/fire-site/engine change" and the
Options-considered framing no longer hold for these four leadership/DR events. Every *other* property is
preserved — the events flow through the **same** `AlertRuleSet.decide` / `realert_seconds` throttle /
ADR 0044 resolvable-state machinery, and empty config is byte-identical.

**Context — the failover blind spot.** Active-passive HA (ADR 0037/A2) and third-tier DR (ADR 0048) move
leadership / promote a standby, but the engine emitted **no alert** on the transition edge — an operator's
only signal was to poll `/cluster/status` or `/dr/status` and diff. A failover (the exact moment you want
paged) was invisible.

**Decision — two page-worthy events + two auto-resolving inverses.**
- **`leadership_acquired`** (a node went non-leader → leader — an HA failover / initial election) and
  **`dr_activated`** (a DR standby was promoted) are **alert event types** (rule-targetable via
  `_ALERT_EVENT_TYPES`): severity/route/cooldown per rule, throttled per `(type, node)`.
- **`leadership_lost`** (a node lost / self-fenced / cleanly released leadership) and **`dr_released`**
  (fail-back to the recovered primary) are the **inverses** — routed through **`_AUTO_RESOLVE`** (NOT
  `_ALERT_EVENT_TYPES`), so they emit **no** notification (a step-down / fail-back needs no page) and
  instead **auto-resolve** the matching open `leadership_acquired` / `dr_activated` instance (ADR 0044),
  exactly like `connection_restored` cancels `connection_error`. The open `leadership_acquired`
  instances therefore track the **current** leader set on the dashboard.

**Payload — node/connection/role/epoch only (no PHI).** Each event carries **only** the node id (also the
`connection`/throttle key), a `role` (`leader`/`follower` for HA, `dr_standby`/`primary` for DR), and —
for `leadership_acquired` — the H1 leader `epoch`. No message content, no queue body: these are
cluster-topology facts. The DR fire sites reuse `DrCoordinator._alert_sink` already threaded for #60; the
cluster fire sites thread a new `alert_sink` into **both** `DbCoordinator` and `SqlServerCoordinator` **in
lockstep** (Postgres + SQL Server active-passive parity) and emit at the three transition points (acquire
in `_maintain_leadership`, lose there + on `_check_fence` self-fence + on `_release_leadership` clean
shutdown). §4's "per-node observation, don't leader-gate the notifier" reasoning is *reinforced*, not
changed: a leadership event is inherently per-node and each node reports its own transition.

**Note — the initial election also emits.** A cold cluster bring-up is a non-leader → leader transition on
the elected node, so it fires one `leadership_acquired` (bounded to one per node per cooldown; an operator
can down-tune or suppress it with a per-rule `severity` / `transports=[]`). There is no engine-level way to
distinguish "initial election" from "failover take-over" at the fire site, and both are genuine "leadership
moved" signals, so they are treated uniformly.
