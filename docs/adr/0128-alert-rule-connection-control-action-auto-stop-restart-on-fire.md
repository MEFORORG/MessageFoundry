# ADR 0128 — Alert-rule connection-control action (auto stop/restart on fire)

- **Status:** Accepted (2026-07-17) — demand-gate build (lane `dg-s1a`); pushes/PR owner-approved.
- **Built:** Yes — additive. `AlertRule.control_action` / `control_target` in
  [`config/settings.py`](../../messagefoundry/config/settings.py), carried through
  `AlertRuleSet.decide → _RuleDecision`, dispatched by
  [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py)'s `NotifierAlertSink` via an
  **injected async control callback** wired from the [`api/app.py`](../../messagefoundry/api/app.py)
  lifespan to `RegistryRunner.restart_inbound` / `restart_outbound`. Off by default
  (`control_action = None`) = today's behaviour.
- **Related:** [ADR 0014](0014-alerting-rules-engine.md) (the rules engine + notifier this rides),
  [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) (the control seam),
  BACKLOG #144.

## Context

A `connection_stopped` / `connection_error` / persistent `lane_stuck` today **pages a human** who then
runs the manual `POST /connections/{name}/{start|stop|restart}` remediation. For the common, safe,
well-understood case — "a lane wedged on a transient fault; just restart it" — that human round-trip is
pure latency. Operators asked for **auto-remediation**: when an alert rule fires, optionally restart the
connection, and still page. This is the alert-engine analog of Corepoint's channel auto-restart.

## Decision

### §1 — A control action is an alert-rule OUTCOME (pure data, whitelisted)

Add two pure-data fields to `AlertRule`: `control_action` (`None` | `"restart_inbound"` |
`"restart_outbound"`, whitelist-validated at config-load) and `control_target` (the connection to act on;
`None` = the event's own `connection`, natural for the connection-scoped events). When a rule matches,
its `_RuleDecision` carries the action; there is **no embedded code/expression** (parity with ADR 0014
§1's "typed data, never `eval`"). The whitelist is exactly the two warm-restart primitives — `stop` +
`start` alone are not offered (a bare stop with no re-arm is an easy way to silently wedge a feed; a
restart is the safe remediation an operator actually wants).

### §2 — The sink is DECOUPLED from the runner: an INJECTED async callback

The `NotifierAlertSink` **must not** import `RegistryRunner` (that would invert the engine layering and
couple the notifier to the runtime graph). Instead the sink holds an **injected** async control callback
`Callable[[str, str], Awaitable[None]]` (`set_control_callback`, mirroring `set_store`); the `api/app.py`
lifespan wires it to a closure over the engine that calls `RegistryRunner.restart_inbound` /
`restart_outbound` (re-reading `engine.registry_runner` each call, so a config reload that swaps the
runner is transparent). The callback lives in `api/` — which *may* import the runner — and is handed
**down** into the sink. The sink→runner relationship is a **pipeline→pipeline** one (both live under
`pipeline/`), which is layering-legal; injecting it rather than importing keeps the sink dependency-light
and unit-testable with a stub callback.

### §3 — Never-block, never-raise, off the delivery worker

The emit path runs **inline on a delivery worker** and must never block (ADR 0014 / the `AlertSink`
contract). So the control action is **dispatched off the worker** as a fire-and-forget `asyncio` task
(exactly like the ADR 0044 state observer) and is **never-raise**: a failed/rejected restart (unknown
connection, not-deployed, shard-not-owner, a hung stop) is swallowed + logged, never propagated into the
worker and never able to break alerting or delivery. The restart itself is `restart_inbound` /
`restart_outbound`, which already return fast (a cooperative stop that does not await an in-flight drain),
so the task cannot hang a lane.

### §4 — Throttled with the notification; independent of transport suppression

The action fires on the **same throttle gate** as the notification — at most once per `realert_seconds`
(or the rule's `cooldown_seconds`) per `(event_type, connection)` — so a flapping lane cannot trigger a
restart storm. It is **independent of transport suppression**: a rule may set `transports=[]` to
auto-remediate **quietly** (restart, no page) or fire alongside a page. The control action requires the
**notifier** to be active (≥1 transport configured), since it is a notifier outcome; a deployment that
wants transportless remediation configures at least one transport (documented; a transportless-notifier
mode is a possible follow-up).

## Options considered

1. **Injected async callback, dispatched off-worker, never-raise (chosen).** Keeps the sink decoupled
   from the runner, honours the never-block emit contract, throttled + safe.
2. **Import `RegistryRunner` into the sink and call it directly.** Rejected — inverts engine layering
   (the notifier would depend on the runtime graph), and couples a dependency-light, unit-testable sink
   to the runner.
3. **Fire the control synchronously inline on the worker.** Rejected — violates the never-block emit
   contract; a slow/hung stop would stall the very lane it is reporting on.
4. **Offer bare `stop` / `start` too.** Rejected for the MVP — a stop with no re-arm silently wedges a
   feed; `restart_*` is the safe, complete remediation. (Manual `stop`/`start` stay on the API.)

## Consequences

**Positive** — the common "just restart the wedged lane" case is auto-remediated at alert latency with a
human still paged (or deliberately quiet); additive, off by default, no new dependency, no layering
change. Reuses the existing throttle so it can't storm.

**Negative / residual** — auto-restarting a lane wedged on a *persistent* fault will restart-loop it (once
per cooldown) until an operator intervenes — the same class of caveat as retry-forever; an operator scopes
the rule (`connection` glob + `event_type`) to lanes where a restart is a sane response. Control requires a
configured transport (the notifier). `stop`/`start` primitives and cross-connection orchestration beyond a
single `restart_*` are out of scope (manual API remains).
