# ADR 0011 — Timer source (scheduled synthetic message emission)

- **Status:** Proposed (2026-06-14) — the first purely *generative* source.
- **Built:** Yes — new [`transports/timer.py`](../../messagefoundry/transports/timer.py)
  (`TimerSource`) + a `Timer(...)` factory in [`config/wiring.py`](../../messagefoundry/config/wiring.py);
  additive `ConnectorType.TIMER`, package exports, and a `connections.toml` loader entry (ADR 0007 —
  declarable as data too). No `wiring_runner.py` / `dryrun.py` / store / API changes.
- **Related:** [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (connector registry),
  [ADR 0004](0004-payload-agnostic-ingress.md) (`content_type` / `RawMessage`),
  [ADR 0001](0001-staged-pipeline-architecture.md) (ingress stage, ACK-on-receipt),
  [ADR 0006](0006-external-data-lookups.md) (the live-lookup exception this mirrors in spirit),
  Track B Step 4b leader-gating ([`transports/base.py`](../../messagefoundry/transports/base.py)).

## Context

Every source today is *reactive* — it waits for an external event: an MLLP/TCP connection, a file
landing ([`transports/file.py`](../../messagefoundry/transports/file.py)), a DB row appearing
([`transports/database.py`](../../messagefoundry/transports/database.py)). Several integration needs
are instead *time-driven*: a periodic heartbeat/keep-alive into a downstream, synthetic load for soak
tests, or a scheduled "kick" that makes a Router/Handler run on a cadence (e.g. to drive a periodic
pull or emit a canned query). There is no way to originate a message from the clock.

A timer is unusual among sources: it **reads no external resource** and instead **emits an
operator-configured body on a schedule**. It must still fit the existing `SourceConnector` contract
([`transports/base.py`](../../messagefoundry/transports/base.py) §`start`/`stop`) and the staged
pipeline unchanged — it hands raw bytes to the inbound handler, which commits them to the **ingress**
stage and (for this fire-and-forget transport) sends no ACK.

Two existing facts make this additive:

1. The runner already leader-gates *all* sources — it passes `leader_gate=is_leader` into every
   `start()` and only poll sources act on it
   ([`wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) ~L240–257).
2. Ingress is payload-agnostic ([ADR 0004](0004-payload-agnostic-ingress.md)) — a body's format is
   declared on `inbound(content_type=…)`, not by the connector.

## Decision

### §1 — A new `TIMER` source connector

Add `ConnectorType.TIMER` and `transports/timer.py: TimerSource(SourceConnector)`, registered via
`register_source(ConnectorType.TIMER, TimerSource)` at import. It follows the File/Database poll
skeleton ([`file.py`](../../messagefoundry/transports/file.py) ~L179–226) — a cooperatively-cancellable
`asyncio` loop with `_stop`/`_task`, a `wait_for(stop.wait(), tick)` sleep, and a try/except that
logs-and-continues so a transient failure never kills the source — but **drops** the resource scan,
content validation/quarantine, and mark/move. Instead of reading, each tick **fires**:
`await self._handler(self._body_bytes)`. The heartbeat fires immediately at `t=0`, then every interval.

### §2 — Schedule model (MVP: interval + run-once; cron deferred)

Settings: `body` (required), `interval_seconds` (fire every N seconds, must be `> 0`), `run_once`
(fire exactly once), `encoding` (default `utf-8`). At least one of `interval_seconds`/`run_once` is
required. `cron_expression` is a **reserved** setting that raises a clear "not yet implemented"
`ValueError` — the MVP stays stdlib-only (no scheduling dependency until an owner-approved lock
refresh). The `wait_for`-based loop is already cron-shaped, so cron is a localized follow-up.

### §3 — Leader-gated firing (`polls_shared_resource = True`)

The schedule is a **shared trigger**: in a cluster, every node firing independently would emit each
message once *per node*. So `TimerSource` sets `polls_shared_resource = True` and checks a `_may_fire()`
gate (the File `_may_poll()` pattern, one log per leader→follower transition) before each fire — **only
the leader emits**. On a single node `NullCoordinator.is_leader()` is always `True`, so behaviour is
byte-identical to an ungated loop. **No runner change:** the existing `start(…, leader_gate=is_leader)`
call already wires this, and the runner already logs poll-source intake as leader-gated at start
([`wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) ~L252).

### §4 — Content-type is operator-declared, not forced

The connector emits bytes and never sets `content_type`. An operator emitting a synthetic HL7 message
uses the default (`hl7v2` → full peek/ACK path); one emitting JSON/text declares
`inbound(…, content_type=ContentType.TEXT)` and Routers/Handlers receive a `RawMessage`
([ADR 0004 §2](0004-payload-agnostic-ingress.md)). The `body` is emitted verbatim (no templating in the
MVP), encoded with `encoding`.

### §5 — At-least-once / re-run contract

A fire commits the body to the **ingress** stage; from there the body is frozen in its row, so the
"Routers/Handlers must be pure" re-run invariant
([`wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) module docstring) is **untouched** —
re-runs re-derive from a fixed body, and the pre-encoded body is identical every fire. The *timing*
boundary is at-least-once and bounded by leader-gating: an `interval_seconds` timer fires ≈once per
interval on the leader; a failover can drop or duplicate a single tick (it is a clock, not a queue —
consumers must tolerate that). `run_once` means **once per leadership term**, not once-ever; true
once-ever (durable fire-state) is a follow-up. This is the deliberate **clock-trigger** source — its
non-determinism is in *when/whether it fires*, documented the way [db_lookup](0006-external-data-lookups.md)
is documented as the deliberate live exception.

## Options considered

1. **Dedicated `TIMER` connector (chosen).** Fits the registry; fully additive; reuses the leader-gate
   plumbing. Honest about being a source that *generates* rather than *reads*.
2. **Reuse `DATABASE`/`FILE` with a "no-op poll".** Rejected — overloads a resource poller with a
   resourceless trigger; confusing config and validation, and the wrong mental model.
3. **An engine-level scheduler firing Routers directly (outside the source model).** Rejected — it
   bypasses source/ingress/disposition accounting (every received message must be counted and logged,
   CLAUDE.md §1); a timer-originated message should be a first-class received message.

## Consequences

**Positive**
- Time-driven origination (heartbeats, soak load, scheduled kicks) with zero pipeline change.
- Correct in a cluster for free (leader-gated; single-node byte-identical).
- Every fired message is counted/logged with a disposition like any other inbound.

**Negative / risks**
- `run_once` is once-per-leadership-term, not once-ever (documented; follow-up for durable state).
- Interval timers are at-least-once at the trigger boundary across failover (clock semantics).
- A static `body` reuses its MSH-10 control-id on every fire — fine for synthetic/test/heartbeat
  traffic; templating (fresh control-id/timestamp) is a deferred follow-up.
- Cron is not in the MVP (the reserved setting raises until it is built).

## To resolve on acceptance

1. Confirm the MVP scope = `interval_seconds` + `run_once`, cron deferred. *(Confirmed.)*
2. Confirm `run_once` = once-per-leadership-term is acceptable for the MVP. *(Confirmed.)*
3. Confirm `body` is a literal (no templating) for the MVP. *(Confirmed.)*
