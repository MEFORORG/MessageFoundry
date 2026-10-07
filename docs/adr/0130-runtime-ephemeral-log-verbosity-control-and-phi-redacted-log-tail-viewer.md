# ADR 0130 — Runtime (ephemeral) log-verbosity control + PHI-redacted log-tail viewer

- **Status:** Accepted (2026-07-17) — DEMAND-GATE-BACKLOG Wave 3 build (lane `dg-s7b`); pushes/PR owner-approved.
  Amended 2026-10-06: a production instance refuses DEBUG at run time (vault BACKLOG #2777; see the end).
- **Built:** Yes — additive. `set_runtime_level` / `current_log_level` in
  [`logging_setup.py`](../../messagefoundry/logging_setup.py); three routes on
  [`api/app.py`](../../messagefoundry/api/app.py) — `GET`/`PATCH /logging/level` (gated by
  `monitoring:diagnose`) and `GET /logs/tail` (gated by the new `logs:view` PHI-read permission); the
  `LogLevelInfo` / `LogLevelUpdate` / `LogTailPage` DTOs in [`api/models.py`](../../messagefoundry/api/models.py);
  the `LOGS_VIEW` permission wired into the OPERATOR role in
  [`auth/permissions.py`](../../messagefoundry/auth/permissions.py). Off-path when no `[logging].log_dir`
  is configured (the viewer degrades to "no file", never raises).
- **Related:** [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
  (the PHI-read hop guard the viewer inherits), [ADR 0065](0065-web-ops-dashboard.md)
  (the console that renders it), `support/redact.redact_log_text` (#49 — the shared redactor the viewer
  reuses), BACKLOG #171. Companion: [ADR 0131](0131-bulk-raw-message-body-export-from-a-search-result-step-up-audited-phi-egress.md)
  (the S7b bulk-export item).

## Context

The service log level is a **startup-only** dial today (`[logging].level` / `--log-level`, applied once
by `configure_logging`). During a live incident an operator who needs `DEBUG` must **restart the engine**
(losing in-flight state and the very repro they are chasing), and to read the application log they must
pull a full **support bundle** (#49) — a one-shot, offline zip. Two ops gaps, both filed as #171:

1. a **runtime** verbosity control that raises/lowers the log level **without a restart**, and
2. an **in-console** viewer over the redacted application-log tail the support bundle already produces.

The viewer is a **new PHI read surface**: the app log is best-effort-redacted (the shared
`support/redact` pass: HL7-segment / field-run / DOB / name spans + secret markers), but a residual
**single-token** identifier can survive that regex pass, so serving log text to a browser must be treated
with the same RBAC + audit rigor as a message view — not as free operational text.

## Decision

### §1 — The runtime level override is EPHEMERAL and resets only on PROCESS RESTART

`set_runtime_level(level, *, production)` validates `level` against `LOG_LEVELS` (raising `ValueError`
otherwise; since the 2026-10-06 amendment it also raises `LogLevelRefused` for a level the production
tier refuses) and
sets the level on the **root logger** and the three `_UVICORN_LOGGERS`, mirroring exactly what
`configure_logging` sets — but it does **not** rebuild handlers (no new stream/forwarder, no filter
churn). The override lives only in the live `logging` module state. It is therefore **ephemeral**:

- a **process restart** re-runs `configure_logging(settings.logging.level, …)`, which re-asserts the
  configured level — so the override is gone;
- a **`/config/reload` does NOT re-run `configure_logging`** (verified — the reload path rebuilds the
  connection graph, not the logging handlers), so a runtime override **survives a reload**. This is the
  documented, intended behaviour: an operator who raised verbosity for an incident keeps it across a
  config reload, and only a deliberate restart returns to the configured baseline.

`PATCH /logging/level` applies the override and writes a `logging_level_change` audit row (actor + old →
new level); `GET /logging/level` reports the current effective level, the configured baseline, and the
valid choices. The level knob is gated by `monitoring:diagnose` (the existing diagnostic tier the
alert-ack / diagnose surface already uses), not the PHI permission. It is **not** PHI-neutral: the level
decides whether PHI reaches the log, so a production instance refuses `DEBUG` through it exactly as
serve's Gate #1 refuses to start at it. *(Corrected 2026-10-06. This sentence read "The level knob is
**not PHI**", which contradicted Gate #1; see the amendment below.)*

### §2 — The viewer is a PHI read surface: `logs:view` + hop-guard + audit, redacted text ONLY

`GET /logs/tail` reads the **newest** file under `[logging].log_dir` (one level, `.log`/`.txt`), pages
back from the end (`offset`/`limit`, newest page first), and returns each line **through
`support.redact.redact_log_line`** — the same redactor the support bundle uses, so the browser sees the
identical PHI/secret coverage. It is gated by a **new `logs:view` permission** via `require_phi_read`,
which folds in the [ADR 0092] `enforce_phi_read_hop` data-path guard (a production-PHI instance on an
unproven-secure serve hop refuses to emit) and the per-actor anti-automation throttle — exactly like the
message-detail read. Each page served writes a `logs_view` audit row (actor + how many lines exposed —
**metadata only, never the content**). When `log_dir` is unset (stdout-only, captured off-process by
NSSM) or the file is unreadable, the route returns an empty, `available=false` page — it **degrades
gracefully and never raises**. Redaction is best-effort (a residual single-token identifier can survive),
which is why the surface is RBAC-gated + audited rather than open: the control is defence-in-depth over
the redactor, mirroring the "never put PHI in a log line" convention.

### §3 — `set_runtime_level` lands CLEAN for the S7a file-handler work to build on

`set_runtime_level` touches only the level (root + uvicorn), never the handler set, so the later S7a
file-handler lane can add a rotating file handler in `configure_logging` without colliding with this
knob — a runtime level change re-levels whatever handlers exist.

## Options considered

1. **Ephemeral in-memory override + redacted paginated viewer behind `logs:view`/`require_phi_read` (chosen).**
   No restart, no new persistence, reuses the shared redactor + the PHI-read hop guard + the audit chain.
2. **Persist the override (survive restart).** Rejected — a persisted DEBUG left on after an incident is
   a standing PHI-in-logs risk; "reset on restart" is the safe default, and the config dial is the durable
   knob.
3. **Serve raw (un-redacted) log text to `logs:view`.** Rejected — the app log can carry a stray HL7
   fragment/secret; the browser must only ever see the redacted stream, same as the bundle.
4. **Re-run `configure_logging` on the PATCH.** Rejected — it rebuilds handlers (stream + off-box
   forwarder + filters) and would reconnect a TCP/TLS collector on every level tweak; level-only is
   surgical.

## Consequences

**Positive** — operators raise/lower verbosity and read the redacted log live, without a restart or a
bundle pull; the viewer reuses the shared redactor (one PHI-coverage source of truth) and inherits the
existing PHI-read hop guard + audit chain; additive, off-path when no log dir is configured.

**Negative / residual** — the runtime override is invisible after a restart (by design — the config dial
is the durable setting), and `/config/reload` intentionally does **not** reset it. The viewer's redaction
is best-effort (residual single-token PHI possible), mitigated by RBAC + audit, not eliminated. Only the
newest log file is paged (rotated-away history stays in the bundle). Per-logger/per-area targeting is out
of scope for the MVP (root + uvicorn only).

## Amendment 2026-10-06: a production instance refuses DEBUG at run time, as it does at start-up

Vault BACKLOG #2777. Decided by adversarial review under the owner's driver rule, which follows a clear
recommendation on an undecided owner question.

**What was wrong.** §1 said the level knob "is not PHI". That contradicts serve's Gate #1, whose whole
premise is that DEBUG is the state that surfaces PHI (full message bodies, raw field values) into the
general log and any off-box forwarder. Both cannot hold, and the gate is the one tied to a stated
threat. This ADR never discussed production posture, so `PATCH /logging/level` applied DEBUG on a
production instance with no check. A permission an Operator holds, and not a PHI permission, could
reach a state serve refuses to start in. The override also survives `/config/reload`, so it could
last until a restart nobody is obliged to perform. In the shipped code this would let a first
deployment's production instance write PHI to its logs at run time.

**Decision.** One predicate, `logging_setup.level_refused_on_production(level, production=...)`,
decides both paths, and one text, `PRODUCTION_DEBUG_REFUSED`, explains both refusals. The predicate
compares the numeric threshold, so anything at or below DEBUG is refused, including a level added to
`LOG_LEVELS` later. `serve` uses it for Gate #1. `set_runtime_level` takes the tier as a required
keyword and raises `LogLevelRefused` for a refused level, leaving the level untouched, so no run-time
caller can switch the level without answering the posture question. `PATCH /logging/level` resolves
the tier from the loaded `[ai]`/`[security]` posture, with an unresolved tier counting as production,
and answers a refusal with a 403 that names the posture and the legitimate route: reproduce on a
separate instance that is non-production from start-up, fed synthetic or de-identified messages. It
says not to relabel the production instance or copy its feed, because either would put PHI in a log
by another door. It audits the refusal as
`logging_level_change_denied` (actor, current level, requested level, reason), best-effort so that a
failed audit write cannot turn the refusal into a 500. `GET /logging/level` and the PATCH response
list only the levels the instance accepts, so DEBUG is not offered on a production instance. A
non-production instance keeps the full §1 behaviour.

**Reload.** §1 still holds that `/config/reload` does not reset a run-time override, and the reload
path does not re-level the log or change the posture. On a production instance there is no DEBUG
override for it to carry, because both entry points refuse one.

**Not decided here.** An audited break-glass with step-up and an expiry that reverts the level would
be a production loosening. It needs its own owner ruling, a `security_loosenings()` entry and its own
record. None exists, so production DEBUG is unreachable at run time exactly as it is at start-up.
