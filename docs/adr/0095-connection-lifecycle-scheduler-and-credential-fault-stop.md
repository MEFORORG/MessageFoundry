# 0095 — Connection lifecycle seam: active-window scheduler + credential-fault lane stop

- **Status:** Accepted  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-07-12
- **Related:** BACKLOG #147 · BACKLOG #109 · [ADR 0070](0070-pooled-infra-fault-lane-stop.md) · [ADR 0031](0031-per-connection-fault-isolation.md) · CLAUDE.md §2 (reliability invariant, count-and-log), §8 (ACK)

---

## Context

Two per-connection *lifecycle* gaps, sharing one seam in the `RegistryRunner` / `StageDispatcher`:

1. **#147 — no time-of-day / day-of-week calendar.** A connection is either always-on or gated by the
   one-shot boot flag `auto_start` (#115). There is no way to say "this feed is only up 08:00–17:00
   Mon–Fri" and have the engine *auto-start and auto-stop it on schedule*. The TIMER source (ADR 0011)
   emits a body on a clock but never gates a connection up/down — it is a source, not a scheduler.

2. **#109 — a bad credential hammers the partner account.** Today an outbound File/FTP/SFTP auth
   failure maps to `_RemoteError(permanent=True)` → `NegativeAckError(permanent=True)` → **dead-letter**
   (wiring_runner `_process_delivery_item`). With a backlog, the worker dead-letters row after row,
   *re-authenticating on each* — a retry storm that can trip the partner's account-lockout policy. The
   only existing auto-stop (ADR 0070 `infra_fault_stop_after`) fires only after N consecutive *transient*
   infra faults, never on a *permanent* auth failure.

Invariants in play (CLAUDE.md), quoted verbatim, that the design must not break:

> "**Reliability invariant (do not break):** the transactional **staged queue on SQLite (WAL)** gives
> at-least-once delivery, retries, replay, and dead-lettering *without* a separate broker."

> "**Count-and-log invariant (do not break):** **every received message is persisted before the ACK** …
> nothing is accepted-and-dropped."

A schedule-park must be a **clean stop** (normal drain/stop, never a crash); a credential stop must
**retain the backlog un-errored** (never lose a message, never dead-letter the good queue).

## Decision

**One lifecycle seam, two behaviours, both reusing the *existing* per-connection start/stop path.**

**#147 active-window scheduler.** A declarative, pydantic-validated per-connection `Schedule`
(`config/models.py`): a list of `ActiveWindow`s (a `datetime.weekday()` day-set + local `start`/`end`
time-of-day + IANA `timezone`, default UTC) plus an `invert` flag. Semantics: with `invert=False`
(default) the windows are **availability** windows — the connection is UP inside any window and parked
outside; with `invert=True` they are **maintenance** windows — parked inside, UP outside. A same-day
span is `[start, end)`; `start > end` **wraps past midnight** anchored on the start weekday;
`start == end` is rejected. `schedule=None` on a connection is **always-on** and **byte-identical** (no
scheduler task).

The `RegistryRunner` spawns **one cooperatively-cancellable asyncio scheduler task per scheduled
connection** (`_schedule_worker`), which every `schedule_tick_seconds` reconciles the connection's live
listen/deliver state against its calendar (`_reconcile_schedule`) via the **same** `start_inbound` /
`stop_inbound` (or `start_outbound` / `stop_outbound`) the console/API use. An inbound park unbinds the
listener (router/transform workers keep draining the in-flight backlog); an outbound park PAUSEs
delivery and **RETAINS its queued rows pending** (never dropped). The clock is **injectable**
(`schedule_clock`, mirroring dry-run's `ingest_time`) so tests drive window boundaries deterministically.

**#109 credential-fault lane stop.** A permanent auth failure is marked as a **credential fault**
distinct from a **content-permanent** failure: `_RemoteError.credential_fault` (set only at the FTP
login-refused / SFTP auth-failed sites, **not** on an operation-level `error_perm` / no-such-dir) is
threaded onto `NegativeAckError.credential_fault`. In `_process_delivery_item`, under
`credential_fault_policy="stop"` (default) a credential fault **STOPs the lane immediately** (reusing the
ADR 0070 / InternalErrorPolicy STOP muscle — `_ItemOutcome.STOPPED` → per_lane worker exits / pooled lane
→ STOPPED phase + `connection_stopped` alert) and **RETAINS the claimed row un-errored** via
`store.release_claimed` (back to PENDING, undoing only the claim's `attempts++`, no backoff, no
`last_error`). Nothing is dead-lettered; the queue is intact for an operator to resume after fixing the
credential (reload/restart re-arms the STOPPED lane). `credential_fault_policy="dead_letter"` keeps the
historical fail-fast dead-letter. A content-permanent reject (AR/CR, no-such-dir) is **unaffected** — it
still dead-letters just that one row.

**Legible stop reasons.** A schedule-park, a credential-fault stop, and a content STOP are three
different reasons — each logs/alerts a distinct message so an operator can tell them apart (both #109 and
#147 touch `stage_dispatcher`/`settings`, so they must compose cleanly).

## Acceptance Criteria

- **AC-1** — WHEN the injectable clock enters a connection's active window, THE SYSTEM SHALL start that
  connection; WHEN it leaves, THE SYSTEM SHALL cleanly stop (park) it.
  → `tests/test_connection_scheduler.py::test_reconcile_starts_in_window_and_parks_out`,
  `tests/test_connection_scheduler.py::test_scheduler_task_autonomously_parks_out_of_window`
- **AC-2** — WHERE a connection declares no schedule, THE SYSTEM SHALL leave its lifecycle byte-identical
  (no scheduler task, always-on).
  → `tests/test_connection_scheduler.py::test_no_schedule_is_always_on`
- **AC-3** — WHEN an outbound sender hits a PERMANENT credential/auth fault under the `stop` policy, THE
  SYSTEM SHALL stop the lane immediately and retain the queued rows un-errored (pending, not
  dead-lettered), draining no further.
  → `tests/test_credential_fault_stop.py::test_credential_fault_stops_and_retains`
- **AC-4** — IF the failure is a TRANSIENT infra fault, THEN THE SYSTEM SHALL follow the existing
  retry/backoff path (no immediate stop).
  → `tests/test_credential_fault_stop.py::test_transient_fault_still_retries`
- **AC-5** — IF the failure is a CONTENT-permanent reject (not a credential fault), THEN THE SYSTEM SHALL
  dead-letter just that one message (unchanged).
  → `tests/test_credential_fault_stop.py::test_content_permanent_still_dead_letters`

## Options considered

1. **Reuse the existing per-connection start/stop + a per-connection scheduler task, and reuse the STOP
   muscle + `release_claimed` for credential faults.** **CHOSEN.** No new lifecycle path, no new store
   mutation kind; the schedule-park and credential-stop both flow through already-proven, already-tested
   machinery, so the reliability/count-and-log invariants are preserved by construction.
2. **A dedicated "channel" object owning schedule + credential policy.** Rejected: CLAUDE.md §1 forbids a
   built channel/route element that bundles the graph. Schedule/policy are per-connection attributes, not
   a new grouping unit.
3. **Credential fault → `mark_failed` (re-pend with backoff) instead of `release_claimed`.** Rejected:
   `mark_failed` writes a `last_error` and a backoff `next_attempt_at` (an *errored* row) and, without a
   lane stop, would still re-authenticate on the backoff cadence — exactly the lockout risk. Stop + a
   clean release keeps the backlog un-errored and quiescent.

## Consequences

**Positive** — Feeds can be scheduled in site-local time (per-window IANA tz), decoupled from the engine
host clock. A leaked/rotated credential can no longer lock out a partner account via a backlog re-auth
storm, and no queued message is lost. Both behaviours are opt-in and default-off/always-on
(byte-identical when unused).

**Negative / risks** — The scheduler reconciles on a fixed tick, so a window boundary is honoured within
one `schedule_tick_seconds` (not to the second); acceptable for start/stop scheduling. A scheduled
connection's lifecycle is owned by its calendar, so a manual operator start/stop out of phase is
re-reconciled on the next tick (documented). A credential-STOPped lane stays down until an operator
fixes the credential and reloads/restarts — intentional (fail-safe for the partner account).

**Out of scope** — Exact next-boundary sleep computation (a tick is enough); a console UI for the
schedule calendar; per-window holidays/exceptions; auto-clearing the credential STOP without operator
action.

## To resolve on acceptance

- [x] Scheduler polarity model — availability windows with an `invert` maintenance flag (chosen; single
  clear model, documented on `Schedule`).
- [x] Retain-un-errored primitive — `store.release_claimed` (undoes the claim, no backoff, FIFO-neutral).
