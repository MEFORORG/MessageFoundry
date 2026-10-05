# 0095 — Connection lifecycle seam: active-window scheduler + credential-fault lane stop

- **Status:** Accepted  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-07-12
- **Related:** BACKLOG #147 · BACKLOG #109 · [ADR 0070](0070-t17-infra-fault-bound.md) · [ADR 0031](0031-startup-connection-fault-isolation.md) · CLAUDE.md §2 (reliability invariant, count-and-log), §8 (ACK)

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

## Amendment A (2026-09-29): configuration-fault STOP and scheduler holds (BACKLOG #2083, batch 178)

> **Status of this amendment: recorded 2026-09-29 by the Manager seat for batch 178.** This amendment
> lands in PR 1821 (BACKLOG #2083). A.1 to A.3 describe code in that PR. A.4 records scheduler
> behaviour that landed earlier in PR 1811 (batch 178). The Decision, AC-1 to AC-5 and the
> Consequences above stay as first written. Where they differ from this amendment, this amendment
> governs.

### A.1 A third fault class: the configuration fault

The Decision names two permanent-fault classes. A credential fault stops the lane and keeps the
queue. A content-permanent reject dead-letters one row. This amendment adds a third, the
**configuration fault**.

A configuration fault is a permanent refusal of the connection's own settings. It is not a fault of
one message or of the credential. `_RemoteError.config_fault` marks it, and
`NegativeAckError.config_fault` carries it to the delivery worker. `remotefile._ftp_connect_refusal`
sets it on these refusals while an FTP session opens:

- a 5xx refusal of `AUTH TLS`, or of `PBSZ`/`PROT P`;
- a 5xx login refusal on a plain FTP session that demands TLS as one phrase (`_demands_tls`). The
  reply must carry no credential word once TLS vocabulary is taken out. So "530 You must
  authenticate over TLS" is a configuration fault, because "authenticate" is removed first;
- a 5xx refusal of the greeting, before any credential is sent.

A configuration fault takes the same STOP as a credential fault. Every queued row would meet the same
refusal, so dead-lettering one row would only be the first of the whole queue. Under
`credential_fault_policy="stop"`, the default, the worker would stop the lane. It would release the
claimed rows to PENDING un-errored through `store.release_claimed`. Under `"dead_letter"` it
dead-letters the one row on the single-row path. On the coalesced-batch path it dead-letters every
member of the batch (`store.dead_letter_batch`).

One policy governs both classes, and no new setting was added. Before #2083 these refusals were read
as credential faults. So neither policy's handling of them changes; only the log line and the alert do.

The routing lives in `messagefoundry/pipeline/wiring_runner.py`. `_lane_stopping_fault` names the
class, and `_stop_lane_retaining` stops the lane and releases the rows. The single-row path
(`_process_delivery_item`) and the batch path (`_deliver_coalesced_batch`) both call them. The batch
path releases every member of the batch.

The alert detail names the class. A configuration stop reads
`configuration fault (<code>); lane stopped, queue retained (#2083)`. A credential stop still reads
`credential fault (<code>); lane stopped, queue retained (#109)`. So the "Legible stop reasons"
paragraph now covers four reasons, not three.

`_list_or_retry` passes a configuration fault through unchanged, as it does a credential fault. It
still makes every other listing fault transient. It runs on the send path when `validate_directory`
is on, and in `_unique` when `overwrite` is off.

### A.2 The credential fault narrows to a refused login

Before #2083, `_FtpClient._op` read every 5xx while an FTP session opened as a credential fault. Now
`_ftp_connect_refusal` classifies a 5xx by the step it answers. The steps are the greeting,
`AUTH TLS`, the login, and `PBSZ`/`PROT P`.

- A 5xx whose last line names a connection limit is transient, at any step
  (`_names_connection_limit`). At the login, the reply must also carry no credential word anywhere.
  A busy server would then be retried rather than stop the lane.
- Any other 5xx at the login is still a credential fault, other than the plain-session TLS demand
  in A.1. That includes an ambiguous 530. The
  rationale is stated once, in the docstring of `remotefile._names_connection_limit`; read it there.
- A 4xx is transient, as before, with one change. A 4xx at the login that names the credential, such
  as `430 Invalid username or password`, is now a credential fault too.

The SFTP auth-failed site is unchanged. The credential words are broad on purpose. So a busy reply
that also carries one, such as "blocked", still stops the lane. That is the cheaper of the two errors:
a stopped lane keeps every message, while a retried bad password could lock the partner account.

### A.3 AC-5 is narrowed, and AC-6 is added

AC-5 now reads: IF the failure is a CONTENT-permanent reject (neither a credential nor a
configuration fault), THEN THE SYSTEM SHALL dead-letter just that one message, or every member of
a coalesced batch (unchanged). Its test is unchanged. The batch clause is not new behaviour: the
batch path already called `store.dead_letter_batch` on a permanent reject.

- **AC-6**: WHEN an outbound sender hits a PERMANENT configuration fault under the `stop` policy, THE
  SYSTEM SHALL stop the lane and retain the queued rows un-errored. Its alert SHALL name a
  configuration fault, not a credential. Under `dead_letter`, THE SYSTEM SHALL dead-letter just that
  one message, or every member of a coalesced batch.
  Tests: `tests/test_credential_fault_stop.py::test_configuration_fault_stops_and_retains`,
  `tests/test_credential_fault_stop.py::test_dead_letter_policy_dead_letters_the_configuration_fault`,
  `tests/test_remotefile_transport.py::test_a_refused_auth_tls_on_a_batch_stops_the_lane_and_keeps_every_row`

The Consequences line on a credential-STOPped lane applies to a configuration STOP as well. The lane
would stay down until an operator fixes the connection's configuration and reloads or restarts.

### A.4 Scheduler holds and reload (batch 178, PR 1811)

The Decision says the scheduler reconciles each connection on every tick through the ordinary
start/stop path. Batch 178 added these limits to `_reconcile_schedule` and to reload.

1. **An operator-required STOP outranks the calendar.** `_schedule_holds` reads the record that
   `_hold_for_operator` writes. A window open never starts a held lane. A window close does not park
   a held outbound either: a park is a pause, and a window open resumes a pause. A held inbound's park
   still runs, since it only unbinds the listener.
2. **The holds are at least these.** A #109 credential fault, a #2083 configuration fault, and the
   internal-error STOP policy. Also a pooled dispatcher's own STOP: the ADR 0070 T17 infra-fault bound
   or the #2074 claimer-death bound. `_pooled_stop_hold` holds those on all four pooled stages
   (BACKLOG #2072). An INGRESS, ROUTED or RESPONSE lane is held as its inbound. The record is cleared
   only where a lane is re-armed or torn down; the `_schedule_holds` docstring names those places.
3. **A DR-filtered connection is left alone (BACKLOG #2067).** A connection the ADR 0048 run-profile
   parked this run is skipped by both the start and the park branch, in both directions. An operator
   start of an inbound clears its marker, and from then its calendar owns it again.
4. **A latched #122 log-write halt counts as a held stop (BACKLOG #2066).** While the process-wide
   latch holds, a window open does not start a halted connection. Before, every in-window tick
   probed the dead sinks and paged again. Only the start branch is gated. An inbound is held only if
   the halt took it down.
5. **A committed reload replaces every scheduler task (BACKLOG #2069).** `_reconcile_schedulers`
   cancels each task and spawns one per schedule in the new graph. So an added schedule runs, an
   edited one takes its new calendar, and a removed connection's task ends. A kept outbound whose
   schedule the reload removed is resumed, when the calendar parked it and nothing else holds it.
6. **A window open that cannot start an inbound is recorded failed and alerted once (#2069
   follow-up).** `_record_window_open_failure` records it through `_record_failed`, as an engine start
   does (ADR 0031). Later ticks retry and log at DEBUG. A reload that finds the inbound outside its
   window clears the record, so the next failed window open alerts afresh. Inside its window the
   reload binds it, and a bind that succeeds clears the record. An outbound start that fails has no
   such record; the scheduler worker logs it and retries next tick.

The Consequences line says a manual start or stop out of phase is re-reconciled on the next tick. That
has exceptions, at least these. Items 1, 3 and 4 name the ones batch 178 added. Older gates skip an
outbound another engine shard owns and a not-deployed connection, and never start an
`auto_start=False` connection.

Tests: `tests/test_connection_scheduler.py`, at least
`test_credential_fault_stop_is_not_resumed_by_the_next_window`,
`test_a_response_lane_infra_fault_stop_is_not_resumed_by_the_next_window`,
`test_a_dr_filtered_inbound_is_not_started_by_its_window`,
`test_a_log_halt_is_not_restarted_or_re_paged_by_every_window_tick`,
`test_a_reload_that_edits_a_schedule_replaces_its_calendar` and
`test_a_window_open_that_cannot_bind_is_recorded_and_alerted_once`.

## Amendment B (2026-10-04): a refused HTTP Digest challenge is a configuration fault (BACKLOG #2323, batch 191)

> **Status of this amendment: recorded 2026-10-04 by a Builder seat for batch 191.** It describes
> the code in the pull request for BACKLOG #2323. Amendment A stays as written. This amendment adds
> one more place that raises the fault class A.1 defines.

A.1 lists the FTP refusals that are configuration faults. The HTTP family now raises one too.

The Digest handlers refuse a challenge they will not answer: a hash other than SHA-256, a malformed
challenge, or a scheme other than Digest or Basic. They raise `HttpAuthError`, which is a
`ValueError`. Before #2323, each send caught it as a bad request value and reported
`bad-request-value`. That is a content-permanent reject, so every queued row would dead-letter in
turn.

The refusal is the connection's, not the message's. The endpoint or the web proxy sends the same
challenge to every request. So `rest.auth_challenge_refused` builds a `NegativeAckError` with code
`auth-challenge-refused`, `permanent` and `config_fault`. `_post` raises it on the REST, SOAP, FHIR
and DICOMweb destinations.

Nothing in the delivery worker changed. Under `credential_fault_policy="stop"` the lane would stop
and the queue would stay. The alert would read
`configuration fault (auth-challenge-refused); lane stopped, queue retained (#2083)`. Under
`"dead_letter"` the one row dead-letters, or every member of a coalesced batch.

A retry was the other choice, and it was not taken. `smart.py` maps the same refusal on the token
hop to a retryable `DeliveryError`, because a token request carries no message body. A delivery
does. urllib answers an endpoint's challenge only after a first send, so each retry would send the
body once more with no credential. A retry also could not succeed until someone changes the peer or
the connection.

The cost is the one A.2 accepts for a credential stop. A peer that sends one bad challenge by
mistake stops the lane until an operator reloads or restarts it. A stopped lane keeps every message.

The probe arms and the `FhirLookup` read are not deliveries, so they carry no fault marker. A probe
raises a plain `DeliveryError`, and the read raises `FhirLookupError`. Both use the same fixed text.
The peer's algorithm token and scheme word stay on the cause and never reach `queue.last_error`.

Tests: `tests/test_digest_refusal_classification.py`, at least
`test_post_reports_a_refused_challenge_as_a_configuration_fault`,
`test_post_still_reports_a_bad_request_value_as_one` and
`test_a_refused_challenge_stops_the_lane_and_keeps_the_row`.
