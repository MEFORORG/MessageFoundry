<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# ADR 0162 — Fail-closed application-log write guard: detect, roll, and stop

- **Status:** Accepted (2026-08-10) — BACKLOG #122; owner-ruled principle (below). Pushes/PR
  owner-approved.
- **Built:** Yes — additive, and opt-in at the file sink. [`logging_guard.py`](../../messagefoundry/logging_guard.py)
  (new, stdlib-only) wraps both sinks; [`logging_setup.py`](../../messagefoundry/logging_setup.py)
  installs them; [`config/settings.py`](../../messagefoundry/config/settings.py) adds `[logging].file`
  / `file_max_bytes` / `file_backup_count` / `on_write_failure` plus the `log_write_failed` alert
  type; [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) owns the stop;
  [`api/app.py`](../../messagefoundry/api/app.py) reports per-sink health on `GET /status`.
  `[logging].file` unset (the default) leaves the engine stdout-only, exactly as before.
- **Related:** [ADR 0014](0014-alerting-rules-engine.md) (the `connection_stopped` rule this now
  drives, and the notifier the new event routes through),
  [ADR 0031](0031-startup-connection-fault-isolation.md) (the "record, alert, keep the rest running"
  precedent), [ADR 0080](0080-offbox-forwarding-tls-defaults.md) (off-box forwarding — durability,
  not enforcement), [ADR 0037](0037-multi-process-sharding-l3.md) (why the stop's scope is a
  process), [`docs/SERVICE.md`](../SERVICE.md) (who owns which log file), BACKLOG #122, #50, #120.

## Context

The owner ruled the principle, and it is a principle rather than a feature request:

> We never want to process stuff if the processing cannot be logged.

That is [CLAUDE.md](../../CLAUDE.md) section 1's count-and-log invariant — *"every message a
connection takes in or puts out is counted and logged; nothing is silently dropped"* — applied to the
application log. Processing a message you cannot log **is** the violation.

**The item's own 2/10 value score is refuted rather than inherited.** The re-score called #122
"substantially covered" by stdout, NSSM rotation, the RFC 5425 TLS syslog forwarder and #50's disk
metering. Verified against the tree at `751ca08a`: every one of those is **durability or visibility**.
NSSM rotates what it captures. The forwarder ships a copy off-box so evidence survives a host
compromise. `GET /status`'s `logs` block meters bytes and free space in `[logging].log_dir` — and it
reads the **supervisor's** directory, so it cannot even observe a sink the engine failed to write.
`grep -rn "FileHandler" messagefoundry/` finds exactly one, and it is not the engine's: the separate
`messagefoundry-tray` process logging to its own `tray.log` (`tray/__main__.py:24`).
`logging_setup.py`'s docstring said the engine "deliberately do[es] not add file handlers here", and
it was accurate. **Not one of those mechanisms stops processing when the log cannot be written.** The
score conflated *we can see the log is broken* with *we stop when the log is broken*, which are the
two halves of the invariant. Only the second was missing, and it is the half the ruling is about.

## Decision

### 1 — Two stages, and the split is the whole safety story

**Stage 1 — RECOVER.** On a write failure the sink is rolled: the broken file is renamed aside
(`<name>.broken-<UTC>-<n>`, preserving it as evidence), a fresh file is opened at the live path, the
**rollover event is recorded into it**, and the record whose write failed is **re-written** rather
than lost. A transient — a momentary lock, an antivirus scan, a rotation race — heals here and stops
nothing.

**Stage 2 — STOP.** Only when the **replacement** also cannot be written does the guard escalate —
and the stop is asked for only when **every** guarded sink is unwritable.

That last clause is a correctness point rather than a softening. The ruling is *"we never want to
process stuff if the processing cannot be logged"*, so the question the halt must answer is **"can
this process still log?"**, not "did a sink break?". With `[logging].file` configured there are two
sinks; one dying while the other keeps accepting every record means the processing **is** still
logged, and halting there is a control resting on a false premise. With one sink — the default,
stdout-only — the two questions coincide and the halt fires exactly as it did. Detection, the alert
and `GET /status` are **unconditional**: only the enforcement is conditioned on the thing the
enforcement is about.

These do not collapse into one. A single-stage stop takes feeds down on a hiccup, which is an outage
generator rather than an enforced invariant. The load-bearing detail is *how* stage 1 decides it
succeeded: it does not assume a fresh file is writable, it **writes to it** — the notice, then the
failed record — and lets the exception propagate. "Is the replacement writable?" is answered by
writing, which is the only answer that cannot be wrong.

**Stage 1 is bounded**, because *heals* and *keeps needing to be healed* are not the same sink. A
sink that accepts the notice and the re-written record and then fails again on the next record would
otherwise roll forever — one rename, one fresh file and one page per log line. Past 5 rolls in 60
seconds the sink is declared unwritable instead; a log you must replace every few seconds is not a
working log. The window is loose enough that a real transient never reaches it, which a paired test
pins from both sides.

### 2 — `logging.Handler.handleError` is the detection seam

`emit()` calls `handleError(record)` on any exception, in both `StreamHandler` and `FileHandler`, so
one override covers every sink and every failure mode the OS can produce (`ENOSPC`, a yanked handle, a
failed rotation) without the engine polling anything. A per-thread re-entrancy latch makes a failure
*while handling a failure* return immediately instead of recursing, and the recovery writes go
**directly** to the stream rather than through `emit`, because an `emit` failure would re-enter
`handleError` and be swallowed by that latch — hiding the very stage 2 it exists to detect.

**The override deliberately ignores `logging.raiseExceptions`.** The stdlib `handleError` is a
complete no-op when that process-global is False; a fail-closed control whose enforcement can be
switched off by an ambient setting the engine does not own is not a control. A test drives the whole
stage-1 path under `raiseExceptions = False`, and a paired test shows the handler this replaces
reports **nothing at all** under the same value — so the pin is load-bearing rather than decorative.

### 3 — An opt-in engine-managed file, because stage 1 needs a file the engine owns

Rolling requires a file the engine may rename. It must never be NSSM's. So `[logging].file` is a
**second, opt-in** sink the engine owns end to end — it opens it, size-rotates it (`file_max_bytes` /
`file_backup_count`, stdlib `RotatingFileHandler`) and rolls it aside on failure — and the settings
validator **refuses a `file` inside `[logging].log_dir`**, which is the supervisor's rotation
territory. One file, one rotation owner; see section 6 and `docs/SERVICE.md`.

The **stdout** sink is guarded too, and its stage 1 is necessarily different: the engine did not open
the file behind stdout and must not rename a supervisor's file out from under it, so the roll is a
**re-resolve** — rebind to whatever `sys.stdout` is *now*, and write the notice and the failed record
to that.

**It was originally a bare re-attempt on the same object, and that made the DEFAULT sink a hair
trigger on the halt.** A handler holds the stream object it was constructed with. When a supervisor
swaps the capture file that object is closed, and every later write raises — *including stage 1's own
notice write* — so stage 1 failed by construction and **every** stdout write failure escalated
straight to stage 2. Measured in the full test suite: a stream swap halted a running load engine's
seven connections and the run sent zero messages. In production the same shape is an NSSM
capture-file swap or a closed pipe: routine events that must not take feeds down. Re-resolving is
what "a re-attempt clears the transient" was always claiming to do — the replacement handle is the
live one. If `sys.stdout` is itself gone, the notice write raises and stage 2 fires with exactly the
fail-closed meaning it should have. A paired test pins both directions.

A path the engine cannot open **refuses startup** (`serve` exits 2 with the reason on stderr).
Starting an engine that cannot log is the silent blindness this item exists to end, so the
fail-closed posture is applied at configuration time as well as at runtime.

### 4 — The stop's scope is the PROCESS, and pretending otherwise would be a lie

BACKLOG #122 says "stop the affected connection". **"Affected" resolves to every connection this
process owns, and the honest answer is that it cannot be narrowed further.** The application log is a
process-global handler set on the root logger; a write failure is a property of the **sink**, and no
per-connection attribution exists anywhere in the record to narrow it with. On a single-process engine
that is all connections. Under **engine sharding** (ADR 0037) each shard is its own process with its
own handlers, so a log failure on one shard stops that shard's connections and leaves its siblings
running — the narrowest honest scope available, and a property of the deployment topology rather than
of this design.

"Stop" means **all three tiers**, because count-and-log counts all three: every inbound is
**stopped** (the listener unbinds; intake ceases), every inbound's **internal stages** are halted
(router, transform, and a loopback's response re-ingress), and every owned outbound is **paused**
(`stop_outbound`, which **retains** its queued rows PENDING and un-errored rather than
dead-lettering them). Delivering a message you cannot log is as much a violation as accepting one,
and so is routing or transforming it.

**The middle tier is the one that is easy to miss, and it was missed.** Stopping the listener stops
*new* arrivals only. The router and transform workers are registry-tied, not source-tied, and
`stop_inbound` is documented as halting intake *while delivery keeps draining* — so a message already
durably committed to the ingress stage kept flowing ingress → routed → outbound with no application
log behind it. Measured on a running engine with a genuinely unwritable sink: the committed row
reached the **outbound** stage after the halt and was held there only by the outbound pause. That is
processing something that cannot be logged; the pause merely made it quiet. The halt therefore also
shuts the internal stages down, **cooperatively and never by `task.cancel`** (a cancelled mid-item
worker strands its claimed row INFLIGHT, and `reset_stale_inflight` is startup/DR-only): under the
default pooled claim mode by `pause_lane` on each stage dispatcher, under `per_lane` by a loop-top
gate that returns out of the worker before its next claim. A lane already mid-episode finishes **at
most its one in-flight head** — bounded, and strictly better than stranding the row.
*(Note, BACKLOG #5704: superseded in mechanism. The internal stages are now held by a claim gate,
`_inbound_log_halted`, which reads the latch and the per-inbound marks: per_lane workers WAIT at
their loop top rather than returning, and a pooled lane parks before its claim, touching no
row, until the gate lifts. A per_lane router or transform worker still finishes a batch it had
already claimed, so for those lanes the one-head bound above holds under per_lane only at
`fifo_claim_batch = 1`; the response worker claims one row at a time. The halt pauses no internal lane, and STOPs one only through its hand-back of a prefix claimed before the gate shut (on leadership loss, or at T17); a lane can still STOP for other causes, at least under its own fault policy. ADR 0189's note says the rest.)*

**Recovery, measured rather than assumed — the two tiers recover differently and an operator needs
both halves.** The inbound re-arm rides `_start_inbound_unsafe`, so **anything that starts an inbound
re-arms it**: `restart_inbound` for one connection, and a `/config/reload` for every inbound it
re-binds (reload quiesces every source and re-binds from the new graph). The inbounds a reload
declines to bind — `deployed=False`, `auto_start=False` and not previously listening, DR-filtered —
stay halted, as do the connections a per-connection restart does not name. *(Note, BACKLOG #5704:
under the pooled claim mode a router, transform or response lane that is STOPPED at a
per-connection restart of its inbound is re-armed by it and its hold released, except a lane that
STOPPED holding claimed rows whose re-pend never landed, which stays STOPPED with a WARNING.)*
The outbound **pause is
operator-owned in both cases** (#115/#233: a reload never resumes a lane an operator has not looked
at), so delivery needs an explicit `start_outbound` or a service restart either way. Stated the other
way round: *a reload alone will not drain the backlog*, and a test pins exactly that — after a reload
the row moves to the outbound stage and stops there.

**Every one of those recovery paths is CONDITIONED ON THE LOG WORKING AGAIN, and that condition is
the other half of the enforcement.** Recovery is an operator assertion — *"I fixed the disk"* — and a
fail-closed control that simply believes it is a control with an off switch. This was a **measured**
hole, not a hypothetical: with the halt firing correctly, `restart_inbound` + `start_outbound` re-armed
the whole pipeline while the guard's own state still read `{'file': 'unwritable', 'stdout':
'unwritable'}`, and the message ran to `PROCESSED` with no application log behind it, in both claim
modes. It was also unrecoverable by construction — `_log_write_stopped` and the guard's per-sink
`already_down` latch are both one-shot, so after that first restart nothing in the process could ever
fail-closed again. So `restart_inbound`, `start_outbound` and a reload's re-bind all pass through
`_log_recovery_ok`, which asks the guard to **re-validate its dead sinks by writing a real record to
each**, and a process that still cannot log **stays halted** — the inbound is not re-armed and its
listener is stopped again rather than left accepting into a lane nothing drains. The refusal is
announced on `log_write_failed` (the log is the broken thing, so it cannot be a log line) and it is
**not a raise**: `reload()` rolls the whole graph back on an exception from that path, and one
unwritable log must not turn a routine reload into a full intake rollback.

Re-validation is **not** the timer polling rejected in section 7. It runs once, on an explicit
operator recovery action, at the moment the decision is made — never on a schedule, never on the hot
path. It has to write rather than read, because `unwritable` is only ever set by a failed write and
nothing clears it on its own: *"repaired"* and *"still broken"* are **identical in memory**, which is
exactly the distinction recovery has to make. The probe rolls the sink first when its live handle is
stale — a repaired directory does not un-close a file object — so "writable" means *a record landed*.
A successful re-validation clears both latches, which matters as much as the refusal: otherwise a
genuine second break, later, would halt nothing.

### 5 — The stop is observable, on channels that do not depend on the broken log

A connection that stops silently is a worse failure than the one being prevented, and the obvious
channel is the one that just broke. So there are three, in decreasing dependence on the failure:

1. **`log_write_failed`** — a new `AlertSink` event routed through the **notifier** (email/webhook),
   which does not go through the application log, carrying the sink, the stage, a `safe_exc` reason
   and the number of connections stopped. It is emitted **before** the stop, so a wedged stop still
   leaves the operator told. It fires on stage 1 as well: a sink that rolls repeatedly is a disk
   about to become stage 2.
2. **`connection_stopped`, per stopped connection** — ADR 0014 already has this rule, and #122's own
   *nearest existing mechanism* note says it "reports a stop but is not driven by a log-write
   failure". It is now driven by one, with the cause in the `detail`, so alert rules, ADR 0044
   durable alert state and the console's stopped view all behave normally and name the reason.
3. **`GET /status.log_sinks`** — per-sink state, rollover count, scrubbed last reason and the path the
   broken file went to. Read from **process memory**, so unlike the `logs` byte metering beside it, it
   cannot be defeated by the unwritable directory it is reporting on, and it still answers when no
   notifier is configured.

A fourth exists only as a floor: one PHI-free line on **stderr**, written directly rather than through
`logging`, because re-entering the logging tree is how a broken sink becomes an infinite loop.

### 6 — What this means for NSSM (there is still exactly one rotation owner per file)

Unchanged by default: NSSM captures the engine's stdout/stderr and rotates those files, and
`[logging].log_dir` keeps pointing at them for #50's metering, #120's retention and the `/logs/tail`
viewer. If an operator sets `[logging].file`, the **engine** owns that file's whole lifecycle and NSSM
must not be pointed at it — enforced by the validator, not left to documentation. `docs/SERVICE.md`
carries the operator-facing statement of which side owns what.

`*.broken-*` files are deliberately **outside** the size-rotation backup chain: they are incident
evidence, and a rotation policy that could delete them would delete the record of the failure. They
are the operator's to review and remove.

### 7 — ACK-on-receipt is preserved, and the boundary is stated in the code

The **message store** (SQLite/SQL Server/Postgres) and the **application log** are different durable
records, and the two are easy to conflate — hence this clause. An application-log failure is not a
store failure, and the guard performs **no store I/O at all**. A message already committed to the
ingress stage was ACKed on receipt; stopping its inbound unbinds the listener and touches no row, and
pausing an outbound retains its rows PENDING un-errored. Nothing is un-ACKed, lost, or double-
delivered — fix the disk, reload, and the backlog drains, with at least these qualifications
(BACKLOG #5704). Under the pooled claim mode, a router, transform or response lane that STOPPED
while holding claimed rows whose re-pend never landed is not re-armed by the lift of the halt,
which logs a WARNING. Any later `notify_work` broadcast re-arms such a lane, at least a reload, a
replay, a resend, an inject or a dead-letter replay, and it can then claim past the unlanded rows;
until one arrives it stays STOPPED. At least a service restart returns its rows to the queue first. Under per_lane, a worker that a content STOP ended during the halt
is respawned by the reload or restart that lifts its inbound's gate, and it retries that STOP's row.
**Fix the disk first**: the reload re-arms
only once the log accepts a record again (section 4), so on a still-broken disk the rows simply stay
where the halt left them. A test asserts store stats are byte-identical across a stage-2 halt and that
the committed ingress row is still claimable afterwards.

### 8 — No PHI on the error path

The stdlib `handleError` writes a traceback, the call stack and `Message: %r` / `Arguments: %s` — the
failing record's content — to stderr, **below the handler's filter chain**. The override writes **no
record content to the last-resort channel at all**: only the sink label and a `safe_exc` reason. The
one place a record is rendered is the stage-1 re-write, via `self.format(record)` on a record the
handler's `RedactionFilter` chain has already mutated in place, onto the sink's own stream — the same
text the sink would have written had it not failed. Nothing here raises the service to DEBUG.

## Alternatives rejected

- **A single-stage stop.** Simpler, and wrong: it converts every transient lock into a feed outage.
  The two-stage split is what makes this an enforced invariant rather than an outage generator.
- **Reuse `connection_stopped` alone and add no event.** It reports *that* a lane stopped, not that
  the engine went deaf, and an operator cannot route the two differently. Both are emitted instead.
- **Guard stdout only, and skip the engine-managed file.** No file the engine may rename means no
  stage 1, which collapses the design into the single-stage stop rejected above.
- **Let the engine rotate NSSM's captured stdout files so no new sink is needed.** Two rotation
  owners on one file is how a log gets shredded, and the loser of that race is the log an operator
  reads after an incident.
- **Poll the log file's writability on a timer.** Detects late, costs I/O per tick, and still misses
  the failure it is meant to catch (a probe write can succeed while the record write fails).
  `handleError` observes the actual failure.
- **Guard `configure_stderr_logging` too** (the ADR 0087 sandbox worker). Left alone deliberately: it
  is a child process whose only sink **is** the last-resort channel, with no second sink to roll to
  and no connection to stop.
- **Detect a *corrupted but still writable* log.** BACKLOG #122's scope line says "corrupted or
  unwritable", and this ADR covers only the second. Deliberate, and the boundary is worth stating
  rather than blurring: the item's own **trigger** is a log that "silently stops recording engine
  activity", and a file that still accepts writes is still recording. Detecting corruption means
  reading the log back — a PHI read of the one artifact §8 exists to keep record content out of, on
  the hot path, to catch a condition with no defined signature. If a corrupted file ever *does* refuse
  a write, `handleError` sees it like any other failure.
- **Cancel the router/transform tasks instead of gating them.** Faster to write and wrong: a
  cancelled worker mid-item strands its claimed row INFLIGHT, and `reset_stale_inflight` only runs at
  startup/DR — so the fail-closed halt would create the strand that count-and-log forbids. The
  cooperative pause/gate costs at most one already-claimed head.
- **Halt the whole engine rather than its connections.** Exceeds the item's scope and destroys the
  operator's ability to read `/status` and the alert state — the surfaces section 5 relies on to
  explain the halt.

## Consequences

- **Positive.** The count-and-log invariant is now enforced on the application log, not merely
  observable. A transient self-heals with the evidence preserved and the failed record re-written. A
  genuine failure stops intake, the internal routing/transform stages, and delivery; pages on channels
  independent of the failure; and leaves the store untouched. The stdlib error path's
  record-content-to-stderr write is gone, as is its silence under `raiseExceptions = False`.
- **The enforcement is tested end to end, over a genuinely unwritable sink, in both claim modes.** A
  test breaks the real file handle, replaces the log's parent directory with a regular file so the
  roll cannot succeed either, and then asserts that a row committed to the ingress stage is still
  `RECEIVED` with no outbound rows — paired with a negative control on the same rig that shows the row
  *is* processed when the log is healthy, and a recovery test that shows the restart drains it. Each
  of the two halting mechanisms was individually disabled and the matching arm confirmed to fail.
- **The refusal to un-halt is tested the same way, and the recovery tests earn their re-arm.** A
  paired test restarts both tiers with the sinks still dead and asserts the inbound stays halted, its
  listener stays down and the row stays `RECEIVED` — then repairs the log, reissues the *same* two
  calls, and watches it drain, so the test cannot pass against an engine that merely never restarts
  anything. The recovery tests now repair the log before restarting; previously they did not, which is
  how the hole shipped looking green. The gate was disabled and that arm confirmed to fail.
- **Negative, and worth naming.** A stage-2 halt is process-wide (section 4) — a single unwritable
  sink stops every connection this process owns, which is the point of the ruling but is a bigger
  blast radius than "the affected connection" first suggests; `[logging].on_write_failure =
  "continue"` is the documented opt-out. `*.broken-*` files accumulate until an operator removes
  them. The stop is not self-healing: it re-arms on reload/restart, deliberately, so a flapping disk
  cannot flap the feeds — and the re-arm is refused while the log is still unwritable, so "restart it
  again" is not a way around the control.

## Amendment A (2026-09-14) — restored to the repository, and two enumerations that no longer hold

**This document was never merged, and the code it describes shipped without it.** Everything above
this heading is the 2026-08-10 decision as written, unedited. It is reproduced rather than rewritten
because an ADR is a dated decision record: a stale one is worse than a missing one only when it is
silently corrected, and correcting it in place would destroy the evidence of what was decided when.

**The measurement that found it.** On `main` at `1aa2d6a1b`, "ADR 0162" was cited **41 times across
15 files** — 12 in [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)
alone, 5 in [`config/settings.py`](../../messagefoundry/config/settings.py), and 7 in the
operator-facing [`docs/CONFIGURATION.md`](../CONFIGURATION.md), [`docs/PHI.md`](../PHI.md) and
[`docs/SERVICE.md`](../SERVICE.md) — while `docs/adr/0162-*.md` did not exist and
[`docs/adr/README.md`](README.md) carried no row for it. Nothing reported this: the citations are
bare numbers rather than relative links, so no rendered link resolves to a 404 and no gate reds. A
reader following "ADR 0162 section 4" found nothing. The only surviving copy was on an unmerged
branch whose tip is `46b3a4437b7d64053851a0787911f861e3127fdb` (2026-08-11), which never had a pull
request. The file also gained the SPDX header every ADR from 0159 onward carries; no gate checks
Markdown for one, so this matches the convention rather than satisfying a check.

**What was re-verified against the shipped code, and held.** At least: the two-stage split and the
anti-flap bound (`_MAX_ROLLS_PER_WINDOW = 5` inside `_ROLL_FLAP_WINDOW_SECONDS = 60.0`); the
`<name>.broken-<UTC>-<n>` rename; `handleError` as the detection seam, with the per-thread re-entrancy
latch and the deliberate disregard of `logging.raiseExceptions`; the stdout roll as a **re-resolve**
rather than a rename; the settings surface (`[logging].file` unset by default, `file_max_bytes`,
`file_backup_count`, `on_write_failure` defaulting to `stop`) and the validator that refuses a `file`
inside `log_dir`; the process scope of the stop and its three tiers; `revalidate()` answering by
writing a real record; `GET /status.log_sinks`; the `log_write_failed` payload; and no store I/O on
the guard path. [`logging_guard.py`](../../messagefoundry/logging_guard.py) is byte-identical to its
state on that branch apart from the copyright-holder rename, so sections 1, 2, 5, 7 and 8 describe
the shipped module exactly.

**What no longer holds — section 4's re-arm list is now incomplete, and it reads as complete.**
Section 4 says *"`restart_inbound`, `start_outbound` and a reload's re-bind all pass through
`_log_recovery_ok`"*. The shipped runner routes **`start_outbound` and `restart_outbound`** through
one shared helper, `_outbound_start_permitted`, which did not exist when this was written — on the
branch above, `restart_outbound` called `_start_outbound_unsafe` straight through and would have
resumed a log-halted lane. That helper's own docstring states, correctly, that it is **not** a claim
that nothing else can resume delivery: `start`'s own outbound spawn does not pass through it, and
that is recorded as an open gap rather than an exemption. **Read section 4's three-item list as "at
least these", never as the set** — an enumeration in a security control is the liability SDS-3.6
names, and this one has already been overtaken once.

**What no longer holds — section 3 describes one startup posture and there are two.** *"A path the
engine cannot open refuses startup (`serve` exits 2 with the reason on stderr)"* still holds exactly,
in [`__main__.py`](../../messagefoundry/__main__.py). It is not the whole of startup: a runner that
comes up into a log that opens but is **unwritable** does not refuse to start. It runs **halted** —
`_unbind_for_log_failure` takes intake back down after the dispatchers exist, and pages through the
notifier saying so. That path is also absent from the branch above. The two are different conditions
with different answers, and section 3 covers only the first.

**Smaller, and noted so a citation does not dangle.** `config/settings.py` refuses the legacy
`[logging].max_bytes` / `[logging].backups` spellings and cites this ADR in the refusal text; nothing
in the decision above mentions them.

**Neither drift reverses the decision.** Both are the enforcement being widened in this ADR's own
direction — one more door gated, one more startup condition covered — which is why the document is
restored rather than superseded.

**No landing dates are claimed for any of the above.** This clone is shallow, so `git log -S` dates a
change at the graft boundary rather than at its commit. The instrument here was a content comparison
between `46b3a4437b7d64053851a0787911f861e3127fdb` and `main` at `1aa2d6a1b`, which establishes *that*
these moved and not *when*.

## Amendment B (2026-11-14) — section 1: a flap latch beside the stage-1 bound (BACKLOG #5812)

**Section 1 above is unedited, and its bound runs as before.** Past 5 rolls in 60 seconds, counted
from the first roll of the window, the sink is declared unwritable, as before this amendment.
Amendment A's statement that section 1 describes the shipped module exactly stops being
true here: section 1 does not describe the latch below.

**What was wrong.** The roll that trips the bound wrote the sink's state as `rolled` and only then
escalated, so for that interval another thread read the sink as writable. And the bound's window
restarts a minute after its first roll, so a sink still rolling every few seconds read `rolled`
again, and `can_log()` read True with no probe, until the bound tripped again.

**The latch, as built in [`logging_guard.py`](../../messagefoundry/logging_guard.py).** It is an
overlay in its own field, `_flap_latch`, holding a `time.monotonic()` reading per held sink, and never in the
bound's `_roll_flap`. `LogWriteGuard.record_rollover`'s docstring states the rule; in short:

- The roll that trips the bound latches the sink, in the same hold of the guard's lock that writes the
  bound's state.
- A later roll keeps the latch while it comes within 60 seconds of the sink's last roll or stage-2
  failure, and the first roll after a longer gap releases it. A stage-2 failure refreshes that clock
  but never starts a latch: a sink stage 2 alone declared dead is not latched.
- `status()` and `can_log()` read a sink unwritable when its own state or the latch says so. On
  `GET /status` the latch changes only the `state` field. The cause, the rolled-aside path and the
  roll count are what the guard records with or without it. At least the runner's halt pages also
  read `status()`, so a page that lists the unwritable sinks can name a latched one too.

**What `revalidate()`, the stage-2 events and the stage-2 stderr line do with the latch is in
Amendment C**, which replaces what this amendment said about them. The latch never writes to, rolls
or probes a sink, and the stop decision does not read it.

**How far "never weaker than section 1" was checked, and no further.** A side-by-side fuzz ran this
guard beside `main`'s `logging_guard.py` (checked byte-identical to `origin/main` at the run) under a
fake clock. Five configurations drive the guard directly: random rolls, stage-2 failures,
`record_healthy` calls where `main` would probe, `revalidate()` with probe outcomes drawn once per
step and shared, and runner restarts (escalation re-wired, then `revalidate()`), on one and two
sinks, one of them with a probe-less sink and the `continue` policy. Two more drive each module's
real `handleError` and probe over a fake stream whose write and roll faults are shared by both
guards, so a write that heals a handle or takes a fault shows up as a later difference. At every
step it compared the reported state, `can_log()`, the `revalidate()` answer, every
stage-1 and stage-2 event, stop requests, the `/status` fields other than `state`, and the bound's own
`_sinks` and `_roll_flap`. Over 8 seeds and those 7 configurations it found no step where `main` was
stricter. It did find such steps on the previous attempt at this item, including a `revalidate()`
that reset the bound, and, through the real-handler configurations, on a draft of this one that
gave a latch-only sink the rolling probe. That is a sampled search over a fake clock and a fake
stream, not a proof, and it does not model threads.
[`tests/test_log_write_guard.py`](../../tests/test_log_write_guard.py) pins the cases by name, among
them a revalidate between two flaps that must still stop at the moment `main` stops, and two
revalidates on real handlers that must neither heal a broken handle nor take a one-shot fault.

## Amendment C (2026-11-17) -- rolls past the bound, owed stage-2 events, and unformattable records (BACKLOG #5812, #5813)

**Amendment A is unedited. Amendment B points here for what `revalidate()`, the stage-2 events and
the stage-2 stderr line do with its latch. Where this amendment disagrees with either, it is the
newer text.**

**Rolls past the bound, and stage-2 events that were not delivered.** Before this amendment
every roll past section 1's bound wrote the sink's state as `rolled` before escalating, so for
that interval another thread could read the sink as writable. Now a roll past the bound on a sink
already unwritable keeps it unwritable, and still fires a stage-2 event and the stderr line, as
`main` does. The row's *one page per break* clause is therefore not closed for these rolls. A
stage-2 event that was not delivered is now owed and fired again later;
`LogWriteGuard.record_unwritable`'s docstring says when. A responder that raises on a stage-2 event
gets a stderr line saying so once per break of the sink and responder, not once per event
fired again.

**The stage-2 stderr line.** Where every other sink reads unwritable but at least one only through
the flap latch, the line now says so, instead of saying another sink is still writable.
The stop decision is unchanged.

**`revalidate()` and the flap latch.** `revalidate()` releases the latch, without writing to the
sink, on each sink whose own state was not `unwritable` at its snapshot. On a sink whose own state
is `unwritable`, the latch goes only through `record_healthy`, after a probe that landed: any write
to a sink the latch alone holds would make the guard weaker than the bound alone. `revalidate()`
probes a sink only if nothing was recorded on it since its snapshot, and marks it healthy only if
nothing was recorded on it by the time its probe ends. The guard's lock is not held across the probe's write.
Its answer is now `can_log()`'s, read under the lock after the probes, so it reads the flap latch.

**A record that cannot be formatted is not a sink failure** (BACKLOG #5813). On `main`,
`handleError` rolls the sink on any failure, so a record its formatter refuses rolls the sink, and
the re-write, which formats the same record, fails too, so the record always reaches stage 2. Now the guard writes in the record's
place a fixed notice naming the record's logger, its level and the exception's type, where the
formatter can format that notice. When the sink takes the notice, neither stage runs and the
engine keeps processing. **The fault is reported on the stderr last-resort line only, at a bounded
rate: no alert is raised and nothing shows on `GET /status`.** This is weaker than `main`, where
such a record went to stage 2. Keeping it was decided by the Manager under the owner's
delegation of 2026-11-17 (decision d20261118T002722950-fa0f70). An alert and a
`/status` signal for it are not built. When the sink refuses the notice, the two stages decide, as
for any write failure. When the formatter cannot format the notice either, the sink is recorded
unwritable with a reason that names a formatter fault, and the file is not rolled or renamed;
stage 2 then decides the stop as for any other stage-2 failure. A record that formats but holds a
character a strict stream has no byte for raised `UnicodeEncodeError` from the write and went to
stage 2 on `main` the same way when the re-resolved stream was the same one. `serve` sets stdout
and stderr to replace such a character with `?` where the stream allows it
(`console_streams.harden_console_streams`), so the service's stdout writes `?` and does not reach
this; a stream left strict does, at least one a caller of `configure_logging` did not harden or one
whose reconfigure was refused. Now the line is written again with each such character as a JSON
`\uXXXX` escape, so its text is kept, and the fault is counted on the same stderr line; a sink
that refuses the escaped line too takes the two stages, and the line a roll re-writes is escaped
for the stream the roll left. `_GuardedSinkMixin.handleError` and `_report_format_faults` in
`logging_guard.py` say what is counted and when the stderr line is written.

**Part of the side-by-side check is now committed.**
`test_the_latch_never_makes_the_guard_less_strict_than_the_bound_alone` runs seeded random steps on
two guards, one with the latch switched off, and compares their events, recorded states, bound and
`revalidate()` answers. It drives the guard directly, not real handlers, and it does not model
threads.
