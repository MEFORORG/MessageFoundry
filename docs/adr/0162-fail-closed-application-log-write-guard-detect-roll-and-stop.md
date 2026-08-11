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

**Recovery, measured rather than assumed — the two tiers recover differently and an operator needs
both halves.** The inbound re-arm rides `_start_inbound_unsafe`, so **anything that starts an inbound
re-arms it**: `restart_inbound` for one connection, and a `/config/reload` for every inbound it
re-binds (reload quiesces every source and re-binds from the new graph). The inbounds a reload
declines to bind — `deployed=False`, `auto_start=False` and not previously listening, DR-filtered —
stay halted, as do the connections a per-connection restart does not name. The outbound **pause is
operator-owned in both cases** (#115/#233: a reload never resumes a lane an operator has not looked
at), so delivery needs an explicit `start_outbound` or a service restart either way. Stated the other
way round: *a reload alone will not drain the backlog*, and a test pins exactly that — after a reload
the row moves to the outbound stage and stops there.

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
delivered — fix the disk, reload, and the backlog drains. A test asserts store stats are byte-
identical across a stage-2 halt and that the committed ingress row is still claimable afterwards.

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
- **Negative, and worth naming.** A stage-2 halt is process-wide (section 4) — a single unwritable
  sink stops every connection this process owns, which is the point of the ruling but is a bigger
  blast radius than "the affected connection" first suggests; `[logging].on_write_failure =
  "continue"` is the documented opt-out. `*.broken-*` files accumulate until an operator removes
  them. The stop is not self-healing: it re-arms on reload/restart, deliberately, so a flapping disk
  cannot flap the feeds.
