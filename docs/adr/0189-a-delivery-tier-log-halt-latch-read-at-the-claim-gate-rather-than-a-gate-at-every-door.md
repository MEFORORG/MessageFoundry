# ADR 0189 — A delivery-tier log-halt latch, read at the claim gate rather than a gate at every door

- **Status:** **Accepted -- BUILT** with the change.
  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-09-15
- **Related:** [ADR 0162](0162-fail-closed-application-log-write-guard-detect-roll-and-stop.md)
  (the fail-closed log-write guard this extends) · [ADR 0066](0066-pooled-stage-claimers.md)
  (the pooled claim path one half of the gate lives on) ·
  [ADR 0070](0070-t17-infra-fault-bound.md) (the reschedule-not-fail reasoning
  the pooled half reuses) · [CLAUDE.md](../../CLAUDE.md) section 2 (count-and-log) and section 11
  (SDS-3.5, SDS-3.6) · BACKLOG #122

---

## Context

CLAUDE.md section 2 states the invariant this whole area exists to keep:

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK**
> (status `RECEIVED` at the ingress stage), so inbound counts still reflect the true received volume
> and nothing is accepted-and-dropped.

and section 1 states its egress half:

> **Every message a connection takes in or puts out is counted and logged** -- nothing is silently
> dropped.

ADR 0162 made the engine fail closed when it cannot write its application log. Delivering while
halted would put bytes on a partner's disk with no application log behind them, which is exactly the
violation.

**The two tiers enforce that rule with different shapes, and only one of them holds.**

The **inbound** tier uses a LATCH. `RegistryRunner._log_halted` is set when the halt fires, is not
cleared by `_teardown_body`, and is read at the loop top of `_router_worker`, `_transform_worker`
and `_response_worker` -- before the claim, so no row is left INFLIGHT. One question, asked at the
point every message passes through.

The **delivery** tier had no state of its own. The halt took it down by PAUSING each owned lane
(`_pause_delivery_lanes` routes through `_stop_outbound_unsafe`), which writes into
`_outbound_paused` -- the OPERATOR-pause set. Two properties of that set make it the wrong carrier:

1. `_teardown_body` CLEARS it, deliberately, because an operator pause is in-memory state that must
   not outlive the process's graph.
2. No consumer can tell a halt-pause from an operator pause, because they are the same bit.

So the rule could only be re-asserted at each DOOR into resuming delivery. **Four doors were found,
one at a time, each only after the previous fix shipped:**

| # | Door | Gated by |
|---|---|---|
| 1 | `start_outbound` | gated when `_outbound_start_permitted` was introduced |
| 2 | `restart_outbound` | added later -- it called `_start_outbound_unsafe` straight through |
| 3 | `stop()` + `start()` -- the teardown clears the pause and `start`'s own outbound spawn asked nothing | `_park_delivery_for_log_failure` |
| 4 | a reload's `_unpark_outbound_lane`, lifting an engine-park the halt never touched | `_reconcile_outbounds` asks the same gate |

Each fix was correct. The SHAPE was not. **Four gates are a completeness claim nobody can verify**,
which is the liability CLAUDE.md section 11 names as SDS-3.6 (*prefer "at least" to an
enumeration*). A fifth door would be found the same way the first four were: in behaviour, after
shipping. There is no deployment to have found it in yet (section 0 -- zero production instances),
so the cost so far has been paid in review time rather than in delivered-unlogged messages; that is
the window in which to change the shape, not a reason the shape is fine.

## Decision

**Give the delivery tier its own halt question and read it at the CLAIM GATE -- the point every
delivery passes through regardless of which door started the lane.**

`RegistryRunner._delivery_halted` answers "may this process deliver at all?". It is read at each
claim mode's own choke point, and the two modes are exhaustive by construction (unlike doors, which
are not):

- **per_lane** -- `_delivery_worker`'s loop top, ABOVE the operator-pause gate and BEFORE the claim,
  so the worker returns with no row INFLIGHT. Byte-for-byte the shape of `_router_worker`'s
  `_log_halted` gate. It sits above the pause gate because a halted-and-paused lane must not park in
  `_wait_for_resume`, where a resume would release it straight into a claim.
- **pooled** -- `_dispatch_delivery`, the first runner-owned code a claimed OUTBOUND row reaches and
  upstream of both the plain and the batch send seams. The runner does not own the pooled claim (the
  `StageDispatcher` does, and it is deliberately runner-agnostic), so the gate here is post-claim:
  it `reschedule_claimed`s the head onto a short backoff and returns `RETRY`, parking the lane.

**`_delivery_halted` is DERIVED from `_log_write_stopped`, not a second flag.** "This process cannot
log and has fail-closed" is one load-bearing fact, and `_log_write_stopped` already states it: both
halt sites set it, and the only path that clears it is `_log_recovery_ok`, which re-tests the sinks
by WRITING to them. A parallel boolean set and cleared at the same moments would be state that must
agree with this one, with nothing checking that it does -- SDS-3.5, *state a load-bearing fact once
and link to it*. What the property adds is the NAME and the delivery tier's ownership of the
question, and one inherited property that is the whole point: `_log_write_stopped` is not cleared by
`_teardown_body`, so **the latch survives a teardown**, which is the mechanism behind doors 3 and 4.

**THE FOUR DOOR GATES ARE KEPT.** They are correct, they fail fast at the door, and a refusal there
PAGES through the notifier with the reason (`_log_write_refused_restart`) -- a far better operator
message than a silent refusal at the claim gate. The latch is defence in depth BEHIND them, never
the recovery path: lifting it stays the doors' job, because `_log_recovery_ok` performs a real
re-validation write and one operator action must mean one probe and one page.

**`/connections` now reports the cause.** `outbound_status` returns a new `log_halted` ahead of the
running/stopping/stopped triple, and `outbound_running` is False for every lane while the latch
holds. See *Consequences* for exactly what an operator sees change.

## Acceptance Criteria

- **AC-1** -- WHILE the application log is unwritable and the halt is latched, IF a delivery lane is
  started by a path that passes NONE of the four door gates, THEN THE SYSTEM SHALL deliver no bytes
  to that lane's destination and SHALL retain its queued row PENDING.
  → `tests/test_log_write_guard.py::test_an_unguarded_start_cannot_deliver_while_the_halt_is_latched`
- **AC-2** -- WHEN the sinks are repaired and a gated door is used, THE SYSTEM SHALL clear the latch
  and deliver the same retained row to completion (the control arm, on the identical rig).
  → `tests/test_log_write_guard.py::test_an_unguarded_start_cannot_deliver_while_the_halt_is_latched`
- **AC-3** -- WHILE the halt is latched, THE SYSTEM SHALL report every outbound as `log_halted`
  rather than as running or operator-paused.
  → `tests/test_log_write_guard.py::test_an_unguarded_start_cannot_deliver_while_the_halt_is_latched`
- **AC-4** -- THE SYSTEM SHALL hold AC-1 through AC-3 in BOTH claim modes, which reach the claim by
  different mechanisms.
  → the same test, parametrized over `CLAIM_MODES = ["pooled", "per_lane"]`
- **AC-5** -- WHILE the halt is latched, IF a reload ADDS an outbound connection that is deployed and
  auto-start (door six), THEN THE SYSTEM SHALL leave that lane PAUSED with no engine park marker and
  SHALL deliver none of its queued rows; and WHEN the sinks are repaired and a gated door starts it,
  THE SYSTEM SHALL deliver the same retained row.
  → `tests/test_log_write_guard.py::test_a_reload_that_adds_an_outbound_into_a_dead_log_lands_it_paused`

## Options considered

1. **A tier latch read at each claim mode's choke point.** **CHOSEN.** The number of doors is
   unbounded and grows with the codebase; the number of claim modes is two and is a closed set the
   constructor validates. Moving the question from the doors to the claim makes the guarantee
   structural rather than enumerative.
2. **Gate a fifth door as each is found.** Rejected -- it is the status quo, and the status quo is
   the defect. It also cannot be tested for completeness: a test per known door proves nothing about
   the next one.
3. **A separate `_delivery_halted: bool` field, set and cleared beside `_log_write_stopped`.**
   Rejected -- two booleans that must agree, with no check that they do. SDS-3.5.
4. **A `_delivery_halted: set[str]` of lane names, mirroring `_log_halted`'s per-inbound shape.**
   Rejected, and the reason is measured rather than aesthetic. `_stop_all_for_log_failure` builds its
   pause list as the owned lanes NOT already paused, so a set populated from it would omit exactly
   the engine-parked lane that door 4 is about -- the narrowing bug, reintroduced. A set also cannot
   cover a lane BUILT AFTER the halt (a reload adding an outbound), which is **door six**. That door
   is now gated -- `_reconcile_outbounds` routes an outbound it would bring up while the latch holds
   through `_stop_outbound_unsafe`, so the lane lands in the same paused state as every other one and
   no lane reaches the claim gate on the ordinary halt (see *Negative / risks*). It is gated with a
   STOP and not a park on purpose: `_park_outbound_lane` writes `_gate_parked`, which the door-4 gate
   a few lines above lifts the moment a probe succeeds, so a park would re-open the door one reload
   later off a marker the method wrote itself. Per-lane
   recovery is meaningless here anyway: the broken sink is process-global, so the moment one lane's
   door re-validates it, no lane's halt reason survives -- leaving the others latched on a premise
   just measured false would be the SDS-3.7 shape.
5. **Filter the pooled `lane_provider` so the dispatcher never claims a halted lane.** Rejected as
   the gate, though it would help: `notify_work` unions the provider's answer with the lanes already
   in `_states`, and `mark_ready` from a producer wake arms a lane the provider never returned. It
   is a partial gate that LOOKS total, which is worse than no gate.
6. **Pooled: `mark_failed` the head and return RETRY.** Rejected -- that spends a retry, and under a
   finite `RetryPolicy.max_attempts` it eventually writes terminal DEAD on a row that was never sent.
   A log-write halt is a machinery fault, not the message's; ADR 0070 fix A already settled that
   distinction and `reschedule_claimed` is its primitive.
7. **Pooled: `release_claimed` and return STOP.** Rejected on two counts. A plain release leaves the
   head past-due, so the ~0.25 s sweep re-readies it and the gate re-fires about four times a second
   for as long as the disk stays broken. And `resume_lane` only re-arms a PAUSED lane, so a later
   `start_outbound` could not lift a STOPPED one -- a PARKED lane's own timer unparks it.

## Consequences

**Positive** -- the guarantee stops depending on an enumeration. The test that carries it
(`test_an_unguarded_start_cannot_deliver_while_the_halt_is_latched`) deliberately uses none of the
four doors: it drives `_start_outbound_unsafe` directly, as a stand-in for the fifth door whatever it
turns out to be, and asserts on BYTES -- `list(outdir.iterdir())` over a real File connector draining
a real store. It was measured RED on `main` in both claim modes before the latch existed: the queued
row was written to `outdir` while `guard.can_log()` read False throughout.

The gate also fires EARLIER than the pause does. `_stop_all_for_log_failure` sets the latch, then
awaits the reload lock before pausing the lanes; delivery was permitted in that window and now is
not.

**What an operator sees change.** A lane the halt took down used to read `stopped` on `/connections`
and in the flow graph, because the halt takes a lane down by pausing it and a pause is what an
operator does. That told an operator the lane was waiting for them to press start, when what it was
waiting for was a writable disk. It now reads `log_halted`, in the BAD colour rather than the muted
grey of "stopped", and `outbound_running` is False for it -- so `/stats`' running/stopped split
counts a halted lane as not running. A lane an unguarded path brought up used to read `running`,
since it is not in `_outbound_paused`, while the claim gate refused every one of its rows; it now
reads `log_halted` too. Three things are deliberately NOT collapsed into the new state:
`not_deployed`, `failed` and `filtered` still outrank it on the display ladder, because those are
per-connection facts an operator fixes on that row, while the halt is process-wide and already has
its own page. `outbound_quiesced` -- the purge precondition -- still answers off the pause set, so a
halted-and-quiesced lane stays purgeable.

**Negative / risks** -- the pooled half is post-claim, so a halted pooled lane that some path readies
will claim a head, reschedule it, and park, once per `_WORKER_ERROR_BACKOFF_SECONDS`, for as long as
the disk stays broken. The claim's `attempts` increment is undone by the reschedule, so the retry
ledger and the poison ceiling are untouched.

**What one of those cycles costs, measured against the SQLite store rather than estimated.** It is
**two write transactions and a payload decrypt per lane per second**, not one round-trip.
`claim_fifo_heads` takes the process-wide `self._lock` and runs a `SELECT`, an `UPDATE` to
`inflight` with `attempts+1`, a re-`SELECT` for the post-increment `attempts`, and a
`delivered_keys` probe, then commits **once for the whole lane chunk** -- so that half is amortized
across up to `_FIFO_HEADS_LANE_CHUNK` lanes. Off the lock, `_outbox_item_from_row` **decrypts** the
row's payload wherever at-rest encryption is on (and dereferences `shared_body` first if the row
carries a `body_ref`). Then `reschedule_claimed` takes `self._lock` again for its own `UPDATE` and
its **own commit, amortized across nothing** -- the gate calls it with one id, for one lane.

That lock is the same one `enqueue_ingress` and every stage handoff serialize behind (both reach it
through `_writer_txn`, whether or not the ADR 0055 group-committer is enabled), so the cost is not
confined to a tier that is already refusing to work: a halted lane's cycle contends with intake and
with routing/transform handoffs on the one writer. It is still bounded and it is still the price of
the dispatcher staying runner-agnostic -- but *"a bounded store round-trip per lane per second"*,
which this paragraph replaces, understated it, and it is the kind of sentence a later reader cites
as a measurement.

**The lane population that pays it should now be zero**, which is what makes the cost tolerable
rather than merely bounded: the halt pauses every owned outbound through `_stop_outbound_unsafe`, a
PAUSED lane is never claimed, and the one path that could still bring an unpaused lane up while the
latch held -- a reload ADDING an outbound, option 4's door six -- is gated in
`_reconcile_outbounds`. A non-zero count here means a door is missing.

`log_halted` is a NEW status string on a free-form `str` field. Any consumer that switch-matched the
old vocabulary sees an unknown value. There are no deployments to migrate (section 0), and the
console derives its CSS class from the raw string, so the new state needed one rule per surface
rather than a mapping.

**Out of scope** -- the INBOUND tier is unchanged; `_log_halted` keeps its per-inbound shape because
its re-arm genuinely is per-connection. Whether the door gates could now be simplified is left alone
on purpose: removing working gates in the same change would make a regression unattributable.
