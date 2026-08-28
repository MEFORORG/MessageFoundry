# 0179 — Front-loaded, time-amortised subtree re-resolution in the connscale FD probe

- **Status:** Accepted
- **Date:** 2026-08-28
- **Related:** BACKLOG #1357 · #1278 (the resource question this holds) · #1210 (the walk's provenance check) · #220 (the PID-set CPU gate) · [ADR 0037](0037-multi-process-sharding-l3.md) · `harness/load/connscale/probe.py`

---

## Context

`FdSampler` sums the engine's handle count, CPU-seconds and working set across the engine's process
**subtree**. It resolves that subtree with a process-table walk, caches the result, and re-walks
periodically so a late-spawned worker joins the sum. A3 added the periodic re-walk; before it the
subtree was resolved exactly once.

The re-walk was gated on a **tick count**: `_RESOLVE_EVERY_TICKS = 8`. Its own comment reasoned about
that number in seconds -- *"at the runner's poll cadence this re-checks the topology every few
seconds."*

**A tick is not the poll interval.** A tick is the poll interval plus the probe's own shell-out: a
process-table walk and a per-PID read. Measured on the maintainer's box, one tick cost 0.21-1.19 s
against a 0.25 s interval, so a tick ran 3-5 times the unit the constant was reasoned in.

The consequence is arithmetic, not statistical. A real `run_connscale` sweep at the CI cell's cadence
(`tests/test_connscale_smoke.py`, `hold_seconds = 1.5`, `poll_interval_s = 0.25`) reported
`fd_probe_ticks = 2` on **all four** of its steps, against the 8 the gate needed. Zero of four steps
could re-resolve. A hold ladder on the same rig confirmed the shape rather than reporting a constant
regardless of input: hold 1.5 gave 0 re-resolutions, hold 3.0 gave 0, hold 6.0 gave 1. Both shipped
smoke profiles sit at hold 3.0.

**Where the cache lands is what makes an arbitrary number look plausible.** The runner constructs one
sampler per sweep step, right after the ports are ready and before the driver opens, so the tick
counter restarts every step. `messagefoundry/pipeline/sandbox.py` spawns the subprocess-sandbox worker
child **lazily on first dispatch**, so under `[sandbox].mode = "subprocess"` those children do not
exist when the sampler is built. The one and only walk therefore fires at tick 1, mid-ramp, while
workers are still appearing, and is then frozen for the rest of the step.

`handles_peak` is a plain `max()` over whatever that one walk caught (`runner.py`, no PID-set
predicate), so the result is not degraded to a gap. It is a plausible number for the wrong process
set.

**Severity: no product axis.** This is an instrument, not shipped engine behaviour, and per CLAUDE.md
section 0 there are zero deployments. The cost is that nothing on this project can currently measure
the resource posture of a multi-process engine, which is what holds BACKLOG #1278.

Three things this is **not**, each checked rather than assumed. It is not probe degradation:
`fd_probe_degraded_ticks = 0` and `fd_probe_degraded = []` on all four records. It is not #220's
PID-set gate, which lives only in the CPU comprehension. And it is not the fix in PR 598 -- worse,
598's guard **passes** against this, because it constructs `FdSampler(os.getpid(), resolve_every=1)`
explicitly. That proves re-resolution works when asked. Production never asks.

## Decision

Replace the tick-counted trigger with two, and drop the tick unit rather than layering over it:

1. **Front-load.** The first `_FRONTLOAD_WALKS = 4` ticks of a sampler's life each re-walk, however
   little time has passed.
2. **Then amortise on time.** After that a walk runs only once `_RESOLVE_INTERVAL_S = 5.0` seconds
   have elapsed since the last one.

`FdSampler.__init__` now takes `frontload_walks` and `resolve_interval_s`; `resolve_every` is gone.
Both call sites (`harness/load/connscale/runner.py`, `harness/load/estate/runner.py`) construct the
sampler bare, so the default change reaches them and every future construction with no plumbing.

**The front-load is bounded by walk COUNT, not elapsed time,** and that is deliberate. Walks happen
only on samples, so the count starts at the first sample rather than at construction. However long the
runner's connection ramp takes between the two, the front-load still covers the beginning of the
measurement window.

**Both counters advance for an ATTEMPT, not for a success.** A failed walk still spent its cost. So the
front-load is capped at four attempts rather than four successes, and once a cache exists a failing
re-walk falls back onto the interval instead of retrying every tick. It does **not** bound the case
where no walk has ever succeeded: with `_pids` still `None` every tick walks, which is the pre-existing
"not cached, so retry next tick" contract and is unchanged here.

### What this changes about the meaning of `handles_peak`

Before, on a short profile, `fd_count_peak` was the peak over the process set the walk caught at tick
1. Now it is the peak over a set re-checked through the ramp and early hold. On a step where the
topology grows, the number gets larger, and it is a different number rather than a corrected one. A
reading taken before this change is not comparable with one taken after.

## Alternatives considered

**Lower the tick count.** Not viable at any value. One tick costs longer than the window it would have
to fire inside, so the unit is wrong regardless of the number written in it.

**Re-resolve every tick (`resolve_every = 1`).** Correct, and rejected on measured cost: walk ticks ran
1056-1278 ms against 210-370 ms cached. At `poll_interval_s = 0.25` the probe rather than the profile
would set the sampling cadence, thinning an already two-tick window further. The existing amortisation
guard exists for this reason and is kept.

**Time-based re-resolution alone.** Fixes the unit exactly as the comment intended and is immune to
tick-cost drift, but at "every few seconds" it still never fires inside a 1.5 s hold. Necessary, not
sufficient.

**Staleness-triggered from data already in hand.** `_sample_windows` returns `cpu_pids`, so a short row
count proves a cached PID died. Cheap, and **insufficient alone**: it detects DEPARTURES only. A newly
spawned worker can never appear in a read keyed to a stale PID list, and arrival is precisely this
defect's case. Recorded here so it is not proposed naively later.

## Consequences

The short profiles now re-walk on every tick they have, because their whole window sits inside the
front-load. That is the cost of seeing a topology change in a two-tick window, and there is no cheaper
way to see one. The long profile (`connscale.toml`, hold 60 / poll 1.0) keeps the amortisation: four
front-loaded walks, then one per five seconds.

**The tick count per step narrows, and that is stated rather than glossed.** A walking tick costs more
than a cached one, so fewer fit. Measured end to end on the CI cell before and after: `fd_probe_ticks`
went from 2 on all four steps to 1, 1, 1, 2. Every step still measured (`fd_count_peak` 383, 419, 387,
423, no degraded ticks) and both `(sweep_mode, claim_mode)` groups still carry two readings, so
`fd_count_monotonic` still compares real pairs -- the bound `tests/test_connscale_smoke.py` places on
exactly this holds.

**Where a window affords ONE tick, no trigger can see growth**, because seeing growth needs two
samples. That is a property of `hold_seconds` against the tick cost, not of the trigger, and this
decision does not claim to fix it. It is why the front-load is walk-counted: on a window that affords
more, every additional tick is spent on a fresh walk rather than on a cached one.

A second interaction, and it is correct rather than a cost: on a tree that is genuinely growing,
consecutive ticks now cover DIFFERENT PID sets, so `_drain_proc` degrades those intervals to a CPU gap
under BACKLOG #220. A CPU delta differenced across a changing PID set was never a CPU delta, so the gap
is the honest answer. On a stable tree the sets still match and CPU still derives.

Measured after the change, same rig, production construction: at hold 1.5 the sampler now re-resolves
once inside the window, its PID set moving 6 to 14 and its handle sum 438 to 1016. Every rung of the
hold ladder re-resolves. The amortisation control -- 30 ticks past the front-load -- made 7 walks, not
30, so the fix did not regress into walking every tick.

**A figure this ADR deliberately does not carry.** An earlier reading of roughly 3745 handles against a
385 baseline, and any per-worker number derived from it, is **withdrawn**: the caught PID count varied
2, 3, 8, 50 across consecutive ticks of one run, so the denominator is not stable enough to divide by.
The 438-to-1016 pair above is a controlled stand-in tree, not an engine measurement, and must never be
presented as the engine's per-worker footprint. The resource question stays open; #1357 is the reason
it cannot yet be answered.
