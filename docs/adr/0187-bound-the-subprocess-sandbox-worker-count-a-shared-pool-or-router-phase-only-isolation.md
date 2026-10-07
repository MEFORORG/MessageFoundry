# 0187 — Bound the subprocess sandbox worker count: a shared pool or router-phase-only isolation

- **Status:** **Accepted (2026-10-07) -- option 1, one bounded shared pool over both phases.** The
  owner chose the shape in session on 2026-10-07; see *Amendment A* below, which also records the
  design points the shape is accepted with. No code accompanies this ADR yet, and
  [BACKLOG #1458](../BACKLOG.md) stays open until the pool is built.
  **This line read** *"Proposed -- an options memo, not a decision. The shape is the owner's to
  choose"* until 2026-10-07. The memo's body below is unchanged and still recommends option 3; the
  owner did not take that recommendation, and *Amendment A* says why.
- **Date:** 2026-09-10
- **Related:** [BACKLOG #1458](../BACKLOG.md) (the row this memo answers) ·
  [ADR 0087](0087-sandbox-subprocess-isolation.md) (the seam being resized) ·
  [ADR 0052](0052-enterprise-scale-target.md) AC-2 (the criterion in tension) ·
  [ADR 0147](0147-hardened-runtime-isolation-for-router-handler-code-ipc-brokered-sandbox-extends-adr-0087.md)
  (orthogonal, and it composes) · [ADR 0176](0176-sandbox-child-stderr-is-captured-and-relayed-content-below-info.md)
  (per-inbound stderr attribution) · [ADR 0084](0084-accepts-router-seam.md) (`accepts=`
  predicates run at router time) · [ADR 0010](0010-handler-callable-db-lookup.md) /
  [ADR 0043](0043-fhir-read-lookup.md) (the live-lookup carve-out) · BACKLOG #1278 (the default flip)
  · BACKLOG #1194 (the measurement) ·
  [the 2026-09-04 sandbox-dispatch benchmark](../benchmarks/results/2026-09-04-adr0087-sandbox-dispatch/README.md)

---

## Context

At `[sandbox].mode = "subprocess"` the engine allocates **one persistent worker process tree per
traffic-carrying inbound**, and nothing pools, caps or evicts it.

`RegistryRunner._sandbox_for` keys a `SandboxSession` by inbound name and caches it in
`self._sandbox_sessions`. The child spawns lazily on first dispatch and is released only at
`RegistryRunner.stop()` or a config reload. One engine-wide `SandboxPolicy` is built in
`Engine._build_runner` and handed to every runner; `SandboxSettings` carries `mode`, `wall_seconds`,
`cpu_seconds`, `mem_mb` and `startup_seconds`, and **nothing per-connection or per-handler**.

Per traffic-carrying inbound the engine therefore holds a process tree, two parent daemon threads,
three parent pipe file descriptors and a Windows kill-on-close job-object handle.

**Severity is conditional, per [CLAUDE.md](../../CLAUDE.md) section 0.** MessageFoundry is a
not-deployed beta with zero instances, and `mode="off"` is the shipped default, so this growth is
reached only by opting in. Everything below is what a deploying site **would** meet. Nothing here is
PHI-bearing.

**This is not an argument against sandboxing.** Routers and Handlers are admin-authored Python that
the engine runs in its own address space at the default, beside the DEK, the audit chain and live
sockets. Isolating them is right. The objection is to the **worker cardinality**, and to nothing else
about ADR 0087.

### The criterion in tension

[ADR 0052](0052-enterprise-scale-target.md) AC-2, verbatim:

> THE SYSTEM SHALL support up to 1,500 concurrent connections without per-connection-worker
> exhaustion (fd/socket/worker-task limits).

Per-inbound worker allocation is precisely that resource class, and **no multiplication is needed to
see it**. The engine adds one unbounded-growth term per traffic-carrying inbound, by construction.

### What the record measures, and what it does not

| | status |
|---|---|
| per-worker footprint: 49.9 - 57.0 MiB unique, 76.8 - 82.5 MiB resident, 1.8 - 2.7 s spawn | **measured** (BACKLOG #1194), on a one-router one-handler graph, so a floor |
| per-tree process count on Windows under a virtual environment: **2** | **measured** — `worker_tree_processes` in all five result files, and reproduced independently below |
| the "roughly 74 GiB at 1,500" total | **retracted** — in place in ADR 0087 on 2026-09-05, and in the benchmark artifact by the change carrying this ADR |
| whether per-worker cost is linear in worker count | **never measured** — one live tree in every result file |
| whether the engine passes or fails AC-2 at 1,500 | **not establishable today** (see below) |

**AC-2 cannot be closed by measurement today, in either direction.** ADR 0052 calls its own
1,500-connection axis *"unvalidated"* (`:99`) and records the connection-scale validation harness as
one that *"does not exist"* (`:108`). So this memo must not assume a number exists, and no shape
below may be justified or refused on a measured 1,500-lane result. **What is establishable without
any harness** is the structural claim: the count grows one-per-inbound with no bound, no cap and no
eviction. A search of `sandbox.py` for `evict`, `idle_`, `lru`, `max_worker` and `pool` returns zero
against 83 occurrences of `worker` in the same file, so that absence is measured rather than assumed.

### Every child already loads the whole graph, which is the fact the options turn on

`_sandbox_worker.main` bootstraps with `registry = load_config(boot.config_dir)`, and `config_dir`
comes from the runner's engine-wide `_sandbox_config_source`. **The child loads the entire
configuration directory, not its own inbound's subgraph**, and then looks the requested Router or
Handler up by name in that registry. The only per-inbound argument `_sandbox_for` passes is
`inbound=name`, which exists to attribute the child's relayed stderr to that feed
([ADR 0176](0176-sandbox-child-stderr-is-captured-and-relayed-content-below-info.md)).

Two consequences follow, and both cut toward pooling:

1. **N children hold N identical copies of one registry.** The duplication is the cost, and the
   children are already interchangeable in everything except a log label.
2. **Pooling does not weaken handler-to-handler confinement, because there is none to weaken.**
   ADR 0087 already disclaims it: *"One Handler is not confined from another inside a worker."* Every
   child already carries every Handler, so sharing a child between inbounds does not put code in
   reach of anything it could not already reach.

### The kill is the only cancellation primitive, and that is the hard part

`SandboxSession.dispatch` holds `self._lock` across its whole body, so **a worker serves exactly one
dispatch at a time**. Inside that body, every isolation fault ends in `self._kill(proc)` — a marshal
rejection, a `wall_seconds` timeout, an EOF from a crashed child, a codec rejection, and a frame no
outstanding request asked for. There is no wire-level cancel: killing the process *is* how a runaway
call is stopped, and `_kill` reaps the whole tree.

Against one inbound, the blast radius of a kill is that inbound. Against a shared worker it is every
lane that worker serves, and that is the design work this memo exists to price.

## A measurement, run here, on the 22-versus-11 process-count contradiction

BACKLOG #1278 records two unreconciled readings of one number. A 2026-09-04 samples smoke counted
**22** operating-system processes for **11** logical workers and explained the doubling as a launcher
artifact, *"so every logical Python process appears twice in `Win32_Process` under the same
`CommandLine`"*, concluding the figure is one worker per inbound. ADR 0087's amendment says each
worker tree is *"two processes on Windows, per `worker_tree_processes` in every result file"*. If
that is right, 22 is the real tree size. The row's instruction stands: **nobody had run the
discriminating test**, and the AC-2 process arithmetic depends on which reading is correct.

**What was run (2026-09-10, this worktree).** A stdlib virtual environment was created with
`python -m venv` from `pythoncore-3.14-64\python.exe` — the same creator `scripts/worktree/new.ps1`
uses (`& $Python -m venv $venv`). Three children were then spawned with
`subprocess.Popen([<venv>\Scripts\python.exe, "-c", ...], stdin=PIPE, stdout=PIPE, stderr=PIPE)`,
mirroring the shape of `SandboxSession._spawn`, each blocked on until it had actually executed Python
rather than merely been created. `Win32_Process` was then read for every live `python.exe`, selecting
`ProcessId`, `ParentProcessId`, `ExecutablePath` and `CommandLine`.

**Result.** 23 rows, and **23 distinct `ProcessId` values**. Each of the three `Popen` pids was a
`.venv\Scripts\python.exe` with **exactly one** live child, whose `ExecutablePath` was the base
interpreter and whose `CommandLine` was **byte-identical** to the stub's.

**What that settles.** Two things, and they point the same way:

- **`Win32_Process` does not report one process twice.** The rows are distinct pids in parent-child
  pairs. So the reading on which the second row is an instrument artifact — and the real process bill
  is 11 — does not hold.
- **The mechanism the 2026-09-04 note described is real, and is exactly why the count looked like a
  duplication.** The venv stub re-execs the base interpreter with an identical command line, so a
  count keyed on `CommandLine` cannot tell the pair apart.

The two readings were never in conflict about the *number*. They conflicted about whether the second
process is real. **It is**, so ADR 0087's per-tree count of two is the one to use, and 22 was the
true operating-system process figure for 11 logical workers.

**What it does not settle, stated plainly.** The engine was not run and the 2026-09-04 samples smoke
was not repeated, so the test #1278 names — read `worker_tree_processes` and the parent-child edges
**on the same run that produced the 22** — remains unrun. This probe substitutes an isolated
reproduction of the launcher mechanism for that run. Two residuals follow:

- The provenance of the `.venv` on the 2026-09-04 box was not verified. Stdlib `venv` was inferred
  because `scripts/worktree/new.ps1` creates one that way; `uv` is also on PATH on this machine and a
  `uv` trampoline may behave differently.
- A logical worker is one interpreter either way, and the stub is a small shim, so **the memory
  arithmetic is unchanged**. What this corrects is the process limb, which is the limb AC-2 names
  most directly.

**The arithmetic to use, therefore:** N traffic-carrying inbounds cost N interpreters and **2N**
operating-system processes under a Windows virtual environment, N outside one. That is per-tree and
measured. Multiplying it by 1,500 still inherits the wrong-multiplier defect ADR 0087 retracted, so
do not.

## Decision

**None — this memo does not choose.** It lays out four shapes with their costs and makes a
recommendation the owner may take or reject. What it does decide is a framing correction that changes
what the choice is about:

> **The two shapes BACKLOG #1458 names are not alternatives for this defect.** Router-phase-only
> isolation changes *what runs* in the child; it does not change *how many children exist*. On its
> own it leaves one worker per inbound and AC-2 exactly where it was. It earns its place here because
> it makes a pool **easy to size**, not because it bounds anything by itself.

## Options considered

### 1. A bounded shared worker pool over both phases

Cap workers at `[sandbox].max_workers` and assign lanes to them, instead of one worker per inbound.

**For.** It is the only shape that attacks the criterion directly, and it removes the N-fold
duplication of one identical registry. It keeps the property ADR 0087 claims — a boundary to the
**engine** — untouched, and drops only one the seam already disclaims.

**Against, and this is the strongest objection in the memo.** The kill stops being private. ADR 0087
records as an accepted residual that a compromised worker *"can deny its own feed"*: a Handler that
writes an unsolicited frame to fd 1 forces `_reject_unsolicited` to drop the worker. Under a pool
that residual **escalates from a single-lane denial of service to a cross-lane one** — one hostile or
buggy Handler can force repeated kill-and-respawn on every lane sharing its worker. That is a
security regression in an isolation feature, and it is the thing a pooled design must answer before
anything else.

Three further costs, smaller but real:

- **Head-of-line blocking.** `dispatch` serializes under `self._lock`, so W workers serving N lanes
  means lanes queue behind each other. The benchmark's case E already measures a **sandbox-only
  per-lane ceiling of roughly 61 to 66 msg/s** against a high single-node tier claiming ~70-100
  msg/s; a pool turns a per-lane ceiling into a shared one.
- **Attribution.** ADR 0176's stderr relay is labelled per session at construction. A shared child
  needs per-dispatch tagging or its relayed stderr lands on the wrong feed.
- **It changes what ADR 0147 must authorize.** A shared child serving several inbounds needs the IPC
  broker to scope a lookup to the *requesting lane*, which a per-inbound child gets for free.

**One thing that is less bad than it looks, recorded so the objection is priced honestly.** Because a
worker serves one dispatch at a time, a kill destroys exactly one in-flight dispatch — the one that
caused it. Lanes queued behind the lock have not written a frame, so they pay a respawn delay of
1.8 to 2.7 seconds rather than a dead-letter. That bound holds **only** if a pooled design keeps
one-dispatch-at-a-time per worker and re-queues waiters instead of failing them, so it is a property
to design for, not one to inherit.

### 2. Router-phase-only isolation

Sandbox the Router and the `accepts=` predicates; run transforms in-process.

**For.** It answers the *default* question, which is BACKLOG #1278's subject: the live-enrichment
carve-out is the stated reason `subprocess` cannot be a default, and it is a transform-phase feature
only. `db_lookup` raises unless a runner is active, and every `run_contexts(..., phase="transform")`
activation site sits in the transform path. So router-phase isolation fails closed on nothing, and
the benchmark prices it at 0.18 ms per message. It also halves the per-message dispatch cost, since a
message stops paying twice.

**Against.** It **does not bound the worker count**, which is this row's defect. And it narrows what
is isolated: transforms — the phase that touches message bodies most — run in the engine's address
space again. Relative to today's opt-in `subprocess`, that is a reduction in isolation breadth.

**A refinement to the reasoning BACKLOG #1458 offers.** The row suggests the router phase is the one
where a shared worker has *"no per-lane live-lookup state to keep straight"*. That is right about the
future and not about today: at `mode=subprocess` the sandbox currently **refuses both live bridges**,
so neither phase carries lookup state in the child. The distinction becomes load-bearing only once
[ADR 0147](0147-hardened-runtime-isolation-for-router-handler-code-ipc-brokered-sandbox-extends-adr-0087.md)'s
broker re-enables them.

### 3. Router-phase-only isolation served from a bounded shared pool — **RECOMMENDED**

Combine 2 and 1: isolate the router phase only, and serve it from a pool sized independently of the
connection count.

**Why this is the recommendation.** It is the only combination in which the worker count stops
tracking the inbound count at all. With transforms unsandboxed there are no per-inbound transform
children, and the router children are a small shared set — so N lanes cost W workers, and W is an
operator setting rather than a consequence of the graph. Every argument for a pool applies at its
strongest here: router dispatches are short (0.18 ms), pure by the reliability invariant, refused the
live bridges by design, and served from a registry that is identical in every child already. The
head-of-line cost that worries option 1 is smallest against the phase with the shortest calls.

**What it costs, and this is the trade the owner is being asked to make.** Isolation breadth for a
bounded worker count. Transforms lose the address-space boundary they have today at
`mode="subprocess"`. That is a real reduction and it should not be sold as free.

**It does not resolve the cross-lane denial of service from option 1**, only shrink it: a hostile
Router can still force respawns on lanes sharing its worker. A pooled design still owes an answer —
per-lane respawn budgets, or quarantining a lane to a private worker after N kills, are the obvious
directions and neither is specified here.

### 4. Keep one worker per inbound; add a cap and idle eviction

`max_workers` plus a least-recently-used idle reaper, leaving worker identity per-inbound.

**For.** By far the cheapest, and it bounds the count.

**Against.** It makes isolation *availability* depend on which lanes are hot. An evicted lane pays
the 1.8 to 2.7 second respawn on its next message, so a site with more inbounds than workers gets
sporadic multi-second latency with no clear operator signal. Rejected as the primary remedy; worth
keeping as a cheap partial if the owner wants the count bounded before the shape is settled.

### 5. Per-connection `[sandbox].mode`

Orthogonal to all of the above, and noted because the row raises it. `[sandbox]` is engine-global
today, so a single Handler needing `mode="off"` — for a live `db_lookup`, say — spends the whole
process's isolation. An operator cannot sandbox the cheap lanes and exempt the expensive one. Any
rearchitecture should decide whether that stays true; it is not itself a cardinality fix, and under
options 1 or 3 a per-connection mode also decides which lanes share a worker.

## Amendment A (2026-10-07) -- option 1 accepted, and what it is accepted with

**The owner chose option 1 on 2026-10-07, in session**, after three adversarial reviews and a
fourth that checked the three against each other. The question put was *"accept option 1 (one
bounded pool running both routers and transforms)?"*, and the answer was *"Accept option 1"*.

**Why not option 3, the memo's own recommendation.** Option 3 runs transforms in the engine process
again. There, nothing bounds a transform's running time: `SandboxSettings` says that at
`mode="off"` there is no timeout at all, and CPython cannot kill a thread, so a transform stuck in a
loop holds a default-executor thread for good. That executor also serves strict validation and
login work. The owner's trust model (2026-10-06: Router and Handler authors are trusted employee
programmers unless security is breached) puts exactly that buggy code in scope, and transforms are
where most of it lives. Under option 1 the same bug costs one dead-lettered message after
`wall_seconds`. Option 3's other two advantages are smaller than the memo priced them: both options
bound the worker count, and a graph that declares no live lookup can run its transforms sandboxed
today.

**Why not option 4.** Reviewers measured a worker spawn at about 3 to 5 s warm and 11 to 21 s cold
at 500 to 1,500 inbounds, on a loaded 20-core Windows box. They are not re-run here. With fewer
workers than active lanes, most messages would pay a full spawn, which fails ADR 0052 AC-1.

**The 2026-09-09 ruling that kept the default off was about BOTH scale and live lookups.** The
records disagreed: BACKLOG #1278 named ADR 0052 AC-2, and option 2 above named the live-lookup
carve-out. The owner settled it on 2026-10-07 (*"Both"*). This session reads that as the default
flip (#1278) waiting on this pool and its connection-scale measurement, **and** on the ADR 0147
broker. That is an inference from the ruling, not a separate ruling. This ADR does not decide the
flip.

### Design points the shape is accepted with

The points below were not each put to the owner. They are the engineering decisions of the session
that carried the reviews, taken under the owner's standing rule to proceed on a strong
recommendation, and every one came out of the adversarial reviews. Treat them as the starting design
for the build, open to the build's own review.

1. **No per-lane kill budget yet.** A shared worker cannot reliably say which lane caused a kill, and
   nothing records why a worker died today. Build the kill-cause record first (BACKLOG #3135), then
   measure how often a kill lands on the wrong lane, then decide.
2. **What bounds harm to sibling lanes instead:**
   - one in-flight dispatch per lane (k = 1), which keeps today's per-lane order;
   - the lane whose dispatch caused a kill waits for its own replacement worker;
   - recycling a worker after a kill, after a run of errors that did not kill it, and after M
     dispatches;
   - a check, after each dispatch, for threads or processes the Handler left behind, against a
     baseline taken after boot;
   - no automatic stop of a lane, except one making no progress at all.
3. **One pool by default, with an optional `worker_group` tag** so an operator can keep named feeds
   apart. **Per-connection `[sandbox]` settings (option 5) are declined.**
4. **Lanes wait for a worker without holding an executor thread.** Sandbox dispatch gets its own
   executor, so slow Handlers cannot push strict validation on other lanes past its timeout.
5. **Infrastructure faults re-queue.** Closing the pool on reload, timing out while waiting for a
   worker, and a worker that cannot boot each re-queue the row with no attempt spent, and the last
   raises an alert (BACKLOG #1693, #2772).
6. **The pool loads one audited config snapshot.** Recycling makes respawn routine, so the respawn
   must not load unaudited code from disk (BACKLOG #2596, steps 1 and 2). The pool waits on that.
7. **Sizing.** Per engine process from `os.process_cpu_count()`, plus warm spares, with a host-wide
   budget when several engine shards share a machine.
8. **The wall timer starts after the request is written,** as `dispatch` does now, so queueing time
   never counts against `wall_seconds`.
9. **Lookups are scoped to the requesting lane** through the dispatch tie ADR 0147's Amendment A
   adds.
10. **Until the ADR 0147 broker exists, a graph whose Handlers call a live lookup** keeps today's
    rule (`mode="off"` for the engine), or uses a per-Handler in-process exemption with a mandatory
    reason, if one is built first. The broker removes the exemption. Neither is a reason to hold the
    pool.

### Order of work

1. The worker's lifetime CPU budget goes first (BACKLOG #3133; the owner ruled on 2026-10-07 to drop
   `RLIMIT_CPU`). It kills innocent dispatches on POSIX, so no POSIX measurement means anything
   until it is gone.
2. The connection-scale harness learns a sandbox arm and a delivery check (BACKLOG #3132, steps 1
   and 2). As built, a sandbox run would pass while delivering nothing.
3. A baseline of today's per-inbound design, driving K of 1,500 declared inbounds, sizes the pool.
4. The one-snapshot loader (BACKLOG #2596), then the pool, with fault-injection tests: a busy loop, a crash,
   a leftover thread, a write to fd 1, `sys.exit`, `os._exit`, a memory leak.
5. The N=1500 two-arm comparison runs against **the pool**, the shape that would ship, on both
   Windows and Linux, with N=750 recorded beside it (BACKLOG #3132).

## Acceptance Criteria

> **Amended 2026-10-07 for option 1.** AC-1, AC-2 and AC-5 stand as written. AC-3 and AC-4 are
> amended in place: AC-3 now names its mechanism, and AC-4 is approximate, because the relay thread
> reads stderr on its own schedule and a tag the child writes cannot be trusted. The paragraph below
> is the memo's original preface.

> Stated for the shape this memo recommends, so that accepting it has a testable meaning. They are
> **not** satisfiable today and several are deliberately unlinked: per the Context above, AC-2 of
> ADR 0052 cannot be closed by measurement until a connection-scale harness exists.

- **AC-1** — WHERE `[sandbox].mode = "subprocess"`, THE SYSTEM SHALL hold a number of worker
  processes bounded by a configured maximum, independent of the number of traffic-carrying inbound
  connections.
  → test to build with the chosen shape
- **AC-2** — IF a worker is killed for any isolation fault, THEN THE SYSTEM SHALL dead-letter only
  the dispatch in flight on that worker, and SHALL re-queue every other lane's pending dispatch
  rather than failing it.
  → test to build with the chosen shape
- **AC-3** — IF one lane repeatedly forces worker kills, THEN THE SYSTEM SHALL bound the effect on
  sibling lanes sharing that worker. *Amended 2026-10-07:* the mechanism is *Amendment A* design
  points 1 and 2 (k = 1, lane-charged respawn, recycling, the leftover check; no kill budget yet).
  → test to build with the chosen shape
- **AC-4** — WHEN a shared worker relays child stderr, THE SYSTEM SHALL attribute it to the inbound
  whose dispatch was in flight when the relay read it, and SHALL keep per-(generation, inbound)
  notice counters. *Amended 2026-10-07:* this read *"to the inbound whose dispatch produced it,
  preserving the guarantee
  [ADR 0176](0176-sandbox-child-stderr-is-captured-and-relayed-content-below-info.md) makes"*.
  Exact attribution is not possible in a shared worker, so the criterion is now approximate.
  → test to build with the chosen shape
- **AC-5** — THE SYSTEM SHALL preserve every fail-closed refusal ADR 0087 rests on: a value outside
  the closed codec grammar, a desynchronized or forged frame, an unsolicited frame, and a
  `wall_seconds` overrun SHALL each still raise rather than degrade.
  → the existing ADR 0087 sandbox suites, which must continue to pass unchanged

## Consequences

**Positive** — the choice is stated in one place with its costs priced, instead of being re-derived
from a benchmark artifact and two ledger rows. The 22-versus-11 contradiction has a measurement
against it rather than an argument. And the framing correction above means nobody spends a build
cycle on router-phase-only isolation expecting it to bound the worker count.

**Negative / risks** — this ADR proposes and does not decide, so BACKLOG #1458 stays open and the
growth it describes is unchanged on `main`. The recommendation trades isolation breadth for a bounded
count, which a reader who values the transform boundary most will reject; that reader should take
option 1 and pay the cross-lane denial-of-service design cost instead.

**Out of scope** — the OS-level confinement question
([ADR 0147](0147-hardened-runtime-isolation-for-router-handler-code-ipc-brokered-sandbox-extends-adr-0087.md),
still Proposed, which composes with any shape here and substitutes for none); whether `subprocess`
becomes the default (BACKLOG #1278); the connection-scale validation harness ADR 0052 records as
non-existent; and the throughput half of the sandbox cost, corrected in ADR 0087 itself under
BACKLOG #1194.

## To resolve on acceptance

- [x] **The shape.** Option 1, owner ruling 2026-10-07. See *Amendment A*.
- [x] **The cross-lane denial of service.** Answered by *Amendment A* design points 1 and 2: no kill
      budget until kill causes are recorded, and k = 1, lane-charged respawn and recycling meanwhile.
- [ ] **The discriminating process-count test #1278 names**, run against a live engine rather than
      against the launcher mechanism in isolation. Now part of BACKLOG #3132, whose Windows run
      waits on #3065.
- [x] **Whether `[sandbox]` gains per-connection settings** (option 5). Declined; an optional
      `worker_group` tag instead. See *Amendment A* design point 3.
- [x] **Whether AC-1 is verifiable before a connection-scale harness exists.** The harness exists
      (`harness/load/connscale/`), but cannot yet run a sandbox arm; BACKLOG #3132 steps 1 and 2 fix
      that. AC-1 itself is a pytest at small N and needs no harness.
