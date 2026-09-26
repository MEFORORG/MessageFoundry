# ADR 0157 — Demotion safety: fence scope on post-claim writes, and a bounded graph stop

**Status:** Accepted **Date:** 2026-08-01 **Implemented:** 2026-08-02 (Inc 1, 4, 5), 2026-09-10 (Inc 0), 2026-09-25 (Inc 2), 2026-09-26 (Inc 3)

> **All six increments are BUILT: 0, 1, 2, 3, 4 and 5.** C1 (terminal writes only, fail-open) and C6
> (yes, bounded, abandon-don't-await) were decided by the owner. Two named residuals stay open: the
> SQL Server renew clamp (Inc 0, deviation 3) and the same-process re-promotion case (Consequence 1c).
>
> **Inc 3 is BUILT (2026-09-26, BACKLOG #1497), on a measured premise.** Its gate asked whether a
> coroutine cancelled mid-`execute` leaves an aioodbc transaction committed or rolled back. Hosted CI
> answered it in runs 36219288548 and 36223227696: rolled back, never committed, in every case that
> gave a reading. That is three cases on SQL Server 2022 and two on 2025; the third 2025 case,
> `claim_ready`, crashed natively and gave no reading. `claim_fifo_heads` is the one exception by
> reading, and it needs no further fence. SQL Server
> now fences `claim_ready` and the same eight terminal resolves as Postgres. It needed nothing from
> Inc 2: D1's re-pend and the successor's promotion reset close recovery. The measurement and the
> as-built note are at the increment.
>
> **Inc 2 is BUILT (2026-09-25, BACKLOG #1497), in two layers and with a narrower scope than its
> re-specification.** A per-lane worker that stops mid-batch now releases its own unprocessed tail,
> as the pooled dispatcher already did. A reload then re-pends anything a worker that has RETURNED
> still left in flight, and touches no lane whose worker is alive. The re-specification scoped the
> reload reset to "the names in the old registry"; built that way it would re-pend rows a live
> worker is sending, because `reload()` stops no worker. It does **not** make SQL Server recover a
> crash strand: that still waits for the next start or promotion. The age-sweep paragraph and the
> re-specification are both kept below; read the as-built note at the end of the re-specification.
>
> **Inc 0 shipped with three deviations from its own paragraph** — the check's subject, refuse-rather-
> than-warn, and a Postgres-only clamp. Each is recorded with its reason at the increment.
>
> Three clauses were corrected during implementation, each because the drafted version was
> **strand-direction** — the one outcome the at-least-once invariant forbids:
>
> - **C3** said a fenced terminal write should roll back and leave the row INFLIGHT for recovery. On
>   SQL Server there is no periodic in-flight recovery at all, so that is an unbounded strand produced
>   by the fence itself. Corrected: roll back, then re-pend via unguarded `release_claimed` (D1).
> - **C4** said "delete the `set_leader_epoch(None)` clear". Alone that is a silent total halt once C5
>   lands: `_reconcile_graph` had only two branches, so `is_leader() and running` matched neither,
>   forever, holding a stale epoch — a live leader claiming nothing, with no exception and no alert.
>   Corrected: delete the clear **and** re-stamp on every reconcile pass while leader (D2).
> - **The cross-backend safety claim for C4 was false.** It read "SQL Server's claim guard already
>   exists ... so a demoted SS node claims nothing". `claim_ready` on SQL Server carries **no** epoch
>   guard, so a demoted SS node retaining a stale epoch still claims and drains every UNORDERED lane,
>   and resolves those rows unfenced. Retaining the epoch is still strictly better than clearing it —
>   but only the three FIFO claim paths are covered there until Inc 3. **Inc 3 closed this on
>   2026-09-26:** `claim_ready` and every terminal resolve on SQL Server now carry the guard.

---

## Context — what the re-check found

The HA construct is **active-passive only**: N engine processes against one shared server database, one
leader plus warm standbys, no broker. Gated on `[cluster].enabled`, `[store].backend` in
`{postgres, sqlserver}` (SQLite rejected at config load), `[store].pool_size >= 2`. Engine sharding and
`[cluster]` are mutually exclusive and fail closed ([`__main__.py:2372`](../../messagefoundry/__main__.py)).

A re-check of the leadership-lease construct found the lease algebra **sound** — expiry is evaluated on
the DB clock on both backends, acquire/renew is one atomic statement, and the `leader_epoch` fencing
token is real and genuinely checked inside the claim transaction. Scope B (failover vs the count-and-log
invariant) and scope C (Postgres/SQL Server divergence) were probed and cleared, not assumed.

**The invariant that decides everything:** at-least-once **permits duplication and forbids stranding or
loss**. A change converting a possible strand into a possible duplicate is an improvement; the reverse is
unacceptable however elegant.

### F1 — the epoch fence guards *some* claims, and nothing after them

The guard is `AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$8) <= $9`, spliced
only when a held epoch is cached: [`postgres.py:2694`](../../messagefoundry/store/postgres.py) and the
sibling FIFO claims; SQL Server twins in [`sqlserver.py`](../../messagefoundry/store/sqlserver.py).

**"The claim is fenced" is true only of the FIFO claims.** `claim_ready` — the UNORDERED path — carries
no epoch predicate on **either** backend.

Post-claim writes resolve by bare id, unguarded:

| write | Postgres | note |
|---|---|---|
| `dead_letter_now` | `:3179-3187` (`WHERE id=$5`) | assigns a **terminal** disposition, then calls `_maybe_finalize_message` |
| `mark_done` | `:3197-3203` (`WHERE id=$3`) | |
| `mark_failed` | `:4125-4133` (`WHERE id=$5`) | decides dead-letter from an `attempts` the *successor* may have incremented |
| `complete_with_response` | `:3288-3294` | not idempotent — inserts a fresh response artifact |

Contrast [`release_claimed`](../../messagefoundry/store/postgres.py) at `:3098-3104`, two methods away,
which **does** carry `AND status=$4`.

The sharp write is not `mark_done`. It is `dead_letter_now` — a demoted node assigning a terminal
disposition and finalizing the message, breaching *"the store finalizer is the single authority"*
(CLAUDE.md §2). A DEAD row is never re-claimed, so H2 skip-and-complete cannot heal it.

Also unguarded: the cross-owner stranded-lease reclaim that is the **first** statement of each FIFO claim
transaction (`postgres.py:2981-2991` and twins). An epoch-rejected claim returns an empty result set
rather than raising, so the transaction still **commits** the re-pend.

### F2 — demotion budgets detection only, never the stop

`_check_fence` ([`cluster.py`](../../messagefoundry/pipeline/cluster.py)) sets `_is_leader = False` and
`_leader_epoch = None` and nothing else. It cancels no listener, no worker, no in-flight send.

**The real budget on stock defaults** (heartbeat 10.0, fence 20.0, ttl 30.0):

- detection = fence 20.0 + up to one `_fence_tick` (1.0) + up to one graph poll (1.0) → **20–22 s**
- lease expires at **30 s on the DB clock**
- ⇒ **≈ 8.0 s**, *minus* the renew round-trip remainder. The fence baseline is stamped **after** the renew
  returns, and that round trip is bounded only by `[store].command_timeout = 30`
  ([`settings.py:505`](../../messagefoundry/config/settings.py)) — which **exactly equals**
  `leader_lease_ttl_seconds = 30.0` (`settings.py:2904`). `_fence_ordering` relates heartbeat/fence/ttl
  only. **The margin can be zero or negative and no validator notices.**

Teardown cost against that ~8.0 s: `_teardown_unsafe` sets `_stop`
([`wiring_runner.py:2481`](../../messagefoundry/pipeline/wiring_runner.py)) then runs the **sequential**
source loop at `:2497-2498` *before* the dispatchers at `:2505-2508`. Each socket listener costs up to
**10.0 s** — 5.0 client grace plus 5.0 `server.wait_closed()`, both off `_CLIENT_SHUTDOWN_GRACE = 5.0`
([`mllp.py:111`](../../messagefoundry/transports/mllp.py)), a module constant with no config surface and
no relation to lease timing. Every File/RemoteFile/Database/DICOM inbound is **unbounded**: `_stop.set()`
then `await asyncio.gather(self._task, return_exceptions=True)` with no cancel and no timeout
([`file.py:448-454`](../../messagefoundry/transports/file.py)). `_stop_graph` wraps nothing in `wait_for`.

So **one** blocked socket inbound already exceeds the budget; N serialize linearly, and the project
targets **1,500 connections**. On the Windows/NSSM deployment target, `mllp.py:1373-1379` documents an
observed ProactorEventLoop wedge (#55) that burns the full cap.

Partial mitigation that does not close it: `_stop` is shared, so no *new* rows are claimed during the
overrun. The residual is one in-flight episode per PROCESSING lane across up to 256 lanes.

### F3 — a false premise, now corrected in all three places

`postgres.py`'s `recover_inflight_on_promotion` and `engine.py`'s SQL Server `reset_stale_inflight` call
both justified themselves with *"the prior leader has stopped processing"*. F2 shows that does not
follow. Corrected in `bc9ccd73`; a **third** site missed by that commit was corrected in `6c81c65e`.

That the first correction's enumeration was incomplete is itself the defect class it was fixing — see
**Consequences**.

### The asymmetry that decides sequencing

Postgres stamps a row lease on every claim and the leader runs a periodic `reclaim_expired_leases` at
`reclaim_interval_seconds = 30.0` against `lease_ttl_seconds = 60.0`. A Postgres row left INFLIGHT is
**latency (~90 s worst case), never a strand**.

**SQL Server has no periodic in-flight recovery at all.** `reclaim_expired_leases` is defined on the
Postgres store alone (**zero** definitions in `sqlserver.py`); the runner is gated on
`reclaims_inflight() and hasattr(self.store, "reclaim_expired_leases")`
([`engine.py:1062`](../../messagefoundry/pipeline/engine.py)) — and `SqlServerCoordinator.reclaims_inflight()`
returns **True**, so the `hasattr` is the sole exclusion. Its only recovery is the on-promotion
`reset_stale_inflight`. **A SQL Server row left INFLIGHT outside a promotion is an unbounded strand** —
and `stage_dispatcher.py:918-919` already banks the cancel path on that recovery
(*"leave the whole prefix INFLIGHT for reset_stale_inflight"*).

This is a strand that exists **today**, with no HA scenario involved.

---

## Decision — the demotion-safety contract

**C1 — Fence direction: guard writes that make a claimed row TERMINAL; never guard a write that returns
a claimed row to PENDING.**

Guarded: `mark_done`, `dead_letter_now`, `complete_with_response`, `mark_failed`'s **DEAD branch**, and
the batch twins. Not guarded: `release_claimed`, `reschedule_claimed`, `mark_failed`'s **retry branch**,
and every stage handoff.

The dominant write on the demotion path is the L1 pre-send bail (`wiring_runner.py:4138-4145`), which
hands the row to the successor. Fencing it leaves the row INFLIGHT instead — a recovery delay on
Postgres, a **strand** on SQL Server, on the one path that today hands over instantly. An ex-leader
re-pending a row the successor is mid-delivering is duplicate-direction (**permitted**); fencing it is
strand-direction (**forbidden**).

**C2 — Two predicates of opposite polarity, each named once.**

- `_EPOCH_GUARD_CLAIM` — today's form, **fail-closed** on a missing lease row. Declining work is free.
- `_EPOCH_GUARD_RESOLVE` — **fail-open** on a missing lease row:
  `COALESCE((SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key = :key), :held) <= :held`.

On a resolve the polarity inverts: a rejected `mark_done` leaves the row INFLIGHT, which on SQL Server is
a strand. Reusing the claim idiom verbatim would ship a mass-strand bug. Extract both as per-backend
constants and test that neither appears at the other's sites.

**No `status='inflight'` conjunct.** `reclaim_expired_leases` is owner-blind by its own docstring and can
re-pend the current leader's own long-running row; today that leader's `mark_done` still lands. A status
conjunct would reject it and force a genuine re-send — a duplicate manufactured on exactly the long-hold
WAN lanes. The epoch does not fire there (same node, same term), so the conjunct would be the only thing
firing, and firing is worse.

**C3 — A fenced write is all-or-nothing, and it RE-PENDS the row. It must not leave it INFLIGHT.**
Zero rows affected ⇒ roll back the enclosing transaction (discarding the `delivered_keys` row, the
`message_events` row and the `_maybe_finalize_message` call), **then re-pend the row with an unguarded
`release_claimed([id])` in a fresh transaction**, bump a `fenced_write` counter, log WARNING.

> **Corrected 2026-08-02, before any implementation.** An earlier revision of this clause ended at
> "roll back … return via the existing `if row is None: return` shape", leaving the row INFLIGHT for
> recovery to collect. **That is strand-direction and must not ship.** On Postgres it costs ~90 s of
> latency via `reclaim_expired_leases`. On SQL Server there is **no periodic in-flight recovery at all**
> (`grep -c reclaim_expired_leases messagefoundry/store/sqlserver.py` → **0**; the `hasattr` gate in
> `engine.py` is the sole exclusion), so the row is stranded until the next promotion — precisely the
> outcome this ADR exists to prevent, produced by its own fence. The re-pend is invariant-legal by C1's
> own rule: `release_claimed` is a *return-to-PENDING* write, which C1 explicitly forbids fencing, and it
> is `status='inflight'`-guarded so it is idempotent. It converts the fence's own residue from a possible
> **strand** into a certain **duplicate**, which is the only direction the invariant permits.
>
> Rejected alternative: preferring `release_claimed` over `mark_done` on the demotion path generally.
> That manufactures a duplicate even when the epoch was **not** bumped — the common self-fence-without-
> takeover case — where the fail-open guard would correctly have let the write land.

Note honestly *why*: a persisted ledger row would record a **true** fact (`mark_done` is reached only
after a successful send), and the successor's H2 skip would then resolve the row without re-sending — so
rollback is not "avoiding a loss". We roll back because a ledger row without a resolved queue row is a
half-applied disposition asserted by a node that is not the authority. **Cost booked: one extra duplicate
per fenced resolve.**

**C4 — A demoted node retains its stale epoch; it does not clear it — AND the epoch is re-stamped on
every reconcile pass while leader.** `_stop_graph` currently calls `set_leader_epoch(None)`, reasoning
that a demoted node should carry no stale token. **The polarity is backwards:** the guard string is
omitted entirely when the epoch is `None`, so `None` means *no fence* while a stale token fails closed.
Delete the clear and correct the comment.

> **Corrected 2026-08-02.** "Delete the clear" **alone is unsafe once C5 lands**, and the failure is
> silent and total. `set_leader_epoch` has exactly one push site, inside `_start_graph`, and
> `_reconcile_graph` has only two branches: `is_leader() and not running` → start, and
> `not is_leader() and running` → stop. If the node demotes and re-acquires with a bumped epoch *during*
> a slow `_start_graph`, the post-bring-up recheck sees `is_leader()` True, so no stop fires — and
> thereafter the state `is_leader() and running` matches **neither branch, forever**, with the store
> still holding the pre-demotion epoch. Today that half-works because `claim_ready` is unfenced. After
> C5 fences every claim path, it is a live leader that claims **nothing**, silently, with no exception
> and no alert. The clause therefore requires a second half: **re-stamp `current_epoch()` on every
> reconcile pass where the node is leader and the graph is running.** That is safe and idempotent —
> `_is_leader` flips False→True only in `_maintain_leadership`, immediately after the renew refreshed
> `_leader_epoch`, with no intervening await, so `is_leader()` implies `current_epoch()` is non-`None`.
>
> **Also required in the same commit:** `tests/test_cluster_graph_gating.py` asserts the demotion push
> is `(None, None)`. That assertion encodes the behaviour being reversed and must be inverted here, or
> the tree goes red on a test that is documenting the old contract.

**C5 — Fence every claim path, including `claim_ready`.** With `claim_ready` open, a demoted node in
teardown overrun can claim a **fresh** row after the successor bumped the epoch, send it, have its
`mark_done` fenced by C1, and on SQL Server leave a row with `owner=NULL`, no lease, and
`updated_at > promoted_at` — invisible to any promotion-scoped recovery. Fencing every claim path is what
makes the design's central argument true: *after the successor's bump an ex-leader can claim nothing, so
every row it still holds was already re-pended by promotion recovery.*

**C6 — Demotion gets its own bounded teardown, distinct from clean shutdown.** `TeardownReason{SHUTDOWN,
DEMOTE}` as a parameter on the same `_teardown_unsafe` body — never a forked function. Under SHUTDOWN the
path is statement-for-statement today's. Under DEMOTE: bounded, **concurrent** source stop; then a
cooperative dispatcher `quiesce()` before any hard cancel; edge-triggered from the fence rather than
waiting on the graph poll.

> **Three constraints added 2026-08-02 from adversarial review; each makes the difference between the
> increment working and being actively harmful.**
>
> 1. **The concurrent stop must be one phase-level `asyncio.wait(tasks, timeout=budget)`, not a
>    semaphore with a per-source `wait_for`.** A semaphore of width *C* bounds the phase at
>    `ceil(N/C) × budget`, not `max()` — roughly **63 s at the 1,500-connection target against an ~8 s
>    margin**, i.e. the fix would not fix it. `asyncio.wait` also never cancels its awaitables, so
>    *abandon-don't-cancel* becomes a property of the primitive rather than of a flag someone can drop.
>    Creating all N tasks eagerly is cheap: every socket source closes its listening socket in its
>    **synchronous prologue**, so accept stops at task-creation time.
> 2. **`quiesce()` must not gate the lane drain on the claimer/sweep loops exiting.** The fence fires
>    *because* renews are failing — i.e. the pool is degraded — i.e. the claimer is parked inside a claim
>    against `[store].command_timeout`. A design that waits for it drains zero serializers on the exact
>    trigger it was built for.
> 3. **`self._running = False` must execute on every path** — `try/finally`, with the `finally` doing
>    *only* that. Do not clear the rest of the state there: a cancelled teardown would orphan live
>    listeners. Leaving `_running=True` (today's behaviour on a cancelled teardown) wedges re-promotion
>    permanently; leaving `_running=False` with dirty state makes the rebind path silently skip every
>    source. Both failure modes need pinned tests, plus a residual-state re-teardown at the top of
>    `start()` and a third branch in `_reconcile_graph`.

**The constraint stated in the brief does not exist.** `grep -c "D3" docs/adr/0066-*.md` → **0**. "ADR
0066 D3" appears only as a code comment (`wiring_runner.py:2499`). There is no ratified decision to
amend: this ADR **corrects a comment**, it does not supersede ADR 0066.

**Single-node SQLite is byte-identical, structurally.** `MessageStore.set_leader_epoch` is a hard
`return None`; the guard string is only emitted in the two server dialects; `build_coordinator` returns
the NullCoordinator whose `current_epoch()` is `None`; and `[cluster].enabled` rejects SQLite at config
load, so `_stop_graph` never runs and `reason` is always SHUTDOWN.

---

## Why this and not the alternatives

**An `owner =` predicate.** Dead on SQL Server, whose claims write `owner=NULL` — always-false (fatal) or
always-true (useless). And `_owner` is per-store-**instance** (`host:pid:uuid4()[:8]`), not per-term, so
it cannot separate a term-N straggler from a term-N+2 worker in the same process.

**Bare `status='inflight'` as the fence.** The successor re-pends then re-claims, so the predicate is
true again. The protected interval is the PENDING gap — milliseconds.

**A per-claim token.** The precise mechanism, and the only thing that closes the re-promotion residual
below. Rejected **for this ADR only**: it changes the `Store` protocol signatures of
`mark_done`/`mark_failed`/`dead_letter_now` and every caller, plus a migration and a backfill question for
rows already INFLIGHT at upgrade. File it; do not fold it in.

**Fencing writes that ADMIT a message** (ingress commit, stage handoffs). Rejected outright. Fencing an
ingress commit converts a permitted duplicate into a **lost** message and breaks count-and-log. A
demoting node that ACKs and persists during teardown is behaving *correctly*.

**Wiring the SQL Server sweep through `LeaderMaintenanceRunner`.** Rejected — it would silently break SQL
Server. Satisfying the `hasattr` gate makes `_leader_maintenance` non-None, the promotion path's `if`
wins, the unconditional `reset_stale_inflight` becomes **dead code**, and `recover_on_promotion` calls a
method that does not exist on SQL Server. The sweep must be a **distinct capability**, additive to the
on-promotion reset.

**A lease-anchored absolute teardown deadline.** Rejected as a *correctness* anchor: it makes the
monotonic clock load-bearing on the one platform the code already warns about (monotonic measures elapsed
**awake** time on Windows while the DB clock never suspends), and with `command_timeout` equal to
`leader_lease_ttl_seconds` a stalled pool drives the margin non-positive, degrading the "deadline" into an
unconditional hard cancel during precisely a DB-caused failover. A deadline that fires on every demotion
is not a deadline.

**Hard-cancel-first as the default demotion ordering.** Rejected as default, retained as timeout
fallback. `_stop.set()` already halts new claim rounds and the L1 bail halts egress the instant the fence
flips, so cancelling first buys little while converting up to 256 in-flight lane episodes into INFLIGHT
residue on **every** failover — the exact row state SQL Server cannot recover.

**Wrapping `stop()` / `_teardown_unsafe` in `wait_for` from outside.** Rejected, and this is the sharpest
implementation trap found. `self._running = False` is the **last** statement of `_teardown_unsafe`
(`wiring_runner.py:2610`), and `_reconcile_graph`'s bring-up branch is `is_leader() and not running`. A
cancelled teardown leaves `_running = True` and the node can **never re-promote, silently, with no
exception**. Any bound goes *inside*, guarding only the source phase.

---

## Increments

Each is independently shippable and ships with the test that would fail before it.

**Inc 0 — make the margin real. BUILT 2026-09-10 (BACKLOG #1497).** Clamp the lease renew's own
statement timeout well below `(ttl − fence)` instead of inheriting `command_timeout`; capture
`t_issue` *before* the renew and stamp the fence baseline from it rather than after the round trip;
config-load warning when `command_timeout >= (ttl − fence)` — noting it fires on **stock defaults
today** (30 vs 30), so ship it with a defaults change or rely on the clamp alone.
*Test:* slow-renew fixture asserting the detection margin stays positive.

> **What shipped, and three places it differs from the paragraph above.** As built: the baseline is
> read before the claim is issued in both coordinators' `_maintain_leadership`; a new
> `[cluster].lease_renew_timeout_seconds` (**derived from the margin** when unset — half of it, capped
> at 5.0 s, so 4.5 at the shipped 10/20/30) is passed to asyncpg as the claim's own per-statement
> `timeout=`; and `ClusterSettings._renew_fits_the_margin` refuses a config at load.
> `tests/test_adr0157_inc0_margin.py` carries the slow-renew fixture with an executed control arm
> (the same `_check_fence`, driven from the pre-Inc-0 baseline, showing the two-leader window), plus
> a mutation-confirmed red for each of the four changes.
>
> 1. **The check's SUBJECT is the clamp, not `command_timeout`.** Once the renew stops inheriting
>    `command_timeout`, a check written against `command_timeout` is a control resting on a premise
>    its own increment made false. The rule is `lease_renew_timeout_seconds < (ttl − fence −
>    fence_tick)`; at the shipped 10/20/30 that margin is 9.0 s and the derived 4.5 sits inside it, so
>    **a stock configuration loads with no error and no warning**. That was the condition for shipping
>    the check at all: one that fires on every install trains operators to ignore it, and an ignored
>    check withdraws the caution its absence would have preserved. See 4: a *stock* install was not a
>    wide enough condition, and the first cut of this increment failed it.
> 2. **It REFUSES rather than warning.** The paragraph above specified a warning because the check as
>    drafted fired on stock defaults, and a hard failure on every install is unshippable. Once the
>    defaults pass cleanly that constraint is gone, the three neighbouring `[cluster]` validators all
>    raise, and — CLAUDE.md §0 — with zero deployments a breaking default costs nothing to change.
> 3. **The clamp is POSTGRES-ONLY, and that is a named residual, not an oversight.** The SQL Server
>    coordinator's renew still inherits `[store].command_timeout` from the ODBC connection; a
>    per-statement override there lives in `store/sqlserver.py`, which was held by other in-flight
>    work. `build_coordinator` therefore does not pass the clamp to `SqlServerCoordinator` at all —
>    naming a bound that does not bind is the defect in 1, one level down. The **baseline stamp** did
>    land on both coordinators, and on SQL Server it is currently the only thing keeping the margin
>    real, which is why it was not scoped to Postgres with the clamp.
> 4. **The default is DERIVED from the margin, not a fixed 5.0 — a correction made inside this
>    increment, before merge.** The first cut shipped a constant 5.0 and it refused **this
>    repository's own failover configurations** at config load: `harness/load/profiles/failover.toml`
>    (fence 4.0 / TTL 6.0, margin 1.2 s) and `tests/_failover_load_support.py` (fence 3.0 / TTL 5.0,
>    margin 1.4 s). Both `messagefoundry serve` subprocesses of a failover load run would have aborted
>    before the scenario started, because `harness/load/failover.py::_node_env` exports the fence
>    timeout and the lease TTL and no clamp. Deviation 1's condition — *a stock install loads cleanly*
>    — was met and was **not wide enough**: it tests one point in a two-dimensional space, and every
>    legitimate tight pair sat outside it. The shipped `EARLY-ADOPTER-GUIDE.md` makes that concrete by
>    telling operators to lower all three timings **proportionally**; under a constant 5.0 *every*
>    proportional lowering past the stock values was refused, so the first operator to follow the
>    shipped advice would have hit the guard and turned it off. A guard that refuses valid
>    configurations does not get tightened, it gets deleted.
>
>    The fix is arithmetic, not a weakening: unset now means `min(5.0, 0.5 × margin)`. A constant
>    cannot be right here, because the clamp's only requirement is `clamp < margin` and the margin is
>    a function of the fence/TTL pair. The 0.5 is deliberately the same fraction as
>    `pipeline.cluster._DEMOTE_BUDGET_FRACTION`, off the same margin: the teardown and a still-in-
>    flight renew are **concurrent**, both start at the fence moment, so each takes half and each is
>    strictly inside. An **explicitly set** clamp is still checked and still refused — never silently
>    shrunk to fit, which would make the check accept everything — and a fence/TTL pair with **no
>    margin at all** (`ttl − fence − fence_tick <= 0`, which `_fence_ordering` accepts: fence 4.0 /
>    TTL 4.5 orders fine and leaves −0.3) is refused before the clamp is resolved, naming the pair
>    rather than blaming the clamp. The derived value falls through the same check rather than
>    returning early, so a mis-retuned derivation is a refusal and not a silently oversized clamp.
>
> **What the baseline stamp is worth, stated once because the rest of this ADR still says otherwise in
> places now corrected.** The margin is `(t_exec + ttl) − (baseline + fence + fence_tick)`. With the
> baseline stamped at `t_return` the round trip's return leg subtracts from it directly and can drive
> it negative; with the baseline at `t_issue <= t_exec` it cancels, leaving `ttl − fence − fence_tick`
> as a floor whatever the round trip costs. So the clamp does **not** widen the detection margin. What
> it bounds is a different window: how long a renew this node issued *before* it self-fenced can still
> be in flight, re-extending the very lease it is standing down from. That is a liveness cost — a
> standby waits out an extension nobody wanted — not a split-brain one.

**Inc 1 — Postgres: fence every claim path + every terminal resolve. BUILT.** `_EPOCH_GUARD_CLAIM`
onto `claim_ready`; `_EPOCH_GUARD_RESOLVE` onto the eight terminal resolves (`dead_letter_now`,
`mark_done`, `mark_batch_done`, `complete_with_response`, `ingress_handoff`'s two DEAD branches,
`mark_failed`, `mark_batch_failed`, `dead_letter_batch`). A rejected resolve rolls back **whole** and
re-pends (D1). `set_leader_epoch(None)` removed from `_stop_graph` (C4), with the D2 re-stamp. No DDL.

**Dropped from Inc 1 (D10):** the additional own-owner promotion-recovery statement. It must be
lease-expiry-bounded to be safe, and every claim stamps `lease_until = now + lease_ttl_seconds`, so in
the promote -> demote -> re-promote-in-one-process case it is a no-op exactly when it would be needed;
once the lease *has* expired the owner-blind sweep already covers it. Deferred, not silently skipped.

*Tests, as built:* 13 runtime tests against a real Postgres + 8 **structural** tests enumerating every
`UPDATE queue ... SET status` site with a written reason for each unguarded one. The structural gate
parses the AST rather than slicing source, because `claim_fifo_heads` splits its claim across two
adjacent literals with a comment between them and a line-oriented regex cannot see it.

> **A gate is evidence only once it has been shown to fail.** The first version of that structural test
> keyed on whether a method *mentioned* `_EPOCH_GUARD_CLAIM`. Deleting `{epoch_guard}` from
> `claim_fifo_heads`' SQL — the exact regression it exists to catch — left the mention intact and the
> gate stayed **green**. It now keys on the emitted SQL, and the mutation is confirmed red.

**Inc 2 — SQL Server: periodic in-flight recovery. Blocking for Inc 3, not for Inc 1.** A leader-gated,
age-based sweep (`status='inflight' AND updated_at < @cutoff`) reached through a **new** capability, not
by satisfying the `hasattr` gate; restructure the promotion path so the unconditional
`reset_stale_inflight` still runs. Its own named cutoff setting, sized **above the longest legitimate
claim-to-terminal hold**, not merely above skew.
*Independently valuable: it closes a strand that exists today with no HA scenario involved.*

**Inc 3 — SQL Server: the same fences. BUILT 2026-09-26 (BACKLOG #1497).** `claim_ready` and the
terminal resolves. No stored-procedure redeploy — every disposition is ad-hoc SQL. **Gate:** pin
empirically, on the live CI leg, whether a coroutine cancelled mid-`execute` leaves an aioodbc
transaction committed or rolled back (`except Exception: await conn.rollback()` does **not** catch
`CancelledError`). If it commits, say so rather than claiming a proof. **Measured 2026-09-26: rolled
back.** The runs, the one exception, and what shipped are in *Inc 3, as built*, after Inc 2's section.

> ⚠️ **Inc 2 is MIS-SPECIFIED above; do not build it as written.** It proposes an owner-blind, age-based
> periodic sweep. The verified defect is narrower — there is no recovery at **graph re-start**, because
> `RegistryRunner.reload()` is a quiesce-and-swap that calls no recovery — and the right fix is a scoped
> reset there. An age sweep on SQL Server has **no populated `owner` column** to discriminate with, so it
> would re-pend rows a live leader is actively working. Re-scope before building.

### Inc 2, RE-SPECIFIED — scoped in-flight recovery at graph re-start (2026-09-10, BACKLOG #1497)

**This replaces the "periodic sweep" paragraph above. The paragraph is kept, not deleted, because other
documents quote it; the warning immediately above it is what made this rewrite necessary.** It was
built on 2026-09-25 with a narrower scope; the note at the end of this section says what shipped and
where it departs from the text below.

**The defect, re-stated in one sentence.** A row left INFLIGHT by a graph re-start is never recovered on
SQL Server, because `reload()` calls no recovery and the backend has no periodic sweep to fall back on.

**Verified against the tree, 2026-09-10.** `RegistryRunner.reload` quiesces every inbound source, swaps
the registry, restarts listeners, re-arms workers and reconciles outbounds. It calls neither
`reset_stale_inflight` nor `recover_on_promotion`, and `reclaim_expired_leases` has zero definitions in
`store/sqlserver.py`. On Postgres that costs latency and nothing else; on SQL Server the only recovery
is the on-promotion `reset_stale_inflight`, so a row stranded by a reload waits for the next promotion.

**The code already says both things, and one of them is wrong.** Two comments in `wiring_runner.py`
call `reset_stale_inflight` *"startup/DR-only"*; two others promise the tail is *"recovered in order by
`reset_stale_inflight` on the next start/reload"*. The second spelling is false today. It is also the
premise the cooperative-stop paths lean on, which makes correcting the comments part of this increment
rather than a tidy-up beside it — the comments are how the next reader concludes the strand cannot
happen.

**What to build.**

1. A **scoped** reset invoked from `reload()`, recovering only rows this runner's own quiesce left
   INFLIGHT — bounded to the inbound/outbound names in the *old* registry, and run while intake is
   already quiesced, before step 2's listener restart.
2. It reaches the store through a **new, distinct capability**, never by satisfying the existing
   `hasattr(self.store, "reclaim_expired_leases")` gate. Satisfying that gate makes
   `_leader_maintenance` non-None, the promotion path's `if` wins, the unconditional
   `reset_stale_inflight` becomes dead code, and `recover_on_promotion` calls a method SQL Server does
   not have. That trap is recorded under *"Why this and not the alternatives"* above and it has not
   moved.
3. **Correct the two `"next start/reload"` comments in the same change.** Either they become true
   because this ships, or they say `start` alone. Leaving them is the compensating-control-on-a-false-
   premise defect CLAUDE.md §11 forbids.

**What NOT to build, and why the scoping is the whole point.** No owner-blind age sweep. SQL Server's
claims write `owner = NULL`, so an age predicate has nothing to discriminate with and would re-pend
rows a live leader is mid-delivery — converting a bounded strand into unbounded duplication on every
long-held lane. Scoping to the re-starting graph's own rows removes the need for a discriminator
entirely: the runner knows which lanes it just quiesced. It also removes the **cutoff setting** the old
specification required (*"sized above the longest legitimate claim-to-terminal hold"*), which was a
number nobody could size without the same information the scope already carries — and a `[cluster]`- or
`[store]`-scoped setting is invisible to the posture completeness floor (Consequence 8).

**What this does NOT close.** A row stranded by a **crash** rather than a reload is still recovered only
at the next promotion on SQL Server. This increment is about the re-start path, which is the one that
happens on a healthy node with no HA event at all. Say so rather than letting a green acceptance
criterion read as "SQL Server now recovers in-flight rows".

**Sequencing is unchanged.** Inc 2 still blocks Inc 3: GAP 1's *recovery closure* criterion — after a
fenced write the row is resolved within a bounded time — cannot pass on SQL Server until some recovery
path exists. Re-scoping narrows what Inc 2 builds; it does not make Inc 3 independent.

> **This sequencing claim did not hold, and Inc 3 was built without leaning on Inc 2 (2026-09-26).**
> A recovery path already existed: D1 makes the fence re-pend its own residue, and the successor's
> promotion reset is the backstop. The reasoning and its two tests are in Inc 3's as-built note.

> **What shipped, 2026-09-25 (BACKLOG #1497), and three places it departs from the text above.**
> A per-lane worker can return mid-batch with the rest of its claimed batch INFLIGHT. At least these
> paths do it: the STOP `internal_error` policy, an inbound a reload removed, and on the delivery
> worker a credential fault or a leadership loss before send. Before this, that tail waited for the
> next start on SQLite and on SQL Server (or a promotion there). On clustered Postgres the leader's
> `reclaim_expired_leases` sweep collected it after its lease expired, and still does.
>
> - **Layer 1, at the source.** The router, transform and delivery workers call
>   `RegistryRunner._release_tail_on_stop` as they return on a STOPPED outcome. It hands the rows
>   behind the one that stopped to `release_claimed`, which touches only rows still INFLIGHT and
>   undoes the claim's `attempts` increment. The transform worker passes its whole batch, which the
>   INFLIGHT guard makes safe. The pooled `_run_lane` already released its tail the same way, so
>   one STOP now leaves the same queue state in both claim modes. The response worker claims one row
>   at a time and has no tail. It does nothing on a node that has lost leadership: the release is
>   unfenced, and those rows belong to the successor's promotion recovery, which may already have
>   re-claimed them. The leadership-lost path therefore still releases only its own head, as before.
> - **Layer 2, the reload backstop.** `RegistryRunner._recover_stopped_worker_residue` runs inside
>   `reload()` after step 1's quiesce and before step 2 restarts the listeners, under
>   `_reload_lock`. It re-pends the INFLIGHT rows of every lane whose per-lane worker has
>   **returned** normally, through `reset_stale_inflight(stage=, owned=)`. It catches a Layer 1
>   release that failed. It too does nothing off the leader, for the reason the engine's
>   `_start_graph` gives for never running the reset in clustered mode outside promotion. A failure
>   logs and leaves the rows for the next start, and the call sits inside the reload's rollback
>   `try`, so it can never leave intake down.
>
> `tests/test_adr0157_inc2_reload_recovery.py` covers both layers: the router, transform and
> delivery STOP paths, the removed-inbound path, the backstop end to end on the real reload, the
> leadership gate on both layers, and a table of worker states. Nine mutations were each confirmed
> red, one per guard and per call site.
>
> 1. **The reload scope is the worker's state, not the old registry's names.** The tree disagreed with
>    the premise of point 1. `reload()`'s quiesce stops the inbound *sources* only. It stops no
>    worker, and outbound workers keep draining by design. So the quiesce itself leaves nothing
>    INFLIGHT, and "every name in the old registry" includes lanes whose worker is mid-send.
>    Re-pending those is a duplicate and a FIFO break. A returned worker holds nothing, and each lane
>    has one consumer (ADR 0059), so its rows are safe. A worker that raised is skipped, because its
>    done-callback respawns it. A cancelled one is skipped, because only teardown cancels. A lane the
>    pooled OUTBOUND dispatcher holds is skipped too. The old-registry bound would also have
>    **missed** a real case: an inbound removed by one reload and restored by a later one is not in
>    the later reload's old registry.
> 2. **The reload-only design was the wrong depth, so the fix moved to the source.** An operator
>    `start_*` or `restart_*`, or an alert rule's `control_action` auto-restart on the
>    `connection_stopped` alert the STOP policy raises, re-arms a returned worker without a reload.
>    The re-armed worker is alive, so every later reload skips its lane, and the tail would have
>    waited for a start while newer rows drained past it. Layer 1 closes that; Layer 2 is kept as the
>    backstop. Neither layer adds a store method. Layer 2 reuses the ADR 0073 ownership-scoped
>    `reset_stale_inflight`, which the `Store` protocol requires and all three backends implement and
>    test. That meets point 2's purpose: nothing probes `reclaim_expired_leases`, so the promotion
>    path's `hasattr` gate cannot move. Layer 2's reset does not undo the claim's `attempts`
>    increment, as Consequence 4 records; Layer 1's release does.
> 3. **The comments were half-corrected already, then had to move again.** BACKLOG #1611 Part A
>    (engine PR 1164) had rewritten the two *"next start/reload"* comments to say *"next START ... NOT
>    on a reload"*. That was true on its day. The two sites are the removed-inbound path, and they now
>    say the worker releases its tail as it returns. The three *"startup/DR-only"* comments are about
>    a **cancelled** worker, which neither layer covers. They now say that plainly.
>
> **What this still does not close.** A crash strand on SQL Server still waits for the next start or
> promotion. If a Layer 1 release fails and a `start_*` door re-arms the worker before any reload,
> the tail waits for the next start: the re-armed worker is alive, so the backstop skips its lane.
> A leadership-lost tail still waits for the successor's promotion recovery, and strands if no node
> takes over, exactly as before. Rows orphaned while their worker stays **alive** are out of scope,
> because nothing can tell them from rows that worker is sending. The #1611 re-pend covers the
> common case of that shape. Because of that limit, Inc 2 as built is **not** a recovery path for a
> fenced write's residue on a live lane. Whoever builds Inc 3 should re-read the sequencing paragraph
> above against this note rather than treat it as satisfied. *(Done 2026-09-26: Inc 3 does not need
> it. See Inc 3's as-built note.)*

### Inc 3, as built — SQL Server fences on a measured cancel premise (2026-09-26, BACKLOG #1497)

**The gate's answer: a cancelled coroutine's transaction rolls back, and never commits, in every case
that gave a reading.** One case gave none, and the table says which. Hosted CI
measured it on a branch that exists only for the measurement and is never merged
(`b137-1497-inc3-probe`, file `tests/test_adr0157_inc3_cancel_probe_sqlserver.py`). The runs are
36219288548 (round 1) and 36223227696 (round 2). Round 2's jobs are 108352322839 (SQL Server 2025) and
108352322940 (SQL Server 2022); grep their logs for `ADR0157-INC3-PROBE`.

| Case, cancelled mid-`execute` | SQL Server 2022 | SQL Server 2025 |
|---|---|---|
| The store's usual transaction pattern | rolled back | rolled back |
| `mark_done`, blocked on the finalize applock | rolled back | rolled back |
| `claim_ready`, blocked and then completing | rolled back | no reading: the child process crashed natively |

- The row locks cleared when the abandoned statement finished, 1.5 to 3.5 seconds after the cancel.
- The next borrower of the pooled connection read `@@TRANCOUNT = 1`. A brand-new connection reads the
  same, because the store runs with implicit transactions, so that is the baseline and not a leak.
  Round 1 printed `LEAKED_OPEN_TXN` for the same number because it had no baseline to compare with.
  Round 2 added that control, and the round 1 verdict is withdrawn.
- **The mechanism, by reading.** The ADR's worry was right: each method's `except Exception` never
  sees a `CancelledError`. It does not matter, because `_acquire` catches `BaseException` (BACKLOG
  #348, ADR 0159). `_release_dirty` then takes the connection out of the pool and closes the raw
  pyodbc handle off the event loop, and a pyodbc close rolls back uncommitted work.

**The one exception, by reading and not measured: `claim_fifo_heads`.** Its shielded `finally` runs
`SET LOCK_TIMEOUT -1;` and then `_commit` on every exit the fold does not cover, a cancellation
included. So a cancel there can COMMIT what its claim statement did. **The fence needs nothing more
there.** The claim statement carries the claim guard on its probe and on its UPDATE, so anything that
commit makes durable was epoch-checked inside that statement. A fenced claim claims zero rows, and the
kept-versus-claimed mismatch path rolls back before the `finally` runs. What such a commit can leave
behind is a claimed row with no worker. That is cancellation residue, not a fence gap. The next start
collects it, and on a demotion so does the successor's promotion reset, because the claim ran before
the successor's epoch bump. It is recorded here and not fixed here.

**Out of scope, and kept out of the tests.** The cancel path can crash pyodbc natively in
`SQLColAttributeW` when a handle is closed while the abandoned statement still runs; that is the
2025 `claim_ready` row above. It is a separate ledger item. No Inc 3 test cancels a statement
mid-flight.

**What shipped.**

- `claim_ready` carries the claim guard on its UPDATE, the placement the FIFO claims and the Postgres
  twin use. With no epoch armed its SQL is character-identical to before.
- The same eight terminal resolves as Inc 1 carry the resolve guard: `dead_letter_now`, `mark_done`,
  `mark_batch_done`, `complete_with_response`, both DEAD branches of `ingress_handoff`, the DEAD
  branch of `mark_failed` and of `mark_batch_failed`, and `dead_letter_batch`.
- A rejection raises a sentinel inside the transaction, so the method's own `except Exception` rolls
  back the queue flip, the ledger row, the event row and the finalize together. A context manager
  entered outside `_acquire` then counts `fenced_writes`, logs a WARNING and re-pends through the
  unguarded `release_claimed` (D1), after the connection is back in the pool.

**Three places it differs from Postgres, each with a reason.**

1. **`ISNULL`, not `COALESCE`.** SQL Server expands `COALESCE(subquery, x)` into a `CASE` that runs the
   subquery twice. An epoch bump committed between the two reads could give the two halves different
   answers. `ISNULL` runs it once and keeps its `BIGINT` type.
2. **A rejection is read from an `OUTPUT inserted.id` rowset,** where Postgres parses the command
   tag. A fenced UPDATE carries the OUTPUT clause, and an empty rowset is the rejection. The unfenced
   UPDATE carries no OUTPUT and reads nothing, so it stays character-identical.

   > **Corrected 2026-09-26, on PR 1576's first CI run.** The first build read `cursor.rowcount`, and
   > this item said a gated test pinned that the count arrives under `SET NOCOUNT ON`. **That was
   > false, and the test that said so failed** on both SQL Server legs (jobs 108370811011 and
   > 108370810994). With `SET NOCOUNT ON` in force for the session, a guarded UPDATE that matched no
   > row did not report 0, so a rowcount check did not fire. The exact value is not recorded; the
   > failing assertion shows only that it was not 0.
   >
   > **What that says about production is narrower, and it is a reading, not a measurement.** That
   > test turned NOCOUNT on with an unparameterized `SET NOCOUNT ON;`, which lasts for the session.
   > Every production site found that sets NOCOUNT (the finalize applock, `_render_batch`, the claim
   > batch and procs, `list_fifo_lanes`) runs it inside a parameterized statement or a procedure, and
   > SQL Server restores NOCOUNT when that call returns. One gated test backs this:
   > `tests/test_sqlserver_store.py::test_resend_plain_parity_ss` passes on both legs, and it needs
   > `cursor.rowcount` to read exactly 0 right after the applock on the same cursor. So the first build
   > was probably not inert in production. An earlier revision of this note said it would have been
   > inert "on almost every write"; that claim rested on a session-persistence premise the evidence
   > above contradicts, and it is withdrawn.
   >
   > The fence reads the OUTPUT rowset anyway. SQL Server returns that rowset whatever NOCOUNT says,
   > as the claim paths already rely on, so the fence no longer depends on a session setting nobody
   > can see at the call site. Two gated tests force a session-wide `SET NOCOUNT ON` on every cursor
   > and check both directions. That is a stress state, not the production state.
3. **The claim guard became one constant.** The three FIFO claims carried it as an inline literal. It
   is now `_EPOCH_GUARD_CLAIM`, byte-identical, and a test pins that.

**Recovery closure needed nothing from Inc 2, so "Inc 2 blocks Inc 3" did not hold.** That claim
assumed a fenced row is left INFLIGHT for recovery to collect, which is what C3 said before D1
corrected it. Two paths now resolve a fenced row in bounded time on SQL Server:

1. **D1, at once.** The fence re-pends its own residue, so a successor claims the row immediately.
2. **The promotion reset, if D1 fails.** The fence fires only after some node's fresh acquire bumped
   the epoch. Every claim path is fenced now, so a row this node still holds was claimed before that
   bump. The successor's `_start_graph` runs `reset_stale_inflight()` after the bump, which re-pends
   it.

Neither uses Inc 2's layers. Inc 2 as built still earns its place, but for a different strand: the
rows a stopped worker leaves behind.

**Tests.** `tests/test_adr0157_sqlserver_fence_offline.py` has 16 tests and is not gated, so it runs
on every leg. It holds the structural gate over every `queue` status write in `store/sqlserver.py`,
the twin of `tests/test_adr0157_fence_scope.py`, and behaviour tests against fake cursors. Its fake
cursor reports a row count of `-1` on every statement, as under NOCOUNT, so a fence that trusts
`rowcount` fails there. Eleven mutations were confirmed red against the first build. After the
correction above, seven more were confirmed red against the OUTPUT mechanism, including a return to
reading `rowcount`.
`tests/test_adr0157_sqlserver_fence.py` has 16 tests and needs a real server. It runs only on the
hosted `sqlserver-store` legs, in the catch-all step of `.github/workflows/ci.yml`. It mirrors the
Postgres runtime tests. It adds the two NOCOUNT tests and both recovery-closure paths above.

**What this still does not close.**

- Consequence 1(c): a promote, demote and re-promote in one process passes every guard, on both
  backends. Only a per-claim token closes it.
- The SQL Server renew still inherits `[store].command_timeout` (Inc 0, deviation 3).
- If D1 fails and no node ever acquires the lease again, the row stays INFLIGHT. No node is leading
  then either, so nothing else moves.
- A cancel that commits a `claim_fifo_heads` claim leaves the row for the next start or promotion, as
  above.
- A laptop run proves nothing about the T-SQL. The runtime tests skip without a server.
- At least six other store methods decide a write on `cursor.rowcount`, among them `resend_to`'s
  exactly-once gate, `reingress`, the attachment increfs, `rekey_audit_chain` and
  `upsert_alert_instance`. They are correct only while no session-wide `SET NOCOUNT ON` is in force.
  By the reading above none is; that is not measured for a zero-match statement in general.
- **Flagged for a decision, not built.** C1 leaves `mark_failed`'s retry branch unguarded, and on SQL
  Server it has no `status='inflight'` conjunct either. So a stalled ex-leader whose send then fails
  can re-pend a row the successor already finished as DONE, and the row is sent again. That is a
  duplicate, which the invariant permits, but it also writes a `failed` event on a PROCESSED message.
  A status conjunct on the retry branch would stop it without risking a strand, because SQL Server
  has no owner-blind lease sweep for such a conjunct to fight. This ADR does not decide that.

**Inc 4 — `TeardownReason` + bounded, concurrent source stop (DEMOTE only). BUILT.** The enum lands
**here**: `_teardown_unsafe` is the single shutdown path, so bounding it unguarded would change
single-node SQLite shutdown, which the parity constraint forbids. Snapshot `list(self._sources.items())`
before the first await. The bound is applied **at the call site** — never by editing transport constants,
which would make `transports/` know about clustering and violate the one-way dependency rule (§4).

**Corrected from the draft (D6): one phase-level `asyncio.wait`, NOT a semaphore with a per-source
`wait_for`.** The semaphore form costs `ceil(N/C) x budget` — ~63s at the 1,500-connection target
against an ~8s margin. `asyncio.wait` also never cancels its awaitables, so "abandon, don't cancel" is a
property of the primitive rather than of an `asyncio.shield` token a later edit can silently drop.

**Abandonment is socket-safe, and only socket-safe.** The four `asyncio.start_server` sources
(MLLP/TCP/X12/HTTP) call `server.close()` in their synchronous prologue. **DICOM does not** — it releases
its port inside `await to_thread(server.shutdown)`, so an abandoned DICOM stop can still hold the port at
re-promotion. File/RemoteFile/Database/Timer only set an Event, but each is leader-gated and parks on that
Event, so an abandoned one finishes at most its single in-flight scan. State this per connector; do not
write "every source".
*Tests:* N parked sources → wall clock is max(), not sum(); a re-promotion after an abandoned stop cannot
double-bind; SHUTDOWN remains byte-identical.

**Inc 5 — DEMOTE ordering + cooperative quiesce + edge trigger.** Under DEMOTE only, move the dispatcher
block above the source loop and split `d.stop()` into a cooperative `quiesce()` (no `task.cancel()`, so
serializers reach a terminal transition and leave zero rows INFLIGHT) with a hard-cancel fallback. Add a
sync, never-raise `on_demote` hook fired from `_check_fence` — safe because it is pure in-memory, so
`.cancel()`/`Event.set()` preserve its no-DB-I/O property.
*Tests, as built:* 21 non-env-gated tests. The `_running` regression (a raised or cancelled teardown
still leaves the node re-promotable, via a `finally` containing no `await`); abandon-not-cancel;
max-not-sum at **N = 200**, because a semaphore of 8 or 64 is structurally incapable of showing the
defect at small N; both demotion edges on both coordinators; and a parity sentinel proving single-node
reaches no DEMOTE-only statement.

**The `cluster_sqlserver.py` compile-time Protocol guard cannot backstop the hook.** It asserts only
assignability to `ClusterCoordinator`, which deliberately does not carry `set_on_demote` (widening that
`@runtime_checkable` Protocol breaks a standalone test stand-in — S3). Omitting the SQL Server twin would
type-check clean. The tests are the only real backstop, so they pin both coordinators explicitly.

---

## Consequences

**What this buys.** A durable predicate evaluated at write time against the authoritative lease row,
which holds when the timing argument fails — and the timing argument *has* failed once already (F3). The
fence can reject an ex-leader's `mark_done`; it cannot un-send its HL7. **If only one thing ships, ship
the fence.**

**Detection is not constraint.** Preconditions on the write are the **detection** half; something has to
make the peer stop, or detection only narrows the window. An ADR that shipped C1 alone would let a
reviewer conclude the problem was solved while a demoted leader is still mid-write.

### What remains true after this ships

1. **The fence's coverage is narrower than "demotion".** The epoch bumps only on a **fresh acquire** and
   is unchanged on a renew by the same owner. Three cases: (a) demotion *with* takeover → fence armed —
   the split-brain case that matters; (b) self-fence with no takeover → fence inert, but there is no
   competing writer; (c) promote → demote → **re-promote in the same process** → the store's cached epoch
   is per-store-**instance**, so a term-N straggler evaluates `N+2 <= N+2` and **passes**. Case (c) is a
   genuine residual that only a per-claim token closes. Anything stronger than this paragraph repeats the
   F3 pattern.
2. **The ex-leader is never "quiescent."** Do not use that word. A message mid-handler finishes its commit
   and its ACK during the grace, and Inc 4 abandons an overrunning `stop()`. That is *correct* under
   count-and-log — the body is durable, the successor drains it, the ACK is honest — and it is a
   split-brain-shaped surprise that today's unbounded wait merely hides.
3. **Duplicates go up on the failover path, and the quiesce budget is a guess.** ADR 0066 §11 records
   failover duplicate/ordering paths as **unmeasured**; this is the first thing to exercise them. Measure
   before adopting the budget.
4. **Recovery re-pends burn retry attempts.** `reclaim_expired_leases` does not decrement; only
   `release_claimed`/`reschedule_claimed` do. A flapping leader can dead-letter deliverable traffic
   without a single delivery having failed. Pre-existing, amplified here.
5. **Two silent ordering traps.** Restoring `set_leader_epoch(None)` to `_stop_graph` looks like tidying
   and disarms the fence; wrapping teardown from outside makes a node permanently un-re-promotable. Both
   need pinned tests, not comments.
6. **Rolling upgrade skew.** No DDL, so the upgrade is clean — but the guard protects only when the
   **straggler** runs new code, and in the natural sequence the straggler is the *old* leader. The fence
   is live only after the last node is upgraded.
7. **DR can invert the guard.** `leader_epoch` restarts at **1** whenever the row is absent. After a cold
   restore, a fresh leader holds 1 while a retained stale node caches 5, and `1 <= 5` **passes** — the
   guard is not merely disarmed, it favours the stale node. The restore path must force the epoch forward.
8. **A new `[cluster]`-scoped setting is invisible to the posture completeness floor.**
   `tests/test_security_posture_defaults.py:203` iterates `SecuritySettings.model_fields` only, so no
   `[store]`- or `[cluster]`-scoped deviation can trip it (BACKLOG #333). Inc 0's setting lands
   into that gap. Inc 2 as built adds no setting.
9. **Out of scope, deliberately.** The in-claim cross-owner reclaim statements stay unfenced this pass —
   Postgres-only exposure. Self-theft by the owner-blind sweep is a **lease-sizing** bug, not a leadership
   bug.

**Hot path:** the guard is a non-correlated scalar subquery on a PK-keyed one-row table spliced into an
UPDATE that already runs — zero added round trips, against methods that already pay a `SELECT`, a ledger
insert, an event insert and a finalizer call. Expected unmeasurable at 520 ev/s; bench it anyway.

### Why this needs a mechanism, not a documented rule

F3 was not an isolated slip. On the day this ADR was written, several sessions working unrelated
subsystems each hit the same reasoning failure — a control whose justification was asserted rather than
enforced. **That general class, its taxonomy and its instances are ADR 0158's subject, not this one's.**
This section keeps only what bears on the decision above.

Three findings from it are load-bearing here:

- **The discipline was already written down and did not bind.** CLAUDE.md §11 already forbids a
  compensating control resting on a false premise, and the project already had standing guidance to make
  a gate fail on purpose before trusting it. F3 happened anyway — and the commit that corrected F3
  enumerated the affected sites and **missed one**, which is the same defect one level up. A rule that
  has already failed in this exact file is not a remedy for this exact file.
- **Attention does not enforce it, including expert attention aimed directly at it.** One session built a
  tool specifically to catch this class, wrote the discipline into its own docstrings, and shipped two
  instances of it inside that tool; both were caught by a mechanism, neither by review.
- **Detection is a stopgap, demonstrated.** A PR fixing a CI-capacity failure was itself stalled by a
  merge-queue failure *while two watchers ran specifically to catch that*. The watchers fired correctly.
  The stall happened anyway.

**Applied to this ADR:** C1 (a precondition on the write) is *detection* — it establishes that a write is
illegitimate at the moment it is attempted. C6 (a bounded, enforced demotion stop) is *constraint* — it is
what actually makes the peer stop. Shipping C1 alone narrows the window and leaves a reviewer entitled to
conclude the problem is solved while a demoted leader is still mid-write. That is why both are in the
Decision, and it is the one thing this ADR should not be talked out of.

**The specific gap that argues for C6:** "the ex-leader has stopped" is a state with **no clearing
evidence**. Nothing anywhere observes it. The fence *fires* on an observable basis — renew timeout
elapsed — and then reports nothing about whether the work it was fencing actually ceased. A control needs
an observable basis for firing *and* for clearing; today this one has only the first.

*See ADR 0158 for the general class, its instances across subsystems, and the proposed lint.*

---

## Test gaps this closes

**GAP 1 — the post-send fenced write.** The interleaving that decides adoption: the ex-leader's `send()`
returns AA, then its `mark_done` is fenced. No test exists, because these methods currently cannot fail.

- Both server backends: claim under epoch N; bump `leader_lease.leader_epoch` out of band; call
  `mark_done`. Assert the row is still INFLIGHT; **no `delivered_keys` row**; no `message_events` row; the
  message is not finalized; `fenced_write` incremented; AlertSink fired once.
- Repeat for `dead_letter_now` (must not flip a successor-delivered row to DEAD — a false terminal is
  functionally a strand until a human intervenes), `mark_failed`'s DEAD branch, `complete_with_response`,
  and both batch forms.
- **Negative twin** — same interleaving, epoch **not** bumped: the write must land. *A green guard is
  evidence only if it has been made to fail on purpose first.*
- **Mass-strand regression for C2** — delete the `leader_lease` row with the epoch armed, call
  `mark_done`, assert the write **lands**. Written against the claim's fail-closed predicate this test
  fails; that is the point.
- **Direction test for C1** — with the epoch bumped, `mark_failed`'s retry branch and `release_claimed`
  must **still land**.
- **Recovery closure** — after a fenced write the row is resolved within a bounded time. On SQL Server
  this **cannot pass before Inc 2**, which mechanically enforces the sequencing. *(Corrected
  2026-09-26: it passes without Inc 2. D1 re-pends at once, and the successor's promotion reset is the
  backstop. See Inc 3, as built.)*

**GAP 2 — independent node and DB clocks.** These are two clocks today and no fixture drives them apart:
`tests/test_cluster_lease.py:222-249` sets `a_mono.t` and `db_clock.t` in lockstep by hand, so it is
structurally incapable of seeing either the round-trip term or the `_fence_tick`. Construct: (a) fence
fires while the lease is still valid; (b) lease already expired when the fence fires; (c) node clock
frozen relative to the DB clock; (d) node self-fenced but the lease still live with no successor — writes
must still **land**. No case may produce a strand; duplicates permitted.

Plus the stalled-renew case. **The stock 30/30 `command_timeout` collision this line was written
against is gone on Postgres** — Inc 0 stopped the renew inheriting `command_timeout` — but the case it
was probing is not: a renew that stalls past the fence must still leave the fence rejecting post-claim
writes, i.e. Inc 1 holds where Inc 5's timing argument does not. **On SQL Server the collision itself
still stands**, since that renew still inherits `command_timeout`; construct it there.

**Standing gate, every increment:** `ruff check` + `ruff format --check`, `mypy` strict, `pytest`, and the
Windows CI legs. Local pytest **silently skips** the Postgres and SQL Server legs, so a green local run
proves nothing about anything above; delete `message_events` before any soak.
