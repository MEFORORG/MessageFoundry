# ADR 0157 — Demotion safety: fence scope on post-claim writes, and a bounded graph stop

**Status:** Proposed **Date:** 2026-08-01

> Proposed only. Nothing here is built. The two questions that need an owner decision are stated in
> **Decision** as C1 (do post-claim writes carry a precondition, and which ones) and C6 (does demotion
> get an enforced deadline, and what happens to an inbound that cannot meet it).

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

**C3 — A fenced write is all-or-nothing and a no-op to the caller.** Zero rows affected ⇒ roll back the
enclosing transaction (discarding the `delivered_keys` row, the `message_events` row and the
`_maybe_finalize_message` call), return via the existing `if row is None: return` shape, bump a
`fenced_write` counter, log WARNING, fire the AlertSink once.

Note honestly *why*: a persisted ledger row would record a **true** fact (`mark_done` is reached only
after a successful send), and the successor's H2 skip would then resolve the row without re-sending — so
rollback is not "avoiding a loss". We roll back because a ledger row without a resolved queue row is a
half-applied disposition asserted by a node that is not the authority. **Cost booked: one extra duplicate
per fenced resolve.**

**C4 — A demoted node retains its stale epoch; it does not clear it.** `_stop_graph` currently calls
`set_leader_epoch(None)`, reasoning that a demoted node should carry no stale token. **The polarity is
backwards:** the guard string is omitted entirely when the epoch is `None`, so `None` means *no fence*
while a stale token fails closed. Delete the clear, correct the comment. Safe because `_start_graph`
pushes `current_epoch()` unconditionally on every promotion and no API path resolves a queue row.

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

**Inc 0 — make the margin real.** Clamp the lease renew's own statement timeout well below
`(ttl − fence)` instead of inheriting `command_timeout`; capture `t_issue` *before* the renew and stamp
the fence baseline from it rather than after the round trip; config-load warning when
`command_timeout >= (ttl − fence)` — noting it fires on **stock defaults today** (30 vs 30), so ship it
with a defaults change or rely on the clamp alone.
*Test:* slow-renew fixture asserting the detection margin stays positive.

**Inc 1 — Postgres: fence every claim path + every terminal resolve.** `_EPOCH_GUARD_CLAIM` onto
`claim_ready`; `_EPOCH_GUARD_RESOLVE` onto the four resolves, the batch forms, and the RESPONSE-stage
re-ingress dead-letters. Drop `set_leader_epoch(None)` from `_stop_graph` (C4). Add an **additional**
own-owner promotion-recovery statement — do **not** widen `owner IS DISTINCT FROM`, which would re-open
engine-shard theft (ADR 0073). No DDL: `leader_lease.leader_epoch` already exists and back-fills
additively.
*Tests:* GAP 1 below; a **structural** test enumerating every `UPDATE queue SET status` site and asserting
each is guarded or in a reviewed allowlist.

**Inc 2 — SQL Server: periodic in-flight recovery. Blocking for Inc 3, not for Inc 1.** A leader-gated,
age-based sweep (`status='inflight' AND updated_at < @cutoff`) reached through a **new** capability, not
by satisfying the `hasattr` gate; restructure the promotion path so the unconditional
`reset_stale_inflight` still runs. Its own named cutoff setting, sized **above the longest legitimate
claim-to-terminal hold**, not merely above skew.
*Independently valuable: it closes a strand that exists today with no HA scenario involved.*

**Inc 3 — SQL Server: the same fences.** `claim_ready` and the terminal resolves. No stored-procedure
redeploy — every disposition is ad-hoc SQL. **Gate:** pin empirically, on the live CI leg, whether a
coroutine cancelled mid-`execute` leaves an aioodbc transaction committed or rolled back
(`except Exception: await conn.rollback()` does **not** catch `CancelledError`). If it commits, say so
rather than claiming a proof.

**Inc 4 — `TeardownReason` + bounded, concurrent source stop (DEMOTE only).** The enum lands **here**:
`_teardown_unsafe` is the single shutdown path, so bounding it unguarded would change single-node SQLite
shutdown, which the parity constraint forbids. Snapshot `list(self._sources.values())` (the live-dict
iteration across awaits is a latent `RuntimeError`), gather under a semaphore, wrap each `source.stop()`
in `wait_for` **at the call site** — not by editing transport constants, which would make `transports/`
know about clustering and violate the one-way dependency rule (§4).
*Tests:* N parked sources → wall clock is max(), not sum(); a re-promotion after an abandoned stop cannot
double-bind; SHUTDOWN remains byte-identical.

**Inc 5 — DEMOTE ordering + cooperative quiesce + edge trigger.** Under DEMOTE only, move the dispatcher
block above the source loop and split `d.stop()` into a cooperative `quiesce()` (no `task.cancel()`, so
serializers reach a terminal transition and leave zero rows INFLIGHT) with a hard-cancel fallback. Add a
sync, never-raise `on_demote` hook fired from `_check_fence` — safe because it is pure in-memory, so
`.cancel()`/`Event.set()` preserve its no-DB-I/O property.
*Tests:* **the `_running` regression test** (after a deadline-expired teardown the node can still
re-promote); both orderings asserted in one test so they cannot drift.

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
   `[store]`- or `[cluster]`-scoped deviation can trip it (BACKLOG #333). Inc 0's and Inc 2's settings land
   into that gap.
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
  this **cannot pass before Inc 2**, which mechanically enforces the sequencing.

**GAP 2 — independent node and DB clocks.** These are two clocks today and no fixture drives them apart:
`tests/test_cluster_lease.py:222-249` sets `a_mono.t` and `db_clock.t` in lockstep by hand, so it is
structurally incapable of seeing either the round-trip term or the `_fence_tick`. Construct: (a) fence
fires while the lease is still valid; (b) lease already expired when the fence fires; (c) node clock
frozen relative to the DB clock; (d) node self-fenced but the lease still live with no successor — writes
must still **land**. No case may produce a strand; duplicates permitted.

Plus `command_timeout >= leader_lease_ttl_seconds` (the stock 30/30 collision) with a stalled renew:
assert the config warning fires and the fence still rejects post-claim writes — i.e. Inc 1 holds where
Inc 5's timing argument does not.

**Standing gate, every increment:** `ruff check` + `ruff format --check`, `mypy` strict, `pytest`, and the
Windows CI legs. Local pytest **silently skips** the Postgres and SQL Server legs, so a green local run
proves nothing about anything above; delete `message_events` before any soak.
