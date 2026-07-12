# 0096 — Cluster leader preference & non-promotable standby

- **Status:** Accepted  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-07-12
- **Related:** [ADR 0048](0048-third-tier-dr-standby-priority-runprofile.md) · [CLAUDE.md §2 "Reliability invariant"] · BACKLOG #101 · builds on the self-fencing leadership lease (Workstream A2, `pipeline/cluster.py` / `pipeline/cluster_sqlserver.py`)

---

## Context

MessageFoundry active-passive HA elects a leader through an **unweighted, first-lease-wins race**: the
first node whose `_claim_or_renew_lease` INSERTs (or takes over an expired) `leader_lease` row becomes
leader and drains the graph. There is **no site preference, node priority, or non-promotable flag** in
`config/settings.py` `ClusterSettings` or the two coordinator modules.

A warm engine at a **remote DR site** therefore wins ~1-in-2 to ~1-in-3 of every *routine* leadership
transition (leader-host death, patching restarts, config restarts, DB blips), binds listeners, and
drives the **primary-site DB cross-WAN** (~7 commits × WAN-RTT per message) silently, with no
auto-fail-back. This is the blocker to ever running a DR engine **warm** — the only safe posture today
is a **cold** (service-stopped) DR box. The `[dr]`/ADR 0048 priority-threshold run-profile does not
help: it gates which *connections* start, never *lease acquisition*.

The forcing constraint is the CLAUDE.md **reliability invariant** — the self-fencing lease gives
at-least-once delivery and must keep exactly one active processor:

> "a leader that cannot renew within `leader_fence_timeout` … halts its leader work BEFORE the lease can
> expire, so a partitioned old leader stops processing before any standby can take over (the split-brain
> guard)."

Any preference mechanism must **not open a two-leader window**.

## Decision

Add two **per-node** `[cluster]` knobs, evaluated in the **expired-lease branch** of
`_claim_or_renew_lease` in **both** `pipeline/cluster.py` (Postgres) and `pipeline/cluster_sqlserver.py`
(SQL Server):

1. **`acquire_delay_seconds: float = 0.0`** — a take-over *handicap*. The take-over-of-an-**expired**
   predicate gains the delay on the **expiry side**: `lease_expires_at + delay < DB_now` (equivalently
   `lease_expires_at < DB_now − delay`). A node may claim an expired lease only once it has been expired
   for `delay` seconds on the **DB clock**, so a preferred (`delay = 0`) node — which may claim the
   instant the lease expires — wins the routine take-over race. The **renew** branch (`owner = me`)
   carries **no delay term**, so the current leader always renews at `DB_now` regardless of its own
   configured delay ("must not delay a renewal").

2. **`promotable: bool = True`** — a non-promotable standby. When `false`, the node **short-circuits to
   not-held before touching the DB**: it never inserts a fresh lease, never takes over an expired one,
   and does not renew. It can neither become nor remain leader; a node that *somehow* already holds
   leadership is demoted by `_maintain_leadership` on its next tick (a clean step-down), with the fence
   watchdog as the backstop.

Both are surfaced per-node in `GET /cluster/nodes` (durable `nodes.acquire_delay_seconds` / `promotable`
columns, written on register, read into `ClusterMember` → `ClusterNode`).

**No-two-leader argument.** Adding a non-negative `delay` to the *expiry side* makes the take-over
predicate **strictly stricter** than the base `lease_expires_at < DB_now`: `lease_expires_at + delay <
DB_now` implies `lease_expires_at < DB_now` for all `delay ≥ 0`. A handicapped node therefore claims at a
**later** real time than an un-handicapped node ever would — never earlier. Since the base predicate is
already safe (the old leader self-fences before `lease_expires_at`, because `fence < ttl`), the stricter
predicate is also safe. `promotable = false` only *removes* claim opportunities. So neither knob can
open a window in which two nodes consider themselves leader. A negative `delay` (which *could* claim
before expiry) is rejected at config load.

**Expired-lease-only semantics.** The delay governs **take-over of an EXPIRED lease** (the
routine-transition path). The very first election on an **empty** lease table has no `lease_expires_at`
to measure against and stays a plain race — cold bring-up ordering is controlled with `promotable` or
operator sequencing, not the delay.

**All-non-promotable caveat.** At least **one** promotable node must exist, or no node ever acquires the
lease and the graph never drains. An all-non-promotable cluster is a documented misconfiguration (not
guarded in code — a node cannot see its siblings' flags at config load).

**Rider — `[dr].activate` + `[cluster]` guard.** A cross-section `ServiceSettings` validator **refuses**
`[dr].activate = true` combined with `[cluster].enabled = true`. The DR run-profile gates *connections*,
not *lease acquisition*; a DR box that also contends for the cluster lease could win leadership and drive
the primary store cross-WAN. The intended warm-DR posture is a **non-promotable cluster member**
(`[cluster].enabled = true, promotable = false`), not a lease-contending `[dr]` box. A
provisioned-but-passive DR box (`enabled = true, activate = false`) may still coexist with cluster
membership.

**What it must not break:** the self-fencing lease + split-brain guard, at-least-once delivery, and
strict FIFO. Default `(delay = 0.0, promotable = True)` is **behaviourally byte-identical** to before —
`lease_expires_at + 0 < now` is exactly `lease_expires_at < now`, the promotable path never
short-circuits, and the added `nodes` columns default to `0`/`TRUE`.

## Acceptance Criteria

- **AC-1** — WHILE a node has `acquire_delay_seconds > 0`, IF an expired lease has been expired for less
  than the delay, THEN THE SYSTEM SHALL NOT let it take over.
  → `tests/test_cluster_lease.py::test_delayed_node_cannot_claim_within_the_delay_window`
- **AC-2** — WHEN a preferred (`delay = 0`) node and a delayed node both become eligible after a leader's
  lease expires, THE SYSTEM SHALL let the preferred node win the routine take-over race.
  → `tests/test_cluster_lease.py::test_preferred_node_wins_routine_expired_lease_race`
- **AC-3** — WHILE a node is the current leader, THE SYSTEM SHALL renew its lease without the acquire
  delay.
  → `tests/test_cluster_lease.py::test_delay_does_not_delay_the_current_leaders_renew`
- **AC-4** — WHERE a node is `promotable = false`, THE SYSTEM SHALL never acquire the lease (empty or
  expired) and SHALL touch no DB row to claim.
  → `tests/test_cluster_lease.py::test_non_promotable_never_acquires_empty_lease`,
  `::test_non_promotable_never_takes_over_expired_lease`
- **AC-5** — IF a `promotable = false` node somehow already holds leadership, THEN THE SYSTEM SHALL
  demote it cleanly on its next maintenance tick.
  → `tests/test_cluster_lease.py::test_non_promotable_already_leader_steps_down`
- **AC-6** — THE SYSTEM SHALL be behaviourally byte-identical at the default `(0.0, True)`.
  → `tests/test_cluster_lease.py::test_default_delay_zero_is_byte_identical_takeover`
- **AC-7** — IF `[dr].activate` is combined with `[cluster].enabled`, THEN THE SYSTEM SHALL refuse the
  config at load.
  → `tests/test_settings.py::test_dr_activate_with_cluster_is_rejected`
- **AC-8** — THE SYSTEM SHALL surface each node's `acquire_delay_seconds` + `promotable` in
  `GET /cluster/nodes`.
  → `tests/test_cluster.py::test_build_coordinator_threads_leader_preference_knobs`

## Options considered

1. **Per-node `acquire_delay_seconds` handicap + `promotable` flag, expired-lease-branch only** — the
   handicap is DB-clock arithmetic on the expiry side (provably no two-leader window); `promotable`
   short-circuits before the DB. **CHOSEN.** Minimal, backend-symmetric, byte-identical at defaults, and
   the delay reuses the existing lease clock so no new coordination primitive is needed.
2. **Integer node priority with a compare-and-swap "steal" of a live lease** — a higher-priority node
   preempts a lower-priority *live* leader. Rejected: preempting a live lease reintroduces the exact
   two-leader window the self-fence exists to prevent, and demands a priority column in the claim
   predicate + a graceful-handover protocol.
3. **Weight the delay by observed WAN latency / health probes** — auto-tune the handicap. Rejected:
   needs a health/latency signal the coordinator does not have, and `AUTO` DR promotion is already a
   deferred future mode (ADR 0048). A static operator-set delay is sufficient for the stated goal.

## Consequences

**Positive** — a warm DR engine can finally run as a **non-promotable** (or heavily-handicapped) cluster
member without winning routine leadership and driving the primary store cross-WAN; operators can SEE each
node's preference/promotability over the API; the split-brain guarantee is preserved by construction.

**Negative / risks** — a handicapped-only cluster has a `delay`-second leaderless gap on each routine
transition (bounded, intended); an all-non-promotable cluster elects no leader (documented caveat, not
code-guarded); the `nodes` table grows two columns (additive `ADD COLUMN IF NOT EXISTS` / `COL_LENGTH`
migrations, REL-1).

**Out of scope** — automatic/health-probe-driven promotion (ADR 0048 `AUTO`, deferred); preempting a
**live** lease; runtime mutation of the knobs (read once at construction — restart to change, like the
other lease timings); a cold-bring-up (empty-lease) handicap.
