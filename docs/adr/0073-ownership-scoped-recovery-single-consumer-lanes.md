# 0073 — Ownership-scoped recovery + single delivery consumer per outbound lane (N-active engine shards on one unified store)

- **Status:** Accepted (Build-B design ruled 2026-07-06 — owner-delegated: option (i), coordinator-assigned single consumer per outbound lane)
- **Date:** 2026-07-06
- **Related:** **amends [ADR 0037](0037-multi-process-sharding-l3.md)** (builds its deferred "shared single-db multi-shard mode" recovery) · **amends [ADR 0063](0063-no-split-store-unified-store-for-sharding.md)** (builds its named single-delivery-consumer-per-outbound-lane prerequisite; its "free-threading-first" gate was inverted by the [ADR 0053](0053-free-threaded-multicore-engine.md) 2026-07-06 re-scope) · [ADR 0066](0066-pooled-stage-claimers.md) (the pooled lane-provider seam the gate rides) · [ADR 0013](0013-increment-2-reingress-design.md) (the RESPONSE stage the scope must cover) · ADR 0070 (*reserved*, T17 infra-fault re-pends — lane-scoped by construction, see Decision) · [ADR 0048](0048-third-tier-disaster-recovery-standby.md) (DR activation reset, scoped here) · CLAUDE.md §2 (reliability + count-and-log invariants) · `docs/CLUSTERING.md` (the *other*, instance-owner recovery axis)

---

## Context

Engine sharding (ADR 0037) is the committed 45M/day scale-out: N `serve --shard` subprocesses partition
**inbound** connections, all sharing **ONE unified server-DB store** (ADR 0063). Measured near-linear
(~193 msg/s/engine; 383 msg/s @ 2 engines) with the store at ~6.5× headroom (B8). Two reliability gaps
blocked running N shards **concurrently active** in production:

1. **Cross-shard reset clobber.** A sharded engine gets the `NullCoordinator`
   (`reclaims_inflight()==False`), so every shard restart ran the **GLOBAL** `reset_stale_inflight()`
   (`pipeline/engine.py` startup): every `INFLIGHT` row of every stage — including rows a **live
   sibling shard** was actively processing — re-pended, and on SQL Server/Postgres their `owner`/
   `lease` columns stripped. Duplicate delivery + per-lane FIFO inversion on every shard restart.
2. **Outbound rows were not attributable to the delivering shard.** Outbound rows carry the
   *originating inbound's* `channel_id`; delivery lanes key on `destination_name`; and every shard ran
   a delivery consumer for **every** shared outbound. So the shard whose crash left a row `INFLIGHT`
   is not necessarily the shard owning its `channel_id` — a channel-scoped reset alone would duplicate
   (re-pend a row a sibling is mid-delivering) or strand (crash residue excluded by the filter — and
   **SQL Server has no lease sweep**, so nothing else ever recovers it). Worse, N concurrent
   head-claimers on one FIFO lane is itself a latent ordering hazard — exactly what ADR 0063:45-51
   deferred as the *single-delivery-consumer-per-outbound-lane* primitive.

Why not the row-claim `owner` column instead? SQL Server writes `owner=NULL` always ("parity only");
Postgres stamps `hostname:pid:uuid`, which does **not** survive a restart of the same shard. The only
attribution axis that is stable across a crash/restart **and** uniform across backends is the **config
graph** — inbound names + destination names. That is the axis built here.

## Decision

Ship **Build A + Build B together** (A alone is incomplete recovery under shared delivery).

### Build A — ownership-scoped `reset_stale_inflight`

- New value object `OwnedLanes(channels: frozenset[str], destinations: frozenset[str])`
  (`store/store.py`), and an additive kwarg on all three backends + the protocol:
  `reset_stale_inflight(now=None, *, stage=None, owned: OwnedLanes | None = None)`.
- `owned=None` (default) = today's unconditional global reset, byte-identical — the existing Postgres
  pinning test (`test_reset_stale_inflight_still_unconditional`) stays green untouched.
- `owned` given = per stage, rows are filtered by that stage's **lane key**: `channel_id` for
  ingress/routed/**response**, `destination_name` for outbound. An **empty set matches nothing** for
  its stages (the statement is skipped — never `IN ()`): recovering "no lanes" must never widen into
  "all lanes".
- SQL shape: keep the per-stage `(status, stage)` equality pair (the WS-B #703 `ix_queue_ready` seek)
  and add the lane list as a **residual** predicate — SQLite/SS a chunked `IN` (≤500 names/statement,
  inside the one transaction), Postgres `= ANY($n::text[])`. **No index hints** (the FIFO lane indexes
  are not seekable for this shape on SQLite/PG<17; the ready-index seek + residual filter is the plan).
- SS/PG still clear `owner`/`lease_expires_at` — now only on rows they re-pend. `attempts` is
  preserved by every reset variant (claims increment it), so crash-recovery cycles keep advancing the
  dead-letter counter.

### Build B — single delivery consumer per outbound lane (option i)

- **Assignment is a pure, deterministic derivation — "coordinator-assigned" with zero runtime
  coordination.** `owner_shard_of_destination(dest, ids)` (`pipeline/sharding.py`) is a rendezvous
  (HRW) hash — `hashlib.sha256`, never the salted builtin — over the **pinned shard universe**. Every
  process loads the same config, so every process derives the identical static map. Three properties
  the design leans on: restart-stable; **total over any lane name** (a destination dropped from config
  but still draining keeps exactly one owner); minimal disruption (adding/removing a destination never
  moves another lane).
- `filter_registry_for_shard` attaches `shard_id` + `all_shard_ids` (the pinned universe) to the
  filtered `Registry` **only when the config names >1 shard** — single-shard and unsharded processes
  carry `None` and keep byte-identical behavior everywhere (the ADR 0037 "single shard ≡ plain
  `serve`" promise holds).
- **The registry's outbound map stays FULL and every connector is still built** — the dead-letter
  sweeps, reload reconcile, DR parking and `/connections` all key off it. Only **claiming** is gated,
  at three points:
  1. **Wake boundary** (`RegistryRunner._wake_lane`): a producer wake for an OUTBOUND lane another
     shard owns — or a RESPONSE lane whose loopback inbound lives on another shard — is **dropped**.
     This is the single choke point for every producer wake (transform handoffs, retry re-wakes,
     response captures); without it, the pooled dispatcher's create-or-stick `mark_ready` would
     register the lane locally and make this shard a second concurrent claimer.
  2. **Pooled lane provider** (`_pooled_lane_provider(OUTBOUND)`): filters
     `registry.outbound ∪ built connectors` by the ownership **predicate** — deliberately not a
     registry-derived set, so a reload-dropped lane keeps draining on exactly its owner.
  3. **Per-lane spawn choke point** (`_spawn_worker`): no local delivery worker for a non-owned lane
     (start/reconcile/respawn all inherit the gate).
  Ingress/routed/response workers are already partitioned by the filtered inbound map. Cross-shard
  produce is discovered by the owner's sweep/idle poll — the **wake gap**: ≤0.25 s in pooled mode (the
  default) or per-lane with wake events off; up to **30 s** with `per_lane_wake=True` (a startup
  WARNING recommends pooled for sharded fleets).
- **T17 / ADR 0070 re-pends are lane-scoped by construction:** `reschedule_claimed`/`release_claimed`
  operate only on row ids from the caller's own claim batch, and claims are lane-gated — a shard can
  never re-pend a row it could not have claimed. No extra scoping needed.

### Call sites, refusals, and the ops surface

| Surface | Behavior |
|---|---|
| Engine startup reset | scoped iff sharded: `OwnedLanes(channels=filtered inbounds, destinations=owned_destination_set(...))`; else global. INFO log states what was recovered and that sibling lanes were left alone. |
| SS on-promotion reset (`_start_graph`) | **stays GLOBAL** — reachable only by the unsharded cluster, because: |
| `--shard` + `[cluster].enabled` | **REFUSED fail-closed at `serve`** (exit 2). The cluster lease is store-wide, so leadership would transfer *across shard ids*, and a promoted shard's scoped reset would permanently strand the dead prior leader's lanes (SS has no lease sweep; a standby skips the startup reset). Sharded HA = the supervisor's restart-on-exit. |
| Sharded `/config/reload` | **REFUSED (`WiringError`) when the new config's shard set differs from the pinned universe** — ownership is a pure function of the universe, and reload is per-process with no fleet coordination: a divergent map gives some lanes two concurrent consumers (FIFO inversion) and others zero (ACKed messages stall, unalerted). Same-universe reloads are safe (HRW minimal disruption); a shard-set change requires a coordinated full-fleet restart. |
| DR activation reset (`dr.py`) | scoped iff sharded (a sharded DR fleet activates shard-by-shard against ONE restored store — the second activation must not clobber the first); global on an unsharded DR box, where "no live siblings" genuinely holds. |
| Outbound controls (stop/start/restart) + require-stopped purge | **owner-only**: a non-owning shard 409s (naming the owner) instead of reporting a vacuous "stopped"/quiesced and unlocking a purge that would race the owner's live claims. The `_purge` dual-control executor skips fail-closed the same way. `/connections` destination rows expose `owner_shard`. |
| Non-owned-lane watchdog | sharded-only background task (30 s tick): every shard runs the existing buildup/stall threshold checks (pure `pending_depth` reads) over the outbound lanes it does **not** own. A hung (not crashed) owner is otherwise invisible — the supervisor's liveness test is process-exit only, and buildup/stall alerts fire only in the owner's delivery path. |

### Operational requirements (documented, some enforced)

- **Identical config across the fleet.** Already required by the (deliberately global) dead-letter
  sweeps at graph start; extended to sharding. **Never leave an un-applied config on disk** — the
  supervisor's restart-on-exit re-execs against the *current* disk config, so a crashed shard would
  adopt a config its siblings don't run.
- **Apply a (same-universe) reload to every shard's API.** A lane owned by a not-yet-reloaded shard
  drains when that shard's reload lands.
- A stray **unsharded** `serve` pointed at the fleet's store still runs a global reset (`owned=None`)
  — the same operator-error class as running two unsharded engines on one store today. Don't.
- **Removed-inbound residue** now strands `INFLIGHT` (was: re-pended to `PENDING` in a lane nothing
  drains). Recovery = restore the channel **and restart its owning shard** (was: reload sufficed).
  Deliberate: the observability loss is bounded (outbound lanes are watchdog-covered; a
  recovery-on-lane-add reload hook is a named follow-up).
- Per-shard `/stats` reports the **unified store** — never sum shard stats; `/connections` rows carry
  `owner_shard` so drain responsibility is attributable.
- An operator **pause on the owner is per-process state** — sibling watchdogs can't see it and may
  page on a deliberately-paused lane (throttled; the owner's `/connections` row disambiguates). A
  store-level pause flag is a named follow-up.

## Acceptance Criteria

- **AC-1** — WHEN `reset_stale_inflight` runs with `owned` on any backend, THE SYSTEM SHALL re-pend
  exactly the `INFLIGHT` rows whose stage lane key is in the corresponding owned set, leaving every
  other row's status (and, on SS/PG, `owner`/`lease`) untouched; an empty set recovers nothing.
  → `tests/test_ownership_scoped_reset.py` (SQLite) · `tests/test_shard_recovery_sqlserver.py` (SS)
  · `tests/test_postgres_store.py` scoped tests (PG; the unconditional pinning test unchanged)
- **AC-2** — WHEN a sharded engine starts, THE SYSTEM SHALL issue the scoped reset (its filtered
  inbounds + rendezvous-owned destinations); an unsharded/single-shard engine SHALL issue the global
  reset. → `tests/test_shard_recovery_engine.py`
- **AC-3** — WHILE sharded, THE SYSTEM SHALL claim an outbound lane on exactly ONE shard (per-lane
  workers, the pooled lane provider, and producer wakes all ownership-gated; a reload-dropped lane
  keeps exactly its owner). → `tests/test_shard_lane_ownership.py`
- **AC-4** — Two shard-filtered engines on ONE SQL Server store with overlapping destinations: after
  shard A "crashes" with residue at every stage and restarts, only A's lanes re-pend, B's in-flight
  rows are untouched, and the full drain shows zero loss, zero duplicate, per-lane FIFO, no stranded
  `INFLIGHT`. → `tests/test_shard_recovery_sqlserver.py` (the target invariant)
- **AC-5** — IF a sharded reload changes the shard universe, THEN THE SYSTEM SHALL refuse it
  (`WiringError` naming the sets); IF `--shard` is combined with `[cluster].enabled`, THEN `serve`
  SHALL refuse to start. → `tests/test_shard_recovery_engine.py`
- **AC-6** — WHEN an outbound control or purge targets a non-owned lane on a sharded engine, THE
  SYSTEM SHALL refuse (409 naming the owner / fail-closed skip in the approval executor) and SHALL
  expose `owner_shard` on `/connections` destination rows. → `tests/test_shard_lane_ownership.py`
- **AC-7** — WHILE sharded, THE SYSTEM SHALL alert on buildup/stall of a NON-owned lane past its
  thresholds (the hung-owner page). → `tests/test_shard_lane_ownership.py`

## Options considered

1. **Build B = deterministic single consumer per outbound lane (rendezvous over the pinned shard
   universe).** **CHOSEN** (owner-delegated ruling 2026-07-06) — ADR 0063's named primitive; gives a
   deterministic delivering shard so "reset the lanes I own" is exact; static v1 (a down owner's lanes
   queue durably until the supervisor restarts it); needs no supervisor↔shard channel because every
   process derives the same map from shared config.
2. **Shard-stable `owner` stamp on claim (option ii).** Rejected — SS writes `owner=NULL` today (new
   plumbing on every insert/claim path), PG's owner is restart-unstable by design, and it creates a
   second meaning for an existing column the cluster machinery already owns.
3. **Lease sweeps (option iii).** Rejected — SS has no lease sweep at all; PG's is cluster-leader
   machinery; expiry-gating startup recovery strands a just-crashed shard's rows for the TTL.
4. **Ownership as a registry-derived set instead of a total predicate.** Rejected (design review) —
   kills the deliberate "reload-dropped outbound keeps draining" guarantee: the dropped name is in no
   set, so its rows strand everywhere, then dead-letter at the next restart.
5. **Scope the SS on-promotion reset for a sharded cluster instead of refusing the combo.** Rejected
   (design review) — leadership crosses shard ids, so the scoped on-promotion reset *strands* the dead
   leader's lanes; the combo is refused fail-closed and the on-promotion reset stays global.
6. **Allow shard-set changes via rolling reload (dual-consumer window accepted).** Rejected (design
   review) — the failure direction is not only dual-consumer (degraded-but-safe) but **zero-consumer**
   (ACKed messages stall indefinitely, unalerted, possibly assigned to a shard process that does not
   exist). Refuse and require a fleet restart.

## Consequences

**Positive** — N-active engine shards on one unified store become crash-safe: recovery is exact
(self-residue only), delivery ordering gets a real single-consumer-per-lane invariant (closing the
latent N-claimer reorder hazard that existed whenever multiple shards ran), operators get truthful
controls + ownership attribution, and a hung owner pages via its siblings.

**Negative / risks**
- **Delivery loses locality**: a cross-shard send waits for the owner's sweep/poll (≤0.25 s default;
  30 s worst-case under `per_lane_wake=True`, warned). Cross-process wakes are a named follow-up.
- **A down/hung owner stalls its lanes** until the supervisor restarts it (crash) or an operator acts
  on the watchdog page (hang). v1 has no lane-ownership failover — deliberate (static assignment keeps
  recovery exact); the supervisor health-probe (hung-child restart) is a named follow-up.
- **Behavior change to the documented sharding model** (`sharding.py` docstring updated): outbounds
  are still shared *definitions*, but no longer shared *consumers*.
- **This ADR builds the mechanism; it does not certify the topology.** The acceptance bench — the
  throughput plan's **clean 4-engine no-loss point** (sustained, zero loss, per-lane FIFO on one
  store) — must pass before `docs/SYSTEM-REQUIREMENTS.md` flips N-active from "mechanism built" to
  "supported production topology". Bench note: read the no-loss verdict from the authoritative
  sink/drain signal, **not** the `/stats`-poller-sampled `in_pipeline` peak (known under-sampling bug
  being fixed in the connscale compare path).

**Out of scope (named follow-ups)** — the 4-engine no-loss bench; multishard-harness overlap mode +
a real `serve --shard` fleet kill harness (fold the ADR 0066 §8.2 pooled-vs-per_lane failover A/B ask
into it); `outbound(..., shard=...)` explicit placement override; lane-ownership failover; cross-shard
wake; recovery-on-lane-add at reload; store-level pause flag; supervisor health-probe restarts.
