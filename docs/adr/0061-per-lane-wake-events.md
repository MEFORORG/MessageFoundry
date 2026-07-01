# ADR 0061 — Per-lane wake events (targeted worker wakeup, default-OFF)

**Status:** Proposed · **Date:** 2026-06-30
**Relates-to:** ADR 0001 (staged pipeline — split router/transform/delivery stages), ADR 0013 Increment 2 (loopback re-ingress / response worker), ADR 0055 (group committer — reliability-core default-OFF precedent + poison-guard), ADR 0057 (B1 inline fast-path — the fused `_work.set()` at `wiring_runner.py:2052`), ADR 0058 (batch-claim — default-OFF `[store]` knob precedent), ADR 0059 (seq-only per-lane FIFO — "exactly ONE serial writer per (stage, lane-key)", asserted at `wiring_runner.py:1141-1152`), issue #285 (no-READPAST per-lane FIFO), CLAUDE.md §2 "Reliability invariant" / "Concurrency = asyncio", docs/throughput-roadmap.md B12, B11 `EmptyClaimCounters` (`wiring_runner.py:155`).

---

## 1. Context

The staged pipeline runs, **per inbound**, a listener + a router worker + a transform worker, and **per outbound** a delivery worker (+ a per-loopback response worker), supervised by `RegistryRunner` in `messagefoundry/pipeline/wiring_runner.py`. The per-stage wake events are **engine-wide singletons**: `self._ingress_work` (`wiring_runner.py:361`), `self._routed_work` (`:362`), `self._response_work` (`:365`), `self._work` (`:366`), plus `self._stop` (`:355`). Every router worker of every inbound waits on the **single** `_ingress_work` via `_wait_for_work` (`:2436`, waiter site `:1927`); every transform worker on the single `_routed_work` (`:2196`); every delivery worker on the single `_work` (`:1749`); every response worker on the single `_response_work` (`:2128`).

A producer that commits work for **one** lane sets the **whole-stage** event — the hot path is the listener at `:1663` ("wake the router worker to route the freshly-committed message"), the router→transform handoff at `:2094`, the transform→delivery handoff at `:2345`. That `.set()` wakes **all N workers of that stage**; each does an empty `claim_next_fifo` on its own (different) lane and finds nothing. This is the **thundering herd** — the #1 connection-scale wall (docs/throughput-roadmap.md): at the ~1,500-inbound target, one committed message wakes ~1,500 workers → ~24k empty-claim round-trips/s. B11 already instruments it — `EmptyClaimCounters` (`:155`, `record_empty(woken=...)`) splits each empty claim into `idle_poll` (a `poll_interval` timeout) vs `wake_fanout` (a producer `.set()`), surfaced via `/stats` → the connscale harness (`harness/load/connscale/runner.py:545-546`, `report.py:141-142`).

The invariants in play bound the choice. CLAUDE.md §2: "the transactional staged queue on SQLite (WAL) gives at-least-once delivery … a message is never lost or partially handed off"; "Concurrency = asyncio … one listener + a router worker + a transform worker per inbound connection, one delivery worker per outbound connection … supervised by the `RegistryRunner`". The code's own lost-wakeup note (`:356-360`): per-stage (not fully shared) events are used so an idle worker of one class can't "swallow another class's wakeup (lost wakeup) — masked by poll_interval but defeating the prompt set()". `asyncio.Event.set()` is **sticky** (a set before `wait()` returns immediately) — the basis of no-lost-wakeup; `poll_interval` (0.25s, `:198`) is today the lost-wakeup backstop; `_wait_for_work` (`:2447-2451`) clears the event in a `finally` and re-loops every `poll_interval` on timeout.

## 2. Decision

Add a **per-(stage, lane) wake registry** and a targeted-wake API that replaces the whole-stage `.set()`: a producer that commits work for lane L at stage S wakes **only** lane L's worker. Router/transform/response lanes are keyed by `channel_id` (inbound name); delivery lanes by `destination_name`. Each worker waits on **its own** lane's `asyncio.Event`. It is **DEFAULT-OFF** behind `[pipeline].per_lane_wake` (bool, default `False`) and **byte-identical AND zero-extra-allocation when off** — the four singleton events remain the OFF path and the lane registry is never populated or consulted when off.

What it must **not** break (reliability-core): strict per-lane FIFO (#285 / ADR 0059 — B12 changes only *when* a worker wakes, never *which* row it claims or the lock hints or the seq); exactly-one-claimer-per-lane; the finalizer as sole disposition authority; ACK-on-receipt (the ingress `.set()` stays after `enqueue_ingress`, before the AA — `:1655-1663`); the poison-guard (ADR 0055); at-least-once (a committed work item must **always** eventually be claimed — no lost wakeup that strands a message).

Concretely:

1. **Registry.** `self._lane_events: dict[_WakeStage, dict[str, asyncio.Event]]`. `_lane_event(stage, key)` is **strict get-or-create** (`setdefault`-style: create+store on miss, else return the SAME stored object) keyed by the stable name string. It **MUST NEVER replace** an existing Event (a replace between a producer's `set()` and the worker's first `wait()` drops the sticky set → lost wakeup). It **MUST actually create+return** the Event on a miss (a `dict.get` no-op would silently drop the wake to a not-yet-spawned worker). Materialization is entirely guarded by `if self._per_lane_wake` — when OFF the dict stays empty.
2. **Consumers.** Each worker resolves **its own** lane Event once before its loop (`ev = self._lane_event(stage, name) if self._per_lane_wake else <singleton>`) and passes `ev` to the unchanged `_wait_for_work`.
3. **Producers.** Every `.set()` site becomes `_wake_lane(stage, key)` (OFF → the exact singleton in use today; ON → `_lane_event(stage, key).set()`), waking the exact downstream lane(s) — including the transform→delivery **fan-out** (wake each DISTINCT destination), the transform→PT-router **cross-lane fan-out**, and the delivery→response **cross-lane** hop. At the two cross-lane sites the producing worker must wake the **produced** lane, provably **not its own** lane. A producer that can't name a lane (`notify_work`, `reload` tail, `stop`) broadcasts across the whole registry via `_wake_all(*stages)`.
4. **Backstop kept.** `poll_interval` (0.25s) is unchanged in BOTH arms as the lost-wakeup correctness backstop; B12 does **not** lengthen it (the idle-poll floor is a separate wall). Combined with the claim-first loop structure (every worker does an unconditional first claim before its first `_wait_for_work` — router `:1919`, transform `:2188`, delivery `:1739`), a missed/mis-targeted/registry-race wake degrades to at-worst-`poll_interval` latency, never a strand.
5. **Lifecycle.** Materialize a lane Event at worker spawn (belt-and-suspenders; the producer-side get-or-create is the true race closer); **never delete on reload-remove**; clear the whole registry only at `_teardown_unsafe` (after `_stop.set()` + all tasks cancelled/gathered).

## 3. Acceptance Criteria (EARS)

- **AC-1** — WHEN `per_lane_wake` is False, THE SYSTEM SHALL behave byte-identically to the singleton-event engine: the same `.set()`/`.wait()`/`.clear()` sites and effects (INCLUDING the reload tail setting exactly `_ingress_work`/`_routed_work`/`_work` and NOT `_response_work`), `_lane_events` empty and `_lane_event` never called.
  → `test_flag_off_is_byte_identical_set_trace`, `test_flag_off_lane_events_never_populated`, `test_flag_off_reload_tail_omits_response`
- **AC-2** — WHEN `per_lane_wake` is True AND a producer commits an ingress row for inbound X, THE SYSTEM SHALL wake **only** inbound X's router lane and no other router lane.
  → `test_ingress_wakes_only_target_router_lane`
- **AC-3** — WHEN a transform handoff produces outbound rows for destinations {A, B, C}, THE SYSTEM SHALL wake **each** of A, B, C's delivery lanes exactly once (fan-out, deduplicated over the target set) and wake no other delivery lane.
  → `test_transform_fanout_wakes_all_destinations`, `test_fanout_dedup_wakes_once`
- **AC-4** — WHEN a capturing delivery produces a `Stage.RESPONSE` token for loopback L (`reingress_to=L`), THE SYSTEM SHALL wake **L's response lane** (cross-lane) and provably NOT the producing delivery worker's own OUTBOUND lane.
  → `test_delivery_wakes_reingress_response_lane`, `test_delivery_does_not_wake_own_outbound_lane`
- **AC-5** — WHEN a transform handoff produces a pass-through child ingress row on PT channel(s) {P1, P2}, THE SYSTEM SHALL wake each of P1/P2's **router (INGRESS)** lane (cross-lane fan-out) and provably NOT the transforming inbound's own INGRESS lane.
  → `test_pt_child_wakes_target_router_lane`, `test_pt_does_not_wake_own_ingress_lane`
- **AC-6** — IF a producer wakes a lane whose worker is not yet registered (startup/reload race) OR mis-targets a wake, THEN THE SYSTEM SHALL still claim the committed row — immediately when the sticky set is honored on spawn, else within `poll_interval` (no permanent strand — at-least-once holds).
  → `test_startup_race_sticky_set_claims_immediately`, `test_mistargeted_wake_self_heals_within_poll_interval`
- **AC-7** — WHEN `notify_work()` is called (replay / DR failback), THE SYSTEM SHALL wake **every** registered lane of all four stages and every backlog SHALL drain promptly (via the wake, before `poll_interval`).
  → `test_notify_work_wakes_all_lanes`, `test_replay_drains_all_stages_promptly`
- **AC-8** — WHEN the runner stops, THE SYSTEM SHALL break **every** per-lane worker out of `wait_for(lane_event)` promptly so cancellation lands (no worker blocks forever), and `_stop` SHALL remain the loop guard.
  → `test_stop_wakes_every_lane`
- **AC-9a** — WHEN a config-reload REMOVES an OUTBOUND whose worker is kept to drain residual rows (`wiring_runner.py:1263`), THE SYSTEM SHALL keep that lane's Event so the residual outbound rows drain (no strand from an eagerly-deleted Event).
  → `test_reload_remove_outbound_keeps_draining_lane_event`
- **AC-9b** — WHEN a config-reload REMOVES an INBOUND, its router/transform/response workers EXIT on the first residual row (`:1940-1943`, `:2200-2209`, `:2131-2136`); THE SYSTEM SHALL keep that lane's Event so a later reload RE-ADDING the inbound respawns the worker (via `_ensure_inbound_workers` `:1324`) and its claim-first loop drains the residual backlog — no strand and `_lane_event` reuses the same object by name.
  → `test_reload_remove_inbound_worker_exits_event_kept_readd_drains`
- **AC-10** — WHERE per-lane wake is enabled at a fixed connection count with 1 active + N idle lanes, THE SYSTEM SHALL drive `empty_claims_wake_fanout` per-second toward ~0 (only the active lane's worker woken per commit) while `empty_claims_idle_poll` per-second is statistically unchanged (poll floor intact), and end-to-end PROCESSED counts + FIFO order SHALL match the OFF arm.
  → `test_per_lane_wake_no_fanout_on_single_lane`, `harness/load/connscale/` A/B run
- **AC-11** — WHILE per-lane wake is enabled, THE SYSTEM SHALL preserve strict per-lane FIFO (#285 / ADR 0059): the claim, lock hints, and seq ordering are unchanged (`claim_next_fifo`/`claim_next_fifo_batch` call args byte-identical between arms); only wake timing differs.
  → `tests/test_ordering_fifo.py` (re-run under the flag), `test_fifo_claim_args_identical_across_arms`
- **AC-12** — WHEN `MEFOR_PIPELINE_PER_LANE_WAKE=true` is set, THE SYSTEM SHALL flip `settings.pipeline.per_lane_wake` to True (requires `"pipeline"` in `_SECTIONS`); WHEN removed from `_SECTIONS` the env var SHALL be silently ignored (regression guard).
  → `test_env_var_flips_flag`, `test_env_var_ignored_without_sections_entry`
- **AC-13** — WHILE `_wake_all` iterates the registry concurrently with a reload/producer mutating `_lane_events`, THE SYSTEM SHALL not raise `RuntimeError: dict changed size during iteration` and SHALL wake every currently-registered lane (`_wake_all` is synchronous / await-free / snapshots the values).
  → `test_wake_all_races_concurrent_reload`

## 4. Options considered

1. **Per-(stage, lane) `dict[name -> asyncio.Event]` with strict get-or-create + poll backstop, default-OFF flag. CHOSEN.** Preserves `asyncio.Event`'s sticky-set (the no-lost-wakeup primitive) per lane; O(1) targeted wake; byte-identical + zero-allocation OFF path; the poll backstop + claim-first loop turn every B12 failure mode into at-worst-`poll_interval` latency.
2. **Single shared `Event` + a concurrent "lanes-with-pending-work" set.** Rejected: re-serializes all wakes through one Event and re-introduces the cross-lane swallow unless every worker re-checks-and-re-sets (the herd in a different shape); loses clean sticky-set-across-spawn.
3. **`asyncio.Condition` per lane.** Rejected: heavier; `Event`'s sticky set already gives the produce-before-consume guarantee with no extra locking on the hot path.
4. **Remove the poll and rely solely on targeted wakes.** Rejected outright: deletes the sole lost-wakeup self-heal; a single registry/race bug would permanently strand a message — an at-least-once violation.
5. **Also lengthen `poll_interval` when ON (attack the idle-poll floor too).** Deferred, not chosen for B12: conflates two distinct B11 measurements (`idle_poll` vs `wake_fanout`) and widens the safety window for B12's own new failure modes. B12 leaves the poll at 0.25s; a later B13-class increment may revisit once per-lane wake proves the poll redundant on the hot path.

## 5. Consequences

**Positive** — the `wake_fanout` term collapses toward ~0 (one commit wakes one lane, not N); the connection-scale wall's herd slope flattens; no new instrumentation needed (B11 already surfaces the signal); default-OFF + byte-identical + zero-extra-allocation-when-off means a zero-risk rollout and a clean harness A/B.

**Negative / risks** — the wake path is **reliability-core**. A lane-registry bug can drop a targeted wake, degrading to `poll_interval` latency (never a strand — the poll backstop + claim-first loop stay). Two cross-lane sites (delivery→response `:1882`, transform→PT-router `:2349`) and three fan-out sites (`:2052`, `:2345`, `:2349`) are where "wake my own lane" is *wrong* — they must wake the **produced** lane(s); a mis-key is caught by AC-3/4/5 and bounded by the poll. Small unbounded growth of `_lane_events` across churny reloads (Events for removed connections are never deleted mid-run) — bounded by distinct connection names over the runner's life, cleared at stop; acceptable.

**Out of scope** — lengthening/removing `poll_interval` (a separate increment); any change to the claim, lock hints, seq assignment, or FIFO grain (#285 / ADR 0059 unchanged); toggling the flag via `/config/reload` (read once at construction — a change requires an engine restart, matching group-commit / batch-claim); EF-6 cursor-teardown and all store internals (untouched — the store sees byte-identical claim/handoff calls).

## 6. Reliability-invariant checklist

- [x] **At-least-once** — a committed row is always claimed: targeted wake OR the retained `poll_interval` backstop OR the unconditional claim-first loop; no delete-on-remove strand; no Event-replace drop-of-sticky-set; get-or-create never no-ops on a missing lane.
- [x] **No lost wakeup** — strict get-or-create keyed by stable name preserves the sticky-set across the spawn/produce race; `_wait_for_work` clears only its own lane (no cross-lane swallow); `_lane_event` never replaces a live Event.
- [x] **Strict per-lane FIFO (#285 / ADR 0059)** — unchanged; B12 touches only *when* a worker wakes, never the claim/lock hints/seq; "one serial writer per (stage, lane-key)" (`:1141`) untouched.
- [x] **Exactly-one-claimer-per-lane** — worker↔lane mapping unchanged (one worker per lane); wake targeting adds no second claimer.
- [x] **Finalizer sole authority** — disposition path untouched; only wake timing changes.
- [x] **ACK-on-receipt / count-and-log** — the listener still commits ingress before ACK; the ingress wake (now `_wake_lane`) is still after `enqueue_ingress`, before the AA (`:1655-1663`).
- [x] **Poison-guard (ADR 0055)** — unchanged (a separate path).
- [x] **notify_work() wake-all** — kept as a full-registry broadcast (`_wake_all(all four stages)`); required for replay/failback promptness; await-free iteration.
- [x] **stop() semantics** — `_stop` stays a singleton loop-guard; every lane Event is set at teardown so no worker blocks on `wait_for(lane_event)`; registry cleared only after cancel+gather.
- [x] **Byte-identical + zero-allocation when OFF** — the four singleton events are the literal OFF branch of `_wake_lane`/`_wake_all`; waiters pass the singleton; `_lane_events` never populated or read; the reload-tail RESPONSE fix is ON-only.
- [x] **PHI** — no message bodies touched; wake keys are connection **names** only (not PHI).

## 7. Residual risks

- **Fan-out / cross-lane mis-key.** The three fan-out (`:2052`, `:2345`, `:2349`) and two cross-lane (`:1882`, `:2349`) sites are the only places a naive "wake self" is wrong. Mitigation: AC-3/4/5 assert each produced lane is woken AND the producer's own lane is NOT; the poll bounds any miss to `poll_interval`.
- **reload asymmetry (G3).** The reload tail today omits `_response_work` (`:1343-1345`). B12 fixes it to also wake RESPONSE lanes **ON-only** (the OFF branch reproduces the exact 3-event set today, preserving byte-identical AC-1). If the ON fix is wrong, a residual `Stage.RESPONSE` token on a reloaded loopback self-heals only on the poll (correct, slower) — no strand.
- **Event replacement dropping a sticky set.** Guarded by: `_lane_event` is strict get-or-create (`setdefault`) + never-delete-on-remove (so no replace path exists) + an explicit code comment forbidding replacement + `test_lane_event_returns_same_object`.
- **Stale doc/code drift.** The reload comment (`:1322-1323`) and prior draft AC-9 wording claimed "a removed inbound keeps its workers"; the code actually EXITS the inbound worker on the first residual row. AC-9 is split into 9a (outbound kept) / 9b (inbound exits, Event kept, re-add respawns). Fix the `:1322-1323` comment as part of this change.
- **Unbounded `_lane_events` growth** across churny reloads — bounded by distinct names, cleared at stop; negligible.
- **Flag not reload-toggleable** — documented in CONFIGURATION.md; the harness respawns per arm.

## 8. To resolve on acceptance (all assumed-YES by the plan)

- [x] Flag lives under `[pipeline]` (pipeline-worker concern; threads via the `max_correlation_depth` path).
- [x] Add `"pipeline"` to `_SECTIONS` so `MEFOR_PIPELINE_PER_LANE_WAKE` is parsed for the harness A/B.
- [x] The reload tail also wakes RESPONSE lanes **ON-only** (fixes G3 without breaking byte-identical-OFF).
- [x] B12 leaves `poll_interval` at 0.25s in both arms.
- [x] Thread the flag through BOTH Engine construction entrypoints (`Engine.__init__` `:89`/`:158` AND `Engine.create()` classmethod `:299`/`:337`) so tests/embedding default to False consistently.