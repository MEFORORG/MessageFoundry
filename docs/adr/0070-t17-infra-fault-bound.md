# ADR 0070 — Bounding a persistent pooled T17 infra fault: release-with-backoff, then STOP the lane (never auto-dead-letter)

**Status:** Accepted (proposed 2026-07-04; **implemented on `main` ahead of this document's merge** — `[pipeline].infra_fault_policy` ships with `default="stop"` ([`config/settings.py`](../../messagefoundry/config/settings.py)), and the dispatcher carries the fix-B streak counter and `is_infra_fault` outcome flag ([`pipeline/stage_dispatcher.py`](../../messagefoundry/pipeline/stage_dispatcher.py)). Verified 2026-07-10.)
**Deciders:** throughput / pipeline-reliability working group
**Related:** ADR 0066 (pooled `StageDispatcher`; the T17 `_drain_lane` path), ADR 0055 (poison-guard / G6 ceiling), ADR 0044 (durable alert dedup state), ADR 0001 (staged-pipeline invariants); the `InternalErrorPolicy` STOP/CONTINUE precedent in [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)

---

## Context

The pooled `StageDispatcher`'s `except Exception` handler in [`stage_dispatcher.py`](../../messagefoundry/pipeline/stage_dispatcher.py) — the branch marked `T17 machinery fault`, "T17" — catches a **machinery/infra-level** fault — a store/handoff/DB error, or any raise from code **outside** the per-item body — and today `release_claimed`s the head+tail and returns a **fixed-backoff RETRY**. `release_claimed` does `attempts = MAX(attempts-1, 0)` (undoing the claim's poison-guard increment, store.py:3132) and leaves `next_attempt_at` **past-due**, so the ~0.25 s sweep re-readies the lane before the 1 s park expires. A **persistent** infra fault therefore re-claims/re-faults at the sweep cadence — an **escalation-less ~4×/s spin** against a broken dependency, the faulting head silently head-of-line-blocking its lane with no lane-level signal, and — because the attempts increment is undone — the **G6 poison ceiling never fires**, so it never terminates. *(Confirmed empirically: an always-raising head → 29 invocations in ~3 s, `attempts` pinned at 0, never dead-lettered; and by two independent adversarial code reviews, 2026-07-04.)*

**Scope — what this ADR is NOT about.** A **message-content** poison (a Router/Handler *user-code* raise, or a bad payload) does **not** reach T17 — it is caught **inside** the per-item body and, per the existing `InternalErrorPolicy`, `dead_letter_now`'d (CONTINUE, the default) or `mark_failed` + lane-STOP (wiring_runner.py router ~2510 / handler ~2780). That path is correct and **untouched** here. This ADR is only about the **T17 machinery-fault** path.

**The dilemma.** The raised exception carries **no** information to distinguish a genuinely-transient-but-**long** infra outage (where dead-lettering the message would be *wrong* — the message is fine, the infra broke) from a **deterministic** machinery bug on this head (which must eventually escalate). And the project already encodes the governing invariant for the content path: content poison is dead-lettered because the **message** is at fault; a T17 fault is **not the message's fault**, so it must **never** send a good message to the DLQ.

## Decision

**Fix (A) — settled — collapse the spin.** On T17, re-pend the head with a durable `next_attempt_at = clock() + exponential-capped backoff` (base `_LANE_ERROR_BACKOFF_SECONDS`, cap ~60 s) instead of a plain release; release **only** `items[i:]` (never `items[1:]`, which strands the head INFLIGHT and breaks FIFO — ADR 0066 §7). `list_fifo_lanes` then reports the head **not-due**, so the sweep's **T21 else-branch** (`:685-686`) arms an exact re-claim timer instead of unparking — collapsing the 4×/s spin to the backoff cadence and recovering within ~1 min of the infra returning.

**Fix (B) — bound a *persistent* fault by STOPping the lane, never by dead-lettering.** Add `[pipeline].infra_fault_policy`, **default `stop`**:

- **`stop` (default):** track an in-memory per-lane `infra_error_streak` on `_LaneState`. Extend `_LaneOutcome` with `is_infra_fault` (set True **only** in the T17 machinery except-branch — the per-item body RETRY at `:534` and every content STOP/dead-letter path stay `False`) and `made_progress = (i > 0)`. In the synchronous terminal block: on a clean drain **or** a forward-progress / non-infra RETRY, **reset the streak to 0**; on an infra RETRY with **`i == 0`** (zero forward progress — the head-of-line-blocked case), **increment** it, and when it reaches `infra_fault_stop_after` (default **10**) transition to **STOPPED** exactly like the existing T16 — `st.phase = STOPPED` + `alert_sink.connection_stopped(lane, …)` — and return with **no park**. Under fix A's exponential backoff, 10 consecutive zero-progress faults span **~4 min** of wall clock, so the count is really a **duration gate**; a short blip self-heals (the resolving pass resets the streak) and never STOPs. STOP performs **no store mutation** — the head is already PENDING (released by fix A), preserved, never dead-lettered. **Resume** reuses the internal-error muscle: fix the cause, **reload → `notify_work()`** re-arms the STOPPED lane (`:288` via `_unpark(woken=True)`); add **one line** there to reset `infra_error_streak = 0` on the **STOPPED→READY path only** (never on the shared PARKED park-timer `_unpark`, or the threshold never accrues and the spin returns). The preserved head is re-claimed head-first; if still faulting it re-STOPs cleanly (idempotent, zero data loss); if healed it drains.

- **`retry_forever` (opt-in):** fix A alone, plus a throttled `lane_stuck` alert once a stuck horizon is crossed (alert only, never terminal), auto-resolved on the next clean head. The lane retries the head at capped backoff forever; a long transient self-heals with no operator action; a deterministic bug head-of-line-blocks that **one** lane until a human dead-letters it. For the deliberately-unattended flaky-infra site.

**Auto-dead-letter of a T17 head is NOT shipped** — neither the count-bounded (`infra_attempts` ceiling) nor the time-bounded (`stuck_since` horizon) form. On a partial/localized fault or an outage outlasting the budget, either would DLQ a **good message on the indistinguishable signal** — the one forbidden error. The liveness those designs sought is delivered by a **human**: an operator may dead-letter the stuck head from the ops console into the replayable DLQ, making the discard call with the context (is the store up?) the signal lacks.

## Invariants preserved

- **At-least-once / never drop the head** — the T17 path never dead-letters; the faulting head is preserved PENDING (`stop`) or retried at capped backoff (`retry_forever`); recovery is reload/replay, never loss.
- **Never DLQ a good message due to infra** — no T17 path reaches the DLQ, which stays reserved for message-content poison (`InternalErrorPolicy`) and explicit operator quarantine.
- **FIFO head-first** — fix A releases `items[i:]` (never `items[1:]`); the faulting head keeps position 0 / lowest rowid and is re-claimed before any sibling on resume.
- **Idempotent handoff** — fix A's reschedule is `status='inflight'`-guarded; STOP is an in-memory phase + alert only (no store mutation); a crash before commit leaves the row INFLIGHT for `reset_stale_inflight`.
- **Count-and-log** — the message stays at its true in-flight disposition (RECEIVED/ROUTED), never falsified to PROCESSED/FILTERED/ERROR; a stopped stage backs up the queue but never un-counts intake; the stall is surfaced via `connection_stopped`, never accepted-and-dropped.
- **Content-poison ledger pristine** — T17 never touches `attempts`/the G6 ceiling, so an infra outage cannot trip the content dead-letter path.

## Alternatives considered

| Alternative | Verdict | Why |
|---|---|---|
| **STOP the lane + alert (default)** | **Chosen** | Non-destructive; a human resolves the indistinguishable transient-vs-bug call; reuses the `InternalErrorPolicy` STOP precedent for the machinery-fault domain; no schema change |
| Count-bounded infra dead-letter (`infra_attempts` ceiling → DEAD) | **Rejected** | Auto-DLQs a good message on a partial fault / an outage outlasting the window — the forbidden false-DLQ; and pays a 3-backend schema column + migration for a terminal transition the invariant forbids |
| Time-bounded dead-letter (`stuck_since` horizon → DEAD) | **Rejected as default** | Same false-DLQ on a store-writable transient outlasting the horizon. Better-engineered of the two (budget advances only on a writable store, exempting a total outage) → the *designated fallback* **if** automatic liveness is ever mandated, shipped only as an explicit off-by-default liveness-over-safety opt-in |
| Alert + retry-forever | **Kept as the `retry_forever` knob** | Never escalates a deterministic bug (spins one lane forever, alert-only) — correct only for the deliberate unattended site, not the default |

## Acceptance criteria / tests

Adversarial-invariant tests (backend-parametrized where the store is exercised — SQLite in-proc + the SS/PG CI legs, per the ADR 0066 rider precedent):

1. **Deterministic infra head bounded per policy** — a stub handoff that always raises T17: under `stop`, the lane reaches STOPPED after exactly `infra_fault_stop_after` (10) consecutive zero-progress faults, emits **one** `connection_stopped` naming stage+lane+streak, and performs **no** store terminal write (head PENDING, never DEAD); under `retry_forever`, never STOPs / never dead-letters — parks at capped backoff and emits the throttled `lane_stuck`.
2. **Transient self-heals** — a head that raises T17 for k < threshold then succeeds resets the streak to 0 on the resolving pass; the lane never STOPs and never fires `connection_stopped`.
3. **Streak-reset scoping (the sharp edge)** — the streak resets on clean drain, on a forward-progress RETRY (`i>0`), and on the STOPPED→`notify_work` resume, but **NOT** on the shared PARKED park-timer `_unpark`; a park-and-timer-unpark of a still-faulting head must show the streak **still accruing** toward the threshold.
4. **FIFO head-first** — on T17 the released set is `items[i:]` (never `items[1:]`); after STOP the faulting head retains position 0 / lowest rowid and is re-claimed before any sibling on reload.
5. **Content path untouched** — a router/handler body-raised poison still hits `dead_letter_now`/STOP per `InternalErrorPolicy` at its existing site; the T17 machinery path never calls `dead_letter_now`/`mark_failed` and never increments `attempts`/the G6 ceiling (assert `attempts` unchanged across an infra episode).
6. **Spin collapses to backoff (fix A)** — with the head re-pended not-due, `list_fifo_lanes` reports it not-due and the sweep arms an exact timer via the T21 else-branch instead of unparking; assert no busy re-claim between backoff deadlines.
7. **Reload resumes idempotently** — a STOPPED lane, after `notify_work` (reload broadcast), re-arms with the streak reset to 0 and re-runs the preserved head; re-STOPs cleanly after another full threshold window if the fault persists (zero data loss); drains if healed.
8. **Correlated outage** — N lanes STOP under one store-down root cause; a single reload/`notify_work` re-arms all of them, and ADR-0044 durable alert dedup collapses the N `connection_stopped` emissions to one actionable signal.

## Consequences

- **Positive:** the spin is gone (A); a persistent T17 fault is now **bounded and paged** with **zero new terminal machinery and no schema change** — STOP reuses the STOPPED phase, `connection_stopped`, the `notify_work` re-arm, the shared `_unpark`, and the `InternalErrorPolicy` STOP precedent already in the tree, so existing routing/paging, ADR-0044 durable alert state, and reload muscle apply unchanged. The hard invariant (never wrongly DLQ a good message) holds **by construction** — no T17 path performs a terminal store write.
- **Costs:** a STOPPED lane halts that lane's post-ACK traffic until an operator reloads — identical blast radius to the existing `InternalErrorPolicy.STOP` (for OUTBOUND/RESPONSE one lane == one connection; for INGRESS/ROUTED intake keeps persisting RECEIVED rows and the backlog just grows). A genuinely-transient outage >~4 min gets STOPped early and needs a reload even after the store recovers — accepted, because the operator is already engaged during a real outage, one reload broadcast re-arms **all** stopped lanes at once, there is zero data loss, and `retry_forever` is one flip away for sites that prefer auto-self-heal.
- **Sharp edge:** the streak-reset scoping (test 3) is the one place a wrong edit silently reintroduces the original spin — it must stay test-locked.
- **Operational:** a store-wide outage STOPs many lanes near-simultaneously (an alert storm collapsed to a single operator action — fix store + reload — by ADR-0044 dedup). The in-memory streak is intentionally lost on restart (a restart is a fresh operator-grade attempt); a crash-looping engine that never accrues the threshold is the NSSM supervisor's domain.
- **Follow-ups:** a `/stats` stopped-lanes-per-stage gauge for the browser ops console; document the ~4-min-to-STOP curve and the `infra_fault_stop_after` / backoff-cap tunables so operators tune deliberately. If a future need for **automatic** liveness (advance the lane without a human) is ever mandated, prefer the time-bounded design (budget advances only on a writable store) as the implementation — never the count-bounded one — and ship it only as an explicit, documented, off-by-default liveness-over-safety opt-in.

## References

- [`messagefoundry/pipeline/stage_dispatcher.py`](../../messagefoundry/pipeline/stage_dispatcher.py) — the T17 `_drain_lane` `except Exception` branch, `:685-686` (T21 sweep else-branch), `:288` (`notify_work` re-arm), `_LANE_ERROR_BACKOFF_SECONDS` `:52`.
- [`messagefoundry/store/store.py`](../../messagefoundry/store/store.py) — `:3116-3135` (`release_claimed`: the `attempts=MAX(attempts-1,0)` that undoes the claim increment).
- [`messagefoundry/pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) — the `InternalErrorPolicy` STOP/CONTINUE handler (the precedent this ADR mirrors; the message-content path this ADR leaves untouched).
- ADR 0066 (pooled claimers, §7 `items[i:]` release), ADR 0055 (poison-guard / G6), ADR 0044 (durable alert dedup), ADR 0001 (staged-pipeline invariants).
- Confirmation: an empirical always-raising-head probe (busy-spin, no dead-letter) + two adversarial verification workflows, 2026-07-04.
