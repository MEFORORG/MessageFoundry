# ADR 0071 — Cutting per-message executor round-trips: the async-marshaling feed wall (build-plan B5)

**Status:** Proposed (2026-07-04)
**Deciders:** throughput working group
**Related:** ADR 0069 (durable-write is not the wall — engine feed concurrency is; this ADR is the concrete B5 lever it defers to), ADR 0066 (pooled stage claimers — the first concurrency lever, `pooled` default since #744), ADR 0001 (staged-pipeline invariants), ADR 0055 (group-commit / durable-write), ADR 0057 (inline Step-A fast path), ADR 0053 / ADR 0040 (free-threading — the complementary track), ADR 0067 (persistent outbound MLLP).  Build-plan **B5**; [`docs/throughput-roadmap.md`](../throughput-roadmap.md), [`docs/throughput-build-plan.md`](../throughput-build-plan.md).
**Evidence (in-repo):** the 2026-07-04 py-spy profile of a single pooled **SQL Server** engine at its ceiling + the 2026-07-04 **B5 micro-bench results** (SQLite/Proactor, mechanism-only) live under [`docs/benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/`](../benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/) (see §8; the harness itself lands with the B5 build PR).
**Adjudication:** the fusion boundary + wakeup lever were put through a multi-agent adversarial adjudication (3 divergent designs → per-design refutation → judge synthesis) + a validated micro-bench on 2026-07-04. It produced a **load-bearing correction — B5 is a blocking-driver (SQL Server / aioodbc) lever, not a general one** — folded into §2–§5 and §10 below.
**Code references** are `origin/main @ 449851e`; line numbers are approximate — locate exactly at implementation time. This ADR is **Proposed / direction-setting**: it names the wall, fixes the lever + its per-backend scope + the invariant fence, and records what is decided vs still-measurement-gated (§10). Nothing here changes the shipped default.

---

## 1. Context — where 0069 left the lever, and what the profile then named

ADR 0069 corrected the at-scale campaign's "store-write-bound" label: the store absorbs **~27,000 commits/s** while the pipeline feeds it only **~750 commits/s** at its ~107 msg/s ceiling — a **~36× feed gap** — and ruled out every durable-write-tier lever (app-side group-commit, faster log, bigger pool — each ~0). It directed effort to **engine-side pipeline-feed concurrency**, naming as build-plan **B5** *"the executor split, batching SQL statements per executor hop, and free-threading (ADR 0053)"* and deferring the specifics to "its own ADR to follow." **This is that ADR.** 0069 said *where* the wall is (the feed). The 2026-07-04 profile says *what the feed wall is, precisely*.

**The regime (anchor, `profile_run.json`):** one engine, `claim_mode=pooled`, **SQL Server** store, driven at **128/s — at the ceiling**: 127/s intake, ~94/s delivered, ACK p50/p99 **5.4 s / 44 s**, `in_pipeline` peak **2,604**, engine **~2.0 of 8 cores**, max thread **~0.60 core**, **store idle** (~1 of 40 conns active). The wall regime has **idle CPU *and* an idle store** — the ceiling is neither.

## 2. The measurement — the wall is per-completion async marshaling, and it is driver-specific

The flame resolves fully. **Pipeline/HL7 logic is ~2% of samples.** The cost is the async machinery *around* the off-loop calls:

| frame | % samples | what it is |
|---|---:|---|
| `_worker` (concurrent/futures/thread.py) | 81.5 | **aioodbc's own executor** threads, parked/idle — the pool is *not* saturated |
| `set_result` / `_invoke_callbacks` / `_call_set_state` | ~9.5 each | executor future completion → asyncio |
| `call_soon_threadsafe` (base_events.py) | 9.1 | cross-thread hand-back to the loop |
| **`_write_to_self` (proactor_events.py)** | **9.1** | **Proactor self-pipe SOCKET wakeup of the IOCP loop** |
| `_run_once` + IOCP | ~9 | loop iteration + Windows IOCP machinery |

**Mechanism, corrected to the driver.** On this SQL Server engine the store runs on **aioodbc** ([`aioodbc.create_pool`](../../messagefoundry/store/sqlserver.py) sqlserver.py:510; `async with conn.cursor()` :888) — a wrapper that dispatches **each pyodbc statement to its own thread executor**. So the 81.5% parked `_worker` is *aioodbc's* executor, and **every store statement — not every store method — is a thread-marshaled crossing**: each completion marshals back to the single loop thread via `set_result → _invoke_callbacks → _call_set_state → call_soon_threadsafe → _write_to_self` (a socket send to the Proactor self-pipe that wakes the IOCP loop). A single handoff (guarded DELETE + insert(s) + `UPDATE messages` + event + COMMIT) is therefore **many** crossings. Add the two off-loop **CPU** hops SEC-013 mandates — `route_only` ([wiring_runner.py:2152](../../messagefoundry/pipeline/wiring_runner.py)) and `transform_one` ([:2176](../../messagefoundry/pipeline/wiring_runner.py)). At ~100 msg/s this is **hundreds of completions/s, all GIL-serialized on the one loop thread** — the governor. Executor threads and six of eight cores sit idle: **a per-completion overhead/latency wall on the loop, not CPU or store.**

**This is driver-specific — the correction that scopes the whole ADR:**

- **SQL Server (aioodbc):** the profiled wall. Per-statement thread crossings ⇒ a multi-statement handoff is many crossings. This is where B5 applies, and where the win is **larger than a naïve "cut 2 of ~7 hops"** — a *synchronous* handoff collapses a whole multi-statement handoff into **one** completion (see §5.1; the micro-bench measured a per-statement async handoff at **~12 crossings/msg → 2**, §8).
- **Postgres (asyncpg):** [`asyncpg.create_pool`](../../messagefoundry/store/postgres.py) postgres.py:587 is **loop-native and loop-bound** — its statements complete through the loop's own IOCP socket reads (`_run_once`/`_loop_self_reading`), **never** `call_soon_threadsafe`/`_write_to_self`. PG incurs only **~2 crossings/message** (the two SEC-013 CPU hops). There is no store-call crossing to fuse, and no synchronous asyncpg entry can exist.
- **SQLite (aiosqlite):** the handoff runs under a **loop-affine `asyncio.Lock`** (`self._lock = asyncio.Lock()`, [store.py:1213](../../messagefoundry/store/store.py)) inside the group-commit serializer. A sync `sqlite3` handoff on a worker thread **cannot take that loop-bound lock** and would be a second WAL writer bypassing the serializer. Edge-only; keep the async path.

## 3. Decision

**Cut the number of executor→loop crossings per message on the backend where they are the wall — SQL Server.** Three ranked levers:

1. **PRIMARY — thread-hop fusion, SQL-Server-scoped.** Run each off-loop **CPU stage together with its adjacent store handoff on a *single* worker-thread hop**, executing the handoff through a **dedicated synchronous pyodbc connection source** so the whole multi-statement handoff marshals back to the loop **once** instead of per statement. **Postgres and SQLite keep the async path unchanged — by construction** (§2): asyncpg is loop-native (nothing to fuse), SQLite's handoff lock is loop-affine (a sync twin is impossible and would corrupt the serializer).
2. **SECONDARY — a cheaper / coalesced loop wakeup.** Reduce/batch the Proactor self-pipe `_write_to_self` tax; **deferred** — measure the residual after fusion first (§5.2). A genuinely cheaper wake (`PostQueuedCompletionStatus` straight to the IOCP) is a CPython-internals fork and out of scope; coalescing is the only in-scope option.
3. **TERTIARY / parallel — free-threading (ADR 0053).** Parallelizes the marshaling across cores but reduces no crossings, and carries the 0053 python-hl7-refcount (~2×) + cp314t caveats. Sequenced behind 1–2, owned by ADR 0053.

**The two load-bearing framing points (why this is safe, and not the lever 0069 blocked):**

- **Hops, not transactions.** 0069 blocked *further commit-depth reduction* because `route_only`/`transform_one` run off-loop *between* a claim and its handoff, so claims cannot fuse with handoffs and the poison-guard claim must stay standalone — that fence is about **transaction fusion (shared rollback fate).** B5 fuses **thread hops**: every commit stays standalone, the poison-guard claim still commits in its own transaction (on the claimer, before dispatch — below), durability is untouched. The micro-bench's **identity guard** proves it empirically: commits/msg was **2.000 in both the fused and unfused arms** (§8), i.e. byte-identical durable work — fewer *completions*, not fewer *commits*.
- **One transaction per fused hop (structural correction).** Under the shipped **pooled** model (ADR 0066) the shared claimer already claims across a lane-chunk in its **own committed transaction**, so a fused hop contains exactly **one handoff transaction preceded by one CPU stage** — *not* two transactions. The earlier draft's "co-locating two independent transactions on one worker" **overstated** it: there is one txn per hop, hence **no intra-hop two-transaction deadlock surface**, and the standalone poison-guard holds because the claim's `attempts+1` committed on the claimer before the hop ever ran.

## 4. What fuses, what must not — the per-backend + invariant analysis

Under pooled, the shared claimer amortizes the **claim** (its own txn, per lane-chunk). The residual per-message crossings owned by the per-lane processing task are `route_only`, `route_handoff`, `transform_one`, `transform_handoff`, delivery-send, delivery-complete. **v1 fuses exactly two adjacencies, on SQL Server only:**

- **`route_only` (CPU) + `route_handoff` (store txn) → one hop** on a **dedicated fusing executor**: copy the run-context (SEC-013), run `route_only`, then — after it returns — acquire a **fresh** connection from the **dedicated synchronous pyodbc pool** and run the handoff as its own committed transaction. **G5 preserved:** no connection is held across the CPU work.
- **`transform_one` (CPU) + `transform_handoff` (store txn) → one hop**, identical shape (the transform's lookup `ExitStack` opens/closes within the hop; live `db_lookup`/`fhir_lookup` reads stay off-loop inside it).

**Held UNFUSED (adjudicated):** (a) the **pooled claim** — stays the claimer's own txn; fusing it re-entangles ADR 0066's cross-lane amortization *and* the standalone poison-guard. (b) **delivery-send** — MLLP send is loop-native async socket I/O (ADR 0067), not an executor crossing; a blocking connector's send is variable-latency and would pin a worker. (c) **delivery-complete** — left as-is unless the bench shows a win. (d) **cross-lane handoff batching** — deferred: batching multiple lanes' handoffs into one txn approaches transaction fusion / cross-lane atomicity, the 0069 fence.

**The mandatory new component — a DEDICATED FUSING EXECUTOR (+ dedicated sync connection source).** A fused hop now holds a worker across DB latency. It **must not** share the **default** `to_thread` executor with strict-validation (the listener hot path) or decrypt, or DB latency would starve that CPU executor. So fused DB-bound hops run on a dedicated bounded executor, sized to a **dedicated synchronous pyodbc connection pool** distinct from the aioodbc async pool (aioodbc's connections are bound to aioodbc's own executor and are not synchronously drivable from a worker). The micro-bench's starvation tripwire (co-tenant validate p99 flat, ~0.18 ms, across arms) is consistent with this being sufficient — §8.

**Invariants preserved (the ADR 0069 fence, as fusion side-conditions):**

- **ACK-on-receipt** — the ingress commit-before-ACK stays its own hop on the listener path; never fused.
- **Per-handoff atomicity** — each handoff stays a single committed transaction, idempotent on re-run. Fusion changes *when the loop is woken*, never the transaction boundary (identity guard: commits/msg unchanged).
- **Standalone poison-guard** — the claim (`attempts+1`) committed on the claimer *before* the hop; a fused-hop rollback cannot un-commit it. A catchable poison still increments attempts and dead-letters at its ceiling. *(Liveness caveat, from the adversarial pass: an **uncatchable** process-crash — segfault/OOM — inside a routed/transform hop re-runs after `reset_stale_inflight`, and the split routed/transform stages lack the inline-ingress G6 attempts-ceiling. This is **pre-existing** — `transform_one` already crashes the process in a to_thread today — **not introduced by fusion**; but the fused crash window is added to the §6 crash-replay gate to confirm no new loss/duplication.)*
- **Off-loop purity / SEC-013** — `route_only`/`transform_one` still run off the loop; a ReDoS/O(n²) message stalls only its lane's worker.
- **G4/G5** — no connection/txn spans the CPU stage inside a fused hop (fresh conn acquired only after the CPU returns).
- **Finalizer sole authority** — `_maybe_finalize` stays in-txn in the outbound handoff / delivery-complete; untouched.
- **Count-and-log** — depth stays store-visible; fusion adds no in-memory buffering of un-persisted work.

## 5. The levers in detail

### 5.1 Thread-hop fusion (primary, SQL Server)

A per-stage **fused callable** run in one dispatch to the dedicated executor, returning the handoff result to the loop in a single completion:

```text
# routed-stage lane processor (pooled, SQL Server) — ONE hop on the dedicated fusing executor:
def _route_and_handoff(registry, ic, payload) -> HandoffResult:
    names = route_only(registry, ic, payload)              # CPU, off-loop (SEC-013); no conn held
    with sync_pyodbc_pool.acquire() as conn:               # DEDICATED sync source, not aioodbc
        return route_handoff_sync(conn, ...)               # own txn, own COMMIT (standalone)
# loop: result = await loop.run_in_executor(fusing_executor, _route_and_handoff, ...)  # woken ONCE
```

**Store-protocol change (additive):** a thin `route_handoff_sync` / `transform_handoff_sync` twin over the **same SQL** as the async handoff, driven by a dedicated synchronous pyodbc pool. The async `handoff` is retained unchanged for Postgres, SQLite, `per_lane` mode, and any non-fused caller. **No SQLite sync twin in v1** (the loop-affine lock). **No asyncpg sync entry** (loop-native — nothing to fuse). Fan-out and cross-lane wakes are returned *in the completion result* and dispatched by the loop after the single wake (`mark_ready` is synchronous, ADR 0066 §4.2), so fan-out costs no extra crossings.

**Open sub-design (§10):** sizing / warm / exhaustion of the dedicated synchronous pyodbc pool (it must track the fusing executor's max workers) — a new sub-component to spec and test.

### 5.2 Cheaper / coalesced loop wakeup (secondary — deferred)

Fusion cuts `_write_to_self` frequency proportionally on the SQL Server path (and collapses the aioodbc per-statement sends inside a handoff). **Defer** the invasive completion-drain (one thread batching finished results behind a single `call_soon_threadsafe`) until the residual self-pipe share is **measured post-fusion**; build it only if `_write_to_self` is still a top-3 active-sample cost. A genuinely cheaper Proactor wake (`PostQueuedCompletionStatus` direct to the IOCP, bypassing the self-pipe socket send) is a **CPython-internals fork — out of scope**. Note: the `_write_to_self` tax is a `to_thread`/aioodbc/aiosqlite phenomenon; **asyncpg store calls never fire it**, so this lever, like fusion, is SQL-Server/SQLite-centric.

### 5.3 Free-threading (tertiary, ADR 0053)

Removes the GIL so the marshaling callbacks parallelize across the idle cores — but reduces no crossings, and ADR 0053 measured the effective ceiling as **python-hl7 refcount contention (~2×)**, not the GIL, plus cp314t maturity risk. Sequenced behind 1–2, owned by ADR 0053. Recorded here as the complementary track; **it is the escalation path if fusion's throughput win is null (§6, §10 item 6).**

## 6. Acceptance criteria / gates (per-backend — SQLite in-proc, Postgres service leg, SQL Server CI leg — × `claim_mode`; correctness gates run BEFORE any throughput leg)

1. **Crossing-count gate (the mechanism proof).** Count the **actual `loop.call_soon_threadsafe` crossings** (not just `to_thread` submissions, so the aioodbc per-statement collapse is captured):
   - **A0/A1 driver-constant control** (confound-immune): with the driver held constant, fusion drops crossings/msg **~4 → 2 (≥40% fewer)** with **commits/msg identical** (the covert-transaction-fusion guard). *Met — micro-bench §8.*
   - **SQL Server B0/B1** (realistic): the aioodbc async handoff (~many crossings/msg) collapses to the one fused hop — a drop **strictly larger** than the A0/A1 delta, commits identical.
   - **Postgres control:** record **~2 crossings/msg** (CPU hops only) with **no fused arm** — the predicted result, **not** a regression.
2. **Invariants preserved (correctness, before throughput), per backend:** at-least-once / crash replay with fusion on — kill after the claim commit; after the CPU stage but before the handoff commit (the **new fused crash window**); after the handoff commit → restart → `reset_stale_inflight` → re-claimed in seq order, re-run idempotently, zero loss, zero duplicate next-stage rows. Re-run the #283 SIGKILL-under-load failover harness fused. Standalone-poison-guard: a catchable handler raise inside the fused hop still increments attempts (claim committed) and dead-letters; a handoff rollback never un-commits the claim. ACK-on-receipt / off-loop purity / G5 (connection-lease tripwire: no conn held across the CPU stage). Finalizer + fan-out disposition-coverage graph complete × 3 backends × both modes.
3. **Byte-identical `per_lane` and non-fused paths** — full `test_staged_pipeline.py` green with fusion behind its flag; the async `handoff` unchanged for Postgres / SQLite / `per_lane`.
4. **Perf gates:** (a) **single-interface ladder — hard gate:** fused e2e within ±5% (target: faster) of ~60 msg/s warm; connscale SLO green. (b) **Throughput GO/NO-GO — SQL Server aioodbc only, at C ≥ 256:** the ~107 msg/s ceiling rises by a margin outside trial spread (**≥10 % and > 2σ**), `in_pipeline` flat-or-lower, delivered/offered ≥ 0.98, zero-loss held; then a rate-walk watching the next walls (finalizer applock; residual self-pipe floor). **SQLite is NOT a valid throughput proxy** — its write-lock regime is not the profiled idle-store marshaling wall (the micro-bench proved this: throughput sign flipped between runs while crossings stayed byte-stable, §8). **A null/negative SQL-Server result banks nothing → escalate to free-threading (ADR 0053), recorded as such.**

*Harness requirements (from the validated micro-bench):* pin `ProactorEventLoop` and **SKIP (not fail) on non-Windows** — the wall is Proactor-specific; assert the **commits/msg identity guard**; hold the driver constant in the A0/A1 control (isolate the async→sync driver change to B0/B1 so it cannot masquerade as the fusion effect); sweep concurrency **C ∈ {1, 64, 256, 1024}** (the wall is a concurrency phenomenon); run fused hops on the **dedicated** executor with a **co-tenant default-executor CPU stream** whose p99 is the starvation tripwire; warmup discarded, ≥ 3 trials with spread; synthetic HL7 only.

*(The paid SQL-Server at-scale re-bench is the promote-to-Accepted / ship-by-default gate — not a merge gate for the flagged, default-off machinery, per ADR 0066 §9.)*

## 7. Consequences

**Positive:** attacks the profile-named wall directly on the backend where it lives; on SQL Server the win is **larger than "2 of ~7"** because a synchronous handoff collapses a multi-statement aioodbc handoff into one completion (~12 → 2 crossings/msg measured for the analogous async driver, §8); no durability change (identity guard); composes with pooled claiming and, later, free-threading; the store-protocol change is additive and behind a flag; Postgres/SQLite are provably unaffected.

**Negative / accepted:** (1) touches the reliability-critical per-lane bodies again — contained by extract-and-wrap (the fused callable wraps the *existing* route/handoff and transform/handoff logic) + the §6 identity/crash-replay gates. (2) A **new component surface** — a dedicated synchronous pyodbc pool *and* a dedicated fusing executor — with its own sizing/exhaustion sub-design (§10). (3) A **second (sync) handoff surface** on SQL Server to keep in step with the async one — mitigated by making it a thin wrapper over the same SQL, both under the same reliability suite. (4) The win is **SQL-Server-only** — Postgres and SQLite bank nothing (by construction, not failure); an all-backends throughput lever this is not. (5) The reachable magnitude is **still open** — the aioodbc per-statement collapse could make it large, or the residual marshaling floor could still dominate; **only the SQL-Server micro-bench + at-scale re-bench settle it** (hence *medium* confidence). If null, the honest outcome is to bank little/nothing and escalate to free-threading (ADR 0053). (6) The uncatchable-poison crash-loop on split stages is pre-existing (not worsened), but is now explicitly in the crash-replay gate.

## 8. Evidence

**Profile** ([`docs/benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/`](../benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/)): the SQL Server flame + `PROFILE_FINDINGS.md` + `profile_run.json` — the ~107 msg/s ceiling with idle CPU and idle store, marshaling-bound on the one loop thread. *Caveat:* py-spy 0.4.2 has partial CPython 3.14 support — the flamegraph resolves fully, but `--gil` could not be captured, so GIL-boundedness is **inferred** (single-loop-thread marshaling chain + per-thread CPU: max thread 0.60 core, engine 2.0 cores → per-completion *overhead*, not a single-core-pinned loop).

**B5 micro-bench (`b5_microbench.py`, SQLite/Windows/Proactor, 2026-07-04) — mechanism proven, throughput correctly out of reach on SQLite.** Independently reproduced across three runs (implementer, an adversarial validator's re-run, and a third confirmation):

| metric | result | reading |
|---|---|---|
| crossings/msg, driver-constant A0→A1 | **4.00 → 2.00 (−50%)** | fusion halves executor→loop completions |
| crossings/msg, async per-statement B0→B1 | **12.00 → 2.00 (−83%)** | the *informative* number — a per-statement async driver spends ~10 marshaling crossings/msg that fusion eliminates (the aioodbc motivation) |
| commits/msg (identity guard) | **2.000 in every arm** | **no covert transaction fusion — direct support for "fuses hops, not transactions"** |
| `_write_to_self` vs crossings | **1:1** | confirms the marshaling→self-pipe chain (arithmetically forced, *not* independent corroboration — per-write cost unmeasured) |
| co-tenant validate p99 | **flat (~0.18 ms) across arms** | dedicated executor does not starve the listener path |
| throughput (SQLite) | **sign-unstable across runs** | **not a valid payoff signal** — SQLite is write-lock-bound, not the profiled idle-store marshaling regime; the throughput GO/NO-GO is the SQL-Server leg |

*Limits (validator, honest):* the harness is self-contained (does not import `messagefoundry`; CPU analogs, not the literal `route_only`/`transform_one`), so it proves the **crossing arithmetic and the no-txn-fusion identity**, **not** the throughput lift and **not** the real-path invariants — those need the §6 gates on the flagged fused path + the SQL-Server aioodbc leg. The profile is in-repo; the mechanism-only harness is operator-local and lands (lint/type-clean) with the B5 build PR — the numbers above are reproduced 3× (synthetic HL7, no PHI).

## 9. Rejected alternatives

| Alternative | Verdict | Why |
|---|---|---|
| **Wholesale selector event loop** (drop Proactor to kill `_write_to_self`) | **Rejected (confirmed sound)** | `WindowsSelectorEventLoop` uses `select()` — a hard **512-FD (`FD_SETSIZE`) cap unchanged through Python 3.14** and O(n)-per-iteration besides; fatal at 1,500 interfaces. Proactor is the Windows default precisely because selector does not scale there. |
| **Direct `PostQueuedCompletionStatus` IOCP wake** (cheaper than the self-pipe send) | **Rejected** | A CPython-internals fork — out of scope. Coalescing is the only in-scope cheaper-wakeup, and it is deferred (§5.2). |
| **Transaction fusion** (merge claim+handoff into one commit) | **Rejected** | Violates the standalone-poison-guard + per-handoff-atomicity invariants (ADR 0069 / 0055 AC-2). B5 fuses *thread hops*, not transactions (identity guard proves commits/msg unchanged). |
| **Fusion on Postgres / SQLite** | **Rejected by construction** | asyncpg is loop-native (no store-call crossing to fuse; no sync entry can exist); SQLite's handoff lock is loop-affine and single-writer (a sync twin can't take it and would corrupt the group-commit serializer). |
| **App-side group-commit / faster log / bigger pool** | **Rejected (0069)** | Measured ~0; the store is idle here. |
| **Free-threading first** | **Deferred** | Cuts no crossings; ADR 0053's ~2× python-hl7 cap + cp314t risk — sequenced behind fusion. |
| **Inline route/transform on the loop** | **Rejected** | Breaks SEC-013 off-loop purity — a ReDoS message would stall the loop. |

## 10. Resolutions & still-open items (adjudicated 2026-07-04)

**Resolved:**
1. **Fusion boundary — RESOLVED.** Fuse `{route_only+route_handoff}` and `{transform_one+transform_handoff}` only; claim stays the claimer's separate txn; delivery-send/complete and cross-lane batching out of v1. **SQL-Server-primary (blocking-driver lever).** Neither too timid nor too aggressive.
2. **Sync store entry — RESOLVED (refined).** A thin `*_handoff_sync` twin additive to the protocol, driven by a **dedicated synchronous pyodbc connection source** distinct from the aioodbc async pool, on a **dedicated fusing executor**. **No SQLite sync twin; no asyncpg sync entry** (both keep async).
3. **Wakeup coalescing — RESOLVED: defer.** Measure residual `_write_to_self` post-fusion; build the drain-thread only if still top-3.
4. **Free-threading — RESOLVED: defer to ADR 0053**, gated on the hot-path-parser prerequisite; not coupled into the B5 PR.
5. **Per-backend scope — RESOLVED (sharper than "measure per backend"): fusion is a blocking-driver lever.** ENABLE on SQL Server (profiled + enterprise store); KEEP the async path on **Postgres** (asyncpg loop-native, ~2 crossings) and **SQLite** (loop-affine lock + single-writer WAL) **by construction**. A PG "no fusion win" is the **expected control**, not a regression.
6. **Selector-loop rejection — CONFIRMED SOUND** (512 `FD_SETSIZE` unchanged in 3.14 + O(n) `select()`).
7. **Dedicated fusing executor — RESOLVED: mandatory** (fused DB-bound hops must not share the default `to_thread` executor with strict-validation/decrypt).

**Still open (measurement-gated, by design):**
- **Promote-to-Accepted gate** — the paid **SQL-Server** at-scale re-bench (ceiling lifts by a worthwhile margin; zero-loss + crash-replay green on live SQL Server *and* Postgres). A measurement, not adjudicable on paper.
- **Magnitude of the throughput win** — the aioodbc per-statement collapse could make it large, or the residual marshaling floor could dominate. Settled only by the §6.4(b) SQL-Server leg. *(Why confidence is medium.)*
- **Dedicated sync connection-source sub-design** — sizing / warm / exhaustion of the synchronous pyodbc pool (must track the fusing executor's max workers).
- **Whether the starvation risk forces the dedicated executor in practice** — the design mandates it pre-emptively; the micro-bench's co-tenant validate-latency tripwire on the real path confirms sufficiency.
- **Postgres residual-crossing lever (out of B5 scope, noted)** — PG's ~2 CPU-hop crossings, if they ever dominate, are a free-threading/parser problem (ADR 0053), not a fusion one.
