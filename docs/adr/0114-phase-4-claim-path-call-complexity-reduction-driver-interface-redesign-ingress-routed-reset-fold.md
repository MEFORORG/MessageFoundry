# ADR 0114 — Phase-4 claim-path call-complexity reduction: driver-interface redesign + the INGRESS/ROUTED reset fold

- **Status:** Proposed (2026-07-16) — commissioned by the owner's **D0-accept + D2-GO** rulings (TO-ENGINE-033,
  2026-07-16). This ADR is the **design of record** for the Phase-4 claim-path redesign; the build ships later,
  **one flag per sub-lever, every flag default OFF**, each flipped only after its own §8 bench gate. It
  authorizes no default-ON behavior change and no bench-gate waiver.
- **Deciders:** owner (D0/D2) + the frozen D1 mechanism-isolation verdict of record (T1/T2/T3; ACK-D1-verdict) +
  a multi-agent draft→adversarial-verify workflow bound to the TO-ENGINE-027 constraints verbatim (three
  competing designs; every blocker/major finding of the verify pass is incorporated below).
- **Related (in-repo):** [ADR 0066](0066-pooled-stage-claimers.md) (pooled claimers — owns `claim_fifo_heads`,
  the probe-then-claim §3.2 semantics and the §9 never-block guarantee this ADR preserves exactly) ·
  [ADR 0058](0058-batch-claim-fifo-prefix.md) (contiguous-due-prefix; OUTBOUND never batched) ·
  [ADR 0101](0101-pre-registered-falsifier-discipline-for-performance-measurement.md) (the discipline §8's gates
  obey) · [ADR 0107](0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md) (Phase 4 **as
  txn-reduction** is closed — the Context draws the boundary this ADR does not cross) ·
  [ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md) /
  [ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) (the closed store-side arc) ·
  [ADR 0075](0075-per-hop-sql-statement-batching.md) (the SQL-Server-scoped flag + provable-no-op precedent) ·
  [ADR 0071](0071-cut-executor-round-trips-b5.md) (B5 — the sync-twin family the D1 record holds
  consistent-with-killed) · [ADR 0064](0064-schema-init-fastpath.md) (the `schema_meta`-hashed DDL batch the §4
  proc DDL rides, guarded) · [ADR 0037](0037-multi-process-sharding-l3.md) /
  [ADR 0063](0063-no-split-store-unified-store-for-sharding.md) (engine shards over ONE unified store — the N=4
  pin topology) ·
  [ADR 0105](0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md)
  (big-body relief is that lane, not a claim-shape lever).
- **Related (bench-campaign record, off-repo, FROZEN per D0):** `MEFOR/aws-bench/STEP6-to-engine/` —
  TO-ENGINE-027 (constraints, verbatim-binding) · TO-ENGINE-032 (packet of record: shares v2, gap statement,
  caveat union) · ACK-D1-verdict (D1 verdict + exclusions) · TO-ENGINE-033 (D0/D2 rulings);
  `…/STEP6-results/` — READY-D1-verdict · READY-D1-T1-readout · READY-shares-v2-owner-packet ·
  `raws-resize-ab/engine-box-932-answers.md` (the H2-noop-at-routed code confirmation + the sampling-gate fix).

---

## Context

### Where the cost is — the frozen D1 verdict (cited, not re-litigated)

At the campaign's fixed operating point (the **B-R2 240-offered pin**: 4 engine shards per ADR 0037 against the
ONE unified store, `claim_mode="pooled"`, 60 s hold, the held B-side rig — 16 vCPU store), the pooled FIFO claim
`claim_fifo_heads` ([`store/sqlserver.py:4515-4854`](../../messagefoundry/store/sqlserver.py#L4515)) costs
**~18.0-18.2 ms/call** (span TOTAL median, replicate pair; nodelog `claim_mean` 18.8-19.0). The decomposition of
record (TO-ENGINE-032 §1):

| bucket | µs/call | share |
|---|---|---|
| EXECUTE client span | 11,718-11,974 | ~65% |
| · server elapsed (6.27 stmts/call × 0.3004 ms) | 1,885 | ~10.5% |
| · wire (1 RTT) | 180-400 | ~1-2% |
| · **residual — per-call, DRIVER-INTERNAL (ODBC/TDS), ~2/3 FIXED** | **9,350-9,990** | **~52-55%** |
| reset+commit#2 (the §1 fold territory) | 1,871-1,909 | ~10.4% |
| H2+commit#1 (outbound carries the H2 work) | 1,262-1,355 | ~7% |

**D1 located the mechanism** (READY-D1-verdict; ACK-D1-verdict): the ~9.7 ms residual is **per-call** (96.1%
inside the blocking `cursor.execute` — T2), **driver-internal**, **~2/3 fixed** (66.8-72.2% — T1: ~6.5-7.0 ms
present at 60/s, where queueing is impossible), and **call-complexity-shaped** — the same driver executes a
trivial 7-statement batch in **0.335 ms**, so the cost tracks what the call *carries*: ~3 KB of batch text
re-sent every call, an arity-varying parameter set whose `(?),(?),…` lane list breaks statement identity, a
10-column payload-bearing result set, ~6 statements per call. **Excluded as remedies, by measurement:**
executor/event-loop/GIL redesign (Python dispatch/GIL is 267 µs, 2.7%); the ADR 0071 sync-twin/fuse family (the
crossing is ~0.3 ms — consistent with its 4× kill record); process-split topology (T3: **worsens** ~20%,
reproduced; remedy-excluding at N=8-on-16-vCPU, mechanism unattributed — not a general anti-scaling law);
connection-count tuning (inert: 320 vs 160 connections = 0.1%). The remedy axis D2 commissions is therefore **the
driver interface itself: reduce what crosses the driver per claim call**.

The attribution of the 6.5-7.0 ms fixed pool **among** text marshaling, per-parameter binding, statement-handle
lifecycle (`sp_prepexec`/`sp_unprepare` churn), and result-set consumption is **unmeasured** — the 0.335 ms
trivial-batch datum differs from the claim on *all* axes simultaneously. This ADR carries that honestly: §8's
G-0 attribution matrix measures the split, and *"the pool lives mainly in binding/result marshaling — the lever
under-delivers"* is a licensed, recordable gate outcome, not a footnote.

### What one clean INGRESS/ROUTED claim call carries across the driver today

Per clean call, in shipped code (batch construction
[`sqlserver.py:4596-4680`](../../messagefoundry/store/sqlserver.py#L4596); finally-guard
[`4776-4817`](../../messagefoundry/store/sqlserver.py#L4776)), **four wire operations** cross the driver
(`fetchall` is a client-side drain of the already-returned sole result set, not a wire op):

1. `cursor.execute(batch)` — **≈3 KB of T-SQL** (measured by reconstruction: 2,513 chars at N=1 requested lane,
   2,765 at N=64, ~4,509 at the 500-lane `_FIFO_HEADS_LANE_CHUNK` clamp; ≈5-9 KB as UTF-16 TDS bytes), re-sent
   **every call**. The `FROM (VALUES (?),(?),…)` lane list makes every distinct lane count (× epoch-guard on/off)
   a **distinct statement identity**; and because `_cursor` opens and closes a fresh HSTMT per call (the EF-6
   close-before-release discipline, [`1694-1718`](../../messagefoundry/store/sqlserver.py#L1694)), pyodbc's
   per-cursor prepare cache **never engages** — every call is a full `sp_prepexec` (text + params) plus
   unprepare bookkeeping. Parameters: **9 + N_requested** (5 scalars + N lane names + the epoch pair × 2 sites)
   — 10-11 at the pin's *claimed*-lane counts (lanes/claim 1.42-1.52 at 240, the R6-replacement closure), **20+
   whenever a tick's requested wake-set carries ≥11 lanes**; the requested-lane distribution is unmeasured (an
   open question, not a pin-typical claim). Statements: ~6 plan-producing statements/call server-side. Result:
   1 set, **10 columns** (`keep_id` LEFT-joined to the claimed row); the `NVARCHAR(MAX)` payload ciphertext
   dominates return bytes and is **contractually irreducible** — the routed/transform worker consumes the
   claimed body, and a lazy fetch would *add* a round trip (big-body relief is ADR 0105's lane).
2. `commit()` — commit#1, the claim transaction.
3. `execute("SET LOCK_TIMEOUT -1;")` — the finally-guard's session reset.
4. `commit()` — commit#2, closing the reset's implicit transaction (M-6).

Ops 3-4 cost a measured **1.87-1.91 ms/call under load** (the whole empty-claim 4-wire-op cycle is 0.55 ms p50
at *idle* — the record's juxtaposition, showing part of the dispatch cost is load-inflated). This pair is the one
**measured-sound** lever, licensed at **+3.7% (ingress) to +8.0% (ingress+routed) sustained ceiling** (TO-032
R9), with the gating fact **code-confirmed** (engine-box-932-answers §9.3): the H2 skip-and-complete loop is
gated `if d["destination_name"] is not None:`
([`sqlserver.py:4737`](../../messagefoundry/store/sqlserver.py#L4737); line 4520 at the pinned bench commit
28f860e), and the ingress/routed INSERT constants **hard-code `destination_name` as literal NULL**
([`sqlserver.py:159-174`](../../messagefoundry/store/sqlserver.py#L159)) — **H2 no-ops at INGRESS and ROUTED**
(span corroboration: h2c1 948/965 µs there vs 2,975 µs outbound).

### The boundary with ADR 0107 — this is not the closed lever

[ADR 0107](0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md) closed Phase 4 **as
transaction-count reduction** (elasticity −0.115) and named the engine side as the unattributed frontier. The
campaign since then did exactly the attribution 0107 called for (spans → D1), and the record re-uses the
"Phase-4" name for this work package (TO-ENGINE-027). Nothing here reopens 0107: the fold removes **two wire
operations and a write-less commit** (commit#2 carries no durable write; it exists only to close the reset's
implicit txn), and the driver-interface work removes **per-call marshaling/parse/identity cost** — neither
changes committed durable transactions per message; the `3 + 2H + 2N` durable-write model is unaffected.
**Commit-amortization (durability-point batching) is scoped OUT by D2** — B-R1a sized it +2.9% sustained; it is
sanctioned in principle by TO-027 c.1 and deliberately **not re-scoped in here**.

### The composed requirement (frozen; a bracket, never a promise)

Reaching the 347 RAW bar from the clean-region pin requires removing **6.35-6.64 ms/call**
(claim 18.8-19.0 → ~12.2-12.65 ms; TO-032 §2). The D1 fixed pool (**6.5-7.0 ms**) brackets that requirement
**from above** — this ADR's job is to remove as much of it as the invariants allow, plus the independent
1.87-1.91 ms fold. **No point throughput projection is licensed** (the 029-F4-replaced rule; TO-032 caveats 4
and 15 — *"MISSES, not straddles"* is the licensed language); the §8 bench gates, stated in **ms/call**, are the
**only forward-looking numbers in this ADR**, and the composed requirement is evaluated **only** at the §9
post-build re-measure — as measurement, never beforehand as projection. The certification run remains the
arbiter (TO-027 c.4).

## Decision

Three sub-levers, each behind its own default-OFF flag, each gated separately, all **SQL-Server-only**
(the D1 finding is SS/pyodbc-specific; `postgres.py` — asyncpg, loop-native, with true per-connection prepared
statements and stable statement text — keeps its existing claim path unchanged; SQLite untouched):

| sub-lever | flag (`[store]`, env `MEFOR_STORE_FIFO_CLAIM_*`) | attacks | evidence grade |
|---|---|---|---|
| **C — reset fold** | `fifo_claim_fold_reset` | the 1.87-1.91 ms reset+commit#2 pair (wire ops 3-4) | **SUPPORTED** (measured) |
| **A — proc-ification** | `fifo_claim_proc` | batch text, per-call parse, statement identity, handle churn | **PLAUSIBLE** (bracketed; gate-verified) |
| **B — stable text + prepared handle** | `fifo_claim_prepared` | text re-send + statement identity, without server DDL | **PLAUSIBLE, strictly conditional** (structural feasibility itself is a gate question) |

### 1. Sub-lever C — fold the LOCK_TIMEOUT reset into the claim batch (clean path, INGRESS/ROUTED only)

**Mechanics.** When `fifo_claim_fold_reset` is ON **and** `stage ∈ {INGRESS, ROUTED}`, append exactly one
statement to the end of the shipped batch — after the final SELECT:

```
… FROM @keep kp LEFT JOIN @claimed c ON c.id = kp.id; SET LOCK_TIMEOUT -1;
```

The append is **strictly additive**: every shipped statement runs under exactly the lock regime it runs under
today (the trailing position means STEPs 1-5 and the SELECT still execute under `SET LOCK_TIMEOUT 0` — the
ADR 0066 §9 never-block guarantee is untouched), and with `SET NOCOUNT ON` the trailing SET emits no result set,
so the EF-6 sole-result-set/`fetchall` discipline is unchanged. commit#1 then durably commits the claim **and**
the reset in one transaction; on the clean path the finally-guard's SET + commit#2 are skipped — **4 wire ops
become 2**.

**Why INGRESS/ROUTED only.** At those stages the post-batch H2 loop executes **no DML** — structurally
(the ingress/routed INSERTs bind `destination_name` as literal NULL; the gate at
[`4737`](../../messagefoundry/store/sqlserver.py#L4737)) and code-confirmed (932 §9.3) — so nothing runs between
the batch and commit#1 that needs `LOCK_TIMEOUT 0`. At OUTBOUND (and RESPONSE, which never folds either) the H2
skip-and-complete + `_maybe_finalize` DML deliberately runs **after** the batch under the session's
`LOCK_TIMEOUT 0` ([`4726-4736`](../../messagefoundry/store/sqlserver.py#L4726)) so a contended finalize yields
1222 → EMPTY-all instead of pinning the pooled connection; a trailing reset would flip that DML to wait-forever
— the exact regression TO-032 R9 names. **The outbound/response batches stay byte-identical**; the all-stage
fold (+11.6-11.7%) is explicitly NOT licensed and NOT designed here, pending the outbound H2/`LOCK_TIMEOUT 0`
redesign.

**Runtime guard on the fold's premise (defense-in-depth, not a test-time-only property).** The H2-noop premise
is structural today, but the fold converts any future producer regression from a loud 1222 into a silent
wait-forever hang. Therefore, when the fold is active for a call, a decoded row with
`destination_name IS NOT NULL` **raises a contract-violation error before the H2 branch is entered** — the
existing except path rolls back, the shielded guard resets the session, and the row is named in an ERROR log.
The same rule binds sub-lever A's `@fold_reset` composition (§4). Frozen by AC-5.

**Control flow** (guard body retained **verbatim** from
[`4776-4817`](../../messagefoundry/store/sqlserver.py#L4776), gaining only the skip condition):

```python
fold = self._fifo_claim_fold_reset and stage in (Stage.INGRESS.value, Stage.ROUTED.value)
sql = _shipped_batch + (" SET LOCK_TIMEOUT -1;" if fold else "")   # append-only

reset_committed = False   # True ONLY once the folded reset is DURABLY committed
async with self._acquire() as conn, self._cursor(conn) as cur:
    try:
        await cur.execute(sql, args)
        ...                                # fetchall; kept!=claimed check (rollback +
        ...                                #   EMPTY-all early return, unchanged);
        ...                                # H2 loop — no-op at INGRESS/ROUTED, plus the
        ...                                #   fold-active destination_name guard (raises)
        await self._commit(conn)           # commit#1 — now also commits the folded reset
        reset_committed = fold             # SOLE assignment site; no await between the
                                           #   commit returning and this line
    except Exception as exc:
        await conn.rollback()
        if _is_lock_timeout(exc):          # 1222 → EMPTY-all — unchanged
            ...
            return ClaimedHeads(by_lane={}, rearm=frozenset())
        raise
    finally:
        if not reset_committed:
            # ===== the shipped shielded guard, VERBATIM (4776-4817) =====
            ...
```

**Exit-path case table** (each row verified against the shipped code paths):

| exit path | `reset_committed` | guard runs? | connection released as |
|---|---|---|---|
| clean success, fold ON, INGRESS/ROUTED | True | **skipped** | `LOCK_TIMEOUT -1`, clean boundary (commit#1); the finally contains **no await at all** on exactly this hot path |
| clean success, fold OFF / OUTBOUND / RESPONSE | False | yes (verbatim) | −1, clean (guard SET + commit#2) |
| kept≠claimed fail-closed (rollback + EMPTY-all) | False | yes | −1, clean (the folded reset DID execute server-side and, being session-scoped, survives the rollback — the guard's re-SET is idempotent; running it keeps the one rule "`reset_committed` ⇔ commit#1 returned") |
| 1222 (never-block yield) | False | yes | −1, clean (whether the trailing reset executed before the abort is client-side unknowable — statement- vs batch-abort semantics; the design **never relies on it**) |
| commit#1 raises / any other error | False | yes | −1, clean, best-effort (as shipped) |
| cancellation at any body await | False | yes, shielded | −1, clean, then CancelledError re-raised (see §2's nuance paragraph — **no rollback ran** on this path) |
| cancellation during the guard's own awaits | False | shield completes it | −1, clean |

**Accounting note (A1).** commit#2 today rides `_commit` and increments `committed_txns`; the fold drops folded
claim calls from 2 counted commits to 1. The removed commit is **write-less**, so the `3 + 2H + 2N`
durable-write model is unaffected — but committed-txns/msg dashboards and cost-model comparisons across the flag
flip must expect the shift, annotated before the bench comparisons run.

### 2. Named review — the shielded-finally / B1 / M-6 territory (TO-ENGINE-027 c.3, verbatim-binding)

**Why the guard exists.** `SET LOCK_TIMEOUT` is **SESSION-scoped**: it persists on the pooled connection across
transactions and does **not** revert on error, rollback, or (for sub-lever A) stored-procedure exit. A leaked
`LOCK_TIMEOUT 0` makes an unrelated next borrower spuriously fail with 1222; under `autocommit=False` the reset
SET itself opens an implicit transaction that must be committed or the connection returns to the pool
**mid-txn** (the **M-6** finding). And because the pool releases the connection on *every* exit type, a task
cancellation delivered at the finally's own await points would skip the reset half-done — the **B1**
cancellation-leak finding — hence `ensure_future` + `shield` + await-to-done + re-raise. **A "modest" fold has
tripped this guard once before** (NOTE-002-003 V3 exists because of it); that is why the fold here is
conditional-skip, never guard-removal.

**What the fold MAY touch:** the clean-success exit only; INGRESS/ROUTED only; and only by making the reset
happen *earlier* (inside the batch / the proc's `@fold_reset` tail) with its durability point being commit#1.
It deletes no guard code.

**What the fold MUST NOT touch:** (a) the guard body — retained byte-for-byte, including the shield discipline
and both swallow-and-log arms; (b) `reset_committed` has exactly **one** assignment site, immediately after
`await self._commit(conn)` returns, with **no intervening await** (no suspension point can land between commit
success and the flag); (c) no reasoning of the form "the batch completed, therefore the reset ran" on any error
path — on 1222 the abort point is client-side unknowable, and on kept≠claimed the guard runs anyway (a doubled
reset is idempotent); (d) no DML may ever be added between the batch and commit#1 at a folded stage — it would
run at `LOCK_TIMEOUT -1` (wait-forever) and re-open the pooled-connection pinning hazard (and the
pyodbc-segfault edge) the never-block guarantee kills; the §1 runtime `destination_name` guard enforces this at
run time, and AC-4/AC-5 freeze it in CI.

**The cancellation nuance, stated so no future edit "fixes" it.** On a cancellation delivered at a *body*
await, there is **no rollback**: `CancelledError` derives from `BaseException`, so the shipped
`except Exception` ([`4760`](../../messagefoundry/store/sqlserver.py#L4760)) never catches it. The guard's
`SET -1` + commit may therefore **durably commit a claim that completed server-side but was never returned to
the caller** — those rows sit INFLIGHT until `reset_stale_inflight` recovers them (attempts bumped;
at-least-once preserved). This is **shipped** behavior, identical before and after the fold; the shipped comment
at 4779-4781 ("the body has always committed or rolled back") **overclaims** for exactly this path.
`reset_committed` stays False there, so the guard always runs; the fold must not alter this path, and no future
edit may remove the guard's commit on it.

**The cancellation-during-finally case** is unchanged verbatim: the shielded task completes the SET + commit
even when the awaiting task is cancelled; the `CancelledError` is re-raised only after the reset is done, so
shutdown or quiesce can never leak `LOCK_TIMEOUT 0` (or a mid-txn connection) into the pool.

### 3. The SET-options ledger (session scope is load-bearing, not a trap to defuse)

- **`SET LOCK_TIMEOUT` does NOT revert at stored-procedure exit** (unlike the ANSI SET options) — and that
  persistence is **load-bearing**: at OUTBOUND the H2 DML runs *after* the claim batch/proc, in the same
  session and transaction, deliberately under `LOCK_TIMEOUT 0`. A proc that reset it unconditionally on exit
  would silently flip that DML to wait-forever. Therefore the §4 procs perform **no** `LOCK_TIMEOUT` reset
  outside the flag-driven conditional tail, and the Python shielded guard remains the **single reset authority**
  on every non-clean path. A `TRY/CATCH` in-proc reset is **rejected**: a client cancellation delivers an
  attention signal that aborts the batch — no CATCH runs; and a second, partial owner of the same session option
  is how the guard was tripped before.
- **`SET NOCOUNT`** *is* exit-restored at proc exit — a real, honestly-stated delta: today the batch's
  session-persistent `NOCOUNT ON` suppresses rowcount DONE tokens for the post-batch outbound H2 statements;
  under the proc those statements may emit them. Harmless for the `execute`/`fetchone` consumers, and verified
  by the outbound leg of the §8 certification battery — never claimed "as today".

### 4. Sub-lever A — proc-ification: two lane-family, name-versioned claim procedures

**Two procedures, not one** — the lane column is a **code-controlled literal** baked into the statement text
(`_lane_col`, [`sqlserver.py:4149-4156`](../../messagefoundry/store/sqlserver.py#L4149): `channel_id` for
ingress/routed/response, `destination_name` for outbound; interpolated at the STEP-1 and STEP-3 predicates), and
a column name cannot be a T-SQL parameter. One static-SQL proc cannot serve both families; dynamic SQL is
**rejected** (it reintroduces per-call parse plus an injection surface at the reliability core). So:

- **`dbo.mefor_claim_fifo_heads_cid_v1`** — the `channel_id`-laned stages (ingress, routed, response),
- **`dbo.mefor_claim_fifo_heads_dst_v1`** — the `destination_name`-laned stage (outbound; `@k` arrives
  pre-clamped to 1 by the existing, untouched Python HARD-1 clamp, which also clamps RESPONSE).

Both carry the identical fixed-arity signature; the Python dispatch selects the CALL text by lane family exactly
as it selects `lane_col` today:

```sql
@now FLOAT, @stage NVARCHAR(16), @k INT, @pending NVARCHAR(32), @inflight NVARCHAR(32),
@lanes NVARCHAR(MAX),                 -- JSON array of lane names (caller-deduped, <=500)
@lease_key NVARCHAR(256) = NULL,
@leader_epoch BIGINT = NULL,          -- NULL = H1 fence disabled (parity with epoch=None)
@fold_reset BIT = 0                   -- §1 composition ONLY; 0 = today's session behavior
```

The call is `{CALL dbo.mefor_claim_fifo_heads_cid_v1 (?,?,?,?,?,?,?,?,?)}` — ~60 chars (schema-qualified: an
unqualified name costs a per-session default-schema resolution probe), **fixed arity 9** at every lane count,
one stable statement identity, plan cached by object id. The pyodbc ~2,100-parameter bound noted at
[`sqlserver.py:116-119`](../../messagefoundry/store/sqlserver.py#L116) becomes structurally unreachable; the
500-lane chunk clamp is retained unchanged client-side as the row-U-lock bound.

**The body is the shipped batch verbatim** — `SET NOCOUNT ON; SET LOCK_TIMEOUT 0;`, the four table variables,
STEPs 1-5 with their exact hint sets, and the same sole 10-column result set — with exactly **three mechanical
substitutions** plus one conditional tail:

1. The `DECLARE @… = ?` block becomes the parameter list.
2. `FROM (VALUES (?),(?),…) AS l(lane)` becomes a decode of the one JSON parameter
   (`OPENJSON(@lanes)` with an explicit cast keeping the `channel_id = l.lane` predicate seek-clean against the
   `NVARCHAR(256)` column; `DISTINCT` as belt-and-suspenders under the caller's preserved dedupe).
3. The conditionally-spliced H1 epoch guard becomes the **fixed nullable form, on BOTH sites** (STEP-3 probe and
   STEP-5 UPDATE), verbatim otherwise:
   `AND (@leader_epoch IS NULL OR (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key = @lease_key) <= @leader_epoch)`
   — with the fence enabled, a **missing lease row yields NULL → UNKNOWN → zero rows (fail-closed on a missing
   lease, identical to shipped)**; `@leader_epoch IS NULL` reproduces `epoch=None` inertness exactly; the
   probe-to-UPDATE fence race (the legitimate kept≠claimed trigger) is unchanged.
4. The proc's **final** statement, after the sole result-set SELECT: `IF @fold_reset = 1 SET LOCK_TIMEOUT -1;`.
   Python passes `@fold_reset` = the same `fold` expression as §1 (fold flag ON ∧ stage ∈ {INGRESS, ROUTED}), so
   A and C compose without a third variant and stay independently measurable; OUTBOUND/RESPONSE **never** set it.

**Hard rule — the proc alters NOTHING about error propagation or transaction state:** no
`BEGIN/COMMIT/ROLLBACK` (it runs inside the client's `autocommit=False` transaction; `@@TRANCOUNT` on exit
equals entry — tested), no `TRY/CATCH`, no `SET XACT_ABORT`, no `LOCK_TIMEOUT` reset outside the `@fold_reset`
tail. Error 1222 raised **inside** the proc reaches pyodbc through the same driver-formatted `"… (1222)"`
message that `_is_lock_timeout` ([`127-142`](../../messagefoundry/store/sqlserver.py#L127)) matches today —
certified explicitly under the flag; the kept≠claimed NULL-twin signal arrives in the same **column-identical
10-column result set** (the c.id→BIT "diet" proposed in drafting is **dropped** — one result contract at every
stage under every flag; the diet is recorded as a follow-up priced by G-0's result axis); a client cancellation
(attention) aborts the proc exactly as it aborts the batch. Everything after `cur.execute` — the drain, the
kept==claimed adjudication and its fail-closed rollback, the message_id-sorted H2 loop, `_commit`, the 1222
EMPTY-all translation, and the shielded finally-guard — is the **same code, untouched**.

**Lane-set encoding — one JSON parameter, and why.** `json.dumps(lane_list)` (default escaping) →
`OPENJSON` decode: no delimiter contract is ever imposed on connection names (lane names are data, never
concatenated into SQL text); dedupe (request-order) and the 500-lane chunk stay client-side. **Lane order is
semantically inert in the claim** (the lane table is set-wise; `ROW_NUMBER()` per lane orders by `seq`; Python
regroups and seq-sorts per lane; H2 iterates in sorted `message_id` order), so no encoding is chosen or rejected
on ordering grounds. Rejected alternatives: **delimited string + `STRING_SPLIT`** (a delimiter appearing in a
lane name silently splits it — a correctness class, not a perf class; the pre-2022 ordering caveat is recorded
though unused); **TVPs** (supported in pyodbc since 4.0.25 but its least-exercised path through aioodbc; a
versioned user-defined table type with no `ALTER TYPE` — an immutable-DDL lifecycle hazard; no byte advantage
over one JSON parameter); **fixed-arity NULL-padded slots** (see §5 — the None-typing/describe hazard,
per-execute descriptor drift, a 64-lane cap vs the 500 chunk, and more marshaling on the dominant 1-2-lane call
shape). **Oversized lane names:** a >256-char requested lane can never match the `NVARCHAR(256)` column today
(claims nothing); a truncating server-side cast could make its prefix match a *real* lane — a shard-safety
contract break (`base.py:522-526`: the lane set is always explicit). The client therefore **skips >256-char lane
names with a WARNING before `json.dumps`**, preserving no-match parity loudly; AC-11 asserts zero claims on both
paths.

**NULL-parameter typing (a hazard the shipped batch never has).** The shipped code splices the epoch guard and
its args out together, so it never binds `None`; the fixed-nullable signature binds `None` for
`@lease_key`/`@leader_epoch` whenever the fence is off, and pyodbc's None-typing can fall back to
`SQLDescribeParam` — on msodbcsql a **server metadata round trip**, never cached on the fresh-HSTMT lifecycle.
All parameters on the proc (and §5 stable-text) path are therefore **driver-pinned** via `cursor.setinputsizes`
(or typed non-NULL sentinels with in-proc `NULLIF` if `setinputsizes` proves unreachable through the pinned
aioodbc 0.5.0 wrapper — a G-A0/G-B0 preflight item); the gate trace asserts **no describe traffic on the claim
path, fence-on and fence-off**.

**Expected mechanism — gate-verified, never assumed.** Whether the parameterized `{CALL}` escape crosses the
pinned stack (pyodbc 5.3.0 / aioodbc 0.5.0 / msodbcsql18) as a **direct TDS RPC** with zero
`sp_prepexec`/`sp_unprepare` traffic is the **G-A0 preflight's finding**, not this ADR's claim — the byte win
(~60 chars vs ~3 KB) holds either way; the parse/identity/handle win differs, and the record states which
framing was observed. Note the honest baseline: after warmup, the server's per-lane-count 'Prepared' plan-cache
entries already amortize server compiles — the removable quantity is client-driver + wire work, whose split G-0
measures.

**Parameter sniffing** is a genuinely new behavior class vs the estimate-neutral batch `DECLARE`d locals:
proc parameters are sniffed; OPENJSON substitutes a fixed cardinality guess for exact VALUES arity. Correctness
is immune by construction (the T6 lesson: correctness lives in the explicit ID pin, not plan shape); the G-A0
plan check asserts the one-seek-per-lane shape at `@k ∈ {1, 64}` per stage, and `OPTION (OPTIMIZE FOR UNKNOWN)`
on the two guarded statements is the **recorded escape hatch** — applied only if the gate shows sniffing
pathology, never preemptively.

**DDL placement — guarded so flag-OFF opens can never break.** The two `CREATE OR ALTER PROCEDURE` statements
join `_SCHEMA` so the ADR 0064 content hash versions them for free (any body edit changes `_schema_hash()` and
forces one guarded, applock-serialized re-apply — a forgotten version bump is impossible). But `_ensure_schema`
executes every `_SCHEMA` statement inside one must-succeed transaction
([`1509-1563`](../../messagefoundry/store/sqlserver.py#L1509)) — unguarded proc DDL would make a compat<130,
pre-2016-SP1, or CREATE-PROCEDURE-denied deployment **fail to open even with every flag OFF**. Each proc
statement is therefore a **self-guarding no-op**:

```sql
IF (SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()) >= 130
   AND HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE PROCEDURE') = 1
   AND /* CREATE OR ALTER available: SERVERPROPERTY('ProductVersion') >= 13.0.4001 (2016 SP1) */
    EXEC(N'CREATE OR ALTER PROCEDURE dbo.mefor_claim_fifo_heads_cid_v1 … AS …');
```

The dynamic `EXEC` defers the body's compile (OPENJSON below compat 130 never parses) and satisfies
`CREATE OR ALTER`'s batch-initial rule; a guard miss leaves the proc uncreated — never a failed open. The
**correct floor, stated once:** OPENJSON needs **database COMPATIBILITY_LEVEL ≥ 130 (SQL Server 2016)** — a
per-database property, not a server version; `CREATE OR ALTER` needs 2016 SP1. AC-10 pins the flag-OFF open on a
compat-120 database and under a DDL-denied principal.

**Startup gate (fail-safe to the batch, loudly).** With `fifo_claim_proc` ON, `open()` probes: (a)
`OBJECT_ID` of **both** procs; (b) a SHA-256 of each deployed body via `OBJECT_DEFINITION()` against the
**stored forms** of the shipped DDL text (normalized) — **existence alone cannot catch a hand-edited body**, and
the ADR 0064 marker covers only in-repo edits, while the proc *is* the claim logic; (c) `compatibility_level ≥
130`. Any failure → the store records `claim_proc_effective = False`, logs a **WARNING naming the reason**,
publishes the degraded gauge (see the second amendment below), and runs the shipped batch — never a lane
outage; the hot path contains **no error-2812 handling**. Out-of-band drift is caught at the next open.

> **AMENDMENT (2026-07-30) — `OBJECT_DEFINITION()` does not return the submitted text, and this gate was
> inert until it was fixed.**
>
> SQL Server does not store a `CREATE OR ALTER` module verbatim: it **deletes the `OR` and `ALTER` keyword
> tokens and keeps their separators**, so a head submitted as `CREATE OR ALTER PROCEDURE dbo.x` is returned by
> `OBJECT_DEFINITION()` as `CREATE` + three spaces + `PROCEDURE dbo.x` (character delta exactly 7; everything
> after the head byte-identical). MEASURED on SQL Server 2022 16.0.4255.1 and 2025 17.0.4055.5, compat
> 130/160/170, across five deploy paths (fresh `CREATE`, the `OR ALTER` re-apply, a plain batch, inside the
> shipped guarded `EXEC(N'…')`, and an out-of-band `ALTER PROCEDURE` — which the engine also rewrites, to a
> single-spaced `CREATE PROCEDURE`). Case is preserved, not folded; `PROC` survives as `CREATE   PROC`.
>
> Because the gate as originally implemented hashed the **submitted** text, it **could never pass for a proc
> deployed by `_claim_proc_ddl`, on any engine that function can deploy to** — sub-lever A degraded to the batch
> on every open, in every deployment, from the feature shipping until this amendment. The lever was inert, not
> merely unused. (Scope note: this is a statement about *this* deploy path, not about every conceivable module.)
>
> The fix is **shipped-side only**: the gate now compares the deployed hash against a small set of
> code-controlled constants — the head forms a server may store for a module *this build* deployed
> (`_CLAIM_PROC_STORED_HEADS`: the measured `rewritten` form, plus the `verbatim` form for a hypothetical
> non-rewriting engine). `_claim_proc_body()` renders byte-identically, so `_claim_proc_ddl`, `_SCHEMA`,
> `_schema_hash()` and the golden body pins are untouched: **no re-pin and no forced DDL re-apply on any live
> database.** The expected map is keyed **per proc**, so the cid body served under the dst name (reachable via
> `sp_rename`, which does not rewrite `sys.sql_modules.definition`) degrades rather than silently swapping the
> lane predicate. Head spellings this deploy path cannot emit (`CREATE PROC`, differing case) keep failing the
> gate: each is affirmative evidence of an out-of-band hand deploy, which is the AC-7 event.
>
> The accepted set is exactly two constants over **normalized** text. It is *not* two byte strings —
> `_normalize_tsql` still applies to the deployed side, so its whitespace collapse remains semantically lossy
> inside comments and string literals. That is contained by the AC-8 body lint (no quotes, no `--`, no `/*`,
> ASCII-only), which is now load-bearing rather than defensive.
>
> **`DELETE FROM schema_meta` was previously prescribed here as the remedy for a body mismatch. It could not
> work** — the re-apply submits the same text, the engine rewrites it the same way, and the hash mismatches
> again — so the advice has been removed from the ADR and from the operator-facing degraded reason.

> **AMENDMENT (2026-07-31) — the degraded gauge now exists, and probe (a) is a real probe again.** Two
> follow-ups the amendment above deliberately held out of the bug fix.
>
> **1. The gauge was aspirational.** AC-7 requires "a WARNING naming the reason **+ degraded gauge**", and this
> section's compensating-control story assumes an operator can SEE the degraded state. Until this amendment
> nobody could: `claim_proc_effective` / `claim_proc_degraded_reason` were read by the store's own tests and
> **nothing else** — no `/stats`, no `/status`, no `/metrics`, no console. The entire operator signal was one
> WARNING line at `open()`. That is not a missing nicety, it is a load-bearing part of *why the amendment above
> was needed*: a fleet running the flag degraded on every open, forever, and the only thing that could have
> told anyone was a log line nobody was watching which named the wrong cause.
>
> The gauge is now a store accessor, `claim_proc_status()`, surfaced on three operator surfaces:
>
> | surface | carries |
> |---|---|
> | `GET /status` → `claim_proc` | `effective`, the human-readable `degraded_reason`, and the matched `head_forms` |
> | `GET /metrics` | `messagefoundry_store_claim_proc_effective` (0/1) and `messagefoundry_store_claim_proc_head_verbatim` (0/1) |
> | the console's store panel (`/ui/status`) | active-vs-degraded, plus the reason when degraded / the head forms when green |
>
> Three shape decisions, so they are not re-litigated. **`None` when the flag is off**, so "not requested" is a
> distinct state from "requested and degraded"; the Prometheus series are correspondingly **absent**, not a
> constant `0` that every SQLite fleet would publish unalertably. **No reason label in the exposition** — the
> reason is free text embedding a proc name and, on the probe-failure arm, an exception string, so a label
> would be unbounded cardinality *and* a breach of the exporter's strict `{connection, destination, status,
> version, le}` allowlist; the string lives on `/status` and the console instead. **It does not feed the
> console's engine-health heart**: a degrade is a performance lever not paying off, claims keep flowing, and
> making the nav cry wolf about it would devalue the signal that means the store is actually unwell.
>
> `head_forms` (proc name → `rewritten` | `verbatim`) is surfaced for the same reason it is logged: a fleet
> reporting `verbatim` is a live counterexample to `_CLAIM_PROC_STORED_HEADS`'s compatibility assumption — no
> engine measured to date stores the `CREATE OR ALTER` head unrewritten — and it was previously visible only
> at INFO. Observability only: the accept/degrade logic is untouched.
>
> **2. A missing `VIEW DEFINITION` grant was reported as a missing proc.** This section has always specified
> probe (a) as "`OBJECT_ID` of **both** procs", but the implementation folded (a) into (b) and inferred absence
> from a NULL `OBJECT_DEFINITION`. **MEASURED** (2026-07-31, on the lab SQL Server): a principal holding only
> `EXECUTE` on the proc gets a non-NULL `OBJECT_ID` and a **NULL** `OBJECT_DEFINITION`; the compat probe still
> passes. So a deployed, working, correct procedure was reported as *missing*, and the operator was sent to fix
> a `CREATE PROCEDURE` permission that was neither the cause nor the cure. `WITH ENCRYPTION` produces the
> identical NULL and the identical misdiagnosis — and because *that* half needs no security principal, it is
> now a live test leg (`test_a_deployed_proc_can_return_a_null_definition`), which pins on a real server the
> one thing an offline stub cannot show: that the two functions genuinely disagree. The permission half stays
> deferred with AC-10's other permission scenarios to a purpose-configured server.
>
> This is not a hypothetical posture here: §5's sub-lever B design explicitly serves "a fleet whose DB
> principal can never hold `CREATE PROCEDURE`" — DBA-provisioned procs plus a least-privilege app principal —
> which is exactly the deployment shape that hits it. The probe now returns `OBJECT_ID` beside the definition
> and the two conditions get separate reasons:
>
> | condition | reason |
> |---|---|
> | `OBJECT_ID` NULL | genuinely absent — guarded DDL skipped, `CREATE PROCEDURE`/ALTER-on-schema denied, or a pre-2016-SP1 engine |
> | `OBJECT_ID` non-NULL, `OBJECT_DEFINITION` NULL | deployed but unreadable — **`GRANT VIEW DEFINITION`**, or the module is `WITH ENCRYPTION` |
>
> Both still **degrade** — the gate hashes the body and cannot pass on one it cannot read — so no accept/reject
> behaviour changed; only the diagnosis did. The probe SQL is pinned by an exact-match assertion in the
> offline suite (a typo'd probe must fail loudly rather than silently match), so that pin moved with it and
> stayed exact.

**Versioning, mixed vintages, downgrade.** Procs are **name-versioned** (`_v1`, `_v2`, …): engine sharding runs
N processes against ONE unified store (ADR 0037/0063), so a rolling upgrade briefly runs two builds against one
database — each build calls exactly the body it shipped; a newer build's `_v2` never touches `_v1`. A retired
version is dropped only by an explicit later `_SCHEMA` statement, one release after nothing ships it.
**Downgrade** to a pre-0114 build leaves the version-named procs **orphaned and inert** (nothing calls or drops
them; re-upgrade reclaims them via `CREATE OR ALTER`); mixed-vintage schema-marker thrash on restarts is
pre-existing ADR 0064 behavior — applock-serialized and idempotent — recorded here so an operator seeing
repeated "schema DDL batch applied" lines mid-rollback knows it is expected. **Grants:** the bootstrap principal
owns the procs (EXECUTE implicit via ownership); a hardened split-principal deployment must `GRANT EXECUTE` — an
ops-doc line, not a code path. **Two-copies drift** (batch vs proc bodies) is contained by the content hash +
the body-definition probe + a lint test diffing the proc DDL's statement sequence against the batch construction.
(Until the 2026-07-30 amendment the body-definition probe was **not** a real compensating control: it compared
against text no server could return, so its verdict was constant and a genuine tamper was indistinguishable from
baseline. The content hash and the DDL-vs-batch lint were carrying that containment alone.)

### 5. Sub-lever B — stable statement text + a retained prepared claim cursor (the non-DDL fallback lane)

**The driver model this stands on (verified against the pinned code and stated so nobody mis-remembers it):**
pyodbc's prepare reuse is per-cursor and one-slot — the same SQL re-executed on the *same* HSTMT skips
`SQLPrepare`; any other statement on the cursor evicts the slot; a new cursor is a new HSTMT is a full
re-prepare. This store opens a **fresh cursor per call** under the EF-6 close-before-release (no-MARS)
discipline — so **stable text alone buys no client-side handle reuse**, only server plan-cache stability inside
the already-small 1.885 ms server bucket. B's standalone stable-text worth is therefore **honestly small**; its
value is as the prerequisite that makes handle reuse possible, and as risk retirement for A's signature.

**Mechanism.** With `fifo_claim_prepared` ON (INGRESS/ROUTED only; OUTBOUND/RESPONSE take the shipped path
byte-identically):

- **Stable text (the same encoding as §4, no proc):** the lane source becomes the one JSON `NVARCHAR(MAX)`
  parameter (OPENJSON decode, compat ≥ 130 probed at open, loud fallback below it); the epoch guard becomes the
  fixed nullable form on both sites (one text across both epoch modes); the trailing `SET LOCK_TIMEOUT -1;`
  rides **inside** the stable text (see the coupling below), so the whole INGRESS/ROUTED scope has **one**
  statement identity, arity-invariant, chunk-preserving (500), with all descriptors pinned via `setinputsizes`
  (the lanes parameter pinned to the long class so a 1-lane and a 500-lane call bind identically — no
  binding-class flip can silently force a re-prepare). Fixed-arity NULL-padded slots are **rejected**: ~62 None
  params per call trigger the None-typing/describe hazard; str↔None slot flips are per-execute descriptor
  drift; it caps the wake-set at 64 vs the shipped 500 chunk (a claim-granularity behavior change); and it binds
  64+ params on a call shape whose pin-typical claimed lanes are 1.42-1.52.
- **Retained prepared handle on store-owned dedicated connections.** The concrete holder is **named**: raw
  connections **owned by the store, not pooled** (an aioodbc pool cannot retain a cursor across
  acquire/release; the ADR 0071 `_SyncHandoffPool` is a sync pyodbc pool and is not this), one small set per
  stage ∈ {INGRESS, ROUTED}, sized as a stated function of the pooled-claimer concurrency per stage (connection
  count is licensed neutral — T3: inert at 2×), opened lazily on the first flagged claim, closed at store
  teardown. Each connection carries one long-lived cursor whose one-slot cache holds the stable text: steady
  state per clean claim = **`sp_execute` (handle + ~10 params) + commit** — no text, no prepare, no cursor
  create/free, no per-call unprepare. **STORE-3 explicitly:** each dedicated connection gets
  `timeout = command_timeout` applied at open **and after every reopen** (the holder bypasses `_acquire`, which
  is where the per-borrow timeout lives — the lesson of the silently-unapplied statement timeout that let a hung
  statement hold row X-locks forever); recycling is disabled — any recycle is an eviction event (one natural
  re-prepare). Observability parity: the holder reports additively through `pool_status()` (a sibling
  `claim_pool` field) so the B11 acquire-wait wall signal stays honest.
- **Why dedicated connections (EF-6):** a drained `UPDATE…OUTPUT` result still holds its statement handle
  active on a no-MARS connection ([`_cursor`, 1694-1718](../../messagefoundry/store/sqlserver.py#L1694) — the
  v0.2.3 lesson); a sibling cursor's execute on the same connection races `HY000 … Connection is busy`. A
  dedicated claim connection is never lent to another statement class, so its open handle can collide with
  nothing.
- **Fail-closed couplings.** `fifo_claim_prepared` **logs and no-ops unless `fifo_claim_fold_reset` is ON**: on
  a clean call the finally-guard would otherwise execute its reset SET on the retained cursor — evicting the
  one-slot cache every call (silently zeroing B, latency indistinguishable from stable-text-only) — and the
  once-drafted "sibling cursor" fallback is **deleted** (it is the EF-6 busy race by construction). With the
  fold ON, the clean path never executes a separate reset; the guard runs only on non-clean paths.
- **Eviction/discard policy (scoped, so a contention burst cannot become a connect storm):** on
  **cancellation or an unclassified error**, run the shipped shielded guard, then **discard** the dedicated
  connection (defense-in-depth above the guard, never a substitute — the guard's M-6 half is
  connection-topology-independent, and TO-027 c.3 is verbatim-binding, so the guard is retained verbatim even
  though a dedicated connection's "next borrower" is only another claim). On **1222 and kept≠claimed** — normal
  contention-yield and fence-race signals, which do not poison the connection — the connection is **kept** after
  the guard completes; worst case is one re-prepare from the guard's one-slot eviction. A leader-epoch flip does
  not change the fixed-nullable text (no re-prepare on promotion; the fence arms via the now-non-NULL params).
- **Proof obligation — reuse is never assumed:** G-B's wire proof requires `sp_execute` ≈ claim calls and
  `sp_prepexec` ≈ dedicated-connections × text-variants on an XE/rpc trace; a re-prepare storm fails the gate
  whatever the latency numbers look like.

**One flag for sub-lever B — the bundle, sanctioned in writing (TO-027 c.2).** Stable text is not independently
promotable: on the shipped fresh-cursor lifecycle it buys near-nothing client-side (above), and its identity win
is subsumed by A — a standalone stable-text flag would be a flag no gate could ever license flipping alone.
`fifo_claim_prepared` therefore gates the sub-lever as a whole; attribution inside the gate is preserved by G-0's
factor matrix plus an instrumented stable-text-only arm in G-B (measurement arms, not flip decisions).

**Compose-or-compete with A (pre-registered decision rule).** B's JSON-lanes encoding and fixed-nullable guard
*are* A's signature — shipping either retires the other's parameter-design risk. But the retained handle
**competes** with A's RPC for the same bytes: if A ships and its gate is green, B is **retired, not stacked**
(two mechanisms holding the same bytes is double reliability-core surface for zero incremental bytes); its flag
still ships, default OFF, recorded superseded-for-now. If G-0's split shows the residual is params/result-bound,
the honest, pre-registered conclusion is that **both** A's and B's ceilings are low — an admissible outcome that
must be recorded, not argued around.

### 6. Flag architecture — one flag per sub-lever, default OFF, SQL-Server-only

`StoreSettings` (`[store]`, env `MEFOR_STORE_<FIELD>` — the `fifo_claim_batch` precedent,
[`config/settings.py:277-286`](../../messagefoundry/config/settings.py#L277)):

```python
# ADR 0114 Phase-4 claim-path sub-levers. All three: DEFAULT OFF (reliability-core), read ONCE at
# store open (restart to change, like claim_mode), and SQL-Server-only by construction: only
# SqlServerStore reads them; MessageStore/PostgresStore never reference them, so on those backends
# they are provable no-ops (the ADR 0075 scoping precedent, frozen by a sentinel test). Each may be
# flipped ON only after ITS OWN ADR 0114 §8 bench gate; default flips are a separate, owner-gated
# follow-up decision recorded against the passed gate (AC-14).
fifo_claim_fold_reset: bool = Field(default=False, description=(
    "Fold the pooled claim's session LOCK_TIMEOUT reset into the claim batch on the CLEAN success "
    "path at INGRESS/ROUTED (commit#2 disappears; the shielded finally-guard remains for every "
    "non-clean exit). SQL Server only; OFF = byte-identical shipped batch + guard."))
fifo_claim_proc: bool = Field(default=False, description=(
    "Execute the pooled claim via the two lane-family versioned procs "
    "(dbo.mefor_claim_fifo_heads_cid_v1/_dst_v1; fixed-arity CALL) instead of the ~3KB ad-hoc "
    "batch. Fails safe to the batch (loud) if the procs are missing/stale or compat < 130. "
    "SQL Server only; OFF = byte-identical."))
fifo_claim_prepared: bool = Field(default=False, description=(
    "Stabilize the pooled claim's statement text (one JSON lanes parameter) and retain a prepared "
    "claim cursor on store-owned dedicated connections (INGRESS/ROUTED). Logs + no-ops unless "
    "fifo_claim_fold_reset is ON. Non-DDL fallback lane to fifo_claim_proc. SQL Server only; "
    "OFF = byte-identical."))
```

**OFF = byte-identical** — the claim's SQL text, parameter tuple, wire-op sequence, and finally-guard are the
shipped construction byte-for-byte, frozen by a golden-text + wire-op-sequence test at N ∈ {1, 4, 64}, epoch
on/off (AC-1). **PG is scoped out explicitly:** the D1 driver-cost finding is SQL Server/pyodbc (ODBC/TDS
text marshaling + `sp_prepexec` on a thread-crossing driver — the ADR 0071 B5 wall's sibling); asyncpg is
loop-native with stable statement text and true prepared statements, so `postgres.py` keeps its path; SQLite
likewise. The per-lane (`claim_mode="per_lane"`) path, `claim_next_fifo`, `claim_next_fifo_batch`,
`claim_ready`, `release_claimed`, lane discovery, and the RCSI pooled-mode startup gate are all outside the
blast radius.

### 7. Invariants — preserved EXACTLY (TO-ENGINE-027 c.1 + c.4)

**Reliability invariant (non-negotiable):** the ACK is issued only after the message's own ingress commit is
durable; every stage handoff stays a single committed transaction; per-message atomicity preserved. The claim is
not a handoff — it is the claim's own poison-guard txn — and the only commit this ADR removes (commit#2) carries
**no durable write**. No sub-lever adds, moves, or removes any other commit boundary; durability-point batching
stays OUT (D2). The count-and-log invariant is untouched: dispositions, dead-lettering, and the
decrypt-after-commit poison containment are byte-identical on every path.

**FIFO-always semantics, statement-for-statement, re-certified under every shipped flag combination:**
probe-then-claim (the #285 inversion — STEP 1 plain-RCSI snapshot discovery, STEP 2 contiguous-DUE cutoff,
STEP 3 `(UPDLOCK, ROWLOCK, READPAST)` per-lane **ordered range-scan** probe confined to the discovered window
(the canonical READPAST skip pattern — never a singleton key seek), STEP 4 head-pinned contiguity (head lost ⇒
lane EMPTY, never `[N+1, …]`), STEP 5 `OUTPUT … INTO` claim of exactly the kept prefixes); never-block
(`SET LOCK_TIMEOUT 0` → 1222 → EMPTY-all fail-closed, heads PENDING, attempts untouched — matched by the
unchanged `_is_lock_timeout` on the driver's `"(1222)"` embedding, which proc origin does not alter, certified
explicitly); the H1 epoch fence on the probe **AND** the UPDATE (fixed nullable form; NULL-epoch inert; missing
lease row fail-closed); kept==claimed fail-closed whole-call rollback (same NULL-twin signal, same 10-column
result, same Python adjudication); H2 skip-and-complete at OUTBOUND in the same txn with the sorted-`message_id`
applock discipline ([`4718-4725`](../../messagefoundry/store/sqlserver.py#L4718)); per-lane contiguous-due-prefix
with the OUTBOUND/RESPONSE `per_lane_limit=1` hard clamp; the `require_rcsi_for_pooled` gate. **The
certification run remains the arbiter of all of it.**

### 8. Pre-registered bench gates (ADR 0101 discipline: rules fixed BEFORE any run; no post-hoc re-cuts)

**Fixed operating point:** the **B-R2 240-offered pin** — 4 engine shards over the ONE unified store, 60 s hold,
the held B-side rig (the D3 hold makes the re-measure B-comparable — **all of §8-§9 must precede any D3 revert
wipe**). **Instrument:** a CLAIM_SPANS3-class span rider, 1-in-8 sampling, **counter-gated**
(`_n += 1; _n % 8 == 0` — the 932 §9.5 fix for the timer-bit residue bias; the shipped timer-bit gate ran
biased), known perturbation ~4.5-7.3% (sustained unmoved) carried; instruments reverted + pinned-clean verified
before certification. **Discipline:** each gate A/Bs exactly **one** flag against the then-current promoted
base; **a replicate pair per arm, both replicates must clear**. Threshold re-cuts are permitted **only before**
a gate's first run, by the owner, in writing — never after (the goalpost rule two prior results were retracted
under). **Middle-zone rule (total decision rules, all gates):** a pooled result in [kill, accept), or replicates
straddling a bound, licenses **one** additional replicate pair; if the pooled median across the four runs still
lands between kill and accept, the arm is recorded **NOT-PROMOTED** (flag stays OFF) *without* being recorded as
a mechanism kill — owner adjudication in writing.

**G-0 — attribution micro-matrix (preflight; idle rig, sync pyodbc — the 0.335 ms instrument extended; no
engine build, no flag).** Factor sweep {text: full-stable vs minimal} × {cursor: fresh-per-call vs persistent} ×
{lane source: VALUES-arity vs JSON param} × {result: full-10-column-with-payload vs empty} × {payload: bench-p50
vs 64 B} **plus a `{CALL}` proc cell** (so the A-vs-B compete decision is measured, not argued); ≥1,000
calls/cell; medians + p99; ODBC-trace/XEvents corroboration of the wire ops per cell (including whether the
shipped per-call `sp_unprepare` is a real wire op or driver-piggybacked). Deliverable: the ms split of the
~9.35-9.99 ms residual across the text / params / statements / result axes, anchored to the 0.335 ms floor.
**G-0 is informative: it may only TIGHTEN the floors below, never loosen them.**

**Common invariant battery (every arm; any trip = KILL for that arm):** FIFO inversions/replays **0/0**;
`no_loss`; `stranded=0`; kept≠claimed mismatch count 0 absent induced failover (rate unchanged vs control under
a forced fence-race micro-arm); 1222 yield-rate within the control band; **`@@LOCK_TIMEOUT = -1` pool assay**
after every run, including a forced-contention (1222) and a forced-cancellation micro-arm; span-vs-nodelog
same-arm mean-to-mean reconciliation ≤15% (the historical admissibility bound; the campaign achieved <1% — a
breach marks the instrument, not the lever); sustained/offered within the control replicate band.

| gate | preconditions | acceptance (both replicates) | kill | registered expectation (bracket, not prediction) |
|---|---|---|---|---|
| **G-C fold** (`fifo_claim_fold_reset`) | battery | ingress AND routed per-stage claim TOTAL medians **each fall ≥1.5 ms/call** vs control; reset2 bucket **≤0.15 ms** at ingress/routed; outbound TOTAL unchanged within replicate spread | reduction **<0.9 ms/call** on both replicates, or any battery trip | **SUPPORTED**: 1.87-1.91 ms available (the ≥1.5 floor honestly discounts the load-inflation share that may reappear in the remaining two wire ops); +8.0% sustained ceiling is Little's-law-conditional — observed, never gated as a projection; idle empty-claim 4-op cycle ~0.55 → ~0.27 ms observed, not gated |
| **G-A proc** (`fifo_claim_proc`) | **G-A0** (hard precondition): XE/rpc trace shows `rpc_starting` naming the proc, the **absence** of `sp_prepexec`/`sp_unprepare` on the claim path, and **no describe traffic** (`sp_describe_undeclared_parameters`/proc-metadata queries), fence-on AND fence-off; plan check — one reused 'Proc' plan across lane counts, per-lane seek shape (no scan/sort/spool) at `@k ∈ {1, 64}`, per stage; the observed framing (RPC vs language batch) is **recorded** either way | ingress AND routed per-stage EXEC client-span medians **each fall ≥2.0 ms/call** vs control; outbound reported separately, **no-regression-only** (within spread); server elapsed must **not rise >10%** (the cost must be removed, not relocated into the proc) | reduction **<0.75 ms/call** on both replicates, or any battery/preflight trip | **PLAUSIBLE**: bracketed from above by the 6.5-7.0 ms fixed pool; the 0.335 ms trivial-batch datum is the small-call existence proof; "the pool lives mainly in binding/result marshaling — the lever under-delivers" is a licensed, recordable outcome |
| **G-B prepared** (`fifo_claim_prepared`) | **G-B0** (structural, idle, no load arm on failure): `SQLPrepare`-once / `sp_execute`-per-call reuse demonstrably reachable on the retained-cursor holder (trace-verified); `setinputsizes` reachable and effective on the pinned aioodbc/pyodbc; EF-6 regression leg (cold start + churn, no busy-handle); structural fail ⇒ recorded **infeasible-on-this-driver**, flag never flips, no load arm | *additional* ingress AND routed per-stage EXEC medians **each fall ≥1.25 ms/call** over the then-current promoted base; the wire **reuse proof** (`sp_execute` ≈ claims; `sp_prepexec` ≈ dedicated-connections × text-variants — a re-prepare storm fails regardless of latency); a mid-run leader-epoch flip (fenced ex-leader claims 0 across all lanes; no text change, no re-prepare storm); a cancellation storm under load (quiesce; post-run session sweep — no `LOCK_TIMEOUT 0` leak, no mid-txn connection); a **hung-statement leg** (command_timeout enforced on the dedicated connections — STORE-3); a forced-contention-storm leg (1222 burst ⇒ no connect/re-prepare churn beyond the one-slot worst case) | additional reduction **<0.5 ms/call** on both replicates, or any battery/preflight trip | **PLAUSIBLE, strictly conditional** on G-B0 + the reuse proof; an instrumented stable-text-only arm attributes B's two halves (measurement, not a flip decision) |

**O-1 — pre-registered observation (excluded from every flip rule):** the low-load fixed-component direct read
(EXEC − server − wire at 60/s, the T1 shape) before/after each promoted lever — reported as a band, no
conversion to throughput, no decision rule.

**Correctness precondition for every gate:** the full FIFO certification suite + the store-primitive tests run
green under the arm's flag combination **before any perf reading is admissible** — probe-then-claim head-pinning
(T6-class plan-shape independence), never-block (1222 → EMPTY-all, heads PENDING, attempts untouched, the
in-proc-1222 `"(1222)"` message-format certification), H1 fence (fenced ex-leader claims 0; NULL-epoch parity;
missing-lease fail-closed), kept==claimed fail-closed rollback, H2 skip-and-complete at outbound
(message_id-sorted applock order; the NOCOUNT-reversion delta observed harmless), per-lane
contiguous-due-prefix, RCSI pooled-mode gate, hostile/oversized-lane-name legs, the 500-lane chunk, and the
differential store-primitive test (shipped vs flagged paths return identical `ClaimedHeads` over identical DB
states, including the mismatch and 1222 translations). **Any miss = the flag stays OFF; no partial credit.**

### 9. Rollout order, post-build re-measure, certification sequencing

1. **Build + gate C (fold) first** — measured-sound, smallest surface, independent of A/B.
2. **Build + gate A (proc)** against the then-current base (fold-ON if promoted); the proc's `@fold_reset`
   composes C's promotion state without a third variant.
3. **B (prepared) runs conditionally**: if A kills, if G-A0 fails structurally, or if the owner wants the
   non-DDL fallback quantified (a fleet whose DB principal can never hold CREATE PROCEDURE). If A promotes, B is
   recorded **superseded-for-now** (retire-not-stack, §5); its flag still ships, default OFF. (B-first is the
   recorded fallback ladder only if the fold gate kills.)
4. **Post-build composed re-measure** at the B-R2 pin with **all promoted flags ON** (replicate pair): report
   claim ms/call against the frozen 18.8-19.0 baseline and the **12.2-12.65 ms composed-requirement line** —
   evaluated here as *measurement*, never beforehand as projection; **MISSES-not-straddles** stays the licensed
   language until this step and the certification run say otherwise.
5. **Wall re-measure** (the 318-330/360-region rungs): pin-region shares and ms/call reductions transfer to the
   wall as **hypothesis only** (TO-032 caveat 3 — the wall's binding constraint is unidentified); measure, don't
   assume, before any bar statement.
6. **Owner D4, then the certification run — the arbiter** (the 347 RAW clean-knee bar), carrying the standing
   out-of-sample riders verbatim wherever certification language appears: **no clean rung exists on this rig
   (all rungs frozen-tail)** — the 347 clean-knee bar is strictly an out-of-sample prediction; **SQL Server
   Developer Edition both sides** makes a Standard-edition production store additionally out-of-sample (TO-032
   caveats 10-11).
7. **Sequencing constraint:** steps 1-6 precede any **D3 revert wipe** (the wipe destroys B-comparability
   permanently — the A-box precedent). D3 timing stays the owner's call.

## Acceptance Criteria

- **AC-1** — WITH all three flags at defaults, the claim's SQL text, parameter tuple, wire-op sequence, and
  finally-guard SHALL be byte-identical to pre-ADR behavior. → golden-text + wire-op-sequence test at
  N ∈ {1, 4, 64}, epoch on/off.
- **AC-2** — WHEN `fifo_claim_fold_reset` is ON, the trailing reset SHALL be appended (and `@fold_reset=1`
  passed) only for stage ∈ {INGRESS, ROUTED}; OUTBOUND and RESPONSE SHALL stay byte-identical. → per-stage text
  + args assertion.
- **AC-3** — On EVERY non-clean exit (1222, kept≠claimed, commit#1 failure, cancellation at any body await,
  cancellation during the finally), the verbatim shielded guard SHALL run and the connection SHALL release with
  `@@LOCK_TIMEOUT = -1` on a clean txn boundary. → fault-injection suite + post-test pool assay.
- **AC-4** — `reset_committed` SHALL have exactly one assignment site, immediately after commit#1's await with
  no intervening await; the guard body SHALL be byte-identical to the shipped 4776-4817 block. → code-shape test
  + review anchor (comment sentinel).
- **AC-5** — WITH fold ON at a folded stage, no statement SHALL execute between the batch/proc and commit#1 on
  the clean path; a claimed row with `destination_name IS NOT NULL` SHALL raise a contract-violation (rollback →
  shielded reset → ERROR log naming the row), never entering the H2 DML branch. → execution-trace assertion +
  injected-row test.
- **AC-6** — The three flags SHALL be provable no-ops on SQLite and Postgres (neither backend references them).
  → sentinel test (the ADR 0075 precedent).
- **AC-7** — WHEN `fifo_claim_proc` is ON and a proc is missing, is deployed but its definition unreadable
  (`OBJECT_ID` resolves, `OBJECT_DEFINITION` NULL), its `OBJECT_DEFINITION` hash mismatches every form this
  build deploys, or compat < 130, the store SHALL degrade loudly to the shipped batch (WARNING naming the
  reason + degraded gauge), never a lane outage; the hot path SHALL contain no error-2812 handling. → startup-
  gate tests incl. a hand-edited-body leg and an unreadable-definition leg.
- **AC-7c** — The degraded gauge SHALL be a surface an operator can READ, not merely an attribute: `/status`
  (with the reason string), `/metrics` (numeric, label-less, ABSENT rather than 0 when the lever is not
  requested) and the console store panel SHALL each emit it. → surface-emission tests
  (`test_adr0114_claim_proc_surfaces.py`), asserting the rendered output, not the property.
  > Added by the 2026-07-31 amendment. AC-7 as written required a gauge and nothing required anyone to be able
  > to see it; the two properties existed and were read by the store's own tests alone. A "loud" degrade whose
  > only audience is a log line is how this lever stayed inert in every deployment for its whole life.
- **AC-7b** — WHEN `fifo_claim_proc` is ON and both procs are deployed **by this build's own DDL**, the gate
  SHALL **PASS** and `claim_proc_effective` SHALL be True, verified against a **real SQL Server** (not a stub
  that echoes the submitted text back as the deployed body). → `test_adr0114_claim_proc_live.py`, plus an
  offline round-trip whose "deployed" fixture independently models the engine's module rewrite.
  > Added by the 2026-07-30 amendment. AC-7 as originally written is **one-directional** — it requires the gate
  > to degrade when the body mismatches, and nothing anywhere required a *correctly deployed* proc to pass. The
  > shipped defect therefore **satisfied AC-7 literally** while leaving the lever inert, and AC review could not
  > have caught it. Any future gate-shaped AC needs both directions or it is not a gate.
- **AC-8** — The proc bodies SHALL contain no `BEGIN/COMMIT/ROLLBACK`, no `TRY/CATCH`, no `SET XACT_ABORT`, and
  no `LOCK_TIMEOUT` reset outside the `@fold_reset` tail; `@@TRANCOUNT` on exit SHALL equal entry. → DDL lint
  test + a trancount probe test.
- **AC-9** — The proc result set SHALL be column-identical to the batch's 10-column `keep_id` LEFT JOIN shape,
  and the kept==claimed adjudication, H2 loop, commit, and finally-guard code paths SHALL be asserted unchanged
  (same functions, no new branches after `execute`). → structural + differential store-primitive tests.
- **AC-10** — WITH all flags at defaults, schema apply SHALL succeed on a compat-120 database and under a
  principal lacking CREATE PROCEDURE (the guarded DDL no-ops; the open never fails on proc DDL). → guarded-DDL
  tests.
- **AC-11** — Lane names containing JSON metacharacters, quotes, brackets, unicode, and 256-char maxima SHALL
  round-trip exactly on every flagged path; a >256-char lane SHALL be skipped client-side with a WARNING and
  claim zero rows on both the batch and flagged paths (no-match parity). → hostile/oversized-lane tests.
- **AC-12** — Under each flagged path: 1222 SHALL yield EMPTY-all with heads PENDING and attempts untouched
  (incl. 1222 raised from inside a proc reaching `_is_lock_timeout` via the driver's `"(1222)"` message); the
  fenced ex-leader SHALL claim 0 rows across all lanes; a forced kept≠claimed SHALL roll back the whole call —
  each asserted equal to the batch path's observable behavior in the same test.
- **AC-13** — `fifo_claim_prepared` SHALL log and no-op unless `fifo_claim_fold_reset` is ON; dedicated claim
  connections SHALL receive `timeout = command_timeout` at open and after every reopen; discard SHALL occur only
  on cancellation/unclassified errors (never on 1222/kept≠claimed alone); reuse SHALL be proven on the wire in
  G-B. → holder tests + the G-B trace legs.
- **AC-14** — No sub-lever default SHALL flip ON except by a follow-up owner-gated change citing its passed §8
  gate (both replicates + battery). → process criterion, recorded in this ADR's ledger.

## Options considered

1. **Stage-scoped fold + two flagged driver-interface levers (this ADR) — CHOSEN.** Attacks the D1-located
   dominant bucket (~52-55%, ~5× the next) on its measured axis; every guard and FIFO semantic preserved;
   nothing default-changes.
2. **All-stage fold (+11.6-11.7%).** Rejected: requires redesigning the outbound H2-under-`LOCK_TIMEOUT 0` path
   — TO-032 R9 demoted it; the license is +3.7% (ingress) to +8.0% (ingress+routed) only.
3. **Commit-amortization / durability-point batching.** Scoped OUT by D2 (B-R1a: +2.9% sustained; a different
   axis, never summed with latency shares). Sanctioned in principle by TO-027 c.1; deliberately not re-scoped in.
4. **Executor/event-loop/GIL redesign.** Excluded by measurement — Python dispatch/GIL is 267 µs (2.7%).
5. **Process-split / connection-count tuning.** Excluded — T3 worsens ~20% (remedy-excluding at N=8-on-16-vCPU,
   mechanism unattributed); connection count inert at 2× (0.1%).
6. **One proc for all stages.** Impossible against the real code — the lane column is a code-controlled literal
   (`_lane_col`); dynamic SQL rejected (per-call parse + injection surface at the reliability core).
7. **TVP lane parameter.** Rejected on pyodbc realism: supported since 4.0.25 but the least-exercised path
   through aioodbc; an immutable `CREATE TYPE` lifecycle (no `ALTER TYPE`); no byte advantage over one JSON
   parameter.
8. **Delimited string + `STRING_SPLIT`.** Rejected: delimiter collision with a lane name is a correctness
   class JSON simply doesn't have (order is immaterial here, but the pre-2022 ordinal caveat is recorded).
9. **Fixed-arity NULL-padded lane slots.** Rejected: the None-typing/describe hazard, per-execute descriptor
   drift, a 64-lane cap vs the 500 chunk (a claim-granularity change), and more parameter work on the dominant
   1-2-lane call shape.
10. **Result-set diet (`c.id` → `claimed` BIT).** Deferred: one NVARCHAR(64) column of unmeasured worth against
    real reliability-core decode churn (every `d["id"]` consumer re-keys to `keep_id`) and a result-contract
    fork between paths; priced by G-0's result axis before it is ever revisited.
11. **Lazy payload fetch.** Rejected: adds a round trip per message (the exact opposite of the lever) and breaks
    the ADR 0058/0066 worker architecture; big-body relief is ADR 0105's lane.
12. **Do nothing / hardware only.** Every measured wall (277 / 307.2 / 329.6 / 332.8) sits below the 347 bar;
    the resize record closed the hardware path (TO-032 §2, §4).

## Consequences

**Positive** — The redesign aims at the only bucket big enough to matter, on the axis D1 isolated, with the one
measured-sound lever (the fold) shipped first and the two speculative levers priced by pre-registered gates
instead of projections. All flags OFF = zero behavior change, pinned in CI; PG/SQLite untouched; the never-block,
probe-then-claim, epoch-fence, and fail-closed semantics survive by construction and are re-certified per flag
combination. The B1/M-6 guard is strengthened in practice: the folded hot path's finally becomes await-free, and
the session-persistence analysis (§3) hardens the record for future levers (the outbound fold must design
against it). The per-call driver payload on the proc path drops from ~5-9 KB text + 10-509 parameters + a new
statement identity per lane count to a ~60-char RPC-shaped call + 9 pinned parameters + one cached plan.

**Negative / risks** — A stored procedure is a new permanent server-side surface: a second copy of the claim
logic whose drift is contained (content hash, name-versioning, the `OBJECT_DEFINITION` probe, a DDL-vs-batch
lint) but real — the batch and proc bodies must be edited together. Parameter sniffing is a genuinely new
behavior class vs the estimate-neutral batch locals (bounded by the two-proc split, the plan gate, and the
recorded `OPTIMIZE FOR UNKNOWN` escape hatch). Sub-lever B may be structurally infeasible through pyodbc's
cursor lifecycle (G-B0 exists to find out cheaply; "infeasible-on-this-driver" is a pre-registered outcome). The
fixed pool's internal attribution is unmeasured — if it lives mainly in per-param binding or result-set
consumption, A and B under-deliver, and that recorded outcome is licensed. Pin-region wins may not transfer to
the wall (caveat 3) — the wall re-measure is mandatory, and the composed requirement may still MISS (the
licensed language). Compat<130 fleets get no proc/stable-text benefit (loud fallback); split-principal
deployments need a documented `GRANT EXECUTE`. The span instrument perturbs ~4.5-7.3% (sustained unmoved) —
carried, as before. `committed_txns` consumers must expect the 2→1-per-folded-claim shift. Bench cost: the rig
hold through §9 is the price of B-comparability.

**Out of scope** — The outbound/RESPONSE fold (needs the H2/`LOCK_TIMEOUT 0` redesign); `ack_after=delivered`;
durability-point batching / group commit; any Postgres/SQLite port of these levers; an `XACT_ABORT` flip; TVP
infrastructure; lazy payload fetch; changes to `claim_next_fifo`/`claim_next_fifo_batch`/`claim_ready`/
`release_claimed`/the per-lane mode/lane discovery; any throughput projection.

## To resolve on acceptance

- [ ] Owner ratifies the §8 gate floors and the middle-zone rule (re-cuts only before a gate's first run, in
      writing; G-0 may only tighten, never loosen).
- [ ] G-A0's observed `{CALL}` framing (direct TDS RPC vs prepared-wrapped) recorded before G-A's load arms run.
- [ ] Whether G-B runs if G-A promotes (default: recorded superseded-for-now; flag still ships OFF) — owner.
- [ ] Rig-hold / D3 timing vs the §9 sequence (owner; §9.7 is the hard constraint).
- [ ] Flag names / env spellings confirmed against `StoreSettings` conventions at build time
      (`MEFOR_STORE_FIFO_CLAIM_FOLD_RESET` / `_PROC` / `_PREPARED`).
- [ ] Split-principal deployments: the `GRANT EXECUTE` requirement recorded as an ops-doc line
      (docs/SERVICE.md or docs/CONFIGURATION.md) when the build lands.
- [ ] Filing discipline: number 0114 was allocated atomically (`scripts/coord/alloc.ps1`); the
      `docs/adr/README.md` index row ships in the same commit as this file (LEDGER-GATE).