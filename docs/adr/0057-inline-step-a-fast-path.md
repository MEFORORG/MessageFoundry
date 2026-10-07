# ADR 0057 — Inline Step-A Fast-Path: Collapse the Routed Stage for No-Lookup, All-Deliver, Single-Handler Messages

> # ⛔ DO NOT PROMOTE (2026-07-13) — MEASURED, AND IT BUYS NOTHING. See [ADR 0107](0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md).
> **P0 ran the gate below. The mechanism WORKS and the throughput gain is ZERO.**
>
> - It cut `committed_txns/msg` **10.47 → 7.49** — a **28.5% reduction**, exactly as designed. The fusion gate fired;
>   the manipulation check passed decisively.
> - Sustained throughput moved **−0.56%** — **inside the null band, and smaller than the replicate noise.**
> - **The txn lever itself is weak.** Arm E measured the cost of the entire `2H` term by *adding* it (H=1→8 on the
>   split path): a **~3× swing in committed transactions costs only 11.7% of throughput** — an elasticity of **−0.115**.
> - **CAUTION: but that does NOT prove F2 fails at a bigger shape, and an earlier draft of this banner wrongly said it did.**
>   F2's arm-E ceiling at H=8 is **+13.2%**, which is **ABOVE** the +8% PROCEED bar **and above**
>   [ADR 0071](0071-cut-executor-round-trips-b5.md) B5's +6.5…+10% band — **not inside it.** Even net of the *measured*
>   H=1 give-back (−4.49 pts) it is **+8.75%**, still above. *A bound that permits clearing the bar cannot prove the bar
>   cannot be cleared.* The deratings that would sink F2 (transform executions it cannot remove; a give-back growing
>   with H) are **argued, not measured**. And **F2 cannot be measured without being built** — the gate is
>   `len(names) == 1`, so inline fusion is **H=1-only by construction**.
>   **⇒ We DECLINE F2 on cost/risk/evidence, NOT on a proof of impossibility.** The ABANDON verdict rests on the
>   **pre-registered primary A/B null (−0.56%)**, not on arm E. See [ADR 0107](0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md).
>
> **This ships `default-OFF` and stays that way, permanently. Do not enable `inline=` on a production inbound. Do not
> build F2/F3.** The design below is correct and is retained for the record; it is simply not a throughput lever.
> **This is now the ONLY surviving Phase-4 mechanism** — [ADR 0055](0055-group-commit-durable-write.md)
> (group-commit), which the Status line below says this "builds on", has been **WITHDRAWN** (its premise was measured
> false and delayed durability breaks at-least-once on PHI). **Inline fusion stands on its own; it does not depend on
> 0055.**
>
> **It is already implemented and shipping in the tree — and it has NEVER been enabled in a single rig run.**
>
> **No further production code may be written for it until a pre-registered P0 measurement clears its bar**
> ([ADR 0101](0101-pre-registered-falsifier-discipline-for-performance-measurement.md)): a decision rule fixed before
> the run, a manipulation check on `committed_txns`, a same-session OFF control, a stated null band, **and a
> regression band** — because fusion *removes stage-level overlap*, which is structurally the trade **C7's `MAXDOP=1`
> made, and it lost.** P0's first job is to measure **`txn/s`**, which has never been counted. If it sits far below
> the store's ~27–29k commits/s ceiling, **the whole Phase-4 premise is dead and we stop.**

**Status:** Accepted (built, ships `default-OFF` **permanently**; the F2/F3 promote is **DECLINED** on the
pre-registered A/B null -- see the banner above and [ADR 0107](0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md); **G1 amended 2026-10-07** -- a `store.handoff` fault is INFRA, see the amendment at the end) · **Date:** 2026-06-30 · **Supersedes/Amends:** ADR 0001 (staged pipeline), builds on ADR 0055 (group-commit durable-write). **ADR number to use: 0057** (next free; 0056 is the highest present).

This is the chosen design out of three candidates. It is the **smallest, default-OFF, byte-identical-when-OFF** lever that meaningfully cuts the 7-deep commit chain, and it survives adversarial review **with a fixed set of guardrails** (all of which are cheap, code-local, and verified against the checkout below). The two rejected alternatives and why are in *Consequences → Alternatives*.

---

## 1. Context

A single-handler fan-out-1 SQL Server message traverses **7 committed serial remote round-trips** receive→PROCESSED (each ~2.84 ms; single-lane ~50 msg/s ≈ 20 ms/msg). Per the commit-bottleneck analysis, **cutting serial commits/msg raises single-lane *and* every sharded lane** — the highest-leverage lever. The chain, ground-truthed in `MessageFoundry-collapse-depth/`:

| # | Commit | Callsite | Lane |
|---|--------|----------|------|
| C1 | `enqueue_ingress` | `sqlserver.py:1194` (commit :1253) | pre-ACK |
| C2 | `claim_next_fifo(ingress)` | `sqlserver.py:2633`, driven `wiring_runner.py:1808` | router |
| C3 | `route_handoff` | `sqlserver.py:1305`, driven `wiring_runner.py:1877` | router |
| C4 | `claim_next_fifo(routed)` | `sqlserver.py:2633`, driven `wiring_runner.py:1973` | transform |
| C5 | `transform_handoff` | `sqlserver.py:1346`, driven `wiring_runner.py:2100` | transform |
| C6 | `claim_next_fifo(outbound)` | `sqlserver.py:2633`, driven `wiring_runner.py:1633` | delivery |
| C7 | `mark_done` | `sqlserver.py:2755` | delivery |

The codebase already contains a **dormant, built, tested, all-three-backends-mirrored** primitive for collapsing the routed stage: **`handoff`** (`sqlserver.py:1259`, `store.py:2132`, `postgres.py:1563`; protocol `base.py:207`). It advances **ingress → outbound in ONE txn**: idempotent `DELETE …OUTPUT` of the in-flight ingress row (:1276–1282) + N `_insert_outbound` (:1283–1286) + finalize applock + `UPDATE messages.status` (:1287–1290). **(Historical note — this sentence was written while `handoff` was dormant and is now STALE: the primitive was subsequently wired per the Implementation Plan below.)** As implemented, the live pipeline **does** call `.handoff(` — from the router worker's inline fast-path, in `_process_ingress_item` in `wiring_runner.py` (called from `_router_worker`) — but it is reached **ONLY** when an inbound sets `[transform].inline=True`; that knob **defaults to `False`** (`InboundConnection.inline` in `config/wiring.py`), so on every default deployment the split pipeline (Step B) path runs and `handoff` stays dormant. Per the **DO-NOT-PROMOTE** banner above it ships **wired-but-permanently-default-OFF** (ADR 0107, measured dead end). Re-activating it for an eligible message class collapses **C3 + C4 + C5 → one commit**, with zero new store SQL.

**The central tension** (ADR 0055 AC-2): the poison-guard `attempts+1` must be **durable-before-work and rollback-independent** of the work, so we cannot fuse *claim* with the work. But we *can* fuse *work + handoff* after a standalone claim — exactly what this design does (C2 stays separate; the fused work runs after C2 commits).

**The adversary found three real defects** in the naive "extend handoff" design, all confirmed against the code:

1. **`handoff` hard-sets `messages.status` and does NOT call `_maybe_finalize`** (`sqlserver.py:1287–1290`), unlike `transform_handoff` which does (`:1445`). A **zero-delivery (filtering) handler** routed through `handoff(deliveries=[])` produces no outbound row → no `mark_done` ever runs → **the message strands at the guessed status, never reaching `FILTERED`** (breaks INV-6 / count-and-log).
2. **The `route_handoff` call is OUTSIDE the router worker's inner `try/except`** (`wiring_runner.py:1877`; inner try closes at `:1875`). A raise from the fused handoff falls to the **outer** `except` at `:1896` → *back-off-and-retry-forever*, **not** the dead-letter policy the transform worker uses (`:2064–2091`). A **partial-handler failure** (handler A produces a Send, handler B raises) would dead-letter the whole ingress row → **A's delivery is silently lost** (breaks INV-1), whereas the split path delivers A and dead-letters only B.
3. **Inlining the transform on the loop** (the originally-proposed "no `to_thread`, wall-clock budget" variant) re-opens **SEC-013/CWE-1322**: a post-hoc budget cannot stop the *first* ReDoS/O(n²) message from freezing the single loop for its full runtime.

The guardrails below neutralize all three by **narrowing the eligible class** (single-handler, all-deliver, no-lookup), **keeping the `to_thread` hop**, and **moving the handoff call inside the inner try**.

*Amended 2026-10-07: defect 2's concern was a Handler raise landing in the retry-forever slot, and G1 still sends
that raise to the `internal_error` policy. The `handoff` call itself no longer sits inside the inner try; see
"Amendment (2026-10-07)" at the end.*

---

## 2. Decision

Add an **opt-in, default-OFF inline fast-path** to `_router_worker`. For a message whose inbound is eligible, the router worker — *after the unchanged standalone ingress claim C2* — runs `route_only` **and** the single selected handler's `transform_one` **off the loop via `asyncio.to_thread`** (hop preserved), then calls the re-activated `handoff` primitive to advance **ingress → outbound in one fused txn**, collapsing C3 + C4 + C5 into one commit. The transform worker and routed stage are simply bypassed for eligible messages. **Anything not strictly eligible falls back to the existing `route_handoff` split path** — so the fused path is *correct-or-skip*, never wrong.

### The exact fusion

For an eligible claimed ingress item:
1. **C2** — `claim_next_fifo(ingress)` — **unchanged** standalone commit (poison-guard `attempts+1`, INFLIGHT).
2. Run `route_only(registry, ic, payload)` **via `asyncio.to_thread`** (`wiring_runner.py:1846` pattern). → `names`.
3. **Eligibility re-check on the result** (see predicate). If it fails → **fall back** to `route_handoff` (the existing :1877 path verbatim).
4. Run the single handler's `transform_one(registry, hname, payload, content_type)` **via `asyncio.to_thread`** (`:2057` pattern; *no* lookup runner activated — the graph declares none). → `(deliveries_preview, state_preview)`.
5. **Result gate** — if `deliveries_preview` is empty, OR any `state_preview`, OR any `is_passthrough` Send → **fall back** to `route_handoff`.
6. **CF** — `await self.store.handoff(ingress_id=item.id, message_id=item.message_id, channel_id=name, deliveries=[(d.to, d.payload) for d in deliveries_preview], disposition=MessageStatus.ROUTED)` — the fused single commit.
7. **C6 / C7** — delivery lane **unchanged**.

### The gating predicate (the "inline-eligible" class)

A per-inbound boolean `inline_ok[name]`, computed **once at graph-build** (cached on the runner), true iff **all** hold:

- **(P-config)** the inbound opts in: new default-`False` transport-config knob **`[transform].inline`** (ADR 0007 data surface; parsed in `config/models.py` alongside `validation.strict` / `ack_after`).
- **(P-lookup)** the graph declares **zero** live lookups: `self._lookup_executor is None AND self._fhir_lookup_executor is None` (`wiring_runner.py:299–303`, built :885–886). This is the only signal available — lookup presence is *graph-level*, not per-handler (`_build_lookup_executor` keys off `registry.lookups`/`fhir_lookups`, :470). So **no** reachable handler can call `db_lookup`/`fhir_lookup` (INV-7).
- **(P-ack)** `ack_after == ingest` (the only built mode; resolver rejects `inline` with `ack_after=delivered`).

Plus **per-message** gates evaluated *after* `route_only`/`transform_one` (steps 3 & 5), any failure of which **falls back to the split path**:

- **(M-single)** `route_only` selected **exactly one** handler. *(Multi-handler is OUT of scope until `handoff` is extended to call `_maybe_finalize` — see §5.)*
- **(M-deliver)** the handler produced **≥1 ordinary delivery** and **zero** state-ops and **zero** pass-through Sends.

If `inline_ok[name]` is False, the worker runs **today's** `claim_next_fifo(ingress) → to_thread(route_only) → route_handoff` path **verbatim** — strictly additive, byte-identical when nobody opts in.

### Mandatory guardrails (from adversarial review — all required)

- **G1 — handoff inside the inner try.** Wrap steps 2–6 in the **same** inner `try/except` that today guards `route_only` (`wiring_runner.py:1822–1875`), so a raise from `transform_one` *or* from `handoff` routes to the **internal_error policy** (`dead_letter_now` on CONTINUE / `mark_failed`+`connection_stopped` on STOP), exactly as the transform worker does at `:2064–2091` — **not** the outer retry-forever `except` at `:1896`.
  *Amended 2026-10-07: G1 now covers Router and Handler code only. A `handoff` raise is an infrastructure fault and
  re-pends the row; see "Amendment (2026-10-07)" at the end. The sentence above is kept as the original decision.*
- **G2 — never call `handoff` with empty deliveries** (M-deliver). `handoff` lacks the `_maybe_finalize` that `transform_handoff` has (`:1445`), so a zero-delivery fused message would strand non-terminal. Filtering handlers take the split path (where `transform_handoff(deliveries=[])` → `_maybe_finalize` → `FILTERED`).
- **G3 — single-handler only** (M-single) so partial-handler delivery loss is impossible (there is no sibling to lose) and the disposition passed to `handoff` (`ROUTED`) is always correct (the later `mark_done`→`_maybe_finalize` reaches `PROCESSED`).
- **G4 — keep the `to_thread` hop.** `route_only` and `transform_one` run off the loop (SEC-013). The fusion saves the *handoff commits*, not the off-loop hop; the hop is **not** a commit. No wall-clock-budget inline-on-loop variant.
- **G5 — no txn across `to_thread`.** Assert in code that no DB connection/txn is open between C2's commit and CF's open. C2 releases its connection on commit; CF opens a fresh one only after the thread returns.

---

## 3. Invariant preservation (with crash-scenario reasoning)

All seven, against the verified code. "Survives" / "held" are the adversary's own verdicts where they confirmed safety.

**INV-1 — at-least-once / pure re-run, no duplicate outbound.**
- *Crash after C2, before CF:* ingress row INFLIGHT; `reset_stale_inflight` (`:2837`) blind-re-pends INFLIGHT→PENDING (attempts untouched). Re-run re-executes the **pure** `route_only`+`transform_one` (identical output) → CF's idempotent `DELETE …OUTPUT` (`:1276–1282`) finds the row present → inserts outbound exactly once. No loss, no dup.
- *Crash mid-CF (before commit):* `handoff` is one txn; rollback reverts DELETE + inserts + status atomically → ingress stays INFLIGHT → re-pend + pure re-run.
- *Crash after CF commit:* ingress gone, outbound PENDING; re-run hits the idempotent DELETE guard → `False` → clean no-op. **No duplicate** because consume + produce + disposition share **one** commit.
- *Partial-handler loss:* eliminated by **G3** (single handler) — no sibling delivery exists to lose.

**INV-2 — ACK-on-receipt.** Untouched. CF replaces only post-ACK C3/C4/C5; `enqueue_ingress` (C1, `:1194`, commit :1253) and the AA-after-ingress write (`mllp.py` listener, after the handler returns) are unmodified. Inline routing/transform happen strictly after C2, i.e. post-ACK — which CLAUDE.md §8 explicitly licenses (post-ingress failures don't NAK). *Adversary: HOLDS.*

**INV-3 — poison-guard (ADR 0055 AC-2), THE central tension.** C2 commits `attempts+1` (INFLIGHT) **standalone, before** any work; CF shares a rollback fate **only with itself**. So:
- *Deterministic exception in `transform_one`/`handoff`:* caught by the inner try (**G1**) → `dead_letter_now` (CONTINUE) terminally dead-letters it immediately, or STOP halts the lane preserving the row — **no loop.**
  *Amended 2026-10-07: this still holds for `transform_one`. For `handoff` it no longer does, and G6 does not take
  its place; the amendment at the end states the bound that applies instead.*
- *Deterministic process-crash (segfault/OOM) inside the work:* no exception to catch, but C2 already durably bumped `attempts`; `reset_stale_inflight` re-pends **without resetting attempts**; the next `claim_next_fifo` bumps again → attempts climbs monotonically. **Guardrail G6 (see residual risk):** because `mark_failed`'s ceiling (`:2813`) is consulted **only on the delivery lane**, the router worker must dead-letter a re-claimed ingress row once `item.attempts >= delivery_defaults.max_attempts` (when finite). This closes the crash-loop ceiling on the ingress lane. *Without G6 the loop is bounded only if a finite cap is wired and checked — see Residual Risk.*

**INV-4 — off-loop purity / no txn across `to_thread`.** `route_only` and `transform_one` run via `asyncio.to_thread` (**G4**) with **no** connection held (**G5**); CF opens a fresh txn only after the thread returns; the row X-lock window is the brief DELETE+INSERTs, identical to today's `handoff`/`transform_handoff`. A slow/pathological body cannot freeze the loop, pin a pooled connection, or hold the FIFO-head lock. *Adversary: HOLDS if enforced (G4/G5).*

**INV-5 — strict per-lane FIFO (no READPAST, #285).** C2 stays `claim_next_fifo` TOP(1) `ORDER BY created_at, seq` with `UPDLOCK, ROWLOCK`, no READPAST — unchanged. The inline body consumes the rightful head in arrival order (one serial router worker per inbound). CF's `_insert_outbound` uses the same `_fifo_created_at` clamp (`:1003`) as the split path, so outbound-lane FIFO is identical. Fall-back re-enters the same lane head in order. *Adversary: HOLDS.*

**INV-6 — finalizer sole authority.** **G2 + G3** guarantee CF is called only with ≥1 delivery and exactly one handler, so it always produces ≥1 outbound row → the terminal disposition is still recomputed **only** by `_maybe_finalize` at C7 `mark_done`. Over `{ingress gone, outbound PENDING}` the finalizer returns "still moving" (clause 1, `:888`) and flips PROCESSED only at C7. The zero-delivery strand the adversary found is excluded by **G2** (filter → split path → `transform_handoff`'s `_maybe_finalize`). The finalize applock order (`mefor:finalize:{id}`, `:1287` / `:881`) matches every other producer — no 1205 inversion. *Adversary: HOLDS with G2/G3.*

**INV-7 — db_lookup carve-out.** P-lookup excludes any graph that declares **any** `db_lookup`/`fhir_lookup` connection from the inline path entirely; an eligible graph has no lookup runner, so `db_lookup()`/`fhir_lookup()` raise (fail-closed). Lookup graphs run the full off-loop split lane unchanged. *Adversary: HOLDS.*

---

## 4. Consequences

**Positive.** Eligible single-handler, no-enrichment, all-deliver fan-out-1 message: **7 → 5 effective serial commits** (router/transform half 4 → 2; C3+C4+C5 collapse to CF). Per-message-per-lane, so it lifts single-lane **and** every sharded lane. Zero new store SQL (re-activates a built, tested, mirrored primitive). Default-OFF and byte-identical when off — zero blast radius on existing deployments.

**Negative / cost.** Benefit applies only to the narrow eligible class (no lookups, single handler, all-deliver). Lookup/enrichment feeds, multi-handler graphs, filtering handlers, state-writing handlers, and pass-through handlers get **zero** benefit (they fall back). The delivery lane (C6/C7) is untouched, so fan-out-1 floors at 5 commits.

**Alternatives rejected.**
- *Design A "fuse claim+inline-work+handoff, run transform on-loop with a wall-clock budget"* — **rejected**: reopens SEC-013 (first ReDoS message freezes the loop before the post-hoc budget can fire) and moved transform failures into the retry-forever slot. The chosen design keeps the `to_thread` hop (G4) and fixes the error slot (G1).
  *(Amended 2026-10-07: "fixes the error slot (G1)" now means the Handler raise only; see the amendment at the end.)*
- *Design B "fold downstream claims by pre-seeding next-stage rows INFLIGHT-leased"* (remove C4/C6) — **viable but deferred**: adversary rated it *safe-with-guardrails* for the C4-only half, but it requires a combined `(INFLIGHT owner=me) OR (PENDING)` drain query to preserve FIFO, lease-epoch fencing, and re-homing the H2 skip-and-complete dedup for the C6 half. It is **complementary** to this ADR (it cuts claim *frequency*; this cuts stage *depth*) and is filed as the next increment. We ship the smaller, lower-risk lever first.

---

## 5. Explicitly OUT of scope

- **Multi-handler fused path.** Requires extending `handoff` to call `_maybe_finalize` (re-verifying the frozen no-transform contract) and to insert all N handlers' outbound rows atomically. Deferred; multi-handler graphs fall back to split today.
- **Filtering / zero-delivery handlers inline** (G2 sends them to the split path).
- **State-writing (ADR 0005) and pass-through (ADR 0013) handlers inline** — `handoff` lacks the state-MERGE and PT-child machinery `transform_handoff` has; they fall back.
- **db_lookup / fhir_lookup graphs** (ADR 0010/0043) — categorically excluded by P-lookup.
- **Collapsing the delivery lane** (C6 `claim_next_fifo(outbound)` + C7 `mark_done`): the `connector.send()` runs off-txn between them and C7 carries the H2 delivered-key ledger + finalizer; fusing them changes re-send semantics. Out of scope.
- **Lever (b) claim-folding** (Design B) — separate increment.
- **B2 batch-claim** — orthogonal; composes on top later.

---

## Implementation plan

Ordered; default-OFF; byte-identical when OFF.

1. **`config/models.py`** — add `inline: bool = False` to the inbound `transform` config model (alongside `validation.strict` / `ack_after`); validate type. Parse it from `connections.toml` (ADR 0007 desugar).
2. **`config/wiring.py` (resolver)** — reject `inline=True` with `ack_after=delivered`; emit a per-inbound startup log line stating the resolved path (`inline` vs `split`).
3. **`pipeline/wiring_runner.py`** —
   - Compute `inline_ok[name]` at graph-build: `inbound.transform.inline AND self._lookup_executor is None AND self._fhir_lookup_executor is None AND ack_after==ingest`. Cache on the runner.
   - In **`_router_worker`** (`:1790`), after the C2 claim (`:1808`), branch on `inline_ok[name]`:
     - **Inline branch** — **inside the inner `try`** (extend the block that today closes at `:1875`, **G1**): `to_thread(route_only)` (`:1846` pattern) → if `len(names) != 1` **fall back** to `route_handoff`; else `to_thread(transform_one)` (`:2057` pattern, **no** lookup-runner ExitStack) → split `deliveries`/`pt`/`state` (`:2097–2099` pattern) → if `not deliveries OR state_ops OR pt_deliveries` **fall back** to `route_handoff`; else `await self.store.handoff(ingress_id=item.id, message_id=item.message_id, channel_id=name, deliveries=deliveries, disposition=MessageStatus.ROUTED)`; on success `self._work.set()` to wake delivery workers.
       *Amended 2026-10-07: as built now, `route_only` and `transform_one` stay inside the inner `try`, and the `handoff` call
       and its wakes run after it, so a store fault re-pends the row. See the amendment at the end.*
     - **G5 assert** — no open connection between C2 commit and the `handoff` call.
     - **G6** — before processing a re-claimed ingress item, if `delivery_defaults.max_attempts` is finite and `item.attempts >= max_attempts`, `dead_letter_now(item.id, "ingress attempts exhausted")` and `continue` (closes the hard-crash-loop ceiling on the ingress lane).
   - **Else branch** = today's `route_handoff` path verbatim.
   - **`_transform_worker`** (`:1955`) unchanged (it simply never sees routed rows for eligible single-handler all-deliver messages).
4. **Store layer** — **no new SQL.** `handoff` already exists in `sqlserver.py:1259`, `store.py:2132`, `postgres.py:1563`; `base.py:207` already declares it. Optionally tighten the `base.py` docstring to note it is now LIVE for the inline fast-path and **must not** be called with empty `deliveries` (the caller enforces G2).
5. **`docs/adr/0057-inline-step-a-fast-path.md`** — this ADR. Note the re-activation under ADR 0001 Step B.

**Stays unchanged:** `enqueue_ingress` (C1), `claim_next_fifo` (C2/C4/C6), `route_handoff`, `transform_handoff`, `mark_done` (C7), `reset_stale_inflight`, `_maybe_finalize`, the delivery lane, the finalize applock, the FIFO claim semantics, and the entire transform worker.

---

## Invariant-test matrix

All run on **SQLite + SQL Server + Postgres** (`handoff` exists in all three; the gate lives in backend-agnostic `wiring_runner.py`). The **SQL Server** leg (PR-blocking) and the **Postgres** failover leg gate the multi-backend parity claims.

| # | Invariant | Test | Gate |
|---|-----------|------|------|
| 1 | **At-least-once / no-dup** | Eligible message; SIGKILL **after C2, before CF** → restart → `reset_stale_inflight` re-pends → pure re-run → assert **exactly one** outbound row + PROCESSED. Repeat with crash **mid-CF** and **after-CF** (idempotent DELETE-guard no-op). | SQL Server + Postgres |
| 1 | **Byte-identity when OFF** | Same no-lookup single-handler graph with `inline=False`: assert store rows (queue/messages/events) + dispositions **byte-identical** to current main (golden snapshot). | all three |
| 1/6 | **Filter fallback (G2)** | Eligible inbound, handler returns no Sends → assert it takes the **split** path and finalizes **FILTERED** (not stranded). | SQL Server + SQLite |
| 1 | **Partial-handler (G3)** | Two-handler route on an `inline=True` inbound → assert **fallback** to split path; both handlers' Sends delivered, no loss. | SQL Server |
| 2 | **ACK-after-durable** | Assert AA is written only after `enqueue_ingress` commit; crash between ingress commit and CF leaves a recoverable ingress row and no premature ACK loss. | SQL Server |
| 3 | **Poison-loop bound (deterministic exception)** | Handler raises every run on `inline=True` → assert it **dead-letters via the internal_error policy (G1)** at the first failure (CONTINUE) — *not* infinite retry; assert STOP variant halts the lane + alerts. | SQL Server + SQLite |
| 3 | **Poison ceiling (hard crash)** | Simulated process-crash inside CF each run → assert `attempts` climbs across restarts and **G6** dead-letters at the finite cap; lane head clears. | SQL Server |
| 4 | **No txn across `to_thread`** | Instrument/assert no DB connection is checked out during `route_only`/`transform_one`; assert a slow inline transform does **not** block a second inbound's listener (loop-free). | SQLite (offscreen) |
| 5 | **FIFO** | Burst of eligible messages on one lane interleaved with a re-pended row → assert outbound order = `created_at, seq`; no READPAST reorder. | SQL Server + Postgres |
| 6 | **Finalizer sole authority** | Eligible single-handler all-deliver → assert `messages.status` reaches PROCESSED **only** via `mark_done`→`_maybe_finalize` at C7, with `{ingress gone, outbound PENDING}` reading "still moving" before delivery. | SQL Server + SQLite |
| 7 | **db_lookup gate** | Graph declaring a `db_lookup` connection with `inline=True` → assert `inline_ok` is **False** (falls through to split); a `db_lookup()` on the inline path would raise (fail-closed). | SQLite |

---

## Expected effect

**Commits/msg, eligible single-handler fan-out-1:** **7 → 5** serial committed round-trips (router/transform half 4 → 2; C3+C4+C5 → one fused CF). Pre-ACK C1 and delivery C6/C7 unchanged.

**Single-lane estimate (derived, not benchmarked):** at the measured ~2.84 ms/round-trip and ~20 ms/msg (~50 msg/s) baseline, removing 2 serial commits ≈ −5.7 ms/msg → ~14.3 ms/msg → **~70 msg/s (~+40%)** on eligible feeds. Because the cut is per-message-serial it **multiplies across every sharded lane**. *Caveat:* actual gain depends on how much of the 20 ms is commit-RT vs the unchanged C1/C6/C7 and the off-loop CPU; the firm floor is "eliminates exactly 2 of the 4 router/transform-lane commits for eligible messages."

---

## Residual risk (explicit)

1. **Eligibility is narrow.** Lookup, multi-handler, filtering, state-writing, and pass-through feeds get **zero** benefit. The common enrichment feed (provider/eligibility lookup) is exactly the case this lever cannot touch — Design B (claim-folding) is needed for those and is the planned next increment.
2. **G6 ingress-lane attempts ceiling is new behavior.** Today no ingress/routed-lane path enforces `max_attempts` (`mark_failed`'s ceiling at `:2813` is delivery-only; `reset_stale_inflight` doesn't touch `attempts`). G6 adds that ceiling to the router worker. This is a *latent gap in the current split pipeline too* — a deterministically process-crashing message already loops there — but the fused path widens the work under one re-runnable unit, so G6 is mandatory here and worth back-porting to the split path separately.
3. **Floor at 5 commits.** The delivery lane (C6/C7) is deliberately untouched (H2 ledger + re-send semantics), so fan-out-1 cannot go below 5 with this lever alone.
4. **Not benchmarked here.** The msg/s figure is derived from the stated ~2.84 ms RT and commit-count delta. **Must be A/B-validated on the Azure remote-SQL / WIN2025 rig** (per the throughput-matrix plan) before the +40% number is claimed, and the off-loop transform CPU / cipher / connector-send (the engine-bound residue the commit-bottleneck memo describes) caps the achievable gain.
5. **Backend parity is asserted, not assumed.** SQLite routes `handoff` through the group committer (`_run_grouped`, `store.py:2461`); SQL Server commits directly. The test matrix runs all three legs; the SQL Server leg is PR-blocking.

**Key files/lines (ground-truth):** `sqlserver.py` `handoff:1259` (hard-sets status, no `_maybe_finalize` :1287–1290), `transform_handoff:1346` (`_maybe_finalize` :1445), `route_handoff:1305`, `claim_next_fifo:2633`, `mark_failed:2795` (ceiling :2813, delivery-only), `reset_stale_inflight:2837` (no attempts touch :2856); `wiring_runner.py` `_router_worker:1790` (inner try :1822–1875, **`route_handoff` outside it at :1877**, outer retry-forever :1896), `_transform_worker` inner try :2026–2091 (handoff inside, :2100), lookup-executor gate :299–303/:885–886/:2051–2056.

---

## Amendment (2026-10-07) — G1 covers Router and Handler code only; a `store.handoff` fault is INFRA

**Source.** ADR 0057 G1 amendment (2026-10-02 full review, decision 9), settled by the Manager's adversarial review
of 2026-10-06 with a recommendation to narrow G1. The original G1 bullet and the INV-3 bullet above are kept as
written; each carries a pointer here.

**What changed.** The inline fast-path in `_process_ingress_item` (`pipeline/wiring_runner.py`, located by the
`ADR 0057 inline Step-A fast-path` comment) still runs `route_only` and the inline `transform_one` inside the
content `try`, so a Router or Handler raise still reaches the `internal_error` policy: dead-letter under CONTINUE,
`mark_failed` plus `connection_stopped` under STOP. The fused `store.handoff` and the outbound wakes that depend on
it now run **after** that `try`. A raise from the handoff propagates to the caller's fault arm, which re-pends the
ingress row PENDING: `_repend_claimed_on_fault` on a per-lane worker (#1611), the ADR 0070 T17 head re-pend on a
pooled lane. It is never dead-lettered as `router error`.

**Why.** The original G1 put two failure classes in one slot. `transform_one` is the operator's Handler; a raise
there is content and is deterministic for that payload. `store.handoff` is the store; a fault there is in the
common case transient (a deadlock victim, a lock or pool-acquire timeout, a failover). Dead-lettering an
already-ACKed, correctly transformed message on a transient store fault turns a self-healing condition into
operator replay work, and its `router error` reason blames the Router for an infrastructure fault. Every other path
already classifies the store write as INFRA: the split path's `route_handoff` and `transform_handoff` sit outside
their content `try` (section 1, defect 2, records that `route_handoff` sits outside it; that defect's concern was a
Handler raise reaching the retry slot, which amended G1 still prevents), and
[ADR 0071](0071-cut-executor-round-trips-b5.md)'s fused path splits `route_exc` (CONTENT, to the `internal_error`
policy) from `handoff_exc` (INFRA, re-raised to T17). The inline path was the only one of the four that treated a
store fault as content.

**What bounds a store fault that never clears. G6 does not.** The 2026-10-06 review text cited G6 as a bound;
measured against the tree it is not one for this case, and is recorded here so nobody relies on it. Both fault arms
re-pend through `reschedule_claimed`, which undoes the claim's `attempts` increment, so `attempts` does not climb
across exception-path re-pends and G6 never fires. G6 still bounds the hard-crash shape it was written for
(`reset_stale_inflight` leaves `attempts` alone). The bound that applies is the one the split path's
`route_handoff` already lives with:

- **pooled** (the default `claim_mode`): T17 counts the fault toward `infra_fault_stop_after` (default 10) and, under
  `infra_fault_policy = "stop"` (the default), STOPs the lane with a `connection_stopped` alert, preserving the
  message; under `retry_forever` it raises a throttled `lane_stuck` alert instead;
- **per_lane**: the worker re-pends and retries at its fixed backoff (`_WORKER_ERROR_BACKOFF_SECONDS`) with no
  ceiling, exactly as a failing `route_handoff` or `transform_handoff` does there. It raises no
  `connection_stopped` alert, under either `internal_error` policy, and the ingress buildup check runs only after
  a pass that succeeds, so the signal is the rate-limited worker fault log. Before this amendment a per_lane STOP
  policy halted the lane and alerted on the first handoff fault.

A store fault that is deterministic for one payload would therefore retry rather than dead-letter at once. That is
the same exposure the split path accepts for the same payload, which `transform_handoff` writes. The case that
matters is a Handler output the store can never write (for example one it cannot encode, or one over a backend
length limit): it now holds its lane, under the bound above, where it used to dead-letter one message. No code
classifies such an exception as content on either path; if one is wanted it belongs in the store, for both paths.

**Unchanged.** G2 to G6, the eligibility predicate, the default-OFF status and the DO-NOT-PROMOTE banner. The
`SandboxSessionClosed` arm (a dispatch that did not run) still re-raises past the `internal_error` policy.

**Tests** (`tests/test_inline_fast_path.py`): `test_inline_handler_raises_dead_letters_via_internal_error_policy`
and `test_inline_handler_raises_stop_policy_halts_lane` pin the unchanged Handler half;
`test_inline_handoff_store_fault_repends_not_dead_lettered` (per_lane and pooled, under CONTINUE and STOP) pins the re-pend and the recovery
to PROCESSED with one outbound row; `test_inline_persistent_handoff_store_fault_counts_toward_pooled_infra_stop`
pins the pooled T17 bound.
