# ADR 0084 — `accepts=` Router-stage seam: let a Handler decline at routing time so a self-filter costs 0 transactions, not 2

**Status:** **Accepted (2026-07-11, owner-ratified)** — the §4 disposition shift (`FILTERED → UNROUTED` for the all-declined case) is **ratified**; see §4 "Ruling". **No engine build is authorized by this ADR** (it specifies the seam + an advisory lint; the build is a follow-on lane, BACKLOG #213). *(Proposed 2026-07-10.)*
**Deciders:** owner (ratifies) + throughput working group + IDE/DX working group
**Related:** **builds on the cost model [ADR 0051](0051-corepoint-throughput-parity-strategy.md) pins** (`txn/msg = 3 + 2H + 2N`, `H` = handlers the Router SELECTS, `N` = destinations) and the A1 gate that measures it (`tests/test_txn_per_message_cost_model.py` — its `test_the_hub_spends_most_of_its_transactions_on_handlers_that_filter` already names this exact `accepts=` seam in a comment); the **Router/Handler purity boundary** (CLAUDE.md §2 reliability/at-least-once/count-and-log + §8 "keep transforms pure") and the sanctioned read-only carve-outs [ADR 0010](0010-handler-callable-db-lookup.md) `db_lookup` / [ADR 0043](0043-fhir-read-lookup.md) `fhir_lookup` (which **raise on a Router / in dry-run** — the constraint the `accepts=` predicate inherits); [ADR 0001](0001-staged-pipeline-architecture.md) (the staged `ingress→routed→outbound` pipeline whose **routed** stage this seam collapses for a declining handler); [ADR 0057](0057-inline-step-a-fast-path.md) (collapses the routed stage for the single-handler all-deliver case — a **structurally adjacent** stage-collapse lever) and [ADR 0058](0058-batch-claim-fifo-prefix.md) / [ADR 0066](0066-pooled-stage-claimers.md) (claim-side transaction reductions this composes with); [ADR 0072](0072-traced-dryrun-mode.md) (traced dry-run — where an `accepts=` decline must surface) and [ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) (the typed-action lens — a natural place to render an `accepts=` predicate as a row); CLAUDE.md §12 "log every received message with its disposition … never accept-and-drop" (the invariant the disposition-shift analysis below must not break).
**Code references** are `origin/main` tip at authoring; module paths are stable, line numbers approximate — locate exactly at implementation time. This ADR supersedes nothing.

---

## 1. Context — a Router filter costs 0 transactions, a Handler filter costs 2, for the same conceptual act

The durable-write cost model ADR 0051 rests its whole capacity argument on is `txn/msg = 3 + 2H + 2N`, now pinned against the **real** `SqlServerStore` methods by `tests/test_txn_per_message_cost_model.py`. `H` is the number of handlers **the Router SELECTS**, and the `2H` term — one ROUTED-row claim commit + one `transform_handoff` commit per selected handler — is charged **before the handler's transform ever runs**. A handler that filters (returns `None` / `[]`, delivering nothing) has already cost its 2 transactions by the time it decides to drop the message.

The A1 gate states the asymmetry outright and even names this seam (`test_the_hub_spends_most_of_its_transactions_on_handlers_that_filter`):

> A Router filter costs 0 transactions. A Handler filter costs 2. Same conceptual act.

The forcing case is the reference estate's ADT hub: the Router SELECTS **20** handlers and only ~4 deliver. `txn/msg = 3 + 2·20 + 2·4 = 51`; if the 16 self-filtering handlers were declined at the **router** stage instead the message would cost `3 + 2·4 + 2·4 = 19` — the A1 test computes `wasted == 32`, **63% of the hub's durable writes buy no delivered message** (a ~2.68× inflation). Those 32 transactions are spent materializing routed rows for handlers that were always going to drop the message.

Today the only zero-cost filter is **in the Router**: a Router that doesn't name a handler never materializes that handler's routed row. But the Router is one script per inbound; pushing 16 distinct per-handler filter predicates up into it re-centralizes logic the code-first model deliberately keeps **beside each handler** (cohesion — each handler owns its own applicability rule). The author's choice today is a false one: *co-locate the filter with its handler and pay 2 transactions, or hoist it into the Router for 0 and lose cohesion.*

The seam this ADR proposes removes that trade-off: a handler declares an **`accepts=`** predicate — evaluated at **routing time**, beside where the handler is wired — that lets the Router decline the handler for a given message **before a routed row is materialized**. The filter stays co-located with its handler (cohesion preserved) but is charged like a Router filter (0 transactions).

## 2. The purity constraint the predicate inherits (load-bearing)

`accepts=` runs in the **router stage**, which the reliability core requires to be **pure** for at-least-once replay. CLAUDE.md §2: *"routers and transforms must be pure (message in → message out, no external side effects) … At-least-once now relies on a re-run re-deriving identical output."* The routed stage's handoff is a single committed transaction that must re-derive the identical routed rows on a crash re-run — so **which handlers were declined must be a pure function of the message**, or a re-run could route differently and violate at-least-once.

Concretely: **`accepts=` MUST NOT call `db_lookup` / `fhir_lookup`.** Those are the sanctioned *non-pure* inputs and they are **only** available inside a live Handler transform — ADR 0010 / ADR 0043 make them **raise on a Router and in dry-run** precisely because a router-stage live lookup would make routing re-run-divergent. `accepts=` is router-stage code, so it inherits that exact prohibition **by construction**: it runs where `db_lookup`/`fhir_lookup` already raise. It is a **pure peek** over the message — the same class of read the Router itself performs (a `python-hl7` field peek; the tolerant hot path, §8) — nothing more. A handler that needs a *live* lookup to decide applicability cannot express that decision in `accepts=`; it keeps its in-handler filter (and its 2 transactions) — an accepted, correct limitation, not a gap.

The predicate is therefore specified as: **`Callable[[Message | RawMessage], bool]`**, run **on the router-stage payload**, returning `True` (materialize this handler's routed row) or `False` (decline — no routed row). It receives the same read-only, isolated payload `route_only` already builds ([`pipeline/dryrun.py`](../../messagefoundry/pipeline/dryrun.py) `route_only`, `_shareable_payload`); a raise inside it is a **content error** classified exactly like a Router raise (dead-letter/`ERROR` at the router stage — never a silent decline, because a swallowed exception would be an accept-and-drop).

## 3. Decision (the seam — spec only, build deferred)

Add an optional **`accepts=`** parameter to the Handler-registration surface so a handler can declare a router-time applicability predicate:

- **Surface.** Extend the `@handler` decorator ([`config/wiring.py`](../../messagefoundry/config/wiring.py) `handler(name)`) with `accepts: HandlerAccepts | None = None`, where `HandlerAccepts = Callable[[Message | RawMessage], bool]`. `accepts=None` (the default) is **byte-identical to today** — every existing handler keeps its current cost and disposition. The predicate is stored on the registry entry beside the handler fn (a new optional field on the handler record; no change to the `HandlerFn` signature itself).
- **Where it runs.** In the **router worker's** `route_only` step ([`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) `_router_worker` / the `route_only(...)` call). After the Router returns its selected handler names, the worker **filters that list** to those whose `accepts=` predicate returns `True` (a handler with no predicate is always kept). The surviving names are what `route_handoff` materializes routed rows for. This is the **one** behavioral change; everything downstream (transform, delivery, finalize) is untouched.
- **Disposition follows the existing rule for free.** The router worker already computes `disposition = MessageStatus.ROUTED if names else MessageStatus.UNROUTED` ([`wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) ~L3289, and the fused twin ~L3654). Filtering `names` *before* that line means an all-declined message naturally falls to `UNROUTED` with **no new disposition code** — see §4 for the semantics this shifts.
- **Purity + lookup prohibition by construction.** The predicate runs in the router stage where `db_lookup`/`fhir_lookup` already raise (§2); no new guard is needed to forbid them — calling one raises today. `accepts=` is documented as a **pure peek**, mypy-typed, and (like the Router) must not perform I/O.
- **Dry-run + trace parity.** `messagefoundry check`'s dry-run ([`checks.py`](../../messagefoundry/checks.py) `_check_dryrun`) and traced dry-run (ADR 0072) MUST evaluate `accepts=` so a fixture's `.expect` disposition (`RECEIVED`/`UNROUTED`/`FILTERED`/`ERROR`) reflects the seam: an all-declined fixture dry-runs as `UNROUTED`, matching the live path. The traced-dryrun stream should surface a declined handler (annotated, e.g. `accepts_declined`) so an author can see *why* a handler didn't run.
- **Idempotency / at-least-once.** Because the predicate is pure over the message, a crash-and-re-run of the router handoff re-derives the **identical** surviving-handler set → identical routed rows. No commit boundary moves; the `commits/msg` identity and the `route_handoff`-commits-once-regardless-of-`H` property (A1) are preserved for the *surviving* `H`.

**Cost effect.** For the ADT hub (SELECT 20, deliver 4, 16 self-filters expressed as `accepts=`): `txn/msg` drops from `3 + 2·20 + 2·4 = 51` to `3 + 2·4 + 2·4 = 19` — the exact `wasted == 32` the A1 test computes, recovered. The seam turns `H` (handlers-selected) into `H_accepted` (handlers-that-actually-take-the-message) in the `2H` term.

## 4. The crux: an all-declined message finalizes `UNROUTED`, not `FILTERED` — recommend accepting the shift

This is the one semantic the owner must rule on, stated plainly.

**Today.** A message the Router selects handlers for, where **every selected handler runs and delivers nothing** (returns `None`/`[]`), finalizes as **`FILTERED`**. Verified against the finalizer: `messages.status` is set to `ROUTED` when the router hands off ≥1 handler; the store finalizer's `_finalize_from_message_status` ([`store/sqlserver.py`](../../messagefoundry/store/sqlserver.py) ~L355) returns `FILTERED` **only if `messages.status == ROUTED`** and no queue rows remain — i.e. FILTERED means *"it was routed to handlers, they all ran, none delivered."* The finalizer's authority is the **`queue`** table GROUP BY (`_finalize_from_queue_rows`, ~L336) with `messages.status` as the fallback tiebreak — confirming FILTERED is reachable only through a prior `ROUTED` stamp.

**With `accepts=`.** If every selected handler **declines at the router stage**, the surviving `names` list is empty, so `disposition = UNROUTED` (§3) — `messages.status` is stamped `UNROUTED`, no routed rows are ever materialized, and the finalizer never reaches the `ROUTED → FILTERED` branch. **The same real-world outcome (routed to handlers, none took the message) now reads `UNROUTED` instead of `FILTERED`.**

**Why the count-and-log invariant is NOT violated.** CLAUDE.md §12 forbids *accept-and-drop*, not a disposition relabel. Under the seam:
- the message is still **persisted at ingress as `RECEIVED` before the ACK** — the inbound count is unchanged;
- it still receives a **final disposition** (`UNROUTED`) — it is never left in-flight or silently discarded;
- it is **never accepted-and-dropped** — `UNROUTED` is a first-class logged disposition an operator can list/replay, exactly like `FILTERED`.

**What is actually lost** is **per-destination FILTERED granularity in the mixed case.** Consider SELECT 20 where 16 decline via `accepts=` and 4 deliver: today (if those 16 filtered *in-handler*) the message is `PROCESSED` (≥1 delivered) and the 16 drops are visible as their handlers' filtered outcomes; with the seam the 16 never materialize a row, so there is **no per-handler FILTERED record for them** — the message is still `PROCESSED` (the 4 delivered), but the audit trail no longer shows "these 16 considered-and-declined." The *pure all-declined* case is the one whose top-line disposition flips `FILTERED → UNROUTED`; the *mixed* case keeps its top-line disposition (`PROCESSED`) but loses the declined-handler detail.

**Recommendation — accept the shift.** `UNROUTED` is arguably the *more honest* label: no handler took the message, which is precisely what `UNROUTED` means, and `FILTERED`'s "a handler ran and dropped it" is a distinction without operational consequence for a message that was never going to be delivered. The gain (recovering up to 63% of a hot hub's durable writes) is large and directly serves the ADR 0051/0052 scale target; the loss (per-declined-handler granularity) is diagnostic detail, not correctness or count integrity.

**Optional mitigation (recommended if the granularity matters to an operator).** Record the **declined-handler names** in `message_events` at router-handoff time — one metadata-only event per declined handler (e.g. `event = "accepts_declined"`, `detail = <handler name>`), written **inside the same router `route_handoff` transaction** so it is atomic with the disposition and re-derives identically on replay. This restores the "considered-and-declined" audit trail (in both the all-declined and mixed cases) **without** materializing a routed row or costing a delivery transaction — the event insert rides the single already-committed router handoff. It is offered as an **opt-in refinement**, not a precondition: the base seam is correct and count-safe without it.

**Decision requested:** accept `FILTERED → UNROUTED` for the all-declined case (recommended), and choose whether to ship the `message_events` declined-handler mitigation in v1 or defer it.

### ✅ RULING (owner, 2026-07-11)

1. **`FILTERED → UNROUTED` for the all-declined case is ACCEPTED.** The relabel is sound: `UNROUTED` means "no handler took the message," which is exactly what happened. The count-and-log invariant holds — the message is still persisted as `RECEIVED` before the ACK, still receives a final logged disposition, and is still listable/replayable. It is a disposition **relabel**, not an accept-and-drop.

2. **The `message_events` declined-handler mitigation is DEFERRED from v1** — and when it is built it must ride the **existing `message_events` verbosity gate** (BACKLOG #63, shipped in #899) rather than writing unconditionally. Rationale: the audit detail it restores is *diagnostic*, and the verbosity gate already exists precisely so per-message event volume is opt-in. Emitting an `accepts_declined` event per declined handler on a 20-handler hub would write up to 16 events per message on the default path — re-spending, in `message_events` rows, a meaningful share of the durable writes the seam exists to recover. Gated and default-off, it costs nothing until an operator asks for it.

   *This is reversible and forecloses nothing:* the seam is correct and count-safe without the mitigation (§4 above), and the event insert can be added later inside the same already-committed `route_handoff` transaction, exactly as specified.

**What this ratification does and does not authorize.** It settles the *semantics* so the build lane is unblocked. It does **not** authorize the engine build — that remains BACKLOG #213, and the open items in §9 (predicate signature, payload sharing, hot-path cost, error-classification exactness) must still be resolved there.

> ⚠️ **Sizing note added 2026-07-11 (why this seam now matters more, not less).** The capacity frontier
> (`docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` §8) establishes that clearing N=16 is **necessary but not
> sufficient**: even a fully successful pooled-claim rewrite leaves the fleet ~1.81× short of 520.83 events/s at
> the swept load. So the `txn/event` levers — this seam chief among them (estate 4.64 → 3.55 txn/event; ADT hub
> `txn/msg` 51 → 19) — are **not** optional follow-ons to the claim-path work. They are **co-requisites**. Do not
> sequence this behind the rewrite.

## 5. Advisory lint spec — flag a Handler that is essentially a guard-filter (belongs in `accepts=`)

Add an **advisory, non-blocking** check to `messagefoundry check` ([`checks.py`](../../messagefoundry/checks.py)) that nudges an author toward the seam, exactly mirroring the existing `raise-fstring` advisory (`_check_raise_fstring`): a `CheckResult(required=False)` that **only ever prints a heuristic reminder and never fails the gate** (the CLI exit policy is "0 iff no required check failed", so an `required=False` result cannot block).

**What it flags.** A `@handler`-decorated function whose body is **essentially a guard-filter** — an early `if` whose whole job is to drop the message, i.e. a leading statement of the form:

```python
@handler("...")
def handle(msg):
    if not msg["MSH-9.1"] == "ADT":   # a pure peek over the message …
        return []                     # … whose only effect is to FILTER
    ...                               # real transform work follows
```

The heuristic (AST, stdlib `ast`, no import/execute of the config module — same static discipline as `raise-fstring` and ADR 0076's `lens parse`):
1. find `FunctionDef`s decorated with `@handler(...)` (a `Call` whose func is `Name`/`Attribute` `handler`);
2. inspect the **first executable statement** (skipping a docstring); flag when it is an `ast.If` whose body is a **single bare filter-return** — `return None`, bare `return`, or `return []` (an empty `ast.List`) — with **no `else`/`elif`**. That shape is a guard that filters and then falls through to the transform: the exact act that belongs in `accepts=`.

**Deliberately conservative (advisory, so false positives are cheap but should be rare).** The heuristic does **not** try to prove the guard condition is pure or lookup-free (an `accepts=` predicate must be — §2 — but the lint only *suggests*, the author ports it and dry-run/`check` catch a bad port). It only flags the *leading* guard-filter (a filter buried mid-transform after real work is genuinely a handler concern, not an applicability rule, and is not flagged). Message text mirrors `raise-fstring`: *"handler `<name>` opens with a guard-filter (`if …: return []`) — consider declaring it as `accepts=` so it declines at routing time (0 transactions, not 2). Advisory; see ADR 0084."*

**Scope + robustness (copy `_check_raise_fstring` verbatim in shape).** Scans every `*.py` under `config_dir` (helpers included); a `SyntaxError`/`OSError` on a file is skipped (validate already reports broken modules); a non-dir `config_dir` yields a skip; the result is appended **after** the ruff/mypy advisory block in `run_checks` so it is purely additive. The check name is **`accepts-candidate`**.

A **stub is included with this ADR** (`_check_accepts_candidate` in `checks.py`, wired into `run_checks`) so the advisory ships mechanically ready; it passes ruff + mypy and is `required=False`.

## 6. Acceptance Criteria

> EARS form; each links (`→`) to the test/fixture that will verify it **once the engine build is authorized**. Placeholders until that code exists — resolve on acceptance. (AC-6 is the only one buildable now — the advisory lint stub this ADR ships.)

- **AC-1** — WHEN a Handler declares `accepts=` and the predicate returns `False` for a message, THE SYSTEM SHALL NOT materialize a routed row for that handler, and the message's `txn/msg` SHALL fall by the `2` transactions that handler would have cost (`H → H_accepted` in the `2H` term).
  → `tests/test_txn_per_message_cost_model.py::test_accepts_declines_before_routed_row` (extend the A1 gate)
- **AC-2** — WHEN **every** selected Handler declines via `accepts=`, THE SYSTEM SHALL finalize the message as **`UNROUTED`** (not `FILTERED`), still persisted `RECEIVED` at ingress with a final logged disposition (never accepted-and-dropped).
  → `tests/test_staged_pipeline.py::test_all_declined_finalizes_unrouted`
- **AC-3** — IF an `accepts=` predicate calls `db_lookup` / `fhir_lookup`, THEN THE SYSTEM SHALL raise (router-stage purity — those lookups already raise off a live Handler), classifying it a router-stage `ERROR`/dead-letter, never a silent decline.
  → `tests/test_accepts_seam.py::test_accepts_lookup_raises`
- **AC-4** — WHEN an `accepts=` predicate raises, THE SYSTEM SHALL classify it as a **content error** at the router stage (dead-letter/`ERROR`), identically to a Router raise — never swallow it into a decline.
  → `tests/test_accepts_seam.py::test_accepts_raise_is_content_error`
- **AC-5** — WHEN a config is dry-run (`messagefoundry check` / traced dry-run), THE SYSTEM SHALL evaluate `accepts=` so a fixture's `.expect` disposition matches the live path (an all-declined fixture → `UNROUTED`), and the trace SHALL surface a declined handler.
  → `tests/test_checks.py::test_dryrun_honors_accepts` · `tests/test_dryrun_trace.py::test_trace_marks_accepts_declined`
- **AC-6** — THE SYSTEM SHALL emit an **advisory, non-blocking** `accepts-candidate` check that flags a `@handler` opening with a guard-filter (`if <cond>: return []/None`) and NEVER fails the gate.
  → `tests/test_checks.py::test_accepts_candidate_is_advisory` *(buildable now — this ADR's stub)*
- **AC-7** — WHERE a Handler declares no `accepts=` (the default), THE SYSTEM SHALL behave byte-identically to today (same routed rows, same disposition, same `txn/msg`).
  → `tests/test_accepts_seam.py::test_no_accepts_is_byte_identical`

## 7. Consequences

**Positive** — Restores the missing symmetry (a self-filter costs 0 transactions like a Router filter, *while staying co-located with its handler* — cohesion **and** cost); recovers up to ~63% of a high-fan-out hub's durable writes (the A1 `wasted == 32`), directly serving the ADR 0051/0052 scale target; additive + fully backward-compatible (`accepts=None` = today); purity is enforced **by construction** (router stage already forbids the live lookups); composes cleanly with ADR 0057/0058/0066 (all reduce transactions on the same path) and with the ADR 0076 lens (an `accepts=` predicate is a natural typed row).

**Negative / risks** — The `FILTERED → UNROUTED` disposition shift for the all-declined case (§4) is a **visible semantic change** operators/dashboards must be told about (release-note + the optional `message_events` mitigation); the mixed case loses per-declined-handler granularity unless the mitigation ships. A misauthored `accepts=` that is *not* actually pure (e.g. reads a module global, hits the clock) would make routing re-run-divergent — the same failure mode a non-pure Router has today, mitigated the same way (docs + the advisory lint's steering + dry-run), not newly introduced by this seam. The seam adds one branch to the hot router path (a per-handler predicate call) — cheap (a pure peek) but non-zero; measured impact is a to-resolve item.

**Out of scope** — a `provides=`/negotiation protocol (handlers advertising capabilities); an `accepts=` on the *Router* itself (the Router already filters for free by not naming a handler); any live/`db_lookup`-backed applicability decision (that is an in-handler filter by necessity — §2); changing what `FILTERED` means for the *in-handler* filter that remains (a handler with no `accepts=` that returns `None` still finalizes `FILTERED` exactly as today).

## 8. Alternatives considered

| Alternative | Verdict | Why |
|---|---|---|
| **`accepts=` router-stage pure predicate** (this ADR) | **Chosen** | Recovers the wasted `2H` transactions while keeping the filter co-located with its handler; purity enforced by construction; additive + default-identical |
| Hoist every self-filter into the **Router** (status quo path to 0 cost) | Rejected | Works for cost but re-centralizes 20 per-handler predicates into one script — destroys cohesion, the exact thing the co-located handler model protects |
| Leave it — pay the `2H` and filter in-handler | Rejected | The A1 gate quantifies the waste (63% of the ADT hub's durable writes); at the 45M/day target (ADR 0052) that is a first-order capacity loss |
| A **live-lookup-capable** `accepts=` (allow `db_lookup` at routing time) | Rejected | Breaks router-stage purity → routing becomes re-run-divergent → at-least-once violated; ADR 0010/0043 already raise there by design |
| Collapse the routed stage generally (extend ADR 0057 to multi-handler) | Rejected here | A different lever (inline fast-path structure), orthogonal to *declining* a handler; `accepts=` reduces `H`, it doesn't restructure the stage |
| Keep `FILTERED` for the all-declined case (synthesize a routed row then drop) | Rejected | Materializing a routed row purely to preserve a disposition label reintroduces the exact `2` transactions the seam exists to avoid — self-defeating |

## 9. To resolve on acceptance

- [x] **The disposition ruling (§4):** ✅ **RULED 2026-07-11** — `FILTERED → UNROUTED` **accepted**; the `message_events` declined-handler mitigation **deferred from v1**, and gated behind the `message_events` verbosity gate (#63) when built. See §4 "Ruling".
- [ ] **Predicate signature + surface finalization:** confirm `Callable[[Message | RawMessage], bool]` and the `@handler(name, accepts=...)` shape (vs a separate `@accepts` decorator or a `connections.toml`-side binding); confirm the registry field name.
- [ ] **Payload sharing:** whether `accepts=` reuses the exact read-only isolated payload `route_only` builds (`_shareable_payload`) for zero extra parse cost, and the HL7 mutable-`Message` isolation rule for the predicate.
- [ ] **Hot-path cost:** measure the per-handler predicate-call overhead on the router path (a pure peek should be negligible, but it is a new per-handler branch — confirm it doesn't erode the recovered transactions).
- [ ] **Error-classification exactness:** confirm an `accepts=` raise routes through the **same** router-stage CONTENT error boundary as a Router raise (`route_only` raise → dead-letter), including the fused-hop twin (`wiring_runner.py` ~L3642).
- [ ] **Lint heuristic tuning:** whether to also flag a guard-filter that is the *last* statement's mirror (`if <cond>: <transform> ; return []`) or keep it to the leading-guard shape only (conservative v1).

## 10. References

- [ADR 0051](0051-corepoint-throughput-parity-strategy.md) — the `txn/msg = 3 + 2H + 2N` cost model + Corepoint parity strategy; [`tests/test_txn_per_message_cost_model.py`](../../tests/test_txn_per_message_cost_model.py) (A1 gate — pins the model against the real store; names this seam).
- [ADR 0010](0010-handler-callable-db-lookup.md) / [ADR 0043](0043-fhir-read-lookup.md) — the read-only `db_lookup`/`fhir_lookup` carve-outs that **raise off a live Handler** (the purity fence `accepts=` inherits).
- [ADR 0001](0001-staged-pipeline-architecture.md) — the `ingress→routed→outbound` staged pipeline; [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) (`_router_worker`, the `disposition = ROUTED if names else UNROUTED` line), [`pipeline/dryrun.py`](../../messagefoundry/pipeline/dryrun.py) (`route_only`).
- [`messagefoundry/store/sqlserver.py`](../../messagefoundry/store/sqlserver.py) — `_finalize_from_message_status` / `_finalize_from_queue_rows` (the finalizer: FILTERED requires a prior `ROUTED` stamp; the `queue` table is its authority).
- [`messagefoundry/checks.py`](../../messagefoundry/checks.py) — `_check_raise_fstring` (the advisory-lint pattern `accepts-candidate` mirrors) + this ADR's `_check_accepts_candidate` stub.
- [ADR 0052](0052-enterprise-scale-target.md) (the 45M/day target the recovered transactions serve), [ADR 0057](0057-inline-step-a-fast-path.md)/[ADR 0058](0058-batch-claim-fifo-prefix.md)/[ADR 0066](0066-pooled-stage-claimers.md) (adjacent transaction-reduction levers), [ADR 0072](0072-traced-dryrun-mode.md)/[ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) (dry-run trace + typed-action lens surfaces).
