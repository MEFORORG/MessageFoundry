# ADR 0005 — Transform-accessible state (cross-message correlation)

- **Status:** Accepted (2026-06-13) — semantics ratified on the owner's go (**transactional /
  exactly-once**, option A of the build decision). This ADR is the design/spec; the implementation
  follows as a separate PR (docs-first, like [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) /
  [ADR 0004](0004-payload-agnostic-ingress.md)).
- **Built:** Implemented. `SetState` + `state_get` authoring surface, the transactional write applied
  inside `transform_handoff` (`store/store.py`), the read-through cache + `config/state.py` read layer,
  at-rest encryption + key-rotation coverage of the `state` table, and a `[retention].state_max_age_days`
  age purge. SQL Server writes state via its staged `transform_handoff` (live; parity with SQLite/
  Postgres). **Clustered (Track B Step 6b):** a clustered
  write bumps a per-namespace `state_version` token **in the same transaction** as the state writes, and
  every node's `StateConvergenceRunner` read-throughs newer namespaces into its own `_state_cache` (a
  background, off-hot-path refresh so `state_get` stays a pure synchronous dict lookup); single-node never
  bumps (the gate is off) so behaviour is byte-identical. See *Consequences → Clustered* below. It builds on the **already-shipped** code-set framework
  ([config/code_sets.py](../../messagefoundry/config/code_sets.py)) for the read-side authoring pattern,
  and on the staged pipeline's **single-transaction handoff**
  ([store/store.py](../../messagefoundry/store/store.py) `transform_handoff`, `BEGIN…commit`) for the
  write-side exactly-once seam.
- **Related:** [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline + the pure-re-run
  invariant this must preserve), [CLAUDE.md](../../CLAUDE.md) §2 (reliability invariant). Migration
  roadmap Phase 2 (`.claude/plans/where-do-we-stand-abundant-meadow.md`): the second cross-cutting
  enabler after code sets.

## Context

Corepoint transforms cache values and correlate across messages via **Data Points / Namespaces /
Associations**: anonymous-patient mapping (persist a real MRN → a stable anonymized id and reuse it on
later messages), order↔result correlation, error capture, running aggregates. MessageFoundry's
Routers/Handlers are **pure today** — message in → message out, no state — so these can't be ported.

The tension: the staged pipeline gives **at-least-once** delivery by re-running a router/transform after
a crash, which is only safe because transforms are pure ("a re-run re-derives identical output", ADR 0001
/ CLAUDE.md §2 — *do not break*). Adding a **write** to a transform is a side effect that could
**double-apply** on a re-run (e.g. a counter increment), corrupting state.

**Key enabler (verified):** the routed→outbound handoff is a **single committed transaction**
(`store.py` `transform_handoff`: `BEGIN` → claim routed row → insert outbound rows → finalize →
`commit`). A state write committed **inside that same transaction** is therefore exactly-once with the
message's processing: a crash before commit rolls back the outbound rows **and** the state write
together; the attempt that commits applies the state write atomically, exactly once. This is what makes
option A feasible without weakening the invariant.

## Decision

### Write side — declared, committed transactionally (exactly-once)

A Handler does **not** mutate state imperatively. It **declares** writes by returning them alongside its
`Send`s; the engine applies them inside `transform_handoff`'s transaction.

- New `SetState(namespace, key, value)` (value JSON-serializable). A Handler returns
  `Send | SetState | list[Send | SetState] | None` (the union is widened; existing `Send`-only returns
  are unchanged — **backward compatible**).
- `transform_one` ([pipeline/dryrun.py](../../messagefoundry/pipeline/dryrun.py)) splits the return into
  `(deliveries, state_ops)`; the transform worker
  ([pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)) passes `state_ops` to a
  new `transform_handoff(..., state_ops=...)` parameter.
- The store applies each op as an `INSERT OR REPLACE` (upsert by `(namespace, key)`) **within the
  handoff transaction**, then the in-memory read cache (below) is updated **on commit**.
- **Re-run safety:** rolled-back attempts leave no state (atomic with the handoff); the committing
  attempt's value is the one that persists. A write is exactly-once *per message*. Cross-message
  consistency (message 2 reads what message 1 wrote) holds once message 1 has committed. Non-deterministic
  values (a random anon id) are still safe because only the committed attempt persists — but authors
  **should** prefer deterministic derivations where cross-run identity matters; documented.

### Read side — synchronous `state_get`, engine-maintained read-through cache

Handlers are **synchronous** functions; a DB read is async — so `state_get` cannot await. Resolution: the
engine keeps an **in-memory read-through cache** of the state table (loaded at startup, updated as writes
commit). `state_get(namespace, key, default=None)` reads that cache synchronously, mirroring how
`code_set()` resolves against an active set via a `ContextVar` the runner publishes around each
router/transform run.

- The **persistent table is the source of truth**; the cache is a process-local mirror (MEFOR is
  single-engine). On reload/restart the cache reloads from the table.
- **Consistency caveat (documented):** reads are *not* linearized with concurrent writes across handlers —
  a handler sees committed state as of its invocation; a sibling handler may have just written. Fine for
  read-mostly correlation (patient-id mapping); race-sensitive read-modify-write within one namespace
  needs author care.
- **Bounded-memory assumption:** the cache holds the whole table. Acceptable for v1 with TTL/eviction
  (below). Unbounded estates (every MRN ever seen) get a follow-up (a synchronous WAL reader handle, or
  declared-key prefetch) — noted as an alternative, not built now.

### Storage, encryption, retention

- New `state` table in **both** store backends (`store.py` SQLite + `sqlserver.py`): `(namespace, key,
  value, set_at, message_id)`, PK `(namespace, key)`. **SQL Server:** its `transform_handoff` now
  applies state writes in the same transaction (the staged pipeline landed there), so state is **live**
  on SQL Server with parity to SQLite/Postgres.
- **Encryption at rest:** state values may carry PHI (MRN↔id). Reuse the store's existing
  `self._cipher` ([store/crypto.py](../../messagefoundry/store/crypto.py) AES-256-GCM keyring) to
  encrypt `value`; cover the `state` table in `reencrypt_to_active()` (key rotation), exactly like
  `messages.raw`.
- **Retention/TTL:** a `max_age`/purge for stale entries (reuse the RetentionRunner pattern) so the table
  + cache don't grow unbounded. v1 ships a simple age-based purge; per-namespace policy is a follow-up.
- **Audit:** record `message_id` per write for traceability; PHI access rules (PHI.md) apply to any
  state-viewing API (none in v1 — file/console state browsing is future).

### Authoring surface

Export `state_get` and `SetState` from the `messagefoundry` top level (alongside `code_set`/`Send`).
Example:

```python
@handler("anonymize")
def anonymize(msg):
    mrn = msg["PID-3.1"]
    anon = state_get("patient_anon", mrn)
    ops = []
    if anon is None:
        anon = derive_anon_id(mrn)          # deterministic preferred
        ops.append(SetState("patient_anon", mrn, anon))
    msg.set("PID-3.1", anon)
    return [Send("OB_DOWNSTREAM", msg), *ops]
```

## Consequences

**Positive**
- Unblocks the Corepoint Data Point / Association feeds (Phase 2) without weakening at-least-once.
- Backward compatible: `Send`-only Handlers and the pure-transform model are unchanged; state is opt-in.
- Exactly-once writes — no double-apply on re-run (the property option B / a side KV store could not give).

**Negative / risks**
- **Most invasive change since ADR 0001:** Store protocol + both backends + handoff transaction + Handler
  return contract + a new cache. Must be adversarially tested for re-run safety (crash-before-commit ⇒ no
  state leak; replay ⇒ idempotent).
- **In-memory cache** assumes bounded state (TTL mitigates); unbounded estates need the follow-up reader.
- **Read non-linearization** across concurrent handlers — documented; not a correctness bug for the target
  read-mostly use cases.
- **SQL Server**: state writes are **live** — the staged pipeline (and its `transform_handoff`) is
  implemented on the SQL Server backend.

### Clustered (Track B Step 6b)

The in-memory cache above is **process-local**, so on a multi-node Postgres cluster a write on node A
would be invisible to node B's `state_get` until B reopened — stale cross-node correlation. Step 6b closes
that with the **same shape** as reference-set convergence (Step 6): a clustered `transform_handoff` (and
`purge_state`) bumps a per-namespace `state_version` token **atomically with** the state rows, so a node
that sees the higher version is guaranteed the rows are committed. Each node runs a `StateConvergenceRunner`
that, every `[cluster].heartbeat_seconds`, calls `converge_state_cache()` to read-through any namespace
whose shared version differs from the one its cache reflects (re-reading + decrypting that whole namespace's
rows before mutating the cache, so a decrypt failure leaves the last-good cache intact). The version scan
runs before the per-namespace rows (read-skew-safe: worst case is one harmless extra re-converge, never a
skipped write). Convergence is a **background, off-path** refresh, so `state_get` stays a pure synchronous
dict lookup on the hot path. The bump is **gated on clustered** (the engine calls `enable_state_convergence()`
only when `coordinator.is_clustered()`), so single-node writes no `state_version` rows and stays
byte-identical. Cross-node reads remain eventually-consistent (bounded by the heartbeat interval), which is
fine for the read-mostly correlation use cases (the same non-linearization caveat the read side already
documents).

## Build plan (separate PR)

1. `SetState` + widened `HandlerFn` union; `transform_one` returns `(deliveries, state_ops)`; `_sends`
   updated. 2. `state` table + `_apply_state_op` in `store.py`; `transform_handoff(state_ops=...)` applies
   within the txn; cache update on commit; `reencrypt_to_active` + retention cover it. 3. Parity table +
   apply-method in `sqlserver.py` (now live). 4. `state_get` + cache + `ContextVar` activation in the runner
   + dry-run (mirror code sets). 5. Exports + docs (CONFIGURATION.md) + sample. 6. **Adversarial tests:**
   exactly-once under simulated crash/replay, encryption round-trip, key-rotation, TTL purge, read
   non-linearization documented behavior.

## Alternatives considered

- **(B) Idempotent side KV store** (read/write directly, separate transaction) — simpler, but
  read-modify-write double-applies on re-run; a foot-gun in the core reliability story. Rejected.
- **(C) Read-only associations only** — can't express anonymous-patient mapping (needs a write). Rejected.
- **Async handlers** (so reads can await the store) — a large breaking change to the pure-sync transform
  contract; rejected for v1 in favor of the read-through cache.
- **Declared-key prefetch** (handler declares which keys it reads; worker async-prefetches before the sync
  call) — bounded-memory, but adds author burden + plumbing. Kept as the unbounded-state follow-up.
