# ADR 0006 — External data lookups for transforms (reference enrichment)

- **Status:** Accepted (2026-06-13) — ratified on the owner's go. Design produced via a judge-panel
  design workflow (4 diverse proposals, adversarially scored against the engine invariants, plus a
  completeness synthesis).
- **Built:** **Tier 1, file source.** `config/reference.py` (the pure read accessor `reference(name)`
  + `ReferenceSet`), the `reference` / `reference_version` store tables (build-new-then-atomic-flip,
  AES-GCM at rest + key-rotation coverage, read-through cache + `reference_view()`), the
  `ReferenceSyncRunner` (supervised loop + startup sync), the `Reference(...)` / `FileRef(...)` author
  surface, the `[reference]` settings, and reference activation in the router/transform workers +
  dry-run. SQLite-only snapshot store (SQL Server has an inert stub, like state). **Increment 2 also
  built:** the **`DatabaseRef`** source — the engine queries SQL directly on the refresh cadence
  (reusing `transports/database.py` for the DSN/pool, gated by the fail-closed `[egress].allowed_db`
  allowlist), experimental + faked-driver tested like the DB connector. **Tier 2** (resolve-at-ingress
  per-message lookups) stays deferred to its own ADR.
- **Decision in one line:** add **reference sets** — managed, hot-swappable, read-only lookup
  snapshots that the engine *materializes* from an external source **off the message path** and that a
  transform reads **purely** (`reference("name").get(key)`, a twin of `code_set()`). Defer
  truly-live, must-be-current lookups to a Tier-2 follow-up ADR.
- **Related:** [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline + the pure-re-run
  invariant this must preserve), [ADR 0005](0005-transform-accessible-state.md) (cross-message **write**
  correlation — this is its **read** complement), the **code-set framework**
  ([config/code_sets.py](../../messagefoundry/config/code_sets.py)) (the read-side pattern this clones),
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability invariant).

## Context

A common migration need is to **enrich** a message from an **external data source**: look up a
provider's NPI or attribute flags from a clinical/reporting database, resolve a code via a
database-backed translation table (the **Corepoint Data Point / DB Association / `ItemCodeLookup`**
pattern), and so on. The lookups are reads against an external system (typically SQL) keyed by a value
in the message.

**The tension.** MessageFoundry Routers/Handlers must be **pure** — message in → message out, no
external I/O — because the staged pipeline gives at-least-once delivery by **re-running** a stage after
a crash, which is only safe when *a re-run re-derives identical output* (ADR 0001 / CLAUDE.md §2 — **do
not break**). A live external query inside a transform is a side effect that is **non-deterministic on
every re-run** (the source can return a different value, or fail), which breaks the invariant outright.

**Why ADR-0005 state is not the answer by itself.** The obvious move — have a transform query the
source once and cache the result in the existing `state` table — is **unsafe**, and the design panel
proved why. The `state` table is keyed `(namespace, key)` with `INSERT OR REPLACE`
([store/store.py](../../messagefoundry/store/store.py) `_apply_state_op`) over a single process-wide
cache. A value cached under a shared key is **mutated** by (a) any later message resolving the same
key and (b) a TTL refresh. So this crash/replay sequence diverges silently:

> Msg *M* looks up key `K` → `{found: false}` (e.g. an entity not yet present); *M* is transformed and
> delivered. Later Msg *M2* re-queries the now-present entity and `INSERT OR REPLACE`s `K` → `V2`.
> *M*'s outbound row dead-letters for an unrelated transient reason; an operator **replays** it
> (per-stage replay is an ADR-0001 feature). The replay re-runs *M*'s transform, now reads `V2`, and
> emits **different outbound bytes than were already delivered** — re-run-NOT-identical. The exact
> failure the invariant exists to prevent.

**The hard rule this ADR establishes (non-negotiable for any future design):** a persisted lookup
result must be keyed so it is **immutable for the lifetime of the message that read it** — either
**per-message** (`message_id`) or **content-addressed**, never the mutating `(namespace, key)` state
table. A re-queried/TTL-refreshed cache in a shared-key table is **not** replay-safe.

A second constraint surfaced by the panel: any *per-message external call* must resolve **once per
message**, not once per handler. `route_handoff` produces **one routed row per selected handler**
([store/store.py](../../messagefoundry/store/store.py)), and the transform worker runs per routed row,
so a naive per-handler lookup would hit the external source **once per handler** — for a high-fan-out
feed (one inbound routed to N handlers) that is **N×** the load on the source for a single message.

## Decision

A **two-tier** capability, split by whether the data must be *current-as-of-message*.

### Tier 1 — Reference sets (this ADR; build first) · effort **L**

For data that is **slowly-changing reference** (provider directories, database-backed translation
tables, most Corepoint Data Points / DB-Association lookups): the engine **materializes** the external
dataset into a managed, versioned, read-only snapshot on a schedule, **off the message path**; the
transform reads it **purely**. There is **no per-message external call**, so re-run-identity holds by
construction.

**Author surface** (declared once in the wiring module, registered into the `Registry` beside code
sets):

```python
PROVIDER_NPI = Reference(
    "provider_npi",
    source=DatabaseRef(server=env("ref_db_host"), database="ReportingDB",
                       key_statement="SELECT provider_id, npi FROM dbo.provider_directory",
                       key_column="provider_id", value_column="npi"),
    refresh="0 2 * * *",        # cadence (cron-ish) or refresh_seconds=...
    max_staleness="36h")        # freshness guard (alert / fail-closed)
```

Read it **purely**, exactly like `code_set()`:

```python
@handler("enrich_provider")
def enrich(msg):
    pid = msg["PV1-7.1"]
    npi = reference("provider_npi").get(pid)             # pure dict lookup — no await, no I/O
    if npi:
        msg.set("PV1-7.13", npi)
    return Send("OB_DOWNSTREAM", msg)
```

**Mechanism** (each piece clones a shipped pattern — low novel surface):
1. **Sync, off the message path.** A new engine-owned `ReferenceSyncRunner` — a near-clone of
   [`pipeline/retention.py`](../../messagefoundry/pipeline/retention.py) `RetentionRunner` (supervised
   loop, injected clock, `run_once`/`_sleep`, one task per process, reload-independent) — runs each
   declared source on its cadence (and once on startup, catch-up). For a `DatabaseRef` it reuses
   [`transports/database.py`](../../messagefoundry/transports/database.py) `_build_dsn` / `_make_pool`
   (aioodbc read pool) to run the operator's statement, gated by the **existing** fail-closed
   `[egress].allowed_db` allowlist (same `check_source_allowed` path as `DatabaseSource` — no new
   egress surface).
2. **Store, build-new-then-atomic-flip.** New `reference (refset, key, value, value_version, set_at,
   source_hash)` + a `reference_version (refset, active_version, synced_at, row_count, status)` pointer.
   The sync writes the whole new snapshot under a fresh `value_version` in one transaction, then
   **atomically flips** `active_version` (GC the prior version after) — a reader never sees a torn set,
   and a **failed sync leaves the last-good active live** (graceful degradation). `value` is
   cipher-encrypted (PHI at rest, store `_enc` keyring + key-rotation, like `messages.raw` / `state.value`).
3. **Read-through cache + pure read.** The store mirrors the *active* version in memory (like
   `_load_state_cache`), swapped wholesale only after a sync commits (like the post-commit `_state_cache`
   update). A new `config/reference.py` (twin of [`config/state.py`](../../messagefoundry/config/state.py))
   publishes a `MappingProxyType` view via a `ContextVar`; the transform worker brackets each handler
   run with `reference_activated(store.reference_view())` alongside the existing
   `code_sets_activated` / `state_activated`. `dry_run` publishes the same view.

**Re-run safety.** The transform does **no** external call, so re-run-identity reduces to "does the
snapshot change between the run and a crash-re-run?" The atomic flip makes a reader see the **old or
new snapshot whole, never torn**, and the engine is single-writer. The only residual non-determinism —
a sync flipping `active_version` in the narrow window between an attempt and its re-run — is **identical
in kind and severity to the code-set hot-reload caveat already accepted and documented**
([config/code_sets.py](../../messagefoundry/config/code_sets.py): "a hot-reload that changes a table
between a run and a crash-re-run can make the re-run derive a different output… acceptable for reference
data… the one way a transform's output can legitimately differ"). It moves the non-determinism from
*per-message-always* (a naive query) to *per-snapshot-flip-rarely* — into the category the project
already deems safe — and needs **no new exactly-once seam** (reads carry no side effect).

**Failure / staleness.** Source down → the active snapshot is untouched; the message path keeps reading
the last-good snapshot; the loop retries and raises a `reference_sync_failed` AlertSink alert. Key miss
→ caller's default (sparse data, like `state_get`). Stale beyond `max_staleness` → `reference_stale`
alert; per-set policy `on_stale="keep"` (default, availability) or `"fail"` (fail-closed refuse, so a
too-old snapshot can't silently mis-enrich). A shipped `references/<name>.csv` **seed** (reusing
`code_sets._load_csv`) makes a set usable before its first live sync and lets tests/dev run with no
external-DB connection.

### Tier 2 — Resolve-at-ingress, per-message lookups (deferred; separate ADR) · effort **XL**

For the cases Tier 1 **cannot** serve — data that must be **current-as-of-this-message**, or
**write-back correlation** — a dedicated **`enrich` stage that drains the `ingress` stage**
(**before** `route_handoff` fans out, so **once per message** — no per-handler amplification), runs the
external queries through a **request/response DB connector built on `transports/database.py`** (reusing
its pooling, `[egress].allowed_db`, transient-vs-permanent error mapping, and PHI-at-rest), and writes
the results into a **`message_lookups` record keyed by `message_id`** — **not** the `(namespace, key)`
state table. The transform then reads that **per-message-immutable** record purely. This is the only
shape that is simultaneously **fan-out-free** *and* **replay-identical**:
- keyed by `message_id` ⇒ never overwritten by a later message or a TTL refresh ⇒ replay reads the
  same bytes;
- resolved at ingress ⇒ one query per message;
- source-down ⇒ the `enrich` stage dead-letters/retries like any other stage (post-ACK, no NAK) — its
  failure handling is **free** from ADR 0001.

Tier 2 is scoped and ADR'd separately once a live-lookup or write-back feed is actually on the critical
path; the **DB-Association write-back** half is already expressible today as a normal outbound DATABASE
`Send` (idempotent MERGE), so only the live-read half is genuinely deferred.

### Unchanged

ADR-0005 **`state`** stays exactly as-is for **cross-message write-once correlation** (e.g. a stable
anonymized-id mapping, order↔result) — it is safe *because* its use is write-once, **not** a mutating
cache. This ADR is its read-side complement, not a change to it.

## Consequences

**Positive**
- Re-run-safe with **zero new exactly-once machinery** — reads carry no side effect; the only
  non-determinism is the already-accepted code-set caveat, bounded by the atomic snapshot swap.
- **No per-message external latency or coupling** — a slow/down source never stalls intake or
  transform (vs a per-message call that re-introduces the exact blocking the staged pipeline removed).
- Reuses **four shipped patterns** nearly verbatim (code-set read, state cache+view, RetentionRunner
  loop, database.py aioodbc pool); fits the modular registry model.
- PHI/sensitive reference data stays **on-prem** in the engine's own encrypted store with retention +
  **counts-only** audit; the fail-closed `[egress].allowed_db` gate governs the one outbound dial; no
  per-message round-trip to the source that could leak query patterns.
- Author API is pure and familiar (`reference(name).get(key)`), dry-run-resolvable, validated by
  `messagefoundry check` / reload — no aioodbc/cron/versioning leaking into handler code.

**Negative / costs**
- **Staleness is intrinsic**: the transform sees data as of the last sync, not real-time. Wrong for a
  lookup that *must* be current within the sync window — that case is Tier 2. `max_staleness` mitigates
  but cannot eliminate it.
- **Bounded-dataset assumption** (like ADR 0005's bounded cache): whole-snapshot materialization fits
  an in-memory mirror; a very large universe needs the delta-sync + on-disk-version-read follow-up.
- A **new moving part** (ReferenceSyncRunner + cadence) to operate, monitor, and seed; a silently
  failing sync serves stale data until the staleness alert fires.
- The **SQL-Server source sync** needs the `[sqlserver]` extra + ODBC Driver 18 and is exercised only
  by the CI service-container leg (experimental), like the DATABASE connector / SQL Server store. The
  **read path** is backend-agnostic (snapshot lives in the SQLite store like state).

## Alternatives considered (scored by the design panel)

| Approach | Verdict |
|---|---|
| **Materialized Reference Tables** *(chosen, Tier 1)* | Highest total; **no fatal flaw**. Re-run-safe by construction; reuses the most shipped machinery; covers all reference-shaped needs. Cost = staleness. |
| **Persisted read-through `lookup()` over the ADR-0005 state seam** | **Rejected.** Scored well on paper but shares the **disqualifying `(namespace,key)` keying flaw** — a TTL refresh or later-message resolution overwrites the cached value, so a replay diverges. Demoted once the keying flaw was made explicit. Its safe core (a *per-message-keyed* read-through) is exactly Tier 2. |
| **Materialize-Before-Transform: an `enrich` stage between `routed` and `outbound`** | **Superseded by Tier 2's ingress placement.** Re-run-safety sound, but it materializes **per-handler-row** (drains `routed`, already fanned out) → re-queries the source once per handler → N× amplification; and its module-level `bind=` API is under-specified for per-message field peeking. Moving the stage to drain **`ingress`** (per-message) fixes both — that is Tier 2. |
| **Enrich-then-transform via a generator/`yield`-barrier handler** | **Rejected (mechanically impossible).** A live generator frame cannot be suspended in the enrich worker and resumed in the transform worker across a durable stage boundary / process restart; `HandlerFn` is a plain `Callable` invoked once. Also inherited the global-key replay flaw. |

The two-tier split is the synthesis: **Tier 1** delivers the majority of reference-shaped lookups at
low risk and ships first; **Tier 2** covers live-current + write-back correlation later, with
**per-message-immutable keying** as the rule both tiers — and any future design — must obey.
