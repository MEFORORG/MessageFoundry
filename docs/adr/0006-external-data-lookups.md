# ADR 0006 — External data lookups for transforms (reference enrichment)

- **Status:** Accepted (2026-06-13) — ratified on the owner's go. Design produced via a judge-panel
  design workflow (4 diverse proposals, adversarially scored against the engine invariants, plus a
  completeness synthesis).
- **Built:** **Tier 1, file source.** `config/reference.py` (the pure read accessor `reference(name)`
  + `ReferenceSet`), the `reference` / `reference_version` store tables (build-new-then-atomic-flip,
  AES-GCM at rest + key-rotation coverage, read-through cache + `reference_view()`), the
  `ReferenceSyncRunner` (supervised loop + startup sync), the `Reference(...)` / `FileRef(...)` author
  surface, the `[reference]` settings, and reference activation in the router/transform workers +
  dry-run. Snapshot store on **all three backends** — SQLite, PostgreSQL, and SQL Server (the last
  ported by BACKLOG #235; see the [2026-07-16 amendment](#amendment-2026-07-16--reference-sets-implemented-on-sql-server-backlog-235)) — see
  [Backend support](#backend-support). **Increment 2 also built:** the **`DatabaseRef`** source — the engine queries SQL directly on the refresh cadence
  (reusing `transports/database.py` for the DSN/pool, gated by the fail-closed `[egress].allowed_db`
  allowlist), production / supported like the DB connector (faked-driver unit tests + a gated CI round-trip). **Tier 2** (resolve-at-ingress
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

## Backend support

*(Amendment, 2026-07-14. The original text called the snapshot store "SQLite-only" and the SQL Server
side "an inert stub". Both were wrong: Postgres is fully ported, and the SQL Server stub is not inert —
it **raises**.)*

| Backend | Reference-set snapshot store | Notes |
|---|---|---|
| **SQLite** | ✅ implemented | The reference implementation: the `reference` / `reference_version` tables, build-new-then-atomic-flip, encrypted at rest, read-through cache. |
| **PostgreSQL** | ✅ implemented | Ported, not stubbed — same tables + flip contract, plus the real multi-node follower read-through (`converge_reference_cache`). |
| **SQL Server** | ✅ implemented | Ported at SQLite/Postgres parity by [BACKLOG #235](../archive/backlog/BACKLOG-CLOSED.md) — see the [2026-07-16 amendment](#amendment-2026-07-16--reference-sets-implemented-on-sql-server-backlog-235) for this port's two recorded divergences (the UTF-16 sizing guard and the BIN2 collation). |

This is advertised as the **`supports_reference_sets`** capability flag on the `QueueStore` protocol
(`store/base.py`) — **allow-list semantics**: `False` by default, so a future backend that hasn't ported
the snapshot store is caught by the same gate. (Since the 2026-07-16 amendment all three shipped
backends declare `True`.)

**A graph declaring ≥1 `Reference(...)` on a non-supporting backend is REFUSED, fail-closed**, at all
three config-application points: `messagefoundry check` (the `reference-backend` required check, keyed on
the declared `[store] backend`), **engine start** (before the startup sync, before any listener binds), and
**reload/promote** (a `WiringError` → 422 from `RegistryRunner.build_check`, so the running graph is left
untouched).

**Engine-refusal, not an [ADR 0031](0031-startup-connection-fault-isolation.md) lane degrade.** A reference set
is registry-**global**, and the read is a runtime-only `reference(name)` call inside a Handler body — there
is no sound static handler→refset edge to scope a degrade to (`config/reachability.py`'s is a self-declared
heuristic and cannot see a computed name), so *any* handler on *any* inbound may read the set. Nor is it
analogous to a capture-incapable lane, which still retries its rows and drops nothing. The gate keys on
**declaration**, so it fires even when the sync is deferred — the set still never materializes.

**What this replaces.** Previously such a graph started clean, the `ReferenceSyncRunner` swallowed the
`NotImplementedError` as a generic source failure and logged `reference set 'x' sync failed (keeping
last-good): NotImplementedError` **every refresh interval, forever** — a line that lies twice (the source
is fine; there is no last-good and never can be) — and every `reference(...)` read raised `ReferenceError`,
per message, **after the ACK**. The runner now reports a permanent backend incapability **once**, at ERROR,
and never retries it (defense-in-depth: the start gate makes it unreachable in a served engine).

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
- The **SQL-Server source sync** needs the `[sqlserver]` extra + ODBC Driver 18 and is exercised by the
  CI SQL Server service-container leg, like the DATABASE connector (now production). The reference
  **snapshot store** is implemented on **all three backends** — SQLite, PostgreSQL, and (since the
  [2026-07-16 amendment](#amendment-2026-07-16--reference-sets-implemented-on-sql-server-backlog-235))
  SQL Server — advertised by the `supports_reference_sets` capability flag; the fail-closed gate stays
  for any future backend that leaves the allow-list default — see
  [Backend support](#backend-support). (The **read path** itself is backend-agnostic: it reads whatever
  store the engine opened, which is where the snapshot lives.)

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

## Amendment (2026-07-16) — reference sets implemented on SQL Server (BACKLOG #235)

The reference-set snapshot store is now **ported to SQL Server at SQLite/Postgres parity**
([`store/sqlserver.py`](../../messagefoundry/store/sqlserver.py)): the `reference` /
`reference_version` tables, `write_reference_snapshot` (build-new-then-atomic-flip in one
transaction), `_load_reference_cache` / `reference_view()`, and the multi-node follower read-through
`converge_reference_cache()`. `supports_reference_sets` is `True` on all three shipped backends;
**the fail-closed capability gate itself stays** (allow-list, `False` on the base protocol), so a
future backend that never ports the snapshot store is still refused at `messagefoundry check`, at
engine start, and on reload/promote — SQL Server's row simply moves out of the refusal table.

Landed across three Plan-12 sessions, in fail-closed order: the T-SQL port with the flag held
`False` (`store-235-port`, PR #1075) → the real-server proof battery (`store-235-ci-tests`,
PR #1078) → this flip. **The flip was gated on PR #1078's sqlserver-store (2022 + 2025 image matrix)
and postgres-store CI legs going green** — the only authoritative T-SQL proof (local pytest silently
skips without a live server) — covering the UTF-16 guard boundary trio, the BIN2 collation
round-trip, the no-key→key reopen migration, the follower converge + writer `== []` pin, and the
first-ever reference-row key-rotation tests on all three backends.

**Decisions this port records:**

- **Schema.** `reference (name NVARCHAR(256), version NVARCHAR(64), [key] NVARCHAR(450),
  value NVARCHAR(MAX))` with `PRIMARY KEY NONCLUSTERED (name, version, [key])`, plus the
  `reference_version` pointer table — the donors' tables, width-bounded. **450 was *chosen* so the
  worst-case composite index key (256 + 64 + 450 code units = 1,540 bytes) can never hit SQL Server's
  1,700-byte nonclustered-index key cap** — the cap is a sizing input, not the runtime failure mode.
  **The runtime rejector for an over-long key is the `NVARCHAR(450)` column width itself
  (truncation)**, which is why the guard below exists. The PK is NONCLUSTERED deliberately: a
  clustered PK (900-byte cap) would declare-with-warning and fail only on actual over-900-byte rows —
  a data-dependent landmine instead of a declared bound.
- **Fail-closed sizing guard (divergence 1 from the donors).** SQLite/Postgres store keys as
  unbounded TEXT and have no equivalent limit. Here, an over-long `name` (> 256) or `key` (> 450) —
  measured in **UTF-16 code units**, what `NVARCHAR` actually counts — raises **before** the snapshot
  transaction, so the sync runner's source-failure handling keeps the last-good snapshot live and
  alerts. The error **never embeds the raw key** (reference keys may be PHI for patient-keyed sets):
  it carries the set name plus the key's length, ordinal, and a truncated SHA-256 only.
- **Binary collation (divergence 2).** `COLLATE Latin1_General_100_BIN2` on `name` / `version` /
  `[key]` (both tables), so key equality is a **byte comparison** like SQLite/Postgres. Under a
  case-insensitive database default (SQL Server's norm), externally-sourced keys differing only by
  case — or by a trailing space, per ANSI padding on index keys — would collide into a PK duplicate
  mid-transaction, turning a valid snapshot into a perpetual per-interval sync failure.
- **Encryption at rest.** Values are `cipher.encrypt(json.dumps(v))` (`mfenc`), covered by **both**
  `reencrypt_to_active` (key rotation) **and** `_encrypt_existing_rows` (the no-key→key migration
  pass). The migration pass is required because "born encrypted" is false: under a no-key deployment
  `IdentityCipher` writes plaintext JSON, and the no-key→key transition is exactly what that method
  exists to migrate — omitting `reference` would leave snapshot PHI plaintext at rest after a key is
  introduced.
- **Convergence.** Multi-node read-through per the donor contract (`reference_version` LEFT JOIN
  `reference`, swap only sets whose active version advanced). The leader's own
  `write_reference_snapshot` updates **both** the read cache and the versions map post-commit, so
  `converge_reference_cache()` returns `[]` on the node that just wrote — no self-refresh.
- **Upsert idiom.** The `reference_version` pointer flip uses `MERGE WITH (HOLDLOCK)` — the
  established `SqlServerCoordinator` idiom
  ([`pipeline/cluster_sqlserver.py`](../../messagefoundry/pipeline/cluster_sqlserver.py), the SQL
  Server store Phase 4 active-passive HA) — rather than a novel upsert shape.

Operational note: the first post-upgrade open of an existing production DB re-runs the full guarded
DDL batch once under the schema applock with the timeout exemption (the content-addressed `_SCHEMA`
changed) — by design, benign.
