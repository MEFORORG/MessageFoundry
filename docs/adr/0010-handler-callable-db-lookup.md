# ADR 0010 — Handler-callable live database lookup (`db_lookup`)

- **Status:** Accepted (2026-06-14) — on the owner's explicit decision that a Handler may make a **live,
  read-only** database call on each pass, accepting that a re-run may re-query and differ.
- **Built:** Implemented. `DatabaseLookup(name, …)` declaration + `Registry.lookups`
  ([config/wiring.py](../../messagefoundry/config/wiring.py)); the `db_lookup(connection, statement,
  params)` accessor + active-runner holder ([config/db_lookup.py](../../messagefoundry/config/db_lookup.py));
  the pooled `DatabaseLookupExecutor` reusing the DATABASE connector's DSN/param/SQLSTATE helpers
  ([transports/database.py](../../messagefoundry/transports/database.py)); and the runner +
  **gated off-loop transform** + fail-closed egress check in the transform worker
  ([pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)). Production / supported
  (SQL Server via the `[sqlserver]` extra), like the DATABASE connector.
- **Related:** [ADR 0009](0009-run-scoped-context-providers.md) (run-scoped accessors + the
  re-run-stability rule this is the exception to), [ADR 0006](0006-external-data-lookups.md) (the
  *synced-snapshot* alternative the owner rejected for these), [CLAUDE.md](../../CLAUDE.md) §2 (the
  reliability invariant amended here) and §8.

## Context

Corepoint feeds enrich/gate messages with **live** database reads — provider NPI from an internal id,
"is this an EIHC provider", "is this a physician" (Clarity stored procs / Data Points), executed *each
time a message passes through*. Several production feeds (provider master-file loads, live
provider-query lookups, an ECG provider sub-leg) cannot be ported without this — it is the one true
**hard blocker** among the remaining engine gaps.

MessageFoundry already offers a *re-run-stable* lookup — `reference()` (ADR 0006), a synced snapshot read
purely. The owner **rejected** materialize-as-reference-set for these: the value must reflect the database
**now**, not a periodic snapshot. So we need a Handler to issue a live query mid-transform.

Two hard tensions:

1. **Purity / re-run safety (CLAUDE.md §2 — "do not break").** At-least-once re-runs a transform after a
   crash and relies on it being pure so the re-run re-derives identical output. A live read is a side
   input that can differ on a re-run.
2. **Never block the event loop (CLAUDE.md §6).** Handlers run **synchronously on the asyncio loop**
   (`transform_one` is called inline by the transform worker). A blocking DB read there would stall every
   listener, worker, and API call.

## Decision

Add a synchronous, handler-callable `db_lookup(connection, statement, params)` returning the rows as
`list[dict]`, with these design points:

- **Named connections, per-call statement.** `DatabaseLookup("clarity", server=…, database=…, …)`
  declares only the *connection* (pooled, env()-resolvable secrets); each `db_lookup` call supplies its
  own read-only `statement` + `params`. Statements are always parameterized (`:name` → positional `?`),
  so a value can never inject SQL. The engine builds one `DatabaseLookupExecutor` from the graph's
  declarations; pools open lazily, one per connection, autocommit (read-only).

- **Off the event loop, gated.** When the graph declares **≥1** `DatabaseLookup`, the transform worker
  runs the handler **in a worker thread** (`asyncio.to_thread`), which copies the run context (the
  ADR-0009 provider views *and* the active lookup runner) into the thread. `db_lookup` bridges the query
  back onto the engine loop (`run_coroutine_threadsafe`) and blocks the **worker thread** — never the
  loop — for the result. **When the graph declares no lookup, the transform path is byte-identical to
  before** (inline call on the loop, no thread hop, no runner): the feature is invisible until used.

- **Re-run-stability exception (ADR 0009), made explicit.** `db_lookup` is the **documented exception**
  to the rule that every run-scoped accessor is re-run-stable: a re-run may re-query and get different
  data — **accepted by design** (owner decision). Because the result is non-deterministic, `db_lookup`
  is unavailable where determinism is assumed: it is published only in the live transform path, so a call
  on a **Router** or in the **dry-run / Test Bench** path finds no active runner and **raises**
  `DbLookupError` (a feed that uses it is previewed by stubbing its wrapper).

- **Fail-closed egress + PHI-safe errors.** Each lookup server is gated by the existing
  `[egress].allowed_db` allowlist at load/reload/start (`check_lookup_allowed`), exactly like a DATABASE
  source. A failed connection/query, an unknown connection, or a missing parameter raises `DbLookupError`
  whose message names the connection and (where available) the SQLSTATE — **never** the statement,
  parameters, or returned rows. The transform worker turns it into that message's `ERROR` / dead-letter
  disposition (the owner's "DB-error → dead-letter" requirement).

## Consequences

- **Unblocks** the provider/eligibility feeds (MFN, BDPQI, the iECG EIHC sub-leg). The migration's
  `_fct.get_provider_npi()` / `is_eihc_provider()` / `is_physician()` stubs become thin wrappers over
  `db_lookup`.

- **CLAUDE.md §2/§8 amended:** the "routers and transforms must be pure" invariant now carries an
  explicit carve-out — a **read-only** `db_lookup` is permitted in a Handler; its re-run divergence is
  accepted. Routers stay pure (no `db_lookup` on a Router). Outbound idempotency is unchanged.

- **Concurrency cost:** a transform that uses `db_lookup` occupies a thread-pool thread for the duration
  of the off-loop run (and blocks it on the query, bounded by `_LOOKUP_RESULT_TIMEOUT_SECONDS = 30s`).
  Under heavy concurrent lookup load this can saturate the default thread pool; a dedicated executor with
  a tuned size is a follow-up if it proves necessary. A lookup exceeding the timeout raises (→ dead-letter)
  rather than pinning a thread forever; the orphaned query still completes on the loop and releases its
  connection.

- **Scope:** transform-only for now (Handlers, not Routers); SQL Server backend only (production /
  supported, like the DATABASE connector). A read-only convention is by design — the executor neither commits nor exposes
  a write path. Extending `db_lookup` to Routers, or adding a dedicated lookup thread pool, are deferred.
