# 0192 — Server-DB schema is provisioned externally by default; the runtime login runs no schema DDL

- **Status:** Accepted (2026-09-23) — built with this ADR.
- **Date:** 2026-09-23
- **Related:** BACKLOG #305 (ASVS 13.2.2) · BACKLOG #1008 (the startup privilege preflight) ·
  BACKLOG #1780 (`open_store` creates what it is pointed at) ·
  [ADR 0064](0064-schema-init-fastpath.md) (the `schema_meta` fast path) ·
  [CLAUDE.md](../../CLAUDE.md) §0

---

## Context

ASVS **13.2.2** asks that backend components talk to each other with the least privilege they need.
The server-DB store could not meet that. `SqlServerStore.open` and `PostgresStore.open` ran the schema
DDL batch as the engine's own runtime login whenever the `schema_meta` marker did not match the build.
[ADR 0064](0064-schema-init-fastpath.md) made a current database skip the batch, so steady state
issues no DDL. But the batch still runs at the first start of any build whose schema moved, so the
runtime login needed **standing** DDL rights: `db_ddladmin` on SQL Server, `CREATE` on the schema on
PostgreSQL. The runbook prescribed exactly that, and the BACKLOG #1008 probe checked the login against
that prescription, so an over-granted login read as clean.

MessageFoundry has zero deployments (CLAUDE.md §0). A breaking change to the first-run sequence costs
nothing today, and nobody needs a migration window.

## Decision

`[store].schema_management` takes `auto` or `external`. **`external` is the default on SQL Server and
PostgreSQL**; SQLite is always `auto`, and an explicit `external` there is refused at load.

- **Under `external`, open runs no schema DDL.** It reads the marker through the existing
  `_schema_marker_current` and raises `SchemaNotProvisionedError` when it does not match. The error
  names the database and the fix. On SQL Server it also stops issuing the two `ALTER DATABASE`
  options (`READ_COMMITTED_SNAPSHOT`, `ALLOW_SNAPSHOT_ISOLATION`) and warns instead.
- **`messagefoundry store provision-schema` runs the DDL** as whoever runs the command: the same
  batch, applock or advisory lock, and marker write that `auto` uses, plus the two SQL Server
  options. It opens a one-connection pool with the identity cipher and touches no row, so the DBA
  running it needs no store key. A re-run on a current schema is a no-op, but its RCSI step uses
  `WITH ROLLBACK IMMEDIATE`, so it runs with the engines stopped. It prints the schema it built in,
  and exits 3 when `READ_COMMITTED_SNAPSHOT` is still off after the run, read back rather than
  inferred, because the pooled default refuses to start then. SQLite is refused, so it cannot create a file it was only pointed at (#1780).
- **The cluster coordinator's tables ride the same batch.** Both coordinators used to create
  `nodes` / `leader_lease` (and on SQL Server `cluster_config`) at every start, as the runtime login.
  The statements are now stated once, as `CLUSTER_SCHEMA` in each store module, and appended to the
  batch; under `external` the coordinator skips its own DDL.
- **A refusal does not send the operator round a loop for the causes the store can see.** It names
  this login's default schema, because the batch creates tables unqualified and a provisioning
  principal with another default schema would build them elsewhere, and on SQL Server it names a
  login with no SELECT on the database, which hides the marker. On PostgreSQL it names a missing `USAGE` grant, which reads
  exactly like an absent marker. And on PostgreSQL a row-grant check over the provisioned objects
  runs first, so a table the runtime role cannot use refuses the start instead of failing
  mid-pipeline.
- **The SQL Server probe also counts directly granted DDL.** Under `external`, `CREATE TABLE` on the
  database and `ALTER` on the default schema count as excess when no `db_ddladmin` or `db_owner`
  membership already names them.
- **The privilege probe follows the mode.** Under `external`, `db_ddladmin` (SQL Server) and
  `CREATE` on, or ownership of objects in, the store's schema (PostgreSQL) count as excess. Under
  `auto` they stay prescribed, which is the #1008 behaviour unchanged.
- **`auto` on a server DB is a named loosening** (`schema_management` in `security_loosenings()`),
  because it hands standing DDL rights back to the runtime login.

## Acceptance Criteria

- **AC-1** — WHILE `schema_management` resolves to `external`, WHEN the marker is absent or records
  another batch, THE SYSTEM SHALL refuse the open, name `provision-schema`, and run no schema DDL.
  → `tests/test_sqlserver_schema_init.py::test_external_mode_refuses_a_virgin_database_and_runs_no_ddl`
  → `tests/test_store_privilege_schema_split.py::test_postgres_external_refuses_without_ddl`
- **AC-2** — WHILE `schema_management` resolves to `auto`, THE SYSTEM SHALL apply the batch exactly as
  before. → `tests/test_sqlserver_schema_init.py::test_the_same_stale_marker_runs_the_batch_under_auto`
- **AC-3** — THE SYSTEM SHALL resolve server backends to `external` by default and SQLite to `auto`,
  and SHALL refuse an explicit `external` on SQLite.
  → `tests/test_store_privilege_schema_split.py::test_an_explicit_external_on_sqlite_is_refused`
- **AC-4** — WHEN `provision-schema` runs, THE SYSTEM SHALL apply the batch whatever the mode says.
  → `tests/test_sqlserver_schema_init.py::test_provisioning_applies_the_batch_whatever_the_mode_says`
- **AC-5** — WHILE `external`, THE SYSTEM SHALL report `db_ddladmin` as excess on SQL Server, and
  only then. → `tests/test_store_privilege_preflight.py::test_external_mode_counts_db_ddladmin_as_excess_on_the_probe`
- **AC-6** — End to end on real servers: an external open of an empty database leaves it empty,
  `provision-schema` builds it, and a row-only login opens it and probes clean.
  → `tests/test_store_privilege_schema_split.py::test_live_sqlserver_external_refuses_then_provisions_then_runs_row_only`

## Options considered

1. **`external` by default on server DBs, with a provisioning command.** **CHOSEN.** It is the only
   mode in which the runtime login can run without DDL rights, and a least-privilege claim needs
   steady state to run that way. Engine PR 1261 (#1780) had already set the shape: `open_store`
   refuses to create by default, and provisioning callers opt in.
2. **`auto` by default, `external` as an opt-in.** Rejected. The shipped posture would still need
   `db_ddladmin` on the runtime login, so 13.2.2 stays failed at the default, and the probe could
   never report the grant as excess where it matters.
3. **Drop the DDL grant after first start, and re-grant it for upgrades.** This was the runbook's
   previous advice. Rejected: it keeps one login, puts the timing on an operator's memory, and a
   forgotten re-grant fails the upgrade start with a permission error that does not name the fix.
4. **Refuse by default on an over-granted login under PHI.** Out of scope. It was superseded by the
   #1008 owner ruling of 2026-09-14, which keeps the refusal behind `[store].require_least_privilege`.

## Consequences

**Positive** — The runtime login holds row access only, and the probe can say so. A refused start
leaves the database exactly as it found it. The DDL happens at a moment a DBA chose.

**Negative / risks** — A fresh server-DB install, or the first start of an upgrade whose schema moved,
fails `serve` until someone runs `provision-schema`. This is the accepted cost. The refusal is loud,
comes at start before any listener binds, and names the command. CI server-DB legs and the dev scripts
set `MEFOR_STORE_SCHEMA_MANAGEMENT=auto`, because their suites drop and rebuild tables as the test
login; the new file's live legs exercise `external` against a scratch database.

**Measured, and not** — CI provisions as `sa`. The runbook's narrower provisioning grant
(`db_ddladmin` + `db_datareader` + `db_datawriter`) is the prescription for the batch, not a measured
minimum.

**Out of scope** — the check-privileges CLI, an AlertSink event on the WARN arm, and the per-hop
privilege matrix (BACKLOG #305's later half, E2). The SQL Server probe reads `CREATE TABLE` and
`ALTER` on the default schema, and at least those; other object-level DDL grants are not enumerated.
The ASVS re-score lives in the vault and is not part of this change.
