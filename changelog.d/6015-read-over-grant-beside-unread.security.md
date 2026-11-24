- **On SQL Server, a store over-grant that was read now refuses under enforce even when a
  neighbouring grant could not be read.** A SQL Server probe answer that is NULL, or any value but
  0 or 1, is not read. Under `[security].enforcement = "enforce"` (the default) with
  `[store].require_least_privilege` unset, an over-grant the store privilege preflight read as
  held, such as `sysadmin`, `db_owner` or a `CONTROL`, used to be demoted to an unobserved
  warning when a fixed role, `CONTROL SERVER` or database `CONTROL` was not read. The report now
  stays OBSERVED with that over-grant in the excess, so the start refuses unless the audited
  over-grant opt-out, `[security].allow_over_granted_store_principal`, accepts it. Whatever the
  enforcement dial and `[store].require_least_privilege` say, `check-privileges` now exits 3
  (over-grant) on such a report where it used to exit 4 (could not read). Under
  `schema_management = "external"` the grants counted only there, at least `CREATE TABLE`,
  `ALTER` on the default schema, `VIEW DEFINITION` and the audit-table rights, count as read
  over-grants the same way. With `[store].require_least_privilege` set, the start refused before
  and still does. At least the fixed roles and grants that were not read are named in the log
  line, the over-grant posture entry and a new `unread` field in the preflight's audit row. On
  that path a user-defined database role is not read, so it is not named either. The PostgreSQL
  store probe fills the `unread` field too, but the two backends differ: an unread audit-table
  grant beside a read over-grant stays OBSERVED and refuses, while under external a
  `current_schema()` that resolves to NULL still reports unobserved before any over-grant is
  weighed, so with `[store].require_least_privilege` unset a read `SUPERUSER` there only warns
  under enforce. Under external,
  `db_securityadmin` no longer adds a separate `VIEW DEFINITION` finding, since the role carries
  that right. (`BACKLOG #6015`, `BACKLOG #6714`)
