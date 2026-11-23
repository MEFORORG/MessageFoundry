- **A store over-grant that was read now refuses under enforce even when a neighbouring grant
  could not be read.** On SQL Server, a fixed role or `CONTROL` the store privilege preflight read
  as held, such as `sysadmin` or `db_owner`, used to be demoted to an unobserved warning when
  another role column answered NULL. The report now stays OBSERVED with that over-grant in the
  excess, so with `[store].require_least_privilege` and no accepted opt-out the start refuses, and
  `check-privileges` exits 3 (over-grant) where it used to exit 4 (could not read). The grants that
  were not read are named in the log line, the over-grant posture entry and a new `unread` field
  in the preflight's audit row. Under `schema_management = "external"`, `db_securityadmin` no
  longer adds a separate `VIEW DEFINITION` finding, since the role carries that right.
  (`BACKLOG #6015`, `BACKLOG #6714`)
