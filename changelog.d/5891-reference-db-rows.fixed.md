- **A `DatabaseRef` reference sync bounds its statement and refuses a result that does not fit its
  columns.** `DatabaseRef(statement_timeout=...)`, whole seconds, `0` for no limit, defaults to 30
  as the DATABASE connector's SQL Server preset does, so an uncancelled statement no longer holds
  the sync pass without bound; one that runs past it fails as `ReferenceStatementTimedOut`. A
  `key_column` or `value_column` the result lacks or holds twice fails the sync as
  `ReferenceColumnMismatch`, and a NULL key or two rows with one key fails it as
  `ReferenceKeyRefused`, where each used to replace the last-good snapshot with `None` values, a
  `"None"` key or whichever duplicate came last. See [CONNECTIONS.md](../docs/CONNECTIONS.md).
  (`BACKLOG #5891`)
