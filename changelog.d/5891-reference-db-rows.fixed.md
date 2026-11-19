- **A `DatabaseRef` reference sync bounds its statement and refuses a result that does not fit its
  columns.** `DatabaseRef(statement_timeout=...)`, whole seconds, `0` for no limit, defaults to 30
  as the DATABASE connector's SQL Server preset does, so a statement the driver times out no longer
  holds the sync pass without bound; one that runs past it fails as `ReferenceStatementTimedOut`.
  The 30 s default was chosen for one statement per message, so a large set's statement can need
  more. A result that did not fit its columns used to replace the last-good snapshot: a missing
  `value_column` gave `None` values, a NULL key a `"None"` key, two rows with one key whichever
  came last, and a column the result held twice, as a join can, whichever of the two came last.
  Now a missing or doubled column fails the sync as `ReferenceColumnMismatch`, and a NULL or
  duplicate key fails it as `ReferenceKeyRefused`; [CONNECTIONS.md](../docs/CONNECTIONS.md) lists
  at least these refusals. A `key_column` the result lacks always failed the sync, and now fails
  it as `ReferenceColumnMismatch`. (`BACKLOG #5891`)
