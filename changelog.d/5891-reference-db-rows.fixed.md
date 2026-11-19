- **A `DatabaseRef` reference sync bounds its statement and refuses a result that does not fit its
  columns.** `DatabaseRef(statement_timeout=...)`, whole seconds, `0` for no limit, defaults to 30
  as the DATABASE connector's SQL Server preset does. A statement that runs past a non-zero value
  fails that sync as `ReferenceStatementTimedOut`, and the last-good snapshot keeps serving; at
  `0` the statement holds the sync pass until it returns. The 30 s default is the store's own
  `[store].command_timeout` default, so a large set's statement can need more. A result that did
  not fit its columns used to replace the last-good snapshot: a missing `value_column` gave `None`
  values, a NULL key a `"None"` key, two rows with one key whichever came last, and a column the
  result held twice, as a join can, whichever of the two came last. Now a `key_column` or
  `value_column` the result lacks or holds twice, or, with no `value_column` set, any column name
  the result holds twice, fails the sync as `ReferenceColumnMismatch`; with a `value_column` set,
  another column held twice is still accepted. A NULL or duplicate key fails it as
  `ReferenceKeyRefused`. [CONNECTIONS.md](../docs/CONNECTIONS.md) lists at least these refusals.
  A `key_column` the result lacks always failed the sync, and now fails it as
  `ReferenceColumnMismatch`. (`BACKLOG #5891`)
