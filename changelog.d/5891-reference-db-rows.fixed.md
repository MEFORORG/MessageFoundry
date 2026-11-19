- **A `DatabaseRef` reference sync bounds each statement call and refuses a result that does not fit its
  columns.** `DatabaseRef(statement_timeout=...)`, whole seconds, `0` for no limit, defaults to 30
  as the DATABASE connector's SQL Server preset does, and bounds each statement call, the execute
  and each fetch, not the pass. A call that runs past a non-zero value fails that sync as
  `ReferenceStatementTimedOut` at least on `HYT00`, the one state read as this timeout; the
  last-good snapshot keeps serving, and a set that never synced stays unloaded. Nothing bounds a
  call in at least these cases: at `0`, on a pool the engine could not track, or on a driver
  connection that carries no timeout, the last two logged at WARNING. In those cases an
  uncancelled statement holds the sync pass until it returns. The 30 s default is the same value as the `[store].command_timeout` default, not read
  from it, and a large set's statement can need more. A result that did not fit its columns used to
  replace the last-good snapshot: a missing `value_column` gave `None` values, a NULL key a
  `"None"` key, two rows with one key whichever came last, and a column the result held twice, as a
  join can, whichever of the two came last. Now a `key_column` or `value_column` the result lacks
  or holds twice, or, with no `value_column` set, any column name the result holds twice, fails the
  sync as `ReferenceColumnMismatch`; a missing `key_column` always failed the sync, and now fails
  it as this class. With a `value_column` set, another column held twice is still accepted. A NULL
  or duplicate key fails it as `ReferenceKeyRefused`. [CONNECTIONS.md](../docs/CONNECTIONS.md)
  lists at least these refusals. (`BACKLOG #5891`)
