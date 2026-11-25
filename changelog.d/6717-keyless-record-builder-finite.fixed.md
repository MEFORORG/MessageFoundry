- **A keyless SQLite store, one with no row-seal key, now refuses a new NaN or infinity in the
  fields a session, user or approval seal covers, unless a stored value of the same kind already
  sits under that field name.** A store sealed through Transit gets no check from this change. The
  store wrote the value unchecked, and SQLite stores a NaN as NULL. The check runs
  where the SQLite store mints a session or account, writes an approval, or rewrites a session or
  account record, and raises `ValueError`, as the local row sealer refuses one. Because a user's
  role grants share the field name `assigned_at`, a new grant's non-finite `assigned_at` is
  admitted when another grant already stores the same kind. At least these are not checked: the
  revoke statements that set `revoked_at`, the approval tombstone's `decided_at`, columns a seal
  leaves out such as a session's `last_used_at`, and the Postgres and SQL Server stores.
  (`BACKLOG #6717`)
