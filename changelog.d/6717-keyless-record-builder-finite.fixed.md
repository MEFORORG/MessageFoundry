- **A SQLite store with no row-seal key now refuses a new NaN or infinity in the fields a session,
  user or approval seal covers, as the local row sealer refuses one.** It wrote the value
  unchecked, and SQLite stores a NaN as NULL. The check runs where the SQLite store mints a session
  or account, writes an approval, or rewrites a session or account record, and raises `ValueError`.
  A non-finite value already in the stored row is carried forward as before. At least these are
  not checked: the revoke statements that set `revoked_at`, the approval tombstone's
  `decided_at`, columns a seal leaves out such as a session's `last_used_at`, a SQLite store
  sealed through Vault Transit, and the Postgres and SQL Server stores. (`BACKLOG #6717`)
