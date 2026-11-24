- **A SQLite store with no row-seal key now refuses a new NaN or infinity in the fields a session,
  user or approval seal covers, where a keyed store's sealer refuses one.** It wrote the value
  unchecked, and SQLite stores a NaN as NULL. The check runs where the SQLite store mints a session
  or account, writes an approval, or rewrites a session or account record, and raises `ValueError`.
  A non-finite value already in the stored row is carried forward as before. The revoke statements
  that set `revoked_at`, columns a seal leaves out such as a session's `last_used_at`, and the
  Postgres and SQL Server stores are not checked. (`BACKLOG #6717`)
