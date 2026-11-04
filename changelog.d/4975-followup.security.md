- **A revoke that declines to keep the caller's session now ends it.** Where signing out
  everywhere else, or the every-account revoke, does not re-stamp the caller's session, at least
  because it is behind on its account's epoch or the global one, because its account's record
  fails its seal, or, on signing out everywhere else, because the store's global epoch row is
  missing, which that revoke now logs at WARNING and goes on past, the revoke now ends that session in the same transaction and counts it, instead of leaving it
  unrevoked. Same on SQLite, PostgreSQL and SQL Server. The per-account revoke also reads the
  global epoch in its own transaction, so a session behind on that epoch alone is no longer
  stamped and called kept. So `DELETE /sessions` replying "this session was ended too" is true,
  the session cap no longer counts such a row, and presenting it again is refused as an ended
  session rather than reported as a seal failure. The reply to `DELETE /me/sessions` still counts
  only the other sessions. See [SECURITY.md](../docs/SECURITY.md), *Limits of the session sweep*.
  (follow-up to `BACKLOG #4975`)
