- **On a store with no row-seal key, the session, user and approval record builders and the
  approval tombstone now raise `ValueError` for a NaN or an infinity in the fields they seal under
  a key, as the local row sealer does.** They wrote an empty seal without checking, so a NaN
  reached SQLite, which stores it as NULL. Writes that do not go through these builders, such as
  the revoke statements that set `revoked_at`, and columns a seal leaves out, such as a session's
  `last_used_at`, are not checked. (`BACKLOG #6717`)
