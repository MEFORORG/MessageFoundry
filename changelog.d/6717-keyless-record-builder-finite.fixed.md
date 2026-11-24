- **A store with no row-seal key now refuses a NaN or an infinity in the fields a session, user or
  approval seal covers, as the local row sealer does with a key.** Those record builders, and the
  approval tombstone, wrote an empty seal without checking, so a keyless store passed a NaN to
  SQLite, which stores it as NULL. They now raise `ValueError` there. Columns a seal leaves out,
  such as a session's `last_used_at`, are not checked. (`BACKLOG #6717`)
