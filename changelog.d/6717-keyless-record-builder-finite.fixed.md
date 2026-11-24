- **A store with no row-seal key now refuses a NaN or an infinity in a sealed record's fields, as
  a keyed store does.** The session, user, role, AD map and approval record builders, and the
  approval tombstone, wrote an empty seal without checking, so a keyless store passed a NaN to
  SQLite, which stores it as NULL. They now raise `ValueError` there. (`BACKLOG #6717`)
