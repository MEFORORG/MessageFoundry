- **A session row's seal cell now reads back as a string.** `SessionRecord.from_mapping` passed the
  cell through, so a seal cell holding a BLOB, written outside the store, left a seal that was not
  a string; it now reads it with `str()`, as the role and approval readers do. A keyed store
  refuses such a row as a failed seal before any rewrite; under the Transit sealer that is now a
  failed seal where it was a `TypeError`. On a keyless SQLite store the session rewrite's compare
  binds the cell as read, so a row with a non-empty BLOB seal is rewritten, as on main, and a row
  with an empty BLOB seal is not rewritten, also as on main. (`BACKLOG #6718`)
