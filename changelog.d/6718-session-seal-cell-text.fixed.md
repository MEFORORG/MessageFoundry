- **A session row's seal cell now reads back as a string.** `SessionRecord.from_mapping` passed the
  cell through, so a seal cell holding a BLOB, written outside the store, left a seal that was not
  a string; it now reads it with `str()`, as the role and approval readers do. A keyed store
  refuses such a row as a failed seal before any rewrite; under the Transit sealer that is now a
  failed seal where it was a `TypeError`. On a keyless SQLite store the session rewrite's compare
  still binds the cell as read, so the row is rewritten as before. (`BACKLOG #6718`)
