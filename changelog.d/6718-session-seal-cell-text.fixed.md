- **A session row's seal cell now reads back as a string.** `SessionRecord.from_mapping` passed the
  cell through, so a seal cell holding a BLOB, written outside the store, left a seal that was not
  a string; it now reads it with `str()`, as the role and approval readers do, so a BLOB reads as
  its Python representation and fails a seal check as malformed, as before. The session rewrite's
  compare still binds the cell as read, so such a row is written through as before.
  (`BACKLOG #6718`)
