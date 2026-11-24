- **A session row's seal cell now reads back as text.** `SessionRecord.from_mapping` passed the
  cell through, so a seal cell holding a BLOB, written outside the store, left a seal that was not
  a string; it now reads it with `str()`, as the role and approval readers do. (`BACKLOG #6718`)
