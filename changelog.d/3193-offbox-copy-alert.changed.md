- **An approval audit row that is in the store but missing from the off-box copy pages its own
  alert.** When the gate reads back that a write's COMMIT landed though the write reported an
  error, a request that reads back as held or an outcome whose row had already moved, it now pages
  `audit_offbox_copy_missing` rather than `audit_write_failed`, which said the row was not written.
  Rules can target the new type. `audit_write_failed`'s reason now says the row was not written
  or its write's outcome is unknown, since a COMMIT can land despite the error. (vault
  `BACKLOG #3193`)
