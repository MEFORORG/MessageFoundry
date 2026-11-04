- **An attachment-write fault in a streaming detach that the engine classes as the document's own
  is a permanent refusal; every other write fault still propagates.** When an inbound sets
  `stream_threshold_bytes`, a large embedded document is written to the attachment store before
  the ingress commit. A write fault there used to escape with no message row. A
  `UnicodeEncodeError` or SQLite's `sqlite3.DataError` from that write is now refused as permanent,
  the way an escaped document is, where the `ERROR` row itself can be written. A body whose text
  cannot be encoded at all, such as a lone surrogate from a UTF-7 inbound, also fails that `ERROR`
  write, so it still escapes with no row and a poll source reads it again. Every other write fault
  still propagates, so the input is kept for a resend: at least a lost connection, a lock or
  deadlock, a key conflict, a cipher or Vault Transit fault, and a server driver's SQLSTATE class
  22, which more likely means a column whose schema drifted than a bad document. A
  sender-controlled OBX-5.2 label wider than SQL Server's 256 UTF-16 code units, holding a NUL, or
  not encodable as UTF-8, is now stored as `application/octet-stream`, as a mislabelled one
  already was. (`BACKLOG #1619`)
