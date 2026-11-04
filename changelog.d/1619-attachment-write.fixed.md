- **An attachment-write fault in a streaming detach is either a permanent refusal or propagates,
  never an escape with no row.** When an inbound sets `stream_threshold_bytes`, a large embedded
  document is written to the attachment store before the ingress commit. A write fault there used
  to escape with no message row. A fault the engine classes as the document's own, a
  `UnicodeEncodeError` or SQLite's `sqlite3.DataError`, is now recorded as one `ERROR` row and
  refused as permanent, the way an escaped document is: `AR` on MLLP, `422` on HTTP, and the file
  or database poll source finishes the file or row. Every other write fault still propagates, so
  the input is kept for a resend: at least a lost connection, a lock or deadlock, a key conflict, a
  cipher or Vault Transit fault, and a server driver's SQLSTATE class 22, which more likely means a
  column whose schema drifted than a bad document. A sender-controlled OBX-5.2 label wider than SQL
  Server's 256 UTF-16 code units, or holding a NUL, is now stored as `application/octet-stream`, as
  a mislabelled one already was. (`BACKLOG #1619`)
