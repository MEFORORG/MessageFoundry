- **A streaming inbound no longer loops on a document the attachment store refuses every time.**
  When an inbound sets `stream_threshold_bytes`, a large embedded document is written to the
  attachment store before the ingress commit. A write fault there used to escape with no message
  row, so a retrying source met the same fault on every resend: the file source left the file for
  its next scan, and MLLP answered `AE` and closed each time. A fault in the document itself, at
  least one that cannot be encoded or SQLite's "string or blob too big", is now recorded as one
  `ERROR` row and refused as permanent, the way an escaped document is: `AR` on MLLP, `422` on
  HTTP, and the file or database poll source finishes the file or row. Every other write fault
  still propagates, so the input is kept for a resend: at least a lost connection, a lock or
  deadlock, a key conflict, a cipher or Vault Transit fault, and a server driver's SQLSTATE class
  22, which with the label bounded more likely means a column whose schema drifted than a bad
  document. A sender-controlled OBX-5.2 label that some backend's column cannot hold, one over SQL
  Server's 256 UTF-16 code units, one holding a NUL, or one that cannot be encoded as UTF-8, is now
  stored as `application/octet-stream`, as a mislabelled one already was. (`BACKLOG #1619`)
