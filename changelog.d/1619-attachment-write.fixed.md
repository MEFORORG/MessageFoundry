- **A detached document's sender-controlled OBX-5.2 label is bounded to what every store backend
  holds.** When an inbound sets `stream_threshold_bytes`, a large embedded document is written to
  the attachment store before the ingress commit. A label wider than 256 UTF-16 code units would
  have failed that write on SQL Server on every resend, and one holding a NUL would have failed it
  on PostgreSQL; either is now stored as `application/octet-stream` on every backend, as a
  mislabelled one already was. A fault from the
  attachment write still propagates with no message row, as before; only a refusal the detach already answered, such as a backend without streaming support,
  is still recorded as an `ERROR`. (`BACKLOG #1619`)
