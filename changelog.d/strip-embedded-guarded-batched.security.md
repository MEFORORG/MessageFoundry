- **The embedded-document strip no longer writes a stripped body back over a purge or key
  rotation that landed after its read.** On SQLite, PostgreSQL and SQL Server, the strip read
  candidate bodies outside its write transaction and wrote each one back by message id alone, so
  a body purge or a re-seal committed in between could have been overwritten with the old body's
  content. Each write-back now applies only while the row is still unpruned, still holds the exact
  stored cell the strip read, and still has no pending or in-flight queue row, so a purge or a
  re-seal that lands in between wins; a row counts as stripped only when its own update changed
  it. On PostgreSQL and SQL Server the batch also locks its message rows and then their existing
  queue rows until it commits, in the order a body purge takes them, so a replay that re-pends one
  either lands first and wins, or waits for the batch; a replay, which takes them in the other
  order, can instead deadlock with the batch, and the server aborts one of the two. The
  pass also reads candidates in keyset batches ordered by received time and message id instead of
  all at once, and runs the decrypt, strip and encrypt in a worker thread with no store connection
  held, rather than on the event loop. A key-service outage (several rows in a row the service gives
  no verdict on) or a failed batch ends the strip phase with what it had committed, rather than
  failing every row in turn or the whole pass; the rest of the retention pass still runs, and its
  audit row records the early end. A strip cancelled part way, as at engine stop, logs at WARNING
  what its earlier batches had already stripped, which no audit row then records.
