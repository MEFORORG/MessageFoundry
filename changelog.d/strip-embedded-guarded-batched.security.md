- **The embedded-document strip no longer writes a stripped body back over a purge or key
  rotation that landed after its read.** On SQLite, PostgreSQL and SQL Server, the strip read
  candidate bodies outside its write transaction and wrote each one back by message id alone, so
  a body purge or a re-seal committed in between could have been overwritten with the old body's
  content. Each write-back now applies only while the row is still unpruned, still holds the exact
  stored cell the strip read, and still has no pending or in-flight queue row, so a purge or a
  re-seal that lands in between wins; a row counts as stripped only when its own update changed
  it. On PostgreSQL and SQL Server the batch also locks the message's existing queue rows until it
  commits, so a replay that re-pends one either lands first and wins, or waits for the batch. The
  pass also reads candidates in keyset batches ordered by received time and message id instead of
  all at once, and runs the decrypt, strip and encrypt in a worker thread with no store connection
  held, rather than on the event loop. A key-service outage stops the pass rather than failing
  every row in turn. Each batch commits on its own, so a pass that fails part way logs, at WARNING,
  what earlier batches had already stripped.
