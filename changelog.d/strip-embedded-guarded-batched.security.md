- **The embedded-document strip no longer writes a stripped body back over a purge or key
  rotation that landed after its read.** On SQLite, PostgreSQL and SQL Server, the strip read
  candidate bodies outside its write transaction and wrote each one back by message id alone, so
  a body purge or a re-seal committed in between could have been overwritten with the old body's
  content. Each write-back now applies only while the row is still unpruned, still holds the exact
  stored cell the strip read, and still has no pending or in-flight queue row, so a purge or a
  re-seal that lands in between wins; a row counts as stripped only when its own update changed
  it. On PostgreSQL and SQL Server the batch also locks its message rows and then their existing
  queue rows until it commits, skipping without waiting any row another writer holds, so a replay
  or body purge holding them is never waited on or deadlocked with; a message it could not lock
  whole is stripped on a later pass. The pass also reads candidates in keyset batches ordered by
  received time and message id instead of all at once, and runs the decrypt, strip and encrypt in
  a worker thread with no store connection held, rather than on the event loop. A row that fails
  on its own is logged and skipped, and a batch that fails is logged and passed over, so no row
  can stall the strip. A key-service outage (several rows with no verdict from the service and no
  verdict between them) or a failed batch read ends the strip phase with what it had committed and
  a WARNING; the rest of the retention pass still runs. A strip cancelled part way, as at engine
  stop, logs at WARNING what its earlier batches had already stripped, which no audit row then
  records.
