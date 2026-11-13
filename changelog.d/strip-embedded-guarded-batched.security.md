- **The embedded-document strip no longer writes a stripped body back over a purge or key
  rotation that landed after its read.** On SQLite, PostgreSQL and SQL Server, the strip read
  candidate bodies outside its write transaction and wrote each one back by message id alone, so
  a body purge or a re-seal committed in between could have been overwritten with the old body's
  content. Each write-back is now a compare-and-swap on the stored cell the strip read, the
  unpruned flag and the message's in-flight state, and a row counts as stripped only when its own
  update changed it. The guard and its limit on PostgreSQL and SQL Server are stated once, in the
  `messagefoundry/store/document_strip.py` module docstring. The pass also reads candidates in
  keyset batches ordered by received time and message id instead of all at once, and runs the
  decrypt, strip and encrypt in a worker thread with no store connection held, rather than on the
  event loop. A failing row is skipped and a failing batch is rolled back and passed over; a
  key-service outage ends the strip phase early with a WARNING, and the rest of the retention pass
  still runs.
