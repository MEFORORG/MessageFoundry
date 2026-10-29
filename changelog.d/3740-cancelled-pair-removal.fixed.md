- **A hung removal of a cancelled upload's file no longer queues every upload in the process.**
  An upload cancelled after its file landed removes that file while it holds the per-process
  upload quota lock, so no other upload in that process counts it meanwhile. That wait had no
  bound, so one unlink the filesystem never answered held the lock, and every later upload in
  the process waited behind it. The wait is now bounded at 5 seconds. Past that the lock is
  released with the removal still running, an ERROR names the file's id as a stored file with
  no `upload.create` row, and the file counts against its uploader's quota until the removal
  lands, which can refuse an upload at the quota edge but never admits one too many. A removal
  that lands later logs a WARNING that withdraws the ERROR. The removal that follows a failed
  `upload.create` row is not changed by this. (vault `BACKLOG #3740`)
