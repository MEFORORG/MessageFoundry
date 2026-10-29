- **A hung removal of a cancelled upload's file no longer queues every upload in the process.**
  An upload cancelled after its file landed removes that file while it holds the per-process
  upload quota lock, so no other upload counts it meanwhile. That wait had no bound, so one
  unlink the filesystem never answered held the lock, and every later upload in the process
  waited behind it. The wait is now bounded at 5 seconds. Past that the lock is released with the
  removal still running, and the file counts against its uploader's quota until the removal
  lands, which can refuse an upload at the quota edge but never admits one too many. A removal
  that then fails is logged at ERROR with the file's id. (vault `BACKLOG #3740`)
