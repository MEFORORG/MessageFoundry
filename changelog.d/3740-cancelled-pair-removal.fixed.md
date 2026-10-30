- **A hung removal of a cancelled upload's file no longer queues every upload in the process.**
  An upload cancelled after its file landed starts removing that file, and the next upload in
  that process waits for the removal before it counts the uploader's files, so it does not count
  a file about to go. That wait used to be the cancelled upload's own, under the upload quota
  lock, with no bound, so one unlink the filesystem never answered held every later upload. The
  wait is now bounded at 5 seconds, and the cancelled upload no longer spins on it when its
  request deadline cancels it again on every pass. Past the bound the removal goes on, an ERROR
  names the file's id as a stored file with no `upload.create` row, and the file counts against
  its uploader's quota until the removal lands, which can refuse an upload at the quota edge but
  never admits one too many. A removal that lands later logs a WARNING that withdraws the ERROR.
  These removals run on their own pool of two threads, so unlinks that hang cannot take the
  threads the rest of the engine shares. The removal that follows a failed `upload.create` row is
  not changed by this. (vault `BACKLOG #3740`)
