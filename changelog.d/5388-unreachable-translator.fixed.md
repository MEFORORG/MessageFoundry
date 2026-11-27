- **An uploads share that goes away is classed as unreachable at every step of a read, and is
  never read as a missing file.** A stale NFS handle or a dropped Windows share at an upload
  part's first check, at the Windows check after its open, or during its read now raises the
  store's storage-unreachable error, which the routes answer as they answer any other outage,
  rather than a server error. Everywhere the uploads store reads a missing file as absence, an
  unreachable share is told apart: the prune keeps the pair, a cancelled save's discard logs it
  as not removed, the class check does not call the body lost, and `rotate-key` skips it rather
  than count it lost. (`BACKLOG #5388`)
