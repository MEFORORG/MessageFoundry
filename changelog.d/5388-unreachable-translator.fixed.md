- **The uploads store classes a share that goes away as unreachable at every step of a read.** A
  stale NFS handle or a dropped Windows share at an upload part's first check, at its open, at the
  Windows check after the open, or during its read now raises the store's storage-unreachable
  error, which the routes answer as they answer any other storage outage, rather than a server
  error. Where the store reads a missing file as absence, an unreachable share is told apart: the
  prune keeps the pair and logs a sidecar it could not remove, a cancelled save's discard logs it
  as not removed, the class check does not call the body lost, and `rotate-key` skips it rather
  than count it lost. (`BACKLOG #5388`)
