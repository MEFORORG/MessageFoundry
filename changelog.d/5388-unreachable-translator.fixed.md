- **The uploads store classes a lost share as unreachable at every step of a read.** This covers
  a stale NFS handle and a dropped Windows share. It applies at a part's first check, its open,
  the checks after the open, and the read itself. The store raises its storage-unreachable error
  there, not a server error, and the routes answer it as any other storage outage. Where the
  store reads a missing file as absence, it now tells an outage apart. The prune keeps the pair
  and logs a sidecar it could not remove. A cancelled save's removal is not called done. The
  class check does not call the body lost, and `rotate-key` skips it. (`BACKLOG #5388`)
