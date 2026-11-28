- **The uploads store classes a lost share as unreachable at every step of a read.** This covers
  a stale NFS handle and a dropped Windows share. It applies at a part's first check, its open,
  the checks after the open, and the read itself. The store raises its storage-unreachable error
  there, not a server error, and the routes answer it as any other storage outage. At least these
  sites that read a missing file as absence now tell an outage apart: the prune keeps the pair and
  logs a sidecar it could not remove, a cancelled save's removal is not called done, the class
  check does not call the body lost, and `rotate-key` skips it. Where a part's removal or a
  `rotate-key` body hangs on the answer, and at the check after a Windows open, only a missing
  final name counts as gone, so a Windows missing folder or drive above it is an outage too. Not
  covered: the sidecar listing still reads a root it cannot reach as empty, the cleanup after a
  failed save and the temporary file's cleanup still swallow an outage, and the by-id reads still
  answer a Windows missing folder or drive at their first check as a missing upload.
  (`BACKLOG #5388`)
