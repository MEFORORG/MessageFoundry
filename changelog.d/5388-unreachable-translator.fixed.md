- **The uploads store classes a lost share as unreachable at every step of a read.** This covers
  a stale NFS handle and a dropped Windows share. It applies at a part's first check, its open,
  the checks after the open, and the read itself. The store raises its storage-unreachable error
  there, not a server error, and the routes answer it as any other storage outage. At least these
  sites that read a missing file as absence now tell an outage apart: the prune keeps the pair and
  logs a sidecar it could not remove, a cancelled save's removal is not called done, the class
  check does not call the body lost, and `rotate-key` skips it. On Windows, at four sites only a
  missing final name counts as gone, so a missing folder or drive above it is an outage: the check
  of a cancelled save's pair, the `rotate-key` replace, the `rotate-key` decision that a body is
  lost, and the Windows check after an open. On POSIX a missing folder above the name still reads as
  the name missing, so an uploads root removed during `rotate-key` still counts bodies as lost. Not
  covered, at least: elsewhere a Windows missing folder or drive still reads as absence, including
  the by-id reads' first check, the re-check after a failed open, the prune's and the delete's body
  unlink, and the body size check `rotate-key` asks of a sidecar's body. On POSIX a dropped mount
  whose mount point still answers reads every name under it as missing. The sidecar listing reads a
  root it cannot reach as empty, and the cleanup after a failed save and the temporary file's
  cleanup still swallow an outage.
  (`BACKLOG #5388`)
