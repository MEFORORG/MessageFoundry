- **The uploads orphan sweep checks its root before it trusts an absent answer.** At least a
  drive letter that is no longer mapped, and an uploads folder that is a link to a lost target,
  now end the retention pass's orphan sweep with a logged error rather than a silent clean pass.
  Once the root's own read has succeeded, a listing that then answers absence is a logged error
  too. Right before it removes a temp leftover, or a body whose sidecar reads as absent, the sweep
  checks that the root still answers with the identity it read before its listing, and removes it
  only when the root does, with one exception: when both reads give no identity (an inode and a
  device of 0), the check cannot tell a swap from the same folder and the removal proceeds. That
  is a residual, one of at least those below. When only one of the two reads gives no identity,
  the sweep stops with a logged warning. A share
  remounted under the root with another identity stops the sweep with a logged error only when the
  remount lands after that first read and before one of these checks, while a temp leftover or a
  body whose sidecar reads as absent, past the age floor, is still to come, or before the root
  check that follows a candidate's own read, sidecar check or removal failing. At least a remount
  before the pass, one during the pass with no such entry left, and one between a check and its
  removal are not caught. Some lost roots still read as a clean pass, at least a root deleted
  after its first save, one under a POSIX mount point whose share dropped, and one that is itself
  a mount point whose share dropped. The
  root check's other limits, including a file system that mints identities on the client and so
  can stop every pass, leaving orphans past retention, are stated in the docstrings of
  `UploadStore._sweep_orphans_sync` and `_root_fault` in `messagefoundry/uploads.py` (BACKLOG
  #6575).
