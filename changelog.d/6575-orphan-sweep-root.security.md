- **The uploads orphan sweep checks its root before it trusts an absent answer.** At least a
  drive letter that is no longer mapped, and an uploads folder that is a link to a lost target,
  now end the retention pass's orphan sweep with a logged error rather than a silent clean pass.
  Once the root's own read has succeeded, a listing that then answers absence is a logged error
  too. Right before it removes a temp leftover, or a body whose sidecar reads as absent, the sweep
  checks that the root still answers as the folder it read before its listing, so a share
  remounted under the root as another folder stops the sweep with a logged error. Some lost roots
  still read as a clean pass, at least a root deleted after its first save, one under a POSIX
  mount point whose share dropped, and one that is itself a mount point whose share dropped. The
  root check's other limits, including a file system that mints identities on the client and so
  can stop every pass, leaving orphans past retention, are stated in the docstrings of
  `UploadStore._sweep_orphans_sync` and `_root_fault` in `messagefoundry/uploads.py` (BACKLOG
  #6575).
