- **A config edit the file system denies (`EACCES`, `EPERM` or `EROFS`) is a refused edit at more
  steps.** At least the lock, the read, the candidate, its companion copy and the replace now raise
  the editor's own refusal, and each of them leaves the file as it was. For `connections.toml` that
  is `WiringError`, which the API maps to 409; the alert, security and code-set editors use their
  own types instead of raising `OSError`. An error after the replace still propagates, because the
  edit has landed, and what a `validate` callback raises is its own. (`BACKLOG #3765`)
- **A config path this account cannot stat no longer reads as absent.** Such a path, a link into a
  directory it cannot search, is now a refused read. Before, an edit would have started from an
  empty document and replaced the link with it, and a listing would have answered empty.
  (`BACKLOG #3765`)
- **The edit lock's handle is read-write off Windows.** An NFS client's exclusive `flock` fails
  `EBADF` on a read-only handle, which would have failed every edit on an NFS mount with working
  locks. This rests on `flock(2)` and a modelled test, not on a real NFS mount. A mount with no
  lock daemon still edits unlocked, with a warning. (`BACKLOG #3765`)
- **A Windows hold on a config file no longer reads only as a permission problem.** A replace, and
  a code-set rename or remove, rides out a momentary hold, such as a virus scanner reading the new
  file, and a refusal on Windows now says another program may have the file open.
  (`BACKLOG #3765`)
