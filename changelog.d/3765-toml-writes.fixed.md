- **A config edit the file system denies (`EACCES`, `EPERM` or `EROFS`) is a refused edit at more
  steps.** At least the lock, the read, the candidate, its companion copy and the replace now raise
  the editor's own refusal, and each of them leaves the file as it was. For `connections.toml` that
  is `WiringError`, which the API maps to 409; the alert, security and code-set editors use their
  own types instead of raising `OSError`. An error after the replace still propagates, because the
  edit has landed, and what a `validate` callback raises is its own. (`BACKLOG #3765`)
- **A config file that may be there no longer reads as absent.** The four editors and their
  listings now share one stat gate, and so does the copy of a code set's policy sidecar into an
  edit's candidate. A stat that fails for any reason but "nothing is there", a link on the path that
  cannot be followed, such as one to an unmounted share, and a share Windows says it cannot reach
  are each a refused read. Before, an edit would have started from an empty document and replaced
  the link with it, a code-set create could have passed its collision check, an edit could have
  overwritten a table it could not stat, a listing would have answered empty, and a candidate could
  have validated without its policy. A path with nothing at it, or a name no file can have, still
  reads as absent. So does a link to a directory or to anything else that is not a file, and a share
  that Windows reports as a plain missing path. `codeset show` still reads a policy sidecar it cannot
  stat as no policy, and a config load does so for a dangling one. (`BACKLOG #3765`)
- **The edit lock's handle is read-write off Windows.** An NFS client's exclusive `flock` fails
  `EBADF` on a read-only handle, which would have failed every edit on an NFS mount with working
  locks. This rests on `flock(2)` and a modelled test, not on a real NFS mount. A mount with no
  lock daemon still edits unlocked, with a warning. The cost is that a lock file this account cannot
  write now refuses the edit. (`BACKLOG #3765`)
- **A Windows hold on a config file no longer reads only as a permission problem.** A replace, and
  a code-set rename or remove, rides out a momentary hold, such as a virus scanner reading the new
  file, and a refusal on Windows now says another program may have the file open.
  (`BACKLOG #3765`)
