- **A config edit the file system denies (`EACCES`, `EPERM` or `EROFS`) is a refused edit at every
  step that leaves the file as it was.** `connections.toml`'s editor now also answers a denied read
  or a denied replace with `WiringError`, which the API maps to 409, and the alert, security and
  code-set editors refuse in their own types instead of raising `OSError`. A failed replace leaves
  the live file whole; an error after the replace still propagates, because the edit has landed.
  (`BACKLOG #3765`)
- **A file in a directory this account cannot search no longer reads as absent to an edit.** Such
  a settings or connections file is now a refused read. Before, the edit would have started from
  an empty document and written it over the file. (`BACKLOG #3765`)
- **The edit lock's handle is read-write off Windows.** An NFS client's exclusive `flock` fails
  `EBADF` on a read-only handle, which would have failed every edit on an NFS mount with working
  locks. This rests on `flock(2)` and a modelled test, not on a real NFS mount. A mount with no
  lock daemon still edits unlocked, with a warning. (`BACKLOG #3765`)
- **A Windows hold on a config file no longer reads only as a permission problem.** A replace, and
  a code-set rename or remove, rides out a momentary hold, such as a virus scanner reading the new
  file, and a refusal on Windows now says another program may have the file open.
  (`BACKLOG #3765`)
