- **A config edit the file system refuses is a refused edit at every step that leaves the file as
  it was.** `connections.toml`'s editor now also answers a denied read or a denied replace with
  `WiringError`, which the API maps to 409, and the alert, security and code-set editors refuse in
  their own types instead of raising `OSError`. A failed replace leaves the live file whole; an
  error after the replace still propagates, because the edit has landed. (`BACKLOG #3765`)
- **The edit lock works on NFS.** Its handle is now read-write, because an NFS client's exclusive
  `flock` fails `EBADF` on a read-only handle, which would have failed every edit there.
  (`BACKLOG #3765`)
- **A Windows hold on a config file no longer reads as a permission problem.** The replace rides
  out a momentary hold, such as a virus scanner reading the new file, and a refusal on Windows now
  says another program may have the file open. (`BACKLOG #3765`)
