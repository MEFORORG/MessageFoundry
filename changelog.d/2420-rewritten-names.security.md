- **The DR staging truncate fail-safe no longer calls a file empty that it never reached.** On
  Windows, Win32 rewrites a path before it opens it: it drops a trailing dot or space from a name,
  and opens a reserved device name such as `NUL` as the device. A staging file named `a.tar.` was
  therefore checked and truncated as `a.tar`, or found missing and read as nothing to empty, while
  the listed file kept its plaintext, and the teardown called the directory clean. A directory
  named that way was walked as another directory. Such names, for files, subdirectories and the
  staging directory itself, are now reported and never opened, and the final path of every file
  opened and directory held must equal the name walked. On both Windows and POSIX, a listed file
  that is gone from its name by the time it is checked or opened is now reported rather than read
  as nothing to empty, since a rename leaves its bytes under another name. Where the directory then
  still cannot be removed, the teardown names what it could not empty rather than saying every
  file was emptied. (`BACKLOG #2420`)
