- **The DR staging truncate fail-safe no longer calls a file empty that it never reached.** On
  Windows, Win32 rewrites a path before it opens it: at least it drops a trailing dot or space
  from a name, and opens a reserved device name such as `NUL` as the device. A staging file named
  `a.tar.` was therefore checked and truncated as `a.tar`, or found missing and read as nothing to
  empty, while the listed file kept its plaintext, and the teardown called the directory clean. A
  directory named that way was walked, or removed, as another directory. The fail-safe now
  reports such a name for a file or a subdirectory and does not open it, and the teardown leaves
  a staging directory with such a name untouched and reports it. On both Windows and
  POSIX, a listed file that is gone from its name by the time it is checked or opened is now
  reported rather than read as nothing to empty, since a rename leaves its bytes under another
  name. Where the directory then still cannot be removed, the teardown names what it could not
  empty rather than saying every file was emptied. A sweep of a shared staging root still reads a
  candidate's lock and owner through such a name, and what else stays open is listed in
  [`docs/PHI.md`](../docs/PHI.md), section 2's staging row. (`BACKLOG #2420`)
