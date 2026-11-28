- **The POSIX key-file check judges more of the Linux mount table.** A key on a host whose `/`
  is a network or cluster file system, such as an NFS export or GFS2, is now refused; a sandbox
  root of `9p`, `virtiofs` or FUSE is still not judged by its type. Where `/proc/self/mountinfo`
  reads but lists no mount under a part of the key's path, as in a chroot whose root is not a
  mount, or lists one there only as an automount point not mounted yet, the path is now answered
  as not fully checked, as where that file cannot be read, rather than passed. The table is read
  both before and after the walk of the key's path, so a mount the walk triggers is judged, and
  the path is walked again where that mount changed it.
  [PHI.md](../docs/PHI.md) section 2 lists what the check still does not judge.
  (`BACKLOG #5636`)
