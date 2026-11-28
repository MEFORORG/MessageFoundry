- **The POSIX key-file check judges more of the Linux mount table.** A key on a host whose `/`
  is a network or cluster file system, such as an NFS export, GFS2 or a network FUSE mount, is
  now refused; a sandbox root of `9p`, `virtiofs` or `fuse-overlayfs` is still not judged by its
  type. Where `/proc/self/mountinfo` reads but lists no mount under a part of the key's path, as
  in a chroot whose root is not a mount, or the path ends on an automount point not mounted yet,
  the path is now answered as not fully checked, as where that file cannot be read, rather than
  passed. The table is read both before and after the walk of the key's path, so a mount the walk
  triggers is judged; where the two reads place the path on different mounts it is walked again,
  both walks' placements are judged, and the table is read a third time. Where only one of the
  first two reads succeeds, the two walks visit different folders, or the third read fails or
  places the path on a different mount again, it is answered as not fully checked.
  [PHI.md](../docs/PHI.md) section 2 lists at least some of what the check still does not judge.
  (`BACKLOG #5636`)
