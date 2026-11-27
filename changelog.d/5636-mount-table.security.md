- **The POSIX key-file check judges more of the Linux mount table.** A key on a host whose `/`
  is a network file system, such as an NFS or CIFS export, is now refused; a sandbox root of
  another type, such as `9p` or `virtiofs`, is still not judged by its type. Where
  `/proc/self/mountinfo` reads but lists no mount under a part of the key's path, as in a chroot
  whose root is not a mount, or lists one there only as an automount point not mounted yet, the
  path is now answered as not fully checked, as where that file cannot be read, rather than
  passed. The table is read again after the walk, so a mount the walk itself triggers is judged.
  [PHI.md](../docs/PHI.md) section 2 lists what the check still does not judge.
  (`BACKLOG #5636`)
