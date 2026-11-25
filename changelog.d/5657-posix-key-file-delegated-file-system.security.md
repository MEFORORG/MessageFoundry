- **On Linux the key-file access check now refuses a key file whose path, as its link walk
  follows it, is on at least an NFS, CIFS or SMB, 9p, Ceph, AFS, Lustre or FUSE mount**, read from
  the process's mount table (vault BACKLOG #5657). On those file systems a server or a user-space
  program, not the owner and mode bits the check reads, decides who may read or replace the file,
  so a clean `0600` key under clean folders on one would have passed. Under
  `[security].enforcement = "warn"` the start gates warn rather than refuse, as for the check's
  other refusals. Any other type, and every type where no mount table can be read, such as on
  macOS, is not judged, and neither is a network file system beneath an overlay mount;
  [PHI.md](../docs/PHI.md), *Key files*, says what else the check leaves to the operator.
