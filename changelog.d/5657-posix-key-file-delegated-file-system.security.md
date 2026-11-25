- **On Linux the key-file access check now refuses a key file whose path, as its link walk
  follows it, is on at least an NFS, CIFS or SMB, 9p, FUSE or automount (`autofs`) mount**, read
  from the process's mount table (vault BACKLOG #5657). On those file systems something other than
  the owner and mode bits the check reads decides who may read or replace the file, so a clean
  `0600` key under clean folders on one would have passed. Under `[security].enforcement = "warn"`
  the key-file start gates warn rather than refuse, as for the check's other refusals. The same
  walk judges at least the secrets directory, which is refused on such a mount under either
  setting, and the key custody directory. The list of types is open, so at least a type it does not name, and
  every type where no mount table can be read, such as on macOS, is not judged, and neither is a
  network file system beneath an overlay mount; [PHI.md](../docs/PHI.md), *Key files*, says what
  else the check leaves to the operator. The store key gate also judges a link to a missing file,
  and a key file whose status cannot be read, rather than leaving them to the key provider.
