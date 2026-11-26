- **On Linux the key-file access check now refuses a key file whose path, as its link walk
  follows it, is on at least an NFS, CIFS or SMB, 9p, virtiofs or FUSE mount**, read from
  `/proc/self/mountinfo`, and refuses where that file cannot be read (vault BACKLOG #5657). On
  those file systems something other than the owner and mode bits the check reads decides who may
  read or replace the file, so a clean `0600` key under clean folders on one would have passed.
  Under `[security].enforcement = "warn"` the key-file start gates warn rather than refuse, as for
  the check's other refusals. The same walk judges at least the secrets directory, which is
  refused on such a mount under either setting, and the key custody directory. Mount types are
  judged only where `/proc/self/mountinfo` can be read, and not elsewhere, for example on macOS and
  the BSDs, whose mount tables the check does not read. At least a type the list does not name, the
  mount at `/`, and a network file system beneath an overlay mount are not judged; [PHI.md](../docs/PHI.md), *Key files*, says what else the check leaves to the
  operator. The store key gate also judges a link to a missing file, and a key file whose status
  cannot be read, rather than leaving them to the key provider.
