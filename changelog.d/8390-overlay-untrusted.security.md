- **The Linux trust-anchor path check no longer trusts an overlay mount.** `overlay` was on the
  list of file systems whose owners and modes the check takes as real, but the check reads only a
  mount's type, never an overlay's lower layers, and one on NFS or CIFS keeps that server's owners
  and modes. So a trust anchor, the SQL Server `[store].ssl_root_cert` pin among them, on an
  overlay over a network share would have passed the path check and been accepted at `enforce` on
  first deployment. An overlay mount now answers *could not settle*, as NFS, CIFS, FUSE and 9p do,
  which `enforce` refuses, unless the anchor's consumer loads the bytes the check read and its
  pin setting matches them; an anchor read again by path has no such escape. An enforcing PHI
  start where `/` is overlay, as in nearly every container, would therefore refuse; read the
  overlay note in [docker/README.md](../docker/README.md#residuals--gotchas). (vault `BACKLOG #8390` item 31)
