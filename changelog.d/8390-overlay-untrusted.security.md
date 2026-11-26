- **The Linux trust-anchor path check no longer trusts an overlay mount.** `overlay` was on the
  list of file systems whose owners and modes the check takes as real, but the mount table does not
  name an overlay's lower layers, and one on NFS or CIFS keeps that server's owners and modes. So a
  trust anchor, the SQL Server `[store].ssl_root_cert` pin among them, on an overlay over a network
  share would have passed the path check and been accepted at `enforce` on first deployment. An
  overlay mount now answers *could not settle*, as NFS, CIFS, FUSE and 9p do, which `enforce`
  refuses, unless the anchor offers a pin setting and a matching pin is set. **A container whose
  root file system is overlay now gets that answer for every trust anchor**; see
  [docker/README.md](../docker/README.md). (`BACKLOG #8390`)
