- **The Linux trust-anchor path check no longer trusts an overlay mount.** `overlay` was on the
  list of file systems whose owners and modes the check takes as real, but the check reads only a
  mount's type, never an overlay's lower layers, and one on NFS or CIFS keeps that server's owners
  and modes. So a trust anchor, the SQL Server `[store].ssl_root_cert` pin among them, on an
  overlay over a network share would have passed the path check and been accepted at `enforce` on
  first deployment. An overlay mount now answers *could not settle*, as NFS, CIFS, FUSE and 9p do,
  which `enforce` refuses. A matching pin loads it only where the anchor's consumer loads the bytes
  the check read; for an anchor read again by path, such as an outbound connection's `tls_ca_file`
  or `[logging].forward_tls_ca_file`, a pin is no escape. **Where `/` is an overlay mount, as in
  nearly every container, an enforcing PHI start would refuse on first deployment until a
  follow-up lands; `warn` starts.** [docker/README.md](../docker/README.md#residuals--gotchas)
  says why. (vault `BACKLOG #8390` item 31)
