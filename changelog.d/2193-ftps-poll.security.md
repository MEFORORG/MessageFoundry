- **The inbound FTPS poll now takes the revocation-hop guard the FTPS upload takes.** An
  `Ftp(tls=True)` poller verifies its partner's server certificate and sends the FTP login, but
  stdlib `ssl` checks no CRL or OCSP, so a revoked certificate was accepted there with no refusal
  and no record. On an instance at `[security].enforcement = enforce`, an off-box poll is now
  refused at construction (`messagefoundry check`, dry-run, reload, and the start, where it is
  recorded failed and the rest of the graph starts) unless a `[tls].crl_file` reaches its context
  or the inbound declares `tls_revocation_attested` with a reason. A CRL that is set but cannot be
  loaded still refuses the poll. A non-enforcing instance warns. On either FTPS direction, a hop
  that sets `tls_allow_expired` is no longer admitted by a CRL, since the relaxation also skips
  the CRL's validity window: only its attestation crosses. An FTPS upload with that setting and
  a CRL was admitted before. See
  [DEPLOYMENT.md](../docs/DEPLOYMENT.md#revocation-guard-behavior). (`BACKLOG #2193`)
