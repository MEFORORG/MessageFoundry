- **The LDAPS AD bind now takes the revocation-hop guard, and a CRL setting of its own,
  `[auth].ad_tls_crl_file`.** Every AD bind sends a password over a context that verifies the
  domain controller, but stdlib `ssl` checks no CRL or OCSP, so a revoked DC certificate was
  accepted there with no refusal and no record. On an instance at `[security].enforcement =
  enforce`, an off-box `ad_server` is now refused when `serve` or `provision-admin` builds the
  auth service, and `messagefoundry check-privileges` reports its AD probe as not run, unless
  `ad_tls_crl_file`
  names a CRL that loads onto the bind's context. The file is loaded again on every bind; one that
  is missing, unloadable or past `nextUpdate` refuses the start or fails that bind. No attestation
  exists for this hop. A non-enforcing instance warns. The CRL expiry monitor watches the file as
  `auth.ad_tls_crl_file`. See
  [DEPLOYMENT.md](../docs/DEPLOYMENT.md#revocation-guard-behavior). (`BACKLOG #2193`)
