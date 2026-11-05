- **A REST connection that sends through an `http://` ECH sidecar is now named, at build and
  in review.** The sidecar must be loopback, so no cleartext-hop gate refused the hop to it, and
  nothing said it carries the request body and every request header, any credential included,
  unencrypted on the host. The engine now logs a WARNING for each such connection at every
  construction, naming the connection and never a header value. `messagefoundry check` prints an
  advisory `ech-sidecar-cleartext` line, and `security_loosenings()`, and so
  `GET /security/posture`, lists an `ech_sidecar` entry. An `https://` sidecar listener encrypts
  the hop and is not listed. A sidecar off this host was already refused at build, whatever the
  connection declares. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md#ech_sidecar-at-an-http-url--the-hop-to-the-ech-sidecar-is-cleartext).
