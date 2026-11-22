- **A REST destination behind an ECH sidecar no longer loads `[tls].crl_file` for its delivery
  hop.** (`BACKLOG #2977`) The sidecar makes the TLS connection to the partner, so the opener the
  engine built for the direct hop was discarded, but it loaded the CRL first, and a CRL the check
  rejects failed a connection that could never consult it. That opener is now built with no CRL.
  Its CA half is built as before, so a `tls_ca_file` that cannot be read still fails the
  connection. The hop's revocation refusal is unchanged.
