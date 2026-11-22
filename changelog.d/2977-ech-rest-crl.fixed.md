- **A REST destination behind an ECH sidecar no longer loads `[tls].crl_file` for its delivery
  hop, and refuses the TLS settings no hop of it applies.** (`BACKLOG #2977`) The sidecar makes
  the TLS connection to the partner, so the opener the engine built for the direct hop was
  discarded, but it loaded the CRL first, and a CRL the check rejects failed a connection that could
  never consult it. That opener is now built with no CRL. `tls_allow_expired`, `tls_ca_file` and
  `tls_ca_pin` beside `ech_egress` are now refused at build, as `verify_tls = false` already was:
  the sidecar verifies the partner, and the engine verifies an `https://` sidecar against the
  system trust store. The refusal names the settings, not their values. The CA check at start and
  reload now treats a CA behind either sidecar scheme as unread. The hop's revocation refusal is
  unchanged.
