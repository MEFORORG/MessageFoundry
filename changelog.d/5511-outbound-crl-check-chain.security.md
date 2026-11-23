- **New opt-in `[tls].crl_check_chain` checks a server's whole chain against `[tls].crl_file`**
  on the outbound hops that block reaches, so a revoked intermediate CA refuses the servers under
  it. It needs `crl_file` and a hop that trusts operator CAs alone, such as one pinned by a connection's
  `tls_ca_file` or a pinned `[tls].internal_ca_file`, whose CA file holds self-signed roots. A hop on the OS trust
  store refuses at build. Off by default, so each hop keeps the leaf check. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md#tls--outbound-client-trust-anchors).
