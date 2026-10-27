- **The revocation refusal's unused egress-terminator input is gone.** `revocation_hop_disposition`
  and `RevocationHopGuard` no longer take `proxy_proven`. No call site ever set it, so no hop's
  decision changes. Two refusal texts stop suggesting a proxy: the PostgreSQL store hop's, which now
  names `[store].ssl_crl_file` or a loopback database, and the one for a `[tls].crl_file` that a
  requests-based Vault client cannot carry. (`BACKLOG #3514`)
