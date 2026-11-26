- **New opt-in `[auth].ad_tls_crl_check_chain` and `[auth].oidc_tls_crl_check_chain` check a
  server's whole chain against the hop's own CRL file** on the LDAPS bind and on both OIDC legs, so
  a revoked intermediate CA refuses the domain controller or the IdP. Each needs the hop's CRL file
  and its own CA file, and is refused at load without either. The CA file must hold self-signed
  roots and any intermediates that chain to them, and the CRL file a CRL from each. Off by default,
  so each hop keeps the leaf check. The log forwarder and the Postgres store still check the leaf
  only. See [CONFIGURATION.md](../docs/CONFIGURATION.md).
