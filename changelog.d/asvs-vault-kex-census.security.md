- **The Vault TLS context now pins the approved key-exchange groups, as every other engine-built
  context does (ASVS 11.6.2).** `assert_hvac_tls_suites` calls `harden_kex_groups` on each context
  it builds. It pins nothing until Python 3.15 adds `SSLContext.set_groups`, the same as every other
  site. The data-layer census in [SECURITY.md](../docs/SECURITY.md) no longer says the Vault hops
  have no scheme gate; engine PR 1880 added one, and those rows are corrected in place.
