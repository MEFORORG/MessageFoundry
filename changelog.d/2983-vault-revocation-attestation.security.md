- **Each Vault hop now refuses an off-box Vault whose certificate revocation nothing checks,
  unless that hop is attested.** The store key provider, the Transit cipher and the connector
  secret provider each verify the Vault server's certificate and check no CRL and no OCSP. The
  client build now refuses an `https://` Vault that is not a loopback host reached with no proxy.
  The way across is a new settings pair, one per Vault: `[store].vault_revocation_attested` or
  `[secrets].vault_revocation_attested`, each with a mandatory `vault_revocation_attested_reason`.
  The attestation adds no check on the wire, and no CRL lever is built for these hops. The
  process-wide `MEFOR_TLS_REVOCATION_ATTESTED` does not cross. `security_loosenings()` names each
  attestation with its reason. Two gaps remain in this build: every client build counts as
  enforcing, also under `enforcement = warn`, and `check-privileges` refuses an off-box Vault even
  with the flag set. See [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
  (`vault BACKLOG #2983`)
