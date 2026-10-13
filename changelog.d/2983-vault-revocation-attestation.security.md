- **Each Vault hop now refuses an off-box Vault whose certificate revocation nothing checks,
  unless that hop is attested.** The store key provider, the Transit cipher and the connector
  secret provider each verify the Vault server's certificate and check no CRL and no OCSP. The
  client build now refuses an `https://` Vault that is not a loopback host reached with no proxy.
  The way across is a new settings pair, one per Vault: `[store].vault_revocation_attested` or
  `[secrets].vault_revocation_attested`, each with a mandatory `vault_revocation_attested_reason`.
  The attestation adds no check on the wire, and no CRL lever is built for these hops. The
  process-wide `MEFOR_TLS_REVOCATION_ATTESTED` does not cross an enforcing hop.
  `security_loosenings()` names each attestation with its reason, `messagefoundry check` lists
  it, and an attested crossing logs a WARNING once per process for each hop.
  On an instance at `[security].enforcement = warn`, a caller that hands its posture to the hop
  crosses with a WARNING. A command that holds no posture is judged as enforcing, so it still
  refuses. `check-privileges` probes each Vault under that hop's own attestation.
  One gap is named and not closed: through an `https://` proxy, nothing checks revocation of
  the proxy's own certificate. See [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
  (`vault BACKLOG #2983`)
