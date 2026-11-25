- **The `alerts.email_tls_revocation_attested` posture entry names when a CRL is checked.** It
  said the SMTP relay checks "no CRL unless [tls].crl_file is set", which overstated the check: a
  loopback relay gets no CRL whatever that file says, and nor does a sink whose caller hands it no
  `[tls]` policy. `GET /security/posture`, the serve-start warning and `security show` now print
  the three conditions. The `ai.endpoint_revocation_attested` entry now says how it reads
  loopback, under which `localhost.` is remote and gets the CRL. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #5527`)
- **The `[alerts]` SMTP login refusal offers `[tls].crl_file` only where the sink holds a `[tls]`
  policy.** A sink built with none gets no CRL whatever that file says, and its refusal now says
  so and names the attestation pair and handing the sink the policy. (`BACKLOG #5527`)
