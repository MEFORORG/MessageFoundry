- **The `[alerts]` SMTP login and the alert webhook now take the revocation-hop guard.** Both
  verify a peer certificate, but stdlib `ssl` checks no CRL or OCSP, so the shipped code would have
  accepted a revoked relay or webhook certificate with no refusal and no record. On an instance at
  `[security].enforcement = enforce`, an off-box SMTP relay with `[alerts].email_username` set is
  now refused when `serve` builds the alert notifier and the per-user security notifier, and the
  alerts test send reports it, unless `[tls].crl_file` reaches the hop or
  `[alerts].email_tls_revocation_attested` is set with its mandatory reason. A relay with no login
  takes no guard. An off-box https `[alerts].webhook_url` is refused the same way unless
  `[alerts].webhook_tls_revocation_attested` is set with its reason; no CRL can reach that hop.
  A transport or notifier built with no instance posture is judged as enforcing, as the AI broker
  is, and one built directly with an attestation but no reason is refused. Each set pair is
  reported as a loosening. A non-enforcing instance warns. See
  [DEPLOYMENT.md](../docs/DEPLOYMENT.md#revocation-guard-behavior). (`BACKLOG #2193`)
