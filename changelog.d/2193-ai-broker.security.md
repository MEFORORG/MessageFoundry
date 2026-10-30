- **The engine AI broker's endpoint hop now takes a revocation guard, with an `[ai]` attestation
  pair.** Every assist call sends `[ai].api_key` over https that verifies the endpoint's
  certificate, but stdlib `ssl` checks no CRL or OCSP, so the shipped code would have accepted a
  revoked endpoint certificate with no refusal and no record. On an instance at `[security].enforcement = enforce`,
  an `[ai].endpoint` whose host is not loopback is now refused at `POST /ai/chat`, answered 503,
  unless `[ai].endpoint_revocation_attested = true` is set with an
  `[ai].endpoint_revocation_attested_reason`. No CRL lever is built for this hop, so
  `[tls].crl_file` does not reach it, and `MEFOR_TLS_REVOCATION_ATTESTED` does not cross it under
  `enforce`. A broker built with no instance posture is judged as enforcing. A non-enforcing
  instance warns, once per process for each endpoint host. The pair is a loosening that
  `security show`, `GET /security/posture` and the serve-time warning name, with the reason. See
  [DEPLOYMENT.md](../docs/DEPLOYMENT.md#revocation-guard-behavior). (`BACKLOG #2193`)
