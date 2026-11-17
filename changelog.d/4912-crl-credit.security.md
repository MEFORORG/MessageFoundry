- **A CRL relaxes a revocation guard only on a TLS context that verifies the peer.**
  `RevocationHopGuard.capture` gives no CRL credit to a context whose `verify_mode` is
  `CERT_NONE`. The Vault and proxy legs in `transports/strict_requests.py` now read the same rule,
  `crl_no_credit` in `config/tls_policy.py`, whose docstring states its conditions. On a
  `CERT_NONE` context the guard's records and the AI broker's no longer call the hop verified, and
  the guard's default remedy no longer offers the attestation. (vault BACKLOG #4912)
