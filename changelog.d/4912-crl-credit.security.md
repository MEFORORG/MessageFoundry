- **The Vault and proxy legs read the revocation guard's CRL rule.** `crl_no_credit` in
  `config/tls_policy.py` gives no CRL credit to a context whose `verify_mode` is `CERT_NONE` or
  that skips validity-period checks; its docstring states the conditions, and
  `RevocationHopGuard.capture` reads it too. Where the guard is handed a `CERT_NONE` context, its
  records and the AI broker's do not call the hop verified, and its default remedy does not offer
  the attestation. (vault BACKLOG #4912)
