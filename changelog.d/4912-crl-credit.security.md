- **A CRL relaxes a revocation guard only on a TLS context that sets `CERT_REQUIRED`.** One rule,
  `crl_no_credit` in `config/tls_policy.py`, now decides CRL credit for every revocation guard,
  the Vault and proxy legs included; its docstring states the conditions. A hop whose context
  lacks `CERT_REQUIRED` or skips validity-period checks is decided as one with no CRL, so some such
  hops a CRL used to admit are now refused or warned on. On a context without `CERT_REQUIRED` the
  guard's records and the AI broker's no longer call the hop verified, and the default remedy
  names that setting instead of a CRL. (vault BACKLOG #4912)
