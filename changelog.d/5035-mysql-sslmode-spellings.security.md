- **A MySQL Connector/ODBC `SSLMODE` must now be one of the spellings MySQL documents.** Under a
  registered MySQL driver name the build accepted any value, so `verify-full`, `require` and `yes`
  counted as TLS addressed while, per engine PR 2691, MySQL would fall back to `PREFERRED`, which
  can send in plaintext. The build now refuses any value but `DISABLED`, `PREFERRED`, `REQUIRED`,
  `VERIFY_CA` or `VERIFY_IDENTITY`, in that upper case, and the cleartext-hop classifier counts no
  other value as a mode. No MySQL driver was run for this change: the spellings are the
  documentation's, and whether the driver reads another case was not measured. See *The `SSLmode`
  spelling* in [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5035`)
