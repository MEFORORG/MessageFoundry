- **A generic DATABASE hop's TLS mode now counts only on the keyword its driver family reads.**
  The engine places the `odbc_driver` name, by whole registered name, as psqlODBC, MySQL
  Connector/ODBC or Microsoft's ODBC Driver for SQL Server. Only `sslmode` counts as a mode on the
  first two, and only `Encrypt` on the third. The shipped code counted either keyword on any driver,
  so `Encrypt=yes` on psqlODBC, which has no such keyword, would have cleared the cleartext-hop
  guard with no TLS attempted. A name the engine cannot place, at least a library path, an
  odbcinst alias such as RHEL's bare `MySQL` and another vendor's driver, now has no keyword that
  counts, so its hop is reported and, off-loopback on an enforcing instance, refused unless the
  connection declares `tls_hop_attested` or, on an outbound, `cleartext_accepted`. A mode set on
  the other family's keyword or spelling is reported with the keyword its driver reads. The
  construction warning now gives each family's own example, and for a name it cannot place points
  at the registered names and `tls_hop_attested`. See *Generic ODBC* in
  [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5053`)
