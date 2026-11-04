- **A generic DATABASE driver the engine cannot place as reading `SERVER` is now reported as one
  `[egress].allowed_db` may not bind.** The generic connection string sends its target as `SERVER`
  alone, and the egress check and the cleartext-hop guard's on-box test read that host, so a
  driver that takes its target from another keyword would dial a host neither judged. The shipped code reported such a driver only for
  its TLS mode (BACKLOG #5053), never for this. Building a generic-dialect hop whose `odbc_driver` is not a
  psqlODBC, MySQL Connector/ODBC or Microsoft registered name now also logs a WARNING naming the
  connection, and `messagefoundry check` has an advisory `generic-db-server` line listing every
  such hop, inbound and outbound. The three families are documented to read `SERVER`. In the
  2026-10-30 probes under BACKLOG #2705, psqlODBC connected, and MySQL Connector/ODBC was run,
  through strings that name the host only in `SERVER`, which is consistent with that; no run was
  designed to test it, and Microsoft's driver was not run. Nothing is refused. See *Accepted
  `odbc_params` keywords* in [CONNECTIONS.md](../docs/CONNECTIONS.md). Superseded before release
  by BACKLOG #5041, which refuses such a name at build; that entry says what replaced the
  WARNING and the line. (`BACKLOG #5163`)
