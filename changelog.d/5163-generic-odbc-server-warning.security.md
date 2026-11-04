- **A generic DATABASE driver the engine cannot place as reading `SERVER` is now reported as one
  `[egress].allowed_db` may not bind.** The generic connection string sends its target as `SERVER`
  alone, and the egress check reads that host, so a driver that takes its target from another
  keyword would dial a host the check never saw. The shipped code reported such a driver only for
  its TLS mode (BACKLOG #5053), never for this. Building a hop whose `odbc_driver` is not a
  psqlODBC, MySQL Connector/ODBC or Microsoft registered name now also logs a WARNING naming the
  connection, and `messagefoundry check` has an advisory `generic-db-server` line listing every
  such hop, inbound and outbound. The three families are documented to read `SERVER`; no driver
  was run to confirm it. Nothing is refused. See *Accepted `odbc_params` keywords* in
  [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5163`)
