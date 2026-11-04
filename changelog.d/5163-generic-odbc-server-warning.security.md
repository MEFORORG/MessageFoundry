- **A generic DATABASE driver the engine cannot place as reading `SERVER` is now reported.** The
  generic connection string sends its target as `SERVER` alone, and `[egress].allowed_db` checks
  that host, so a driver that takes its target from another keyword would dial a host the check
  never saw. The shipped code built such a hop with no report. Building one whose `odbc_driver` is
  not a psqlODBC, MySQL Connector/ODBC or Microsoft registered name now logs a WARNING naming the
  connection, and `messagefoundry check` has an advisory `generic-db-server` line listing every such
  hop, inbound and outbound. The three families are documented to read `SERVER`; no driver was run
  to confirm it. Nothing is refused. See *Accepted `odbc_params` keywords* in
  [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5163`)
