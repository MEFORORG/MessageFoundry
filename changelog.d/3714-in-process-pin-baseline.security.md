- **The SQL Server store pin is also compared with an in-process baseline.** Each settings
  check of `[store].ssl_root_cert` on SQL Server, which runs at least at start and at a real
  reload, compares the file
  with the first pin bytes the engine process checked, at its store open or else at its first
  check, and logs a WARNING when they differ. The compare reads no store row, so a server a
  swapped pin admits cannot answer it away. It writes no audit row and refuses nothing, and a
  restart starts a new baseline. The module docstring of `messagefoundry/auth/trust_anchors.py`,
  item 11, states its limits. (`BACKLOG #3714`)
