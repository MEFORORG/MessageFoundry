- **The SQL Server cluster lease claim/renew now runs under `[cluster].lease_renew_timeout_seconds`.**
  It inherited `[store].acquire_timeout` and `[store].command_timeout` (30 s each by default) while
  it held the leadership lock, so a hung claim could hold a stepdown past that lock's fence-length
  wait. The claim's wait for a pooled connection and its statement are now each bounded by the
  clamp; the statement's bound is its own ODBC timeout, in whole seconds rounded down, and a shorter
  `command_timeout` still wins. A clamp under 1 s is refused on the SQL Server backend, because the
  driver cannot apply one. Unlike Postgres, the two bounds do not share one deadline, so a renew can
  land up to about twice the clamp after it is issued, while the config check compares the clamp
  alone with the detection margin; `serve` logs a warning at start-up when twice the clamp reaches
  that margin, which the shipped 10/20/30 timings do. The COMMIT after the statement is not bounded
  by the clamp at all. ADR 0157 Inc 0, deviation 3. (`BACKLOG #1497`)
