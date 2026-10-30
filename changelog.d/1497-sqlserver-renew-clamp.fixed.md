- **The SQL Server cluster lease claim/renew now runs under `[cluster].lease_renew_timeout_seconds`.**
  It inherited `[store].command_timeout` (30 s by default) while it held the leadership lock, so a
  hung claim could hold a stepdown past that lock's fence-length wait. The clamp is now the claim
  statement's own ODBC timeout, in whole seconds rounded down, and a shorter `command_timeout` still
  wins. A clamp under 1 s is refused on the SQL Server backend, because the driver cannot apply one.
  ADR 0157 Inc 0, deviation 3. (`BACKLOG #1497`)
