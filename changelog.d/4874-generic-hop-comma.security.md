- **A generic DATABASE `server` holding a comma is no longer judged on-box by its first element.**
  The cleartext-hop guard read the host from the text before the first comma, so
  `127.0.0.1,remote` with no TLS keyword would have counted as a loopback hop and crossed under
  the empty `[egress].allowed_db` opt-out. libpq reads a comma in a host as a list of hosts, so the
  guard now reads such a `server` whole, as a remote host. `127.0.0.1,5432` is remote too now; on
  psqlODBC and MySQL put the port in the `PORT` keyword, as the `allowed_db` check already
  requires. On Microsoft's `ODBC Driver <n> for SQL Server`, which reads `host,port` and ignores
  `PORT`, a host, one comma and a port in digits, such as `127.0.0.1,1433`, is read as that host
  and port; anything else holding a comma is read whole there too. (`BACKLOG #4874`)
