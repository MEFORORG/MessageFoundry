- **The `sslmode` refusal no longer steers a driver the engine cannot place to a libpq value.**
  Under a MySQL driver with a name the engine does not place, such as RHEL's bare `MySQL` section
  or a library path, `VERIFY_IDENTITY` was refused with a message offering only libpq's spellings,
  `verify-full` among them, which MySQL ignores. The refusal for such a name now advises no value:
  it leads with the engine being unable to place the `odbc_driver` family and names the psqlODBC
  and MySQL registered names, inside the part of the message a stored failure keeps. Microsoft's
  `ODBC Driver <n> for SQL Server`, which reads no `sslmode`, now refuses any `sslmode` and points
  at `Encrypt`, where it built a libpq value it would ignore. The construction warning gives each
  driver family's own example. See *The `SSLmode` spelling* in
  [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5029`)
