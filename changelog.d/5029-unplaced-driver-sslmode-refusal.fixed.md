- **The `sslmode` refusal no longer steers a driver the engine cannot place to a libpq value.**
  Under a MySQL driver with a name the engine does not place, such as RHEL's bare `MySQL` section
  or a library path, `VERIFY_IDENTITY` was refused with a message offering only libpq's spellings,
  `verify-full` among them, which MySQL ignores. The refusal now says the engine cannot place the
  `odbc_driver`, points a MySQL spelling at MySQL's registered driver name, and gives libpq's list
  only beside that pointer. See *The `SSLmode` spelling* in
  [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5029`)
