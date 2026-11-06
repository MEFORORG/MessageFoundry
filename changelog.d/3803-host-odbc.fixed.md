- **The `host.odbc` verify row no longer fails a host whose configuration takes no hop that names
  ODBC Driver 18.** It read FAIL wherever `pyodbc` was installed without Driver 18, so `verify`
  exited 1 on a host with no SQL Server store and no DATABASE connection, `DatabaseRef` or
  `DatabaseLookup` on that driver. A missing driver, or a driver list that cannot be read, is now
  judged by the hop census the `host.ciphers` row uses: with a hop that names Driver 18 it still
  reads FAIL or ERROR and names the hop, with none it SKIPs and keeps the reading in its detail,
  and where the configuration could not be read it is MANUAL. A driver that is there still PASSes.
  Both rows now judge an entry by its `odbc_driver`, not its dialect, and leave out a connection
  that is not deployed: a generic-dialect connection on Microsoft's driver is now a hop of
  `host.ciphers`, where it read MANUAL. The `--config` graph is now loaded once per run, and the
  hop census and the self smoke share that load. See
  [testing/VERIFY.md](../docs/testing/VERIFY.md). (`BACKLOG #3803`)
