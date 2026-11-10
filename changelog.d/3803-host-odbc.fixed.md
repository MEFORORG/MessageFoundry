- **The `host.odbc` verify row no longer fails a host whose configuration takes no hop that names
  ODBC Driver 18.** It read FAIL wherever `pyodbc` was installed without Driver 18, so `verify`
  exited 1 on a host with no SQL Server store and no DATABASE connection, `DatabaseRef` or
  `DatabaseLookup` on that driver. A missing driver, or a driver list that cannot be read, is now
  judged by a hop census over the graph load the `host.ciphers` row reads, with its own question:
  with a hop that names Driver 18 it still reads FAIL or ERROR and names the hop, with none it SKIPs
  and keeps the reading in its detail, and where the configuration could not be read it is MANUAL. A driver that is there still PASSes.
  `host.odbc` counts an entry only where its `odbc_driver` names Driver 18. `host.ciphers` counts
  every SQL Server preset entry, since the preset builds only on a Microsoft driver, and an entry
  on another dialect where its `odbc_driver` is a Microsoft driver: a generic-dialect connection on
  Microsoft's driver is now a hop of `host.ciphers`, where it read MANUAL. Neither row counts an
  entry the build refuses, on its dialect or its driver, or a connection that is not deployed. The `--config` graph is now loaded once per run, and the
  hop census and the self smoke share that load. See
  [testing/VERIFY.md](../docs/testing/VERIFY.md). (`BACKLOG #3803`)
