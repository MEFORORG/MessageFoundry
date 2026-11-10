- **The `host.odbc` verify row checks the driver each configured ODBC hop needs, and no longer
  fails a host that takes no such hop.** It read FAIL wherever `pyodbc` was installed without ODBC
  Driver 18, so `verify` exited 1 on a host with no SQL Server store and no DATABASE connection,
  `DatabaseRef` or `DatabaseLookup`. It now reads every hop from the graph load the `host.ciphers`
  row reads: a hop that names a registered SQL Server driver, Driver 18 or another, FAILs where
  `pyodbc` does not list that driver, and a hop that names the driver library by an absolute path FAILs
  where that file is not there; the row names each hop and driver. A driver list that cannot be read is
  ERROR where the configuration takes an ODBC hop, one with an `env()` driver included. The row is now titled "SQL
  Server ODBC drivers". `host.ciphers` counts every SQL Server preset entry, since the preset builds
  only on a Microsoft driver, and an entry on another dialect where its `odbc_driver` is a Microsoft
  driver: a generic-dialect connection on Microsoft's driver is now a hop of `host.ciphers`, where
  it read MANUAL. Neither row counts an entry the build refuses, on its dialect or its driver, or a
  connection that is not deployed. The `--config` graph is now loaded once per run, and the hop
  census and the self smoke share that load. See [testing/VERIFY.md](../docs/testing/VERIFY.md).
  (`BACKLOG #3803`)
