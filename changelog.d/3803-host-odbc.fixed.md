- **The `host.odbc` verify row no longer fails a host whose configuration takes no ODBC Driver 18
  hop.** It read FAIL wherever `pyodbc` was installed without Driver 18, so `verify` exited 1 on a
  host with no SQL Server store, DATABASE connection, `DatabaseRef` or `DatabaseLookup`. A missing
  driver, or a driver list that cannot be read, is now judged by the hop census the `host.ciphers`
  row uses: with a hop it still reads FAIL or ERROR and names the hop, with no hop it SKIPs and keeps
  the reading in its detail, and where the configuration could not be read it is MANUAL. A driver
  that is there still PASSes. The `--config` graph is now loaded once per run, and the hop census
  and the self smoke share that load. See [testing/VERIFY.md](../docs/testing/VERIFY.md).
  (`BACKLOG #3803`)
