- **The SQL Server call gate now covers the store's open-time connections and the cluster table
  setup.** The gate from `BACKLOG #2049` covered only pooled store connections and claim holders.
  It now also covers at least the connection the open uses to check `READ_COMMITTED_SNAPSHOT`. It
  covers the fresh connections that re-read it after a failed `ALTER`, and the explicit autocommit
  set. A cancellation there, during a statement or during the cleanup, hands the cursor and the
  connection to the gate. The gate closes them once the running driver call returns, and the
  cancellation does not wait for it. On the normal path those connections now close their cursor
  first. The cluster coordinator's table setup now uses the store's cursor helper. Its cursor
  closes before the connection returns to the pool, and goes to the gate on a cancellation. The
  gate moved to the leaf module `messagefoundry.odbc_call_gate`. Not covered: the DATABASE
  connector, and a cancellation while a cursor is still being created, which leaves that cursor
  for the collector, on pooled and open-time connections alike. (`BACKLOG #2394`)
