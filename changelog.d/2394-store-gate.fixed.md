- **The SQL Server call gate now covers the store's open-time connections and the cluster table
  setup.** The gate from `BACKLOG #2049` covered only pooled store connections and claim holders. It
  now also covers at least the connection the open uses to check `READ_COMMITTED_SNAPSHOT`. It
  covers the fresh connections that re-read it after a failed `ALTER`, and the explicit autocommit
  set. A cancellation during a statement there hands the cursor and the connection to the gate,
  which closes them once the running driver call returns. Those connections now close in one job,
  their cursor first. Where the connection and its cursor both carry their driver handles, a
  cancellation during that close lets it finish and closes each handle once, on a gated or an
  ungated connection. A connection or cursor without its handle is closed through its own methods
  instead, and a cancellation can cut that short. On an ungated connection, a cancellation during a
  statement still closes the handles beside the running driver call. On a gated connection, neither
  cancellation waits for the driver call. The cluster coordinator's table setup now uses the store's cursor helper. Its cursor
  closes before the connection returns to the pool, and goes to the gate on a cancellation. The gate
  moved to the leaf module `messagefoundry.odbc_call_gate`, and the one-shot connection exits live
  there too. At least these are not covered: the DATABASE connector, and a cancellation while a
  cursor is still being created, which leaves that cursor for the collector, on pooled and open-time
  connections alike. (`BACKLOG #2394`)
