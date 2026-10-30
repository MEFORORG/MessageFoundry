- **A cancelled SQL Server store open or cluster table setup no longer frees ODBC handles under a
  running statement.** The call gate from `BACKLOG #2049` covered only pooled store connections and
  claim holders. It now also covers the connection the open uses to check `READ_COMMITTED_SNAPSHOT`.
  It covers the fresh connections that re-read it after a failed `ALTER`, and the explicit
  autocommit set. A cancellation there hands the cursor and the connection to the gate. The gate
  closes them once the running driver call returns, and the cancellation does not wait for it. On
  the normal path those connections now close their cursor first. The cluster coordinator's table
  setup now uses the store's cursor helper. Its cursor closes before the connection returns to the
  pool, and goes to the gate on a cancellation. The gate moved to the leaf module
  `messagefoundry.odbc_call_gate`. The DATABASE connector is not covered by this change.
  (`BACKLOG #2394`)
