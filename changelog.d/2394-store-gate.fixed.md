- **A cancelled SQL Server store open or cluster table setup no longer frees ODBC handles under a
  running statement.** The per-connection call gate added for `BACKLOG #2049` covered only pooled
  store connections and claim holders. The open-time connection that checks and enables
  `READ_COMMITTED_SNAPSHOT`, the fresh connections that re-read it after a failed `ALTER`, and the
  explicit autocommit set on the first of them now run through the gate too, so a cancellation
  closes such a connection only once its running driver call has returned. A cancellation there
  waits for that call before the open unwinds. The SQL Server cluster coordinator's table setup now
  uses the store's cursor helper: the cursor is closed before its connection returns to the pool,
  and on a cancellation it is handed to the gate. The gate moved to the leaf module
  `messagefoundry.odbc_call_gate`, so other ODBC users can reach it; the DATABASE connector is not
  covered by this change. (`BACKLOG #2394`)
