- **The DATABASE connector's pooled connections now go through the ODBC call gate.** A destination
  send, a source poll or mark, a `db_lookup` and a `DatabaseRef` sync borrow their connections with
  the gate the SQL Server store uses, and the autocommit set and the cursor close run through it. A
  cancellation during a statement no longer closes the cursor on another thread while the statement
  still runs, which on a real driver frees the handle the statement returns to and can crash the
  process. The cursor now closes once the statement returns, and the connection goes back to its
  pool after that. The cancelled task does not wait for the statement. Until it returns, the
  connection keeps its pool slot, and since this connector has no statement timeout, nothing in the
  engine bounds that time. At least these are not covered: a cancellation while a cursor is still
  being created, and a cancelled destination send whose transaction is left open on the connection
  it returns. (`BACKLOG #2394`)
