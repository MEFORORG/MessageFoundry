- **The DATABASE connector's pooled connections now go through the ODBC call gate.** A destination
  send, a source poll or mark, a `db_lookup` and a `DatabaseRef` sync borrow their connections with
  the gate the SQL Server store uses, and the autocommit set and the cursor close run through it. A
  cancellation during a statement no longer closes the cursor on another thread while the statement
  still runs, which on a real driver frees the handle the statement returns to and can crash the
  process. The cursor now closes once the statement returns, on the statement's own thread, and the
  same step rolls back what the cancelled statement left open, so a destination's connection no
  longer goes back holding a cancelled INSERT for the next send to commit. A connection whose
  rollback fails is discarded. The connection then goes back to its pool. The cancelled task does
  not wait for the statement, but the connection keeps its pool slot until the statement returns,
  and since this connector has no statement timeout, nothing in the engine bounds that time. The
  destination's, the lookup's and a `DatabaseRef` sync's pool close now wait at most 2 s for it. At
  least these are not covered: a cancellation while a cursor is still being created, and a
  source's ordinary stop, whose pool close is still unbounded. (`BACKLOG #2394`)
