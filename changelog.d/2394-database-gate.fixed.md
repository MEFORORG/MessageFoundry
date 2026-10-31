- **The DATABASE connector's pooled connections now go through the ODBC call gate.** A destination
  send, a source poll or mark, a `db_lookup` and a `DatabaseRef` sync borrow their connections with
  the gate the SQL Server store uses, and the autocommit set and the cursor close run through it. A
  cancellation during a statement no longer closes the cursor on another thread while the statement
  still runs, which on a real driver frees the handle the statement returns to and can crash the
  process. The cursor now closes once the statement returns, on the statement's own thread, and the
  same step rolls back what the cancelled statement left open, so a destination's connection no
  longer goes back holding a cancelled INSERT for the next send to commit, unless that rollback
  fails while the session is still alive; the failure is logged. The connection then goes
  back to its pool. The cancelled task does not wait for the statement, but the connection keeps
  its pool slot until the statement returns, which nothing in the engine bounds. While a pool holds
  such a connection back, its close waits at most 2 s for it, then goes on by itself: the
  destination's, the lookup's, a `DatabaseRef` sync's and a source's stop, so the connection test of
  a source no longer hangs behind a `SELECT 1` its own timeout cancelled. With no connection held
  back, a close waits for in-flight calls as before. After the 2 s a new pool can open beside the
  one still closing. At least these are not covered: a cancellation while a cursor is still being
  created, and a cancellation before the cancelled call has entered the gate. (`BACKLOG #2394`)
