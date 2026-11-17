- **The DATABASE read-only statement gate refuses more T-SQL verbs, and a DATABASE error with no
  SQLSTATE no longer has its text quoted where it could carry DSN attributes.** A `db_lookup`,
  `DatabaseRef` or `poll_statement` that opens with `SELECT` or `WITH` is now refused when it
  carries, outside a literal or comment, at least `SET`, `USE`, `DECLARE`, `OPEN`, `CLOSE`,
  `COMMIT`, `ROLLBACK`, `SEND`, `BACKUP`, `RESTORE`, `KILL`, `DBCC` or `RAISERROR`, since T-SQL
  runs such a verb as a second statement with no `;`. It also refuses `OPENQUERY`, `OPENROWSET`
  and `OPENDATASOURCE` inside a read's `FROM`, because each sends a pass-through query the gate
  cannot read to another server or provider. This refuses some valid reads, at least an
  `OPENQUERY` read, a `USE HINT`, `USE PLAN` or `DISABLE EXTERNALPUSHDOWN` query hint and an
  unquoted column named `send` or `move`; [CONNECTIONS.md](../docs/CONNECTIONS.md) lists them.
  An error with no SQLSTATE that no driver raised, a connect failure or any other, is now named
  by its type alone in the connect and connection-test errors and in the mark-failure,
  poll-failure and stopped-poll-task logs, so a DSN echoed in its text would not reach the log,
  the queue or an alert on a first deployment. The engine's own fixed-text errors keep their text
  there, at least the pool-acquire timeout, the `statement_timeout` refusal and the autocommit and
  call-gate borrow refusals. In the poll-failure log a bug's message is withheld the same way;
  its frames still print. (`BACKLOG #5346`, `BACKLOG #5348`)
