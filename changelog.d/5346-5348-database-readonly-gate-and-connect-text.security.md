- **The DATABASE read-only statement gate refuses more T-SQL verbs, and a no-SQLSTATE connect
  error no longer quotes its text.** A `db_lookup`, `DatabaseRef` or `poll_statement` that opens
  with `SELECT` or `WITH` is now refused when it carries at least `SET`, `USE`, `DECLARE`, `OPEN`,
  `CLOSE`, `COMMIT`, `ROLLBACK`, `SEND`, `BACKUP`, `RESTORE`, `KILL`, `DBCC`, `RAISERROR` or
  `OPENQUERY`/`OPENROWSET`/`OPENDATASOURCE` outside a literal or comment, since T-SQL runs such a
  verb as a second statement with no `;`. This refuses some valid reads, at least an `OPENQUERY`
  read, a `USE HINT`, `USE PLAN` or `DISABLE EXTERNALPUSHDOWN` query hint and an unquoted column
  named `send` or `move`; [CONNECTIONS.md](../docs/CONNECTIONS.md) lists them. A connect failure
  with no SQLSTATE that no driver raised is now named by its type alone in the connect and
  connection-test errors, the mark-failure and poll-failure logs, so a DSN echoed in its text
  would not reach the log, the queue or an alert on a first deployment. (`BACKLOG #5346`,
  `BACKLOG #5348`)
