- **The SQL Server store now refuses an aioodbc connection the ODBC call gate cannot wrap.** Before,
  such a connection was used ungated, and a cancellation during a driver call on it closed its
  handles beside that call: in the pooled quarantine and its cursor helper, on the open-time
  connections that check `READ_COMMITTED_SNAPSHOT`, and on the dedicated claim connections. Each of
  those now checks the gate when it opens or borrows the connection, before any driver call runs
  on it. A connection that fails the check is closed at once, while nothing runs on it, and the
  open or the borrow fails with an error that names the cause. Under the pinned `aioodbc` release
  every connection can be gated, so this changes nothing there. The DATABASE connector is not
  covered by this entry. (`BACKLOG #2394`)
