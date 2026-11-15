- **The DATABASE connector now refuses an aioodbc connection the ODBC call gate cannot wrap.**
  Before, such a connection was borrowed ungated, and a cancellation during a driver call on it
  left its handles unclosed, for pyodbc to free with a rollback and a disconnect wherever the last
  reference dropped, which could be the event loop thread. Every pooled borrow, at least an
  outbound send, an inbound poll or mark, a `db_lookup`, the login role probe and a `DatabaseRef`
  sync, now checks the gate before the connector makes any driver call on the connection. A
  connection that fails the check is closed while nothing runs on it, and the borrow fails with
  `UngatedConnectionError`, which each caller handles as it does any other failed borrow: an
  outbound send reports it as a transient connect failure. The pool gets the connection back
  closed, except on an aioodbc that also renamed the connection's handle: there the connection
  goes back only once its own close has returned, and goes back open if that close failed, to be
  refused and closed again on its next borrow. Under the pinned `aioodbc` release every connection
  can be gated, so this changes nothing there. (`BACKLOG #2394`)
