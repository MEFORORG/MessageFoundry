- **A SQLite store whose upgrade is stopped by a view or trigger another tool left now names that
  object.** When SQLite's re-check after a migration's `ALTER` fails on such a view or trigger with
  an error that names the store's shape, such as "no such module", the open refuses the store with
  the remedy to drop that object and restart, not to recreate the store. A view under the name of a
  table or index this build creates still gets the recreate remedy. A failure on the store's shape
  raised by the check's own read of the live store, after the schema script and the migrations of
  a writable open, is now refused with the recreate remedy rather than escaping as SQLite's bare error.
  (`BACKLOG #6719`, `BACKLOG #6720`)
