- **A SQLite store whose upgrade is stopped by a view or trigger another tool left now names that
  object.** When SQLite's re-check after a migration's `ALTER` fails on a view or trigger, the open
  refuses the store with the remedy to drop that object and restart, not to recreate the store. A
  failure on the store's shape raised by the check's own read, after the schema script and the
  migrations, is now refused with the recreate remedy rather than escaping as SQLite's bare error.
  (`BACKLOG #6719`, `BACKLOG #6720`)
