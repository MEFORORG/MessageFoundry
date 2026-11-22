- **A SQLite store whose upgrade is stopped by a view or trigger another tool left can now name
  that object.** When SQLite's re-check after a migration's `ALTER` fails on such a view or trigger
  with an error that names the store's shape, such as "no such module", and the error's text fits
  exactly one such object, the open refuses the store with the remedy to save that object's CREATE
  statement, drop it and restart, not to recreate the store. The object is named only when that
  remedy survives the 200-character cut and the redaction of a printed error whole; otherwise,
  and whenever the text fits more than one object, the store gets the plain remedy. A
  failure on the store's shape raised by the check's own read of the live store, after the schema
  script and the migrations of a writable open, is now refused with the recreate remedy rather
  than escaping as SQLite's bare error. (`BACKLOG #6719`, `BACKLOG #6720`)
