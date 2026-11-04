- **SQL Server reports an older `state` table and refuses reference keys that would collide.** At
  every open the engine reads the collation of the `state` table's key columns and logs a WARNING
  when it is not binary, as in a table made before `BACKLOG #1588` under a case-insensitive
  default, naming the collation and the remedy. It repairs nothing, and a row that then fails to
  decrypt carries a note naming that collation as a possible cause. A reference snapshot holding two
  keys that differ only by trailing spaces, which SQL Server compares as equal, is now refused
  before its transaction as a `ReferenceKeyCollision`, naming the keys by ordinal only, so the sync
  keeps the last-good snapshot instead of failing mid-write every interval. (`BACKLOG #4917`)
