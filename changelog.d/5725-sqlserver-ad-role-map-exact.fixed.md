- **On SQL Server the AD group-to-role map no longer seals in a role id that names no role.** SQLite
  and PostgreSQL refuse such an id with a roles foreign key; SQL Server's map declared none, so a
  map write that raced a role delete, or named a case or trailing-space variant of a live role id,
  would have committed and sealed it. The map now carries the roles foreign key, the writer checks
  every role id it adds exactly inside its transaction and refuses an unknown one, and the map read
  counts a pair as live only on an exact role id. A custom role edit or delete also takes only the
  role's exact id: any other spelling SQL Server's lookup finds, at least a case or trailing-space
  variant, is refused as not found, and a delete the store refuses writes no `role.deleted` audit
  row. (`BACKLOG #5725`)
