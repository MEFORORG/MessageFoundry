- **The log and support-bundle redaction now hides two more DSN password shapes.** A password with
  an empty user that holds a bracket, such as `postgres://:Kv[9]x@db`, and the part after a
  password's own `@` that holds a `;`, such as the `Zq7;w` of `postgres://svc:Kv9x@Zq7;w@db`,
  would have printed in a log line, a store error or a support bundle. Both are now hidden. A host
  with no `.` or `:`, followed by a `;` and a later `@`, as in `smtp://ops:pw@mail;alerts@corp`, is
  now hidden with the password. A bracketed
  run of letters alone, which has a placeholder's shape, and a `;` group holding a `.`, a `:` or an
  `=` still print, as before. (`BACKLOG #5386`)
