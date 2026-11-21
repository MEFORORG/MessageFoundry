- **The log and support-bundle redaction now hides two more DSN password shapes where the DSN
  stands alone.** A password with an empty user that holds a bracket, such as
  `postgres://:Kv[9]x@db`, and the part after a password's own `@` that holds a `;`, such as the
  `Zq7;w` of `postgres://svc:Kv9x@Zq7;w@db`, would have printed in a log line, a store error or a
  support bundle. Each is now hidden when no credential label stands before the DSN. A host with
  no `.` or `:`, followed by a `;` and a later `@`, as in `smtp://ops:pw@mail;alerts@corp`, is now
  hidden with the password, and the redacted line then names `corp` as the host. What still prints
  as before, at least: a bracketed run of letters alone, which has a placeholder's shape; a `;`
  group holding a `.`, a `:` or an `=`; the tail of a DSN that follows a credential label, as in
  `password: postgres://svc:Kv9x@Zq7;w@db` and `dbPassword=postgres://svc:Kv9x@Zq7;w@db`, of which
  at least `;w` prints, and all of `Zq7;w` for the second where the store-error path redacts the
  raw line; and the tail on a line the
  redaction reads only as it did before this change, such as one whose camelCase label would
  otherwise lose a connection-string member's `;`. (`BACKLOG #5386`)
