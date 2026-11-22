- **On Windows, the key-file access check now also reads the folder that holds a key file.** It
  reads that folder's owner and access list, in most cases where the path resolves to, after any
  junction, link or `subst` drive, and refuses the key file when a broad group or an application
  package may delete a file in that folder, change its access list or take it over, or when that
  folder's owner is such a group or cannot be read. Where that folder is read, and what is
  refused when the path is on a network share or a mapped network drive, is in the 2026-11-17
  entry of the
  [ADR 0214 amendments](../docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md#amendments),
  under *The share rule*. It also refuses, at least, a key file whose own owner is such a group or
  cannot be read, a key at the path where the engine mints its TLS key, when it mints or reuses
  its own pair, that is not owned by the engine's own account, SYSTEM or Administrators, and a
  junction or link its walk finds on the path that an account it does not trust could change;
  [PHI.md](../docs/PHI.md), *Key files*, names accounts it trusts. Under
  `[security].enforcement = "warn"` the start gates and the connection key-file check warn about
  the key files they judge rather than refuse them. It is not a complete check of the file's
  surroundings. (`BACKLOG #5657`, `BACKLOG #5656`)
