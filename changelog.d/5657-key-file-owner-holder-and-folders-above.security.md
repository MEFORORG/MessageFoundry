- **On Windows, the key-file access check now also reads the folder just above a key file in its
  path.** It reads that folder's owner and access list at the path as written, and refuses the key
  file when a broad group or an application package may delete a file in that folder, change its access list or take it over, or when that
  folder's owner is such a group or cannot be read. It is not a
  complete check of the file's surroundings; see
  [ADR 0214](../docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md#amendments).
  (`BACKLOG #5657`, `BACKLOG #5656`)
