- **On Windows, the key-file access check now also reads the folder that holds a key file.** It
  reads that folder's owner and access list where the path resolves to, after any junction, link
  or `subst` drive, and refuses the key
  file when a broad group or an application package may delete a file in that folder, change its access list or take it over, or when that
  folder's owner is such a group or cannot be read. It is not a
  complete check of the file's surroundings; see
  [ADR 0214](../docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md#amendments).
  A key reached through a junction, link or `subst` drive onto a network share is refused, and
  so is one on a share named by at least some of this host's own names.
  (`BACKLOG #5657`, `BACKLOG #5656`)
