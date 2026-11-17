- **On Windows, the key-file access check now also reads the folder that holds a key file.** It
  reads that folder's owner and access list, in most cases where the path resolves to (the ADR
  amendment names the exception), after any junction, link
  or `subst` drive (on a network share or mapped network drive the path names, by its path as
  written, refusing the key file when that folder is itself a reparse point, such as a junction or
  link), and refuses the key
  file when a broad group or an application package may delete a file in that folder, change its access list or take it over, or when that
  folder's owner is such a group or cannot be read. It is not a
  complete check of the file's surroundings; see
  [ADR 0214](../docs/adr/0214-a-secrets-directory-and-one-accessor-for-the-engine-s-secret-class-settings.md#amendments).
  The check also refuses at least these: a key reached through a junction, link or `subst` drive
  on this host that leads onto a network share or a mapped network drive; one on a share named by
  at least some of this host's own names or addresses; and one on a volume whose drive type cannot
  be read. The docstrings of `_windows_surroundings_problem` and `_loopback_share_problem` in
  `messagefoundry/restricted_file.py` name more of them. The walk to that folder does not read a volume's file system.
  (`BACKLOG #5657`, `BACKLOG #5656`)
