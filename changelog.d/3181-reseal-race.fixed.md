- **`rotate-key` no longer brings back an upload that a running engine deletes while it runs.**
  The command refuses a running engine only on SQLite, so on PostgreSQL or SQL Server an engine
  could delete or prune an upload between the re-seal's read and its write, and the write re-created
  the file. Every engine removal and every re-seal write now hold one lock file in the uploads
  directory, `.mefor-edit.lock`, and the re-seal replaces a file only while it is still the one it
  read. Such an upload is a skip, so the run exits non-zero and a re-run completes. See
  [PHI.md](../docs/PHI.md). (`BACKLOG #3181`)
