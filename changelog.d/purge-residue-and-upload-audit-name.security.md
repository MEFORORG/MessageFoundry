- **A purge on SQLite now overwrites the old bytes, and the WAL is truncated hourly, by default.**
  A purge blanked a body but left its bytes in the file's free space and in stale `-wal` frames.
  The new `[store].secure_delete` (default `true`) sets `PRAGMA secure_delete` on the writer
  connection, so SQLite zeroes what a delete or a purge frees. `[retention].wal_checkpoint_seconds`
  now defaults to `3600`, so the retention pass truncates the `-wal` file after its purges. Both
  cost some extra write I/O; set them off for throughput only if leaving purged bytes in the file is
  acceptable. SQLite only. Turning `secure_delete` off on a file-backed store is a loosening that
  `security_loosenings()` names. When a reader or a DR snapshot copy stops the retention pass's
  truncate, the pass now logs a WARNING instead of passing in silence. (`vault BACKLOG #2619`)
- **No upload audit row carries the file name.** `upload.create`, `upload.delete`, `upload.reject`
  and `upload.reject_quota` wrote the operator-chosen file name into `audit_log.detail`, which is
  plaintext and kept. A stored file is now named by its `file_id`, and a refused one by its reason.
  The uploader's own error response still names the file. (`vault BACKLOG #2619`)
