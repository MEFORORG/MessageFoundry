- **The WARNING for a log spool directory reported in use by another process now states what that
  means.** It still says off-box log forwarding runs without an on-disk spool, and adds facts, not
  a procedure, because it cannot say which process holds the lock. It reads the same whether
  another process holds the lock or taking the lock failed. This process runs without a spool
  until it restarts with a spool it can lock. Only the process holding a spool directory's lock
  sends that directory's segments, so any change to a process's spool directory leaves the
  segments in its old directory unsent until a process opens that directory again. The directory
  changes with at least `[logging].forward_spool_dir` (environment variable
  `MEFOR_LOGGING_FORWARD_SPOOL_DIR`), the working directory when that setting is a relative path,
  and an engine shard's shard id; with no setting, it also changes with the store path the default
  directory is derived from. One directory serves one process (ADR 0200, "One process per
  directory"). The behaviour is unchanged: it is still a WARNING and the engine still starts
  without a spool. (`BACKLOG #5400`)
