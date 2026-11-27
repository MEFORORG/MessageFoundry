- **The WARNING for a log spool directory reported in use by another process now names a
  remedy.** It still says off-box log forwarding runs without an on-disk spool, and adds, first:
  if this is a second start of the same service, stop the duplicate, because moving the directory
  would strand the segments already in it, then restart this one once the other has exited; until
  it restarts, the process runs without a spool. Then: if a different service or deployment
  shares the directory, give that one its own `[logging].forward_spool_dir` (environment variable
  `MEFOR_LOGGING_FORWARD_SPOOL_DIR`), the root its spool subdirectories are made under, as an
  absolute path, and never change it for one process of a `supervise` deployment, whose engine
  shards and supervisor share that root. The behaviour is unchanged: it is still a WARNING and the
  engine still starts without a spool. (`BACKLOG #5400`)
