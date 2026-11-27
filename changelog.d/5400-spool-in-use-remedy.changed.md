- **The WARNING for a log spool directory reported in use by another process now names a
  remedy.** It still says off-box log forwarding runs without an on-disk spool, and adds, first:
  if this is a second start of the same service, stop one of them, and if you stop the other one,
  restart this one once it has exited; until it restarts, this process runs without a spool. Stop
  one rather than give either a different `[logging].forward_spool_dir`: moving the one holding the
  lock would strand the segments already in the directory, and moving this one would leave both
  starts running. Then: if a different service or deployment
  shares the directory, give this process, the one logging the WARNING, its own
  `[logging].forward_spool_dir` (environment variable `MEFOR_LOGGING_FORWARD_SPOOL_DIR`), the root
  its spool subdirectories are made under, as an absolute path, and restart it. Leave the process
  holding the lock where it is, because moving that one would strand its unsent segments. Never
  change the root of a running `supervise` deployment, whose engine shards and supervisor share
  that root. The behaviour is unchanged: it is still a WARNING and the engine still starts without
  a spool. (`BACKLOG #5400`)
