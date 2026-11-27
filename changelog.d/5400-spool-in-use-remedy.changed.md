- **The WARNING for a log spool directory reported in use by another process now names a
  remedy.** It still says off-box log forwarding runs without an on-disk spool, and adds: if
  another process shares this directory, leave one of them on it and give each of the others a
  different `[logging].forward_spool_dir` (environment variable
  `MEFOR_LOGGING_FORWARD_SPOOL_DIR`), the root its own spool subdirectory is made under. The
  behaviour is unchanged: it is still a WARNING and the engine still starts without a spool.
  (`BACKLOG #5400`)
