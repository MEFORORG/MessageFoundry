- **The WARNING for a log spool directory another process holds now names the remedy.** It still
  says off-box log forwarding runs without an on-disk spool, and adds: give each process its own
  `[logging].forward_spool_dir` (environment variable `MEFOR_LOGGING_FORWARD_SPOOL_DIR`). The
  behaviour is unchanged: it is still a WARNING and the engine still starts without a spool. The
  default directory is not keyed by HA node id, because an unset `[cluster].node_id` is new on
  every start, so each restart would strand the previous run's unsent records. (`BACKLOG #5400`)
