- **The WARNING for a log spool directory reported in use by another process now states what that
  means.** It still says off-box log forwarding runs without an on-disk spool, and adds facts, not
  a procedure, because it cannot say which process holds the lock. The facts cover at least the
  causes the same WARNING stands for, that its forwarder sends nothing from that directory until
  the process restarts with a spool it can lock, that moving the lock holder's spool directory
  leaves the segments in its old one unsent while moving a process without the lock strands none,
  and that a process spools in the subdirectory `engine`, `shard-<engine shard id>` or
  `supervisor` of a root: `[logging].forward_spool_dir`, or with the setting unset or empty
  `log-spool` in the directory that holds the store path (`--db`, or else
  `[store].path`), so two stores in one directory share it. The behaviour is unchanged: it is
  still a WARNING and the engine still starts without a spool. (`BACKLOG #5400`)
