- **The WARNING for a log spool directory reported in use by another process now states what that
  means.** It still says off-box log forwarding runs without an on-disk spool, and adds facts, not
  a procedure, because it cannot say which process holds the lock. The facts cover at least the
  causes the same WARNING stands for, that its forwarder sends nothing from that directory until
  the process restarts with a spool it can lock, that a change to the lock holder's spool directory
  leaves the segments in its old one unsent, and the inputs the spool directory changes with,
  including the directory that holds `[store].path` when `[logging].forward_spool_dir` is not set,
  on every store backend. The behaviour is unchanged: it is still a WARNING and the engine still
  starts without a spool. (`BACKLOG #5400`)
