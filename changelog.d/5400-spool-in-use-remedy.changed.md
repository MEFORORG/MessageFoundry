- **The WARNING for a log spool directory reported in use by another process now states what that
  means.** It still says off-box log forwarding runs without an on-disk spool, and adds facts, not
  a procedure, because it cannot say which process holds the lock. The facts hold for every cause
  the same WARNING names: that its forwarder has no on-disk spool until the process restarts with
  one it can lock, that only the process holding a spool directory's lock sends its segments, so
  changing a process's spool directory can leave segments unsent in its old one, that processes
  whose spool directories resolve to one path share that directory, with an example of two
  engines that share the spool directory itself, and that one directory serves one process (ADR
  0200). The behaviour is unchanged: it is still a WARNING and the engine still starts without a
  spool. (`BACKLOG #5400`)
