- **The WARNING for a log spool directory reported in use by another process now states what that
  means.** It still says off-box log forwarding runs without an on-disk spool. It adds facts, not
  a procedure, because the same WARNING stands for more than one cause and cannot say which one
  applies. Each fact holds for every cause the WARNING names, and it no longer restates how the spool
  directory is derived. It says that two engines can share the spool directory itself, not only
  its root. The behaviour is unchanged: it is still a WARNING and the engine still starts without
  a spool. (`BACKLOG #5400`)
