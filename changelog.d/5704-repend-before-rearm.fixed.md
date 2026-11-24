- **The per-connection restart that recovers from a log-write halt re-arms a pooled router,
  transform or response lane that STOPPED holding claimed rows in flight, when the engine recorded
  those rows.** Such a lane returns the recorded rows to the queue before its next claim (BACKLOG
  #5744), so the restart no longer needs to leave it STOPPED with its listener bound and nothing
  draining the stage. A lane whose rows in flight no record covers, at least after another node took
  the lead while their return was retried, is still left STOPPED with a WARNING.
  (`BACKLOG #5704`)
