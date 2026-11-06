- **`supervise` refuses on the interpreter's remote debugging before it logs the residual.**
  The supervisor now logs its `remote_debug_enabled` or `remote_debug_unguarded` WARNING only once
  its start has passed its own remote-debugging gate. So a fleet refused under
  `enforcement = enforce` because remote debugging is on in the supervisor's own process, or
  refused at any gate before that one under any enforcement setting, no longer logs that line. A
  fleet refused at a later gate has still logged it. Where the acceptance lifts the refusal, the
  line follows the remote-debugging `AUDIT:` line, and does so again in the off-box forwarder's
  copy where a forwarder is installed. (`BACKLOG #3795`)
