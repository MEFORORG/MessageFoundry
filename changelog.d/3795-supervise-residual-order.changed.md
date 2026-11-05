- **`supervise` refuses on the interpreter's remote debugging before it logs the residual.**
  The supervisor now logs its `remote_debug_enabled` or `remote_debug_unguarded` WARNING only once
  its start has passed its remote-debugging gate, as `serve` reports its own. So a fleet refused
  under `enforcement = enforce` because remote debugging is on in the supervisor's own process, or
  refused at any gate before that one under any enforcement setting, no longer logs that line.
  Where the start goes on, the line follows the remote-debugging `AUDIT:` line, in the off-box
  forwarder's copy too. (`BACKLOG #3795`)
