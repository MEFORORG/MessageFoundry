- **`supervise` refuses on the interpreter's remote debugging before it logs the residual, with
  one exception below.**
  The supervisor now logs its `remote_debug_enabled` or `remote_debug_unguarded` WARNING only once
  its start has passed its own remote-debugging gate. So a fleet refused under
  `enforcement = enforce` because remote debugging is on in the supervisor's own process, or
  refused at any gate before that one under any enforcement setting, no longer logs that line. A
  fleet refused at a later gate has still logged it. One exception: where the engine's hook did
  not answer, the remote-debugging refusal logs `remote_debug_unguarded`, in `serve` too, because
  the relaunch it names turns the interface off and says nothing of
  what stopped the hook. `supervise` logs that line to stdout and the refusal to stderr. Where the
  acceptance lifts the refusal, the residual line follows the remote-debugging `AUDIT:` line, and
  does so again in the off-box forwarder's copy once the start goes on to install that forwarder.
  (`BACKLOG #3795`)
