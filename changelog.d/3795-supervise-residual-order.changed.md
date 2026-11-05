- **`supervise` refuses on the interpreter's remote debugging before it logs the residual.**
  Under `enforcement = enforce`, a fleet refused because remote debugging is on in the supervisor's
  own process no longer first logs the `remote_debug_enabled` or `remote_debug_unguarded` WARNING.
  Where the start goes on, that line now follows the remote-debugging `AUDIT:` line, in the
  off-box forwarder's copy too. (`BACKLOG #3795`)
