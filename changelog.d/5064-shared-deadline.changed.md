- **A SQL Server lease renew no longer lands past its clamp.** From a 2 s
  `[cluster].lease_renew_timeout_seconds` up, the renew's wait for a pooled connection and its
  statement share one deadline of that value, as on Postgres: the wait gets at most the clamp less
  1 s, the statement the whole seconds the wait left, and a wait that leaves under 1 s issues no
  statement and fails the renew with `StoreAcquireTimeout`. Before, each got the whole clamp, so a
  renew could land up to about twice it after it was issued. The heartbeat, config-version refresh
  and stepdown release, and `stop()`'s two writes at their own bound, share their deadline the same
  way. Under a 2 s clamp the whole-second statement timeout cannot share it, and a renew can still
  land up to the wait plus 1 s after it is issued. The COMMIT after the statement stays outside the
  deadline; by a reading of pyodbc's documentation, not a measurement, nothing bounds it. The load
  check counts the shared deadline, so an explicit clamp of 2 s or more that fits the detection
  margin now loads where it was refused, and a derived one is no longer stepped down.
  (vault `BACKLOG #5064`)
