- **A SQL Server lease renew's statement timeout now expires within its clamp.** The claim's wait
  for a pooled connection and its statement share one deadline of
  `[cluster].lease_renew_timeout_seconds`, as on Postgres: the wait gets at most the clamp less
  1 s, never under 1 s, the statement the whole seconds the wait left, and a wait that leaves under
  1 s issues no statement and fails the renew with `StoreAcquireTimeout`. Before, each got the
  whole clamp. Under a 2 s clamp the whole-second statement can still overrun it by up to a second,
  and the cursor's creation and the COMMIT stay outside the deadline. The heartbeat, refresh and
  release keep their two windows, and the load check and start-up warning are unchanged.
  (vault `BACKLOG #5064`)
