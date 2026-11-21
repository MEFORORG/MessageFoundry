- **A cluster node whose coordinator no longer reads it as leader now refuses more of the sends
  and reloads it would have run in that window.** "The lease" below is the coordinator's cached
  `is_leader()` flag, which can lag the lease row. A single-row delivery now asks the lane gate
  again right before its send, as the coalesced batch already did. That gate covers the lease, a
  pause and the log-write halt. A row it refuses is not sent and is charged no attempt; a flag
  that goes false during the send itself is not caught. An applied (not dry-run) reload, on a node
  whose graph still runs, reads the flag twice: once the runner holds the reload lock, which is
  after the engine has loaded the config and run its preflights, and again before it stops any
  listener. It is refused with no lane changed when either read is false; a flag that goes false
  after the second read is not refused. On such a node an ungated `POST /config/reload` answers
  503 and writes a `config_reload_failed` row with reason `lease_lost`. A gated one files its
  hold, which reads no lease. Approving that hold on such a node answers 409 before the request is
  claimed, so it stays pending and can be approved on the leader; a flag that goes false only after
  that check is refused by the reload itself, and that approval is then marked failed. A cluster convergence pass there
  is logged once at INFO with no traceback and retried, and a DR activation's abort row names the
  lease. A dry run there is not refused for the lease. (`BACKLOG #5906`)
