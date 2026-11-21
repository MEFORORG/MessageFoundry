- **A cluster node that lost its lease sends fewer claimed rows, and applies no reload it reads
  the loss before.** A single-row delivery now asks the lane gate again right before its send, as
  the coalesced batch already did. That gate covers the lease, a pause and the log-write halt. A
  row it refuses is not sent and is charged no attempt. A config reload reads the lease on entry
  and again before it stops any listener. On a lost lease an applied reload is refused with
  nothing changed, and a `config_reload_failed` row with reason `lease_lost` is written. A
  `POST /config/reload` that dual control does not gate answers 503. A gated one files its hold,
  and its release answers 422. A dry run is not refused. (`BACKLOG #5906`)
