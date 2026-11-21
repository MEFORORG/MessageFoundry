- **A cluster node that lost its lease sends fewer claimed rows, and applies no reload it reads
  the loss before.** A single-row delivery now asks the lane gate again right before its send, as
  the coalesced batch already did. That gate covers the lease, a pause and the log-write halt. A
  row it refuses is not sent and is charged no attempt. A config reload reads the lease on entry
  and again before it stops any listener. On a lost lease it is refused with nothing changed.
  `POST /config/reload` then answers 503 and writes a `config_reload_failed` row with reason
  `lease_lost`. A released reload answers 422. (`BACKLOG #5906`)
