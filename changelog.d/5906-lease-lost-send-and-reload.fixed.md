- **A cluster node that lost its lease sends fewer claimed rows, and applies no reload it reads
  the loss before.** A single-row delivery now asks the lane gate again right before its send, as
  the coalesced batch already did. That gate covers the lease, a pause and the log-write halt. A
  row it refuses is not sent and is charged no attempt. An applied (not dry-run) reload, on a node
  whose lease is gone while its graph still runs, reads the lease on entry and again before it
  stops any listener, and is refused with no lane changed. On such a node, an ungated
  `POST /config/reload` answers 503 and the route writes a `config_reload_failed` row with reason
  `lease_lost`. A gated one files its hold, which reads no lease; a release on that node while it
  is still in that state answers 422. A dry run there is not refused for the lease.
  (`BACKLOG #5906`)
