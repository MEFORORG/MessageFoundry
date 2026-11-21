- **A cluster node that lost its lease no longer sends a claimed row, or applies a reload, in the
  window before its graph stops.** A single-row delivery now reads the lease again right before
  its send, after the payload and metadata reads, so a lease lost during those reads releases the
  row un-errored, with no attempt spent, and stops the lane for the new leader, as the coalesced
  batch already did. A config reload on such a node is refused before it unbinds or binds any
  listener or changes any lane: `POST /config/reload` answers 503 and writes a
  `config_reload_failed` row with reason `lease_lost`, and a released reload answers 422. A
  calendar park the reload would lift is kept when the lease goes during the reload's own awaits.
  (`BACKLOG #5906`)
