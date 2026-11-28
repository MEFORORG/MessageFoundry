- **A cluster node that lost its lease refuses an inline config reload and a DR activation before
  either reads or recovers anything.** An ungated `POST /config/reload` on such a node still answers
  503 with reason `lease_lost`, but now refuses right after its target check, before the settings
  preflight reads the trust anchors and before the load runs any config module; before, the
  refusal came only once the runner held its reload lock. A directory outside the reload roots is
  still refused and audited as denied. A dry run and a released dual-control hold are unchanged.
  `POST /dr/activate` on such a node, or on a cluster follower, now aborts with kind `lease` (a
  503) and a `dr_activation_aborted` row, read after the archive confinement and again before the
  store recovery and before the takeover hook; before, it ran the cold-seed checks, the store
  recovery that re-pends in-flight rows and the takeover hook, and was refused only at the
  run-profile reload. That step now also refuses before its anchor preflight. A node that holds
  the lease, and a single node, are unchanged. (`BACKLOG #5906`)
