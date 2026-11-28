- **A cluster node that lost its lease refuses a config reload and a DR activation before either
  acts.** A non-dry-run reload, whether from `POST /config/reload`, a released dual-control hold or
  cluster convergence, is refused with the lease-lost 503 before the settings preflight reads the
  trust anchors and before the load runs any config module; before, the refusal came only once the
  runner held its reload lock. A dry run is unchanged. `POST /dr/activate` on such a node now aborts
  first, with kind `lease` (a 503) and a `dr_activation_aborted` row; before, it ran the cold-seed
  verify, the store recovery that re-pends in-flight rows and the takeover hook, and was refused
  only at the run-profile reload. A node that holds the lease, and a single node, are unchanged.
  (`BACKLOG #5906`)
