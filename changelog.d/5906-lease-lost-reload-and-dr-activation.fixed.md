- **A cluster node that lost its lease refuses an inline config reload and a DR activation earlier.**
  An ungated `POST /config/reload` on such a node still answers 503 with reason `lease_lost`, but
  now reads the lease before its target check and, once that check has run, refuses before the
  settings preflight reads the trust anchors and before the load runs any config module; before,
  the refusal came only once the runner held its reload lock. A directory outside the reload roots
  is still refused and audited as denied. A dry run and a released dual-control hold are
  unchanged. `POST /dr/activate` on such a node, or on a cluster follower, reads the lease after
  the archive confinement and again before the store recovery and before the takeover hook, and
  aborts with kind `lease` (a 503) and a `dr_activation_aborted` row. Before, a lease-lost node ran
  the cold-seed checks, the store recovery that re-pends in-flight rows and the takeover hook, and
  was refused only at the run-profile reload; a follower was not refused at all. A lease lost
  after those reads is still refused at the run-profile step with kind `profile`, now before its
  anchor preflight where the engine sees it. A node that holds the lease, and a single node, are
  unchanged. (`BACKLOG #5906`)
