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
  after those reads is refused at the run-profile step with kind `profile` in at least these
  cases: before its anchor preflight where the engine reads it, at the runner's reads, and when a
  demotion stopped the graph during the step, which before was recorded active with nothing
  bound. A lease lost after the runner's second read while the graph runs is still not refused.
  A graph stopped during the run-profile step on a node that holds the lease, or on a single
  node, is refused too, with kind `profile`; such a node is otherwise unchanged.
  (`BACKLOG #5906`)
