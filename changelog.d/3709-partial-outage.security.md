- **A directory that stays partly unreachable now pages too.** Before, one answered probe ended
  the outage run, so a directory that answered for some accounts and never for the rest paged
  nobody, and the shipped code would have left those accounts' sessions unreconciled. Each
  account now has a run of the
  probes the directory left unanswered, on every pass that probes it, which any answer ends and a
  probe fault or a pass that does not probe it leaves alone. A pass that reaches the directory
  pages each account whose run has reached `[auth].ad_reconcile_outage_passes`, once as it enters
  that state, as an `ad_reconcile_aborted` alert with reason `directory_partly_unavailable` under
  its own source, `directory-reconciler-partial-outage:<username>`, or once for all of them under
  the bare source where many stand at once, and audits one
  `auth.ad_reconcile_partial_outage` row per account. It has no inverse; an operator resolves it. A group search
  refused for the engine's own paging bound counts as answered, since it pages on its own. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md#auth--authentication--rbac). (`BACKLOG #3709`,
  `#4772`)
