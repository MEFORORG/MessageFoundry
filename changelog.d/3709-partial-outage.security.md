- **A directory that stays partly unreachable now pages too.** Before, one answered probe ended
  the outage run, so a directory that answered for some accounts and never for the rest paged
  nobody, and those accounts' sessions went unreconciled. A pass that leaves at least one probe
  unanswered, a whole outage pass included, now extends a run of its own, and only a pass whose
  every probe was answered ends it. Once that run is `[auth].ad_reconcile_outage_passes` long, a
  pass that reached the directory in part raises one `ad_reconcile_aborted` alert with reason
  `directory_partly_unavailable` under the source `directory-reconciler-partial-outage`, apart
  from the whole outage's, and audits `auth.ad_reconcile_partial_outage`. Its text names how many
  probes went unanswered; the whole outage's says none succeeded. A group search refused for the
  engine's own paging bound counts as answered, since it pages on its own. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md#auth--authentication--rbac). (`BACKLOG #3709`,
  `#4772`)
