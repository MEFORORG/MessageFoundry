- **A directory that stays partly unreachable now pages too.** Before, one answered probe ended
  the outage run, so a directory that answered for some accounts and never for the rest paged
  nobody, and those accounts' sessions went unreconciled. Each account now has a run of the
  probes the directory left unanswered, whole outage passes included, which any answer ends and a
  pass that does not probe it leaves alone. Once one is `[auth].ad_reconcile_outage_passes` long,
  the pass that finds that account unanswered raises one `ad_reconcile_aborted` alert with reason
  `directory_partly_unavailable` under the source `directory-reconciler-partial-outage`, apart
  from the whole outage's, and audits `auth.ad_reconcile_partial_outage`. Its text says an
  account went unanswered; the whole outage's says no probe succeeded. It resolves once no
  account's run is that long. A group search refused for the
  engine's own paging bound counts as answered, since it pages on its own. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md#auth--authentication--rbac). (`BACKLOG #3709`,
  `#4772`)
