- **The rolled-up unreachable-account alert now counts every account standing.** Where more than
  five accounts the directory keeps failing to answer for stand at once, those entering page as one
  `ad_reconcile_aborted` alert under the bare `directory-reconciler-unreached` source. Its text
  counted only the accounts entering on that pass, so a later rollup that updated the open alert
  replaced the earlier count with a smaller one. It now counts every account standing, says how
  many are new, and calls the run a count of probes rather than passes. The security loosenings
  for a longer `[auth].ad_session_recheck_seconds` and a smaller `ad_session_recheck_max_users`
  now also name the delay to that per-account page. (`BACKLOG #3709`)
