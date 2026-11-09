- **The rolled-up unreachable-account alert no longer reads as a total.** Where more than five
  accounts the directory keeps failing to answer for stand at once, those entering page as one
  `ad_reconcile_aborted` alert under the bare `directory-reconciler-unreached` source. Its text
  read "N accounts' sessions are not revoked", counting only the accounts entering on that pass,
  so a later rollup that updated the open alert replaced the count with a smaller one while more
  accounts stood. It now names the count as accounts newly unreachable, and calls the run a count
  of probes rather than passes. Where refused audit rows leave five or fewer accounts standing,
  each written one now pages under its own source rather than under the bare one. The security
  loosenings for a longer `[auth].ad_session_recheck_seconds` and a smaller
  `ad_session_recheck_max_users` now also name the delay to the per-account page.
  (`BACKLOG #3709`)
