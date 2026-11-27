- **The rolled-up unreachable-account alert no longer reads as a total.** Where the accounts
  entering on one pass whose audit row was written are more than five, they page as one
  `ad_reconcile_aborted` alert. Its text
  read "N accounts' sessions are not revoked", counting only the accounts entering on that pass,
  so a later rollup that updated the open alert replaced the count with a smaller one while more
  accounts stood. It now names the count as accounts newly unreachable, and counts failures in
  probes rather than passes. Where refused audit rows leave that count at five or fewer,
  each written one now pages under its own source rather than in the rollup, and a refused
  row no longer logs the per-account WARNING. The security
  loosenings for a longer `[auth].ad_session_recheck_seconds` and a smaller
  `ad_session_recheck_max_users` now also name the delay to the per-account page.
  (`BACKLOG #3709`)
