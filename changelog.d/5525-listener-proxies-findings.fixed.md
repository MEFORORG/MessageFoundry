- **An HTTP listener's `trusted_proxies` budget keying is tightened** (BACKLOG #5525). One failed
  request whose ambiguous bare IPv6 hop keys two per-peer budgets now spends one unit of the global
  budget, not two. A listed inner proxy whose hop's other reading is one no host can hold is
  skipped as its plain hop is, rather than taken for the client. A refused entry is named by the
  form the parse refused, so a zoned network is no longer worded as a zoned address. `messagefoundry
  check` gains an advisory `listener-trusted-proxies` line naming every listener with a non-empty
  list, as `GET /security/posture` does.
