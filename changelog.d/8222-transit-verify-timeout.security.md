- **Under `vault_transit`, a timeout on one audit row's verify is a walk that could not run, and a
  malformed Transit reply to a range row's handover tag is a break again.** A Transit HTTP 504 or
  408 on one row's verify call, while a verify over fixed input succeeded, read as a tamper break at
  that row; it now reads as an outage, so the walk could not run and no tamper alert fires. A 413,
  which Vault answers a planted oversize row, stays a break. The store's Vault client now records
  each failed reply's HTTP status on hvac's error, since hvac raises one class for both. In the
  chain walk, a non-empty Transit reply to a handover tag's regeneration that is not a well-formed
  MAC, such as one naming no key version, read as a walk that could not run; it is a break at that
  range row again, as it was before engine PR 2903. The store open still refuses to open on such a
  reply. (`BACKLOG #8222`)
