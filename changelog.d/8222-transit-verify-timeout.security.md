- **Under `vault_transit`, a persistent timeout on one audit row's verify is a check that could
  not run, and a malformed Transit reply to a range row's handover tag is a mismatch again.** A
  Transit HTTP 504 or 408 on both asks of one row's verify, while a verify over fixed input
  succeeded, read as a tamper break at that row; it now reads as an outage, so the walk could not
  run and no tamper alert fires. A timeout that clears on the second ask is read as that answer. A
  413, which Vault answers a planted oversize row, stays a break. The store's Vault client now
  records each failed reply's HTTP status on hvac's error, since hvac raises one class for all
  three. A non-empty Transit reply to a handover tag that is not a well-formed MAC, such as one
  naming no key version, made the walk fail to run and refused the store open; it is now logged
  and read as a tag that does not match, as before engine PR 2903: a break in the walk, and at
  open a logged error on a store that opens with its ranges untrusted, so `audit-verify` can
  report it. (`BACKLOG #8222`)
