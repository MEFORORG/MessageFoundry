- **Under `vault_transit`, an HTTP 504 or 408 on the second ask of one audit row's verify is a
  check that could not run, and a malformed Transit reply to a range row's handover tag is a
  mismatch again.** When the first ask of one row's verify failed in a way not read as a refusal or
  an outage, and the second ask failed too while a verify over fixed input succeeded, the row read
  as a tamper break. Now, when that second ask fails with HTTP 504 or 408 and the first did not
  fail with 413, it reads as an outage, so the walk could not run and no tamper alert fires. A
  first-ask timeout that clears on the second ask is read as that answer. A 504 or 408 after a
  first-ask 413, and a 413 on the second ask, are read as before. The store's Vault client now
  records each failed reply's HTTP status on hvac's error, since hvac raises one class for all
  three. A non-empty Transit reply to a handover tag that is not a well-formed MAC, such as one
  naming no key version, made the walk fail to run and refused the store open; it is now logged
  and read as a tag that does not match, as before engine PR 2903: a break in the walk, and at
  open a logged error on a store that opens with its ranges untrusted, so `audit-verify` can
  report it. (`BACKLOG #8222`)
