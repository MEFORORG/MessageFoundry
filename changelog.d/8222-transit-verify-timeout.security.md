- **Under `vault_transit`, an HTTP 504 or 408 on both asks of one audit row's verify is a check
  that could not run, and a malformed Transit reply to a range row's handover tag is a mismatch
  again.** When the first ask of one row's verify failed in a way not read as a refusal or an
  outage, and the second ask failed too while a verify over fixed input succeeded, the row read as
  a tamper break. Now, when both asks fail with HTTP 504 or 408, it reads as an outage, so the walk
  could not run and no tamper alert fires. Every other pair of failures, a timeout on one ask only
  among them, is read as before. The store's Vault client now records each failed reply's HTTP
  status on hvac's error, since hvac raises one class for 408, 413 and 504. A non-empty Transit
  reply to a handover tag that is not a well-formed MAC, such as one naming no key version, made
  the walk fail to run and refused the store open; it is now logged and read as a tag that does
  not match, as before engine PR 2903: a break in the walk, and at open a logged error on a store
  that opens with its ranges untrusted, so `audit-verify` can report it. (`BACKLOG #8222`)
