- **Under `vault_transit`, an HTTP 504 or 408 on both asks of one audit row's verify is a check
  that could not run, and the chain walk reads a malformed Transit reply to a range row's handover
  tag as a break again.** When the first ask of one row's verify failed in a way not read as a
  refusal or an outage, and the second ask failed too while a verify over fixed input succeeded,
  the row read as a tamper break. Now, when both asks fail with HTTP 504 or 408, it reads as an
  outage, so the walk could not run and no tamper alert fires. Every other pair of failures, a
  timeout on one ask only among them, is read as before. The store's Vault client now records each
  failed reply's HTTP status on hvac's error, since hvac raises one class for 408, 413 and 504. In
  the walk, a non-empty Transit reply to a handover tag that is not a well-formed MAC, such as one
  naming no key version, made the walk fail to run; it is now logged and read as a tag that does
  not match, a break at that range row, as before engine PR 2903. The store open still refuses on
  such a reply; that path is unruled and on the owner's queue, so for a planted range row the
  walk's reading is not observable while the open refuses. (`BACKLOG #8222`)
