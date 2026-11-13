- **Under `vault_transit`, in the audit chain walk, an HTTP 504 or 408 on both asks of one row's
  verify is a check that could not run, and a malformed Transit reply to a range row's handover
  tag is a break.** In the walk, when both asks of one row's verify fail with HTTP 504 or 408 while
  a verify over fixed input succeeds, the walk could not run and no tamper alert fires, where the
  row read as a tamper break. Every other pair of failures keeps ADR 0193's 2026-11-11 item 4 path,
  and outside the walk, the store open among them, such a pair still reads as a MAC that does not
  verify. The store's Vault client now records each failed reply's HTTP status on hvac's error,
  since hvac raises one class for 408, 413 and 504. In the walk, a non-empty Transit reply to a
  handover tag that is not a well-formed MAC, such as one naming no key version, is logged and read
  as a tag that does not match, a break at that range row. The store open refuses on such a reply;
  where its check reaches such a row, no walk runs to read it. (`BACKLOG #8222`)
