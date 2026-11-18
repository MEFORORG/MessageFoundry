- **A Transit audit MAC 400 reads "refused" only when its errors list names a version refusal.**
  At least unknown Vault wording, an empty list and a body past the re-parse bound that hvac
  parsed now take the "could not be confirmed" text instead. Only the text changes, not the
  row's verdict. The warning logged beside such a 400 is logged at most once an hour per process
  for each audit key and stated cause, unless logging it raises; it names neither the body's
  length nor a suppressed 400's key version. (vault `BACKLOG #6707`)
- **The data-key decrypt's warning about an unread oversized 400 body is reported when its log
  call raises.** Its exception class goes to stderr, rate-limited, where it can be written, and a
  later such decrypt tries the warning again rather than holding it back for the interval. Out of
  memory or stack, that report can itself raise. (vault `BACKLOG #6707`)
- **In the store's Vault key provider and Transit cipher, a fault while rendering a Vault
  failure's text gives the failure's type name instead.** (vault `BACKLOG #6707`)
- **An audit row check outside the walk that timed out is still read as a MAC that does not
  verify when the log call beside it raises.** The failure's class goes to stderr, where it can be
  written. Out of memory or stack, that report can itself raise out of the check. The store open
  can still fail when a failing filter meets `settle_audit_ranges`' own `log.error`.
  (vault `BACKLOG #6707`)
