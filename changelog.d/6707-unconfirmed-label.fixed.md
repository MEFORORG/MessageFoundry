- **A Transit audit MAC 400 reads "refused" only when its errors list names a version refusal.**
  At least unknown Vault wording, an empty list and a body past the re-parse bound that hvac
  parsed now take the "could not be confirmed" text instead. The row is still a break with the
  tamper alert. The warning logged beside such a 400 is logged at most once an hour for each audit
  key and cause, so a later such 400 in that hour logs nothing; it names neither the body's length
  nor a suppressed 400's key version. An exception raised while building or logging that warning,
  or the one beside a malformed stored MAC whose cost-only call failed, now leaves the row a
  break. Before, an exception from either log call ended the walk with that exception, so it could
  not run. (vault `BACKLOG #6707`)
- **The data-key decrypt's warning about an unread oversized 400 body is reported when its log
  call raises.** Its exception class goes to stderr, and a later such decrypt tries the warning
  again rather than holding it back for the interval. (vault `BACKLOG #6707`)
- **In the store's Vault key provider and Transit cipher, a fault while rendering a Vault
  failure's text gives the failure's type name instead.** The Transit cipher's error is still
  raised, and a malformed stored MAC whose cost-only call failed is still a break. A log call
  that raises beside a Transit failure classifier fault no longer replaces the cipher's error.
  (vault `BACKLOG #6707`)
- **An audit row check outside the walk that timed out is still read as a MAC that does not
  verify when the log call beside it raises.** The failure's class goes to stderr. The store
  open's own later log calls are unchanged. (vault
  `BACKLOG #6707`)
