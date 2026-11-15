- **A directory account's TOTP or recovery-code attempt re-reads its session, account and lock
  once between the directory lookup and the code check, not twice, unless a rename sends it to
  another queue.** `verify_mfa` no longer re-reads right after the lookup. The re-read inside the
  account's queue, which already ran before any code is checked, is now that read. The directory
  check's role test still reads the account once, right after the lookup, for the roles it judges.
  The re-reads after the code check are unchanged. A lock that lands during the lookup is now
  refused after the in-queue factor and lapse checks, the order a local account already had. The
  dropped read also supplied the queue's key, so the in-queue read now rejoins the queue once under
  the account's new name, and reads again there, when a directory rename landed after the queue was
  keyed. (`BACKLOG #3780`)
