- **A directory account's TOTP or recovery-code attempt re-reads its session and account once
  between the directory lookup and the code check, not twice, unless a rename sends it to another
  queue.** `verify_mfa` no longer re-reads right after the lookup. The re-read inside the
  account's queue, which already ran before any code is checked, is now that read. The directory
  check's role test still reads the account once, right after the lookup, and that row now keys
  the account's queue and names a lost session, as the dropped read did. A lock that row shows,
  one that landed during the lookup, is refused as `locked` with its `auth.mfa_failed` row right
  after the in-queue session read, before the factor and lapse checks, as the dropped read refused
  it. The re-reads after the code check are unchanged. A rename that lands while the attempt waits
  in the queue sends it, once, to the queue of the account's new name, where it reads again.
  (`BACKLOG #3780`)
