- **A directory account's TOTP or recovery-code attempt re-reads its session and account once
  between the directory lookup and the code check, not twice, unless a rename sends it to another
  queue.** `verify_mfa` no longer re-reads right after the lookup. The re-read inside the
  account's queue, which already ran before any code is checked, is now that read. The directory
  check's role test still reads the account once, right after the lookup, and that row now keys
  the account's queue, as the dropped read did. A session lost during the lookup is now named with
  the account's current name, read in the queue, while its row is still there; the dropped read
  named it with the name read before the lookup. Inside the queue a live second-step lock is now
  asked right after the session read, on every account, and writes its `auth.mfa_failed` locked
  row whatever else landed with it, as the dropped read did for a lock that landed during the
  lookup. A temporary credential that lapsed is still asked after it and still ends the session,
  so a lock and a lapse together write both rows and end the session; a lock alone answers
  `locked`, ahead of a TOTP disable. The re-reads after the code check are unchanged. A rename that
  lands while the attempt waits in the queue sends it, once, to the queue of the account's new
  name, where it reads again. (`BACKLOG #3780`)
