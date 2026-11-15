- **A directory account's TOTP or recovery-code attempt reads its session once between the
  directory lookup and the code check, not twice, and its account twice, not three times, unless a
  rename sends it to another queue.** `verify_mfa` no longer re-reads the session, the account and
  its lock right after the lookup. The re-read inside the account's queue, which already ran
  before any code is checked, is now that read. The directory check's role test still reads the
  account once, right after the lookup, and that row now keys the account's queue. A session lost
  during the lookup is now named with the account's current name, read in the queue, while its row
  is still there; before, it was named with the name read before the lookup. Inside the queue a
  live second-step lock is now asked right after the session read, on every account, and writes
  its `auth.mfa_failed` locked row before the TOTP and lapse checks. For a lock that lands during
  the lookup, the attempt used to answer `locked` and leave the session live, without asking
  whether the temporary credential had lapsed; it still writes the locked row, and now a lapsed
  credential also ends the session and writes `auth.temp_password_expired`. For a lock and a lapse
  that land while the attempt waits in the queue, the lapse still ends the session and writes
  `auth.temp_password_expired`, and the locked row is now written as well. A lock or a disable
  reversed between the lookup and the queue read no longer refuses the attempt. No guess, counter
  or audit bound is lost, because an attempt that was refused in that window could be resent after
  the reversal and admitted. A reversal is an administrator's unlock or re-enable, or the lock's
  own expiry, never the caller's act. The re-reads after the code check are unchanged. A rename that lands
  while the attempt waits in the queue sends it, once, to the queue of the account's new name,
  where it reads again. (`BACKLOG #3780`)
