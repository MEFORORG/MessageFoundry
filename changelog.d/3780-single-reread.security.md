- **A directory account's TOTP or recovery-code attempt reads its session once between the
  directory lookup and the code check, not twice, and its account twice, not three times.**
  `verify_mfa` no longer re-reads the session, the account and its lock right after the lookup. The
  re-read inside the account's queue, which already ran before any code is checked, is now that
  read. The directory check's role test still reads the account once, right after the lookup, and
  that row now keys the account's queue. The directory check carries on only with that vouched row:
  any other answer refuses as `directory_unconfirmed`, and an answer of a shape it does not know is
  recorded under the fixed outcome `unknown_answer`.
  The dropped read answered `session_lost` when its account read came back empty, which a rename,
  rebind or re-key racing the seal check's second read could cause. So for a directory account the
  in-queue read now refuses as `session_lost`, with the same `auth.mfa_failed` row, whenever the
  account's lookup keys (its id, username, OIDC issuer and subject, and directory object id) moved
  after the role test read it. Before, such a move refused only when it lost that race; otherwise a
  rename while the attempt waited carried on in the old name's queue. A session lost during the
  lookup is now named with the account's current name, read in the queue, while its row is still
  there; before, it was named with the name read before the lookup.
  Inside the queue, a live second-step lock on a directory account is now asked right after the
  session read, and writes its `auth.mfa_failed` locked row before the TOTP and lapse checks. For a
  lock that lands during the lookup, the attempt used to answer `locked` and leave the session live,
  without asking whether the temporary credential had lapsed; it still writes the locked row, and
  while TOTP is still on, a lapsed credential now also ends the session and writes
  `auth.temp_password_expired`. For a lock and a lapse that land while the attempt waits in the
  queue, the lapse still ends the session and writes `auth.temp_password_expired`, and the locked
  row is now written as well. For a lock that lands while the attempt waits, with TOTP turned off,
  the attempt now answers `locked` and writes the locked row, where it used to give the plain
  refusal with no row; as before, it asks no lapse and the session stays live. A local account
  keeps its order: TOTP, then the lapse, then the lock.
  A change reversed between the lookup and the queue read no longer refuses the attempt where the
  dropped read refused it: at least a lock or a disable, a rename, rebind or re-key put back, and a
  record that failed its seal and was repaired. No guess, counter or audit bound is lost, because an
  attempt that was refused in that window could be resent after the reversal and admitted,
  whoever made it. A reversal is at least an administrator's or the directory's act, the lock's
  own expiry, or a directory sign-in by Kerberos or OIDC that owes no further factor, which clears
  the second-step lock and which the account's holder can make. The re-reads after the code check
  are unchanged. A rename of a local account that lands while the attempt waits in the queue
  sends it, once, to the queue of the account's new name as well, still holding the queue it
  joined first, where it reads again. (`BACKLOG #3780`)
