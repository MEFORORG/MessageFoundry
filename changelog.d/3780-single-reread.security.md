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
  after the role test read it and no second-step lock is live; with a live lock it answers `locked`
  with the locked row, as the dropped read did whenever it found the row. With TOTP on, a lapsed
  temporary credential still ends the session first and writes `auth.temp_password_expired`.
  Otherwise the session is not ended, so its token may still authenticate. Before, such a move
  refused only when it lost that race; otherwise a rename while the attempt waited carried on in
  the old name's queue. A session
  lost during the lookup is now named with the account's current name, read in the queue, while
  its row is still there; before, it was named with the name read before the lookup.
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
  record that failed its seal and was repaired. A reversal is at least an administrator's or the
  directory's act, the lock's own expiry, or the account holder's own passkey, Kerberos or OIDC
  success clearing the second-step lock while the attempt waited. The re-reads after the code
  check are unchanged. A local account's in-queue read now runs its TOTP, lapse and lock checks
  before the attempt leaves its queue on a rename. A rename of a local account that lands while the
  attempt waits in the queue makes it, once, let its queue go, then take the queue of the name it
  first joined and the queue of the new name together, and read and check again. While it waits
  for them it holds neither. (`BACKLOG #3780`)
