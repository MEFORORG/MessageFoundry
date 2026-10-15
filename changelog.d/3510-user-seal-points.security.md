- **The account seal checks the TOTP code against the secret it checked, and names its rollback
  limit.** The two-step sign-in, the combined sign-in and the enrolment confirm now take the TOTP
  secret from the account record whose seal the loader checked, instead of reading the cell again.
  A secret swapped into the store after that load is no longer the one a code is checked against.
  On the password sign-in, a store write that refuses the account's record because it stopped
  passing its seal after the load now gives the usual refusal, padded like a wrong password. A
  warning is logged, and the checked loader reports the record if it still fails when read again.
  The second-step, passkey and re-proof legs do not handle that case yet. `admin-unlock`,
  `admin-reset-totp` and `admin-set-notify-email` refuse such a record with a fixed message that
  names both causes, a store key this shell lacks or a change made outside the engine, where each
  used to fall through to the command dispatcher's generic error. A user seal stops an account
  record forged outside the store, not an older sealed copy put back: a writer who kept an
  account's `users` row with its seal and its role rows can restore it, and with it a removed
  role, a disabled account's access, an old password, a cleared lockout or an ended session.
  (vault BACKLOG #3510)
