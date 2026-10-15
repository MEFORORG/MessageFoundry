- **The account seal checks the TOTP code against the secret it checked, and names its rollback
  limit.** The two-step sign-in, the combined sign-in and the enrolment confirm now take the TOTP
  secret from the account record whose seal the loader checked. They no longer read the cell a
  second time, so a secret swapped into the store after that load is never the one a code is
  checked against. On the password sign-in, a store write can refuse the account's record because
  it stopped passing its seal after the load. That sign-in now gets the usual refusal, padded like a
  wrong password, with the same failed-sign-in audit row. A warning is logged, and the checked
  loader reports the record if it still fails when read again. The second-step, passkey and
  re-proof legs do not handle that case yet. `admin-unlock`, `admin-reset-totp` and
  `admin-set-notify-email` now refuse such a record with a fixed message. It names both causes: a
  store key this shell lacks, or a change made outside the engine. Before, each fell through to
  the command dispatcher's generic error. **The seal has a limit: it does not catch a rollback.**
  A writer who kept an earlier copy of an account's `users` row, with its seal and its role rows,
  can put it back, and it verifies. That can restore a removed role, a disabled account's access,
  an old password, a cleared lockout or an ended session. (vault BACKLOG #3510)
