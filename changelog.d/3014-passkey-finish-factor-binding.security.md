- **A passkey registration staged before the account gained a factor can no longer finish.**
  `finish_webauthn_registration` now asks the factor-binding rule again at finish. A session that
  has not proven its second factor, on an account that holds one, is refused with a 400 and its
  ceremony is ended; the refusal is audited `auth.mfa_denied`. Before, a ceremony staged while the
  account had no factor would still finish after a TOTP was enrolled on another session, binding a
  passkey and promoting a session that never proved the TOTP.
  (`BACKLOG #3014`)
