- **A passkey assertion now re-anchors the session, as a TOTP code does.** After a verified
  assertion at `POST /ui/reauth/webauthn`, the session's address anchor moves to the address
  that proved it, on any session but an `oidc` one, whose window and anchor move only at the
  IdP. So the new-address signal and the sign-in address record agree after a passkey. The
  step-up window opens too, but only when the authenticator reports user verification (the
  UV flag in the signed authenticator data); a passkey without it re-anchors and leaves the
  window shut. Enrolling a passkey or a TOTP still moves no anchor. See
  [SECURITY.md](../docs/SECURITY.md) (vault BACKLOG #2964 item 14).
