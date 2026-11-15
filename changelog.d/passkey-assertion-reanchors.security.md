- **A passkey assertion now re-anchors the session, as a TOTP code does.** After a verified
  assertion at `POST /ui/reauth/webauthn` that completes a factor the session had not yet met,
  the session's address anchor moves to the address that proved it, on any session but an
  `oidc` one, whose window and anchor move only at the IdP. So the new-address signal and the
  sign-in address record agree after such a passkey. The step-up window opens too, but only when
  the authenticator reports user verification (the UV flag in the signed authenticator data);
  a passkey without it re-anchors and shuts the window, including one that was already open.
  An assertion on a session that had already met its factor neither re-anchors nor opens a
  window; the store decides that inside the factor write. A refused code at `POST /ui/mfa` on a
  session that already met its factor now lands on `/ui`, as the page's GET does, instead of a
  re-rendered gate. Enrolling a passkey or a TOTP still moves no anchor. See
  [SECURITY.md](../docs/SECURITY.md) (vault BACKLOG #2964 item 14).
