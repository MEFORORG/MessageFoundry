- **A passkey assertion now re-anchors the session, as a TOTP code does.** After a verified
  assertion at `POST /ui/reauth/webauthn`, the session's address anchor moves to the address
  that proved it and its step-up window is stamped, on any session but an `oidc` one, whose
  window and anchor move only at the IdP. So the new-address signal and the sign-in address
  record agree after a passkey. An action-bound grant still comes only from the password,
  directory or IdP leg. Enrolling a passkey or a TOTP still moves no anchor. See
  [SECURITY.md](../docs/SECURITY.md) (vault BACKLOG #2964 item 14).
