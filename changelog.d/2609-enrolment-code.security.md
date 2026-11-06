- **A directory account's first engine factor binds only with a single-use enrolment code.** Before
  this, whoever held a directory password could sign in by Windows SSO and enrol the account's first
  authenticator, shutting the real holder out of it. Now the TOTP confirm and the passkey finish ask
  a code an Administrator issued whenever the session is not stamped MFA-verified, with
  `[security].require_mfa` on or off. An Administrator issues it from `POST /users/{id}/enrolment-code`
  or the console's user page (revoked with `DELETE`), an MFA reset of an enabled directory account
  issues one in its reply, and `messagefoundry issue-enrolment-code` issues one from the host. The
  code lives 24 hours, is stored only as a digest, and must be handed over after confirming who is
  asking, never through the account's own mail or chat
  ([ADR 0207](../docs/adr/0207-a-single-use-enrolment-code-for-a-directory-account-s-first-engine-factor.md),
  [SECURITY.md](../docs/SECURITY.md#directory-account-enrolment-codes-adr-0207)). (`BACKLOG #2609`)
