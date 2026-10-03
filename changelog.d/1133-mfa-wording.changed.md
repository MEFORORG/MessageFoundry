- **The MFA posture texts say which sign-ins the second-factor switches free, and no longer say
  "admin".** With `[security].require_mfa` off, `security show` and `GET /security/posture` now
  say a checked OIDC amr/acr claim counts as the second factor, whether or not one is enrolled.
  The exposed-without-MFA refusal no longer names the OIDC exception twice. Its directory clause
  points back at the sentence that names it. In VS Code, the Security Settings label for
  `allow_single_factor_admin_when_exposed` now reads "Allow single-factor sign-in when exposed".
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md) and
  [CONFIGURATION.md](../docs/CONFIGURATION.md) say that switch covers every account with no second
  factor enrolled, OIDC exception aside. The setting's name is unchanged. (`vault BACKLOG #1133`)
