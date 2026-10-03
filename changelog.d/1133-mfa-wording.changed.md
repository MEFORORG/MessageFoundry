- **The MFA posture texts say which sign-ins the second-factor switches free, and no longer say
  "admin".** With `[security].require_mfa` off, the `security show` and `GET /security/posture`
  text now says a checked OIDC amr/acr claim counts as the second factor whether or not one is
  enrolled. The exposed-without-MFA refusal no longer names the OIDC exception twice; its
  directory clause points back at the sentence that names it. The VS Code Security Settings label
  for `allow_single_factor_admin_when_exposed` now reads "Allow single-factor sign-in when
  exposed", and [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md) and
  [CONFIGURATION.md](../docs/CONFIGURATION.md) describe that switch as covering every account with
  no second factor enrolled. The setting's name is unchanged. (`vault BACKLOG #1133`)
