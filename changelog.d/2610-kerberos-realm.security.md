- **Windows SSO accepts a ticket from one Kerberos realm only, named by a new required
  `[auth].kerberos_realm`.** The engine used to keep the text before the first `@` of the ticket's
  client principal and drop the realm unread, so on a KDC that trusts another realm,
  `admin@PARTNER` would have signed in as the local `admin`. The realm, after the last `@`, must
  now equal `kerberos_realm` up to ASCII case. A principal with no realm, or an account part
  holding `@`, `/` or `\`, is refused too, audited as `no_principal` with a `refusal` field that
  names the case and none of the principal's text. `kerberos_enabled` without
  `kerberos_realm` is refused at load, and the realm is never taken from `ad_domain`. A principal
  in the `DOMAIN\user` form is refused; whether Windows SSPI reports that form is unverified
  against a real domain. See [CONFIGURATION.md](../docs/CONFIGURATION.md) and
  [SECURITY.md](../docs/SECURITY.md#local-vs-active-directory). (`BACKLOG #2610`)
