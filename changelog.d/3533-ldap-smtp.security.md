- **A plain `ldap://` AD bind is refused at every posture, and `[auth].ad_allow_insecure_ldap`
  is removed.** The opt-in released that bind at `[security].enforcement = warn`, which sent the
  service-account and user passwords in cleartext, while verify-off LDAPS was already refused with
  no escape. A config that still sets the key is refused at load, by name. Use an `ldaps://`
  `ad_server`, and pin a private CA with `ad_tls_ca_cert_file` if the directory needs one. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md#no-escape-sends-a-credential-to-an-unverified-peer).
  (`BACKLOG #3533`)
- **An `[alerts]` SMTP login never crosses a hop that does not authenticate the relay.** With
  `[alerts].email_username` set, `email_use_tls = false` or `email_tls_verify = false` is now
  refused at load, at every posture. `[security].allow_unverified_alert_smtp_tls` still permits
  such a hop with no login, but it no longer lets the SMTP AUTH password cross. See
  [ADR 0029](../docs/adr/0029-email-smtp-destination.md). (`BACKLOG #3533`)
- **A string in a connector's default-on TLS setting is refused rather than read with `bool()`.**
  An empty string for `tls_verify`, `verify_tls`, `use_tls`, `tls_check_hostname` or
  `encrypt` turned the check off, and `"false"` read as on. An `env()` reference was already
  cast strictly; this covers a string written past every factory. (`BACKLOG #3533`)
