- **A plain `ldap://` AD bind is refused at every posture, and `[auth].ad_allow_insecure_ldap`
  is removed.** The opt-in released that bind at `[security].enforcement = warn`, which sent the
  service-account and user passwords in cleartext, while verify-off LDAPS was already refused with
  no escape. A config that still sets the key is refused at load, by name. Use an `ldaps://`
  `ad_server`, and pin a private CA with `ad_tls_ca_cert_file` if the directory needs one. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md#no-escape-sends-a-credential-to-an-unverified-peer).
  (`BACKLOG #3533`)
