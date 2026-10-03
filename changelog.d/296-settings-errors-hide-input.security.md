- **A settings error no longer shows the mapping it refused.** Every service-settings section, and
  the settings as a whole, now replaces the refused input with `[not shown]` in the error text, in
  `errors()` and in the JSON form. Before, a refusal such as an `http://` OIDC token endpoint could
  print the whole `[auth]` section, the signing key and its passphrase included, from any command
  that printed the error. A validator's own message is not hidden, so the OIDC URL refusals now
  name the scheme rather than quote the URL. `[auth].oidc_client_secret_ref` set to whitespace, or
  set beside `oidc_client_secret`, is now refused at load. (`BACKLOG #296`)
