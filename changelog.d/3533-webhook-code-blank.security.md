- **An alert webhook over plain `http` is refused, with no escape, in every posture.** The URL can
  carry the hop's credential as a path token, so `[alerts].webhook_url` must be `https`.
  `MEFOR_ALLOW_INSECURE_TLS` at `[security].enforcement = warn` used to let an `http` URL build.
  A `?code=` query parameter, such as an Azure Functions function key, now counts as a credential
  for the HTTP-family `verify_tls = false` refusal and the off-box plain `http` refusal. The
  query-credential warning and `check` still leave it out. A boolean transport setting written as
  an empty string, such as `tls_verify = ""`, no longer turns a default-on TLS check off: a literal
  one, or an `env()` value that resolves to one, is refused at load (vault BACKLOG #3533 items 5, 7 and 11).
