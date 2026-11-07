- **An alert webhook over plain `http` is refused, with no escape, in every posture.** Every POST
  carries the path token the webhook service issues, so `[alerts].webhook_url` must be `https`.
  `MEFOR_ALLOW_INSECURE_TLS` at `[security].enforcement = warn` used to let an `http` URL build.
  A `?code=` query parameter, such as an Azure Functions function key, now counts as a credential
  for the HTTP-family `verify_tls = false` refusal and the off-box plain `http` refusal. The
  query-credential warning and `check` still leave it out. A boolean transport setting written as
  an empty string, such as `tls_verify = ""`, now takes the setting's default, as an unset one
  does, so it no longer turns a default-on TLS check off (vault BACKLOG #3533 items 5, 7 and 11).
