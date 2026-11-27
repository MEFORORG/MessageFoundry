- **A literal `encoding` that names no codec is refused without quoting it.** The load's encoding
  check quoted the value it refused, so config-module text reached the load error, the operator
  log and a 422 body. It now names the connection and says the value is withheld, as the
  environment-value pass already did. (`BACKLOG #3765`)
