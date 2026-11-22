- **A trust anchor `serve` refuses before its API lifespan runs is now reported in a WARNING,
  for at least two kinds of refusal.** A start refused before the lifespan writes no
  `auth.trust_anchor` row: it opens no store. It now logs a WARNING with the refusal's reason, at
  any `[logging].level`, for at least the collector CA (`[logging].forward_tls_ca_file`) and an
  API client CA (`[api].tls_client_ca_file`) the TLS build refused as an anchor refusal or as an
  `OSError` naming that file. Other refusals may log nothing, at least a client CA path that is
  a directory, pipe or device, a path the OS rejects, and other CRL build refusals. So may at
  least an interrupt, an exit uvicorn takes before the lifespan starts, and an exit inside the
  lifespan before its audited check runs. (`BACKLOG #5391`)
