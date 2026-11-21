- **A trust anchor `serve` refuses before its API lifespan runs is now reported on at least
  these refused exits: `_start_logging`'s refusal, the API TLS build's refusals, a later gate's
  refusal, and a raise.** The collector CA (`[logging].forward_tls_ca_file`) and the API client
  CA (`[api].tls_client_ca_file`) are checked before the lifespan, whose audited check writes
  their `auth.trust_anchor` rows. A start refused before then used to say nothing about the
  missing row. It now logs a WARNING for each such anchor, at any `[logging].level`, saying no
  audit row records the refusal and giving its reason. The refused start still writes no row and
  opens no store. At least these log nothing: an interrupt, an exit uvicorn takes before the
  lifespan starts, and an exit inside the lifespan before its audited check runs.
  (`BACKLOG #5391`)
