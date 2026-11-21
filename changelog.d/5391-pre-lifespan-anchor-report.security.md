- **A trust anchor `serve` refuses before its API lifespan runs is now reported on every
  refused way out.** The collector CA (`[logging].forward_tls_ca_file`) and the API client CA
  (`[api].tls_client_ca_file`) are checked before the lifespan, whose audited check writes their
  `auth.trust_anchor` rows. A start refused before then, at `_start_logging`, the API TLS build, a
  later gate or a raise, used to say nothing about the missing row. It now logs a WARNING for each
  such anchor, with the refusal's reason, that no audit row records it, at any `[logging].level`.
  The refused start still writes no row and opens no store. An interrupt logs nothing.
  (`BACKLOG #5391`)
