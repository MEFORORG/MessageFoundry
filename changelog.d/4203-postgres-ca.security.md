- **The PostgreSQL store CA takes the audited trust-anchor checks in `serve`.** On PostgreSQL,
  `[store].ssl_root_cert` now joins the settings preflight under the label `store_postgres_ca`,
  at start and at every reload: the ACL and path checks, a change check and the private-key
  refusal. Under `[security].enforcement = enforce` a file another account could replace refuses
  the start or the reload. The store runs none of these checks when it opens, so the start check
  runs after the store has opened with the file, and a command that opens the store without the
  preflight does not check it. (`BACKLOG #4203`)
