- **The PostgreSQL store CA takes the audited trust-anchor checks in `serve`.** On PostgreSQL,
  `[store].ssl_root_cert` now joins the settings preflight under the label `store_postgres_ca`,
  at start and at every reload: at least the ACL and path checks, a change check, the
  private-key refusal and a refusal of a file larger than 1 MiB. Under
  `[security].enforcement = enforce` a file or folder a broad principal can write refuses the
  start or the reload. The store runs none of these checks when it opens, so the start check
  runs after the store has opened with the file, and a command that opens the store without the
  preflight does not check it. (`BACKLOG #4203`)
