- **The PostgreSQL store CA takes the audited trust-anchor checks.** On PostgreSQL,
  `[store].ssl_root_cert` now joins the settings preflight under the label `store_postgres_ca`,
  at start and at every reload: the ACL and path checks, a change check and the private-key
  refusal, with `auth.trust_anchor` rows as the other anchors write them. Under
  `[security].enforcement = enforce` a file another account could replace refuses the start or the
  reload. The store opens with the file before the start's check runs. The `store_sqlserver_pin`
  item of the `messagefoundry/auth/trust_anchors.py` module docstring says what the check does not
  cover. (`BACKLOG #4203`)
