- **CI and load rigs sign in.** Every test-harness runner that starts a real engine
  (`--failover`, `--connscale`, `--estate`, `multishard`, `shardcert`) now provisions one
  Administrator in that engine's store and reads the API with that account's session. The CI
  legs that serve an engine do the same. A run against a store you keep needs
  `MEFOR_RIG_ADMIN_USERNAME` and `MEFOR_RIG_ADMIN_PASSWORD` set, because a store that already has
  an Administrator cannot be provisioned again. The helper is test tooling and adds no password
  input to any shipped command. No engine behaviour changes. See
  [LOAD-TESTING.md](../docs/LOAD-TESTING.md). (`vault BACKLOG #2719`)
