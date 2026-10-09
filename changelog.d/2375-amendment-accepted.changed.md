- **ADR 0200 Amendment A is accepted.** The forwarding start gate's own-host check was built
  ahead of a ruling. The owner accepted it as built on 2026-10-08: the gate refuses this host's
  own OS name and addresses, reads local host state to do so, and fails open with a logged
  WARNING. The ADR and its index row say so, and the `forward_spool_max_bytes` row of
  [CONFIGURATION.md](../docs/CONFIGURATION.md) no longer says the gate reads configuration only.
  No behaviour changes. (`vault BACKLOG #2375`)
