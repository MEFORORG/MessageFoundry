- On a cluster, a convergence reload's `config_reload` row now carries `initiator_digest`, parsed
  from unsigned text read from the shared `cluster_config` row, beside the row's own
  `fingerprint`. The shared `cluster_config` table gains `config_digest` and
  `config_digest_version` columns for it, added in place on an existing table.
  [CONFIGURATION.md](../docs/CONFIGURATION.md), under `[alerts]`, says how to compare the two and
  when the key is absent. (`vault BACKLOG #3109`)
