- On a cluster, a convergence reload's `config_reload` row now carries `initiator_digest`, the
  digest the node that ran the operator reload took of what it applied, beside the row's own
  `fingerprint`. The shared `cluster_config` table gains a `config_digest` column for it, added in
  place on an existing table. [CONFIGURATION.md](../docs/CONFIGURATION.md), under `[alerts]`, says
  how to compare the two and when the key is absent. (`BACKLOG #3109`)
