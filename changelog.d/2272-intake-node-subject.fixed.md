- **Each engine process now raises and clears its own `intake_paused` alert.** Every node and engine
  shard on one store raised the pause under one shared subject, `intake:<reason>`. So one node's
  clear could resolve a pause another node still held, and a node that started inside the no-flap
  band kept a stale alert open. The subject now names the process, as
  `intake:<reason>@node:<node_id>` or `intake:<reason>@shard:<id>`; a lone engine keeps
  `intake:<reason>`. A process reports its own pause state at its first measurement, even inside
  the band. A cluster node without a pinned `[cluster].node_id` gets a new id on every start, so it
  clears its own pause alerts when it stops. (`vault BACKLOG #2272`)
