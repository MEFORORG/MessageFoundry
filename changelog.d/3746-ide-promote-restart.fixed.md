- **The VS Code promote now reports the trust anchors the reload's `restart_required` list names.**
  Where the list holds a setting, the promote's message becomes a warning that leads with the
  restart and the setting names: the engine trusts the old CA for those settings until it restarts.
  The promote and its counts follow, since the graph is still live, and then a caveat. The list is
  not complete. It leaves out at least these cases: it covers only the engine that answered, another
  engine shard reports only once a reload reaches its own API, a cluster node reports only in its
  own log and only if it converges on the reload, and the dialling CAs are never listed. So a
  promote without this warning does not prove that no restart is needed; the section "Outbound TLS
  trust anchor — pinned internal CA" of [SECURITY.md](../docs/SECURITY.md) says which dialling CAs
  need one. A list that is null, missing or unreadable also leads with a warning, because this
  engine always sends one on an applied reload. An empty list adds nothing. (`BACKLOG #3746`)
