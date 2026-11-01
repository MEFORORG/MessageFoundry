- **The VS Code promote now reports the trust anchors the reload's `restart_required` list names.**
  Where the list holds a setting, the promote's message becomes a warning: the graph is still live,
  and it adds that the engine trusts the old CA for those settings until it restarts. The list is
  not complete. At least, it covers only the engine that answered, another engine shard reports
  only once a reload reaches its own API, a cluster node reports only if it converges on the
  reload, and the dialling CAs are never listed. So a promote without this warning does not prove
  that no restart is needed; [SECURITY.md](../docs/SECURITY.md) says which dialling CAs need one. A
  list that is null, missing or unreadable also gives a warning, because this engine always sends
  one on an applied reload. An empty list adds nothing. (`BACKLOG #3746`)
