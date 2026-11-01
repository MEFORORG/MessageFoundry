- **The VS Code promote now reports the trust anchors the reload's `restart_required` list names.**
  Where the list holds a setting, the promote's message becomes a warning: the graph is still live,
  and it adds that the engine trusts the old CA for those settings until it restarts. The list is
  not a complete set. At least anchors on another engine shard or cluster node, and the dialling
  CAs in the settings, are not on it, so a promote without this warning does not prove that no
  restart is needed. A list that is null, missing or unreadable also gives a warning, because an
  applied reload always sends one. An empty list adds nothing. (`BACKLOG #3746`)
