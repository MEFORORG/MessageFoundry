- **The VS Code promote now reports the trust anchors the reload's `restart_required` list names.**
  Where the list holds a setting, the promote's message becomes a warning that leads with the
  restart and the setting names: the engine trusts the old CA for those settings until it restarts.
  The promote and its counts follow, since the graph is still live. The list is not complete, so a
  promote without this warning does not prove that no restart is needed: see "What a reload's
  `restart_required` list covers" in [SECURITY.md](../docs/SECURITY.md). A list that is null, missing
  or unreadable also leads with a warning, because this engine always sends one on an applied
  reload. An empty list adds nothing. (`BACKLOG #3746`)
