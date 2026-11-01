- **The VS Code promote now reports the trust anchors the reload's `restart_required` list names.**
  Where the list holds a setting, the promote's message becomes a warning: the graph is still live,
  and it adds that the engine trusts the old CA for those settings until it restarts. The list
  covers only the engine that answered, and never the anchors it does not track, so a promote
  without this warning does not prove that no restart is needed. A list the extension cannot read
  also gives a warning. An empty list, or `null` from a reload that did not check, adds nothing.
  (`BACKLOG #3746`)
