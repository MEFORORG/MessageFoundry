- **The VS Code promote now says when a changed trust anchor needs an engine restart.** Where the
  reload reports `restart_required`, the promote ends with a warning that names each anchor, in
  place of the plain success message. The graph is still live; the engine trusts the old CA for
  those anchors until it restarts. An empty list, or `null` from a reload that did not check, adds
  nothing. (`BACKLOG #3746`)
