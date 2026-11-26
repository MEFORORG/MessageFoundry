- **The config load's trust check walks each linked member as the start check walks its files.**
  A config module, `__pycache__`, `connections.toml`, `codesets` or code-set table that is a link,
  or a config directory that is one, was checked at what it resolves to and that object's folder
  only. The link in between, for a link to a link, the folder holding it outside the config
  directory, and on Windows each link's own access list went unchecked, so a writer of one could
  re-point the link to other code. The load now also checks what the start check's link walk
  names, and refuses where that walk cannot run, reaches nothing, or reaches another object than
  the resolution did. The folders above each target's folder stay unchecked, as the folders above
  the config directory are. (`BACKLOG #2596`)
