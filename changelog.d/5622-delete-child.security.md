- **The Windows config-source check refuses delete-child on a folder.** An account other than the
  owner, the run-as account or an administrator that holds `FILE_DELETE_CHILD` on the config
  directory, its `__pycache__` or its `codesets` folder can delete any file in it whatever that
  file's own access list says, so it could drop a module from the graph the engine runs. Such an
  entry now refuses the load and the `serve` start check, as a write right does. On a file the bit
  means nothing; it is refused there too, which costs nothing real. (`BACKLOG #5622`)
