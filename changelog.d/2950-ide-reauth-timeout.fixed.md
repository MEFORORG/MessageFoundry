- **The IDE's step-up re-proof now times out, and `messagefoundry check` reads the service
  settings once per run.** The IDE posted `/me/reauth` with no timeout, so an engine that stopped
  answering could hold the step-up request open with no bound of the IDE's own; it now takes the sign-in's 150
  second timeout, as the Python client's `reauth` already did. `check` used to resolve and load
  `messagefoundry.toml` again for each settings leg; one run now resolves it once and loads it once
  per distinct set of overrides, and a refused file fails every settings leg with the same line.
  (`vault BACKLOG #2950`)
