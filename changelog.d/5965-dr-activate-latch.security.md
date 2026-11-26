- **`[dr].activate` is removed, and a DR box always starts passive.** With `[dr].enabled` it
  latched the DR run-profile at engine construction and bound the priority feeds without the
  seed verification, the takeover hook or the `dr.activate` audit row that `POST /dr/activate`
  runs. The key is now refused at load as a removed key, `true` or `false`, from the file, the
  environment (`MEFOR_DR_ACTIVATE`) or code, and its refusal names `POST /dr/activate` as the
  route. The engine and the DR coordinator no longer read any setting to start active. A box
  with `[dr].enabled` and no `activate` key behaves as before. (`BACKLOG #5965`)
