- **`messagefoundry check`'s `url-query-credential` line reads an `env()` URL against the instance's
  environment values,** the ones `build-check` loads, where a settings file or an environment
  declaration resolves; before, it read the literal `default=` only, so an `env()` URL with no
  default was never read. With no settings, or values that do not load, it still reads the
  defaults. Its detail now says which reading ran on a hit too, not only on a clean graph, and
  settings that are present but refused fail the line, as `static-credentials` does.
  (`BACKLOG #3766`)
