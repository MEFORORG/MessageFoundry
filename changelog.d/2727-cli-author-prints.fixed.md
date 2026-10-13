- **`messagefoundry validate` and `messagefoundry graph` send a `print()` in a config module to
  stderr.** Stdout now carries only the command's result, so a debugging print no longer breaks
  the JSON, as `dryrun` already did for its own load. The load that `validate`, `graph`, `dryrun`
  and `check` share under `--project-root` with `--env` is redirected too; it ran before `dryrun`
  redirected anything. Other config loads are not redirected, at least those `check` makes
  afterwards and those of `connection`, `impact` and `cert inventory`. Nothing redacts what an
  author's own print writes, so stderr is no safer than stdout. (vault `BACKLOG #2727`)
