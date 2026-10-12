- **`messagefoundry validate` and `messagefoundry graph` send a `print()` in a config module to
  stderr.** Stdout now carries only the command's result, so a debugging print no longer breaks
  the JSON, as `dryrun` already did for its own load. The same holds for the load the three
  commands share under `--project-root` with `--env`, which ran before `dryrun` redirected
  anything. Nothing redacts what an author's own print writes, so stderr is no safer than stdout;
  see [PHI.md](../docs/PHI.md). (vault `BACKLOG #2727`)
