- **`messagefoundry check` reports a missing `--config` directory instead of crashing.** With
  `--messages` fixtures, the dry-run leg let the loader's `ConfigDirMissing` escape, so the gate
  ended in a traceback, ran no later leg and wrote no `--json` report. The dry-run leg now fails
  with `config did not load`, and the rest of the report runs. (`BACKLOG #5810`)
