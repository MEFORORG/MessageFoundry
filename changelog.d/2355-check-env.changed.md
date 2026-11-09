- **`messagefoundry check --env` names the instance as `serve --env` does.** Before, `check` used
  the flag only to look for `environments/<env>.toml` under `--project-root`, so a site naming its
  environment only on `serve --env` got a skip from every settings check, and the retention checks
  printed a placeholder name. Every settings check now reads `--env` as an override of
  `[ai].environment`, above the file and `MEFOR_AI_ENVIRONMENT`, so a custom name with no
  production tier fails the `posture` check as it stops `serve`. With no `messagefoundry.toml`,
  `--env` now counts as declaring the instance, so those checks grade the environment's settings
  instead of skipping, and can fail where they skipped before. ADR 0050 AC-6 is amended for
  `check --env` alone: with no `--env`, `check` still skips, where `serve` refuses, an instance
  that names no environment, and `validate`, `graph` and `dryrun` still read `--env` for values
  alone.
  (`BACKLOG #2355`)
- **A `--service-config` that names no file fails `messagefoundry check`.** `serve` exits 2 on it;
  `check` skipped every settings check and passed. (`BACKLOG #2355`)
- **The offline value-file check reads `MEFOR_ENVIRONMENTS_DIR`.** Under `--project-root` with
  `--env`, `check`, `validate`, `graph` and `dryrun` looked for `<env>.toml` under the file's
  `[environments].dir` alone, where `serve` lets the variable beat the file. (`BACKLOG #2355`)
