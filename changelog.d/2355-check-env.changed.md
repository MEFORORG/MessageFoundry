- **`messagefoundry check --env` names the instance as `serve --env` does.** Before, the flag only
  checked that `environments/<env>.toml` exists, so a site naming its environment only on
  `serve --env` got a skip from every settings check, and the retention checks printed a
  placeholder name. Every settings check now reads `--env` as an override of `[ai].environment`,
  above the file and `MEFOR_AI_ENVIRONMENT`. With no `messagefoundry.toml`, `--env` now counts as
  declaring the instance, so those checks grade the environment's settings instead of skipping,
  and can fail where they skipped before. (`BACKLOG #2355`)
