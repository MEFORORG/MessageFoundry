- **BREAKING -- `messagefoundry check` now fails settings the retention start gate refuses.**
  `serve` refuses to start under `enforce` on an explicit `0` for an auto-bounded PHI retention
  window, and on a warn-only tier with neither a window nor its own acknowledgement. `check`
  passed the same settings. A new required check, `retention`, calls the function `serve` calls,
  so the refusal reads the same in both. Under `enforcement = warn` it passes and carries the
  warnings `serve` would write. It is skipped at least with no settings file, and with no
  active environment in the file or in `MEFOR_AI_ENVIRONMENT`, because `check` has no `--env`.
  `serve`'s own text, exit code and defaulting are unchanged, with one exception: the notice for
  a defaulted window now reads the bound from each window instead of a fixed `(30 days)`, which
  prints the same text while every bound is 30.
  `messagefoundry init` now writes the two settings a new repository needs to pass this check:
  `[security].allow_keeping_transform_state_indefinitely = true`, an audited loosening, and
  `[retention].search_preset_days = 30`.
  **Who this would bite on first deployment:** a config repository whose CI runs `check` against
  settings that leave transform state or saved searches with no window and no acknowledgement.
  **Remedy:** the failure names each tier and its switch.
  [CONFIGURATION.md](../docs/CONFIGURATION.md#retention) has the table.
  (`BACKLOG #2280`, `BACKLOG #2369`)
