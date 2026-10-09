- **BREAKING -- `messagefoundry check` now fails settings the retention start gate refuses.**
  `serve` refuses to start under `enforce` on an explicit `0` for an auto-bounded PHI retention
  window, and on a warn-only tier with neither a window nor its own acknowledgement. `check`
  passed the same settings. A new required check, `retention`, calls the function `serve` calls,
  so the refusal reads the same in both. Under `enforcement = warn` the gate warns instead, so
  the check passes and carries the warnings `serve` would write. A pass is about this gate
  alone; `serve` has other start gates. The check is skipped at least with no settings file, and
  for an environment name whose production tier is unresolved. Settings that name no
  environment are still judged, because a site may name it only on `serve --env`; the line
  then prints a placeholder for the name and says so.
  `serve`'s own text, exit code and defaulting are unchanged, with one exception: the notice for
  a defaulted window now reads the bound from each window instead of a fixed `(30 days)`, which
  prints the same text while every bound is 30.
  `messagefoundry init` now writes the two settings a new repository needs to pass this check:
  `[security].allow_keeping_transform_state_indefinitely = true`, an audited loosening, and
  `[retention].search_preset_days = 30`.
  `supervise` does not pre-check this settings gate. On settings the gate refuses, each engine
  shard would refuse to start and the supervisor would restart it until its crash-loop breaker
  trips. Run `check` first.
  **Who this would bite on first deployment:** a config repository whose CI runs `check` against
  settings that leave transform state or saved searches with no window and no acknowledgement.
  **Remedy:** the failure names each tier and its switch.
  [CONFIGURATION.md](../docs/CONFIGURATION.md#retention) has the table.
  (`BACKLOG #2280`, `BACKLOG #2369`)
