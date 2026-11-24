- **`dryrun`, the `check` dry-run leg and `alert add` report the section-name refusal instead of
  falling back.** A `MEFOR_*` variable that is a config section's name alone refuses the load. These
  callers used to read that refusal as "no settings": the previews ran with the default
  `[pipeline].snapshot_on_send` rather than the file's; `alert add` refused a routed rule as naming
  an unconfigured transport, and skipped its recipient-override check on a rule that overrides
  recipients (its post-write settings check then refused that edit). They now refuse, or fail the
  leg, naming the variable, when they reach their settings load; the `SectionNameEnvError`
  docstring in `messagefoundry/config/settings.py` lists what stops them first. (`BACKLOG #2600`)
