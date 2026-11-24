- **`dryrun`, the `check` dry-run leg and `alert add` report the section-name refusal instead of
  falling back.** A `MEFOR_*` variable that is a config section's name alone refuses the load. These
  callers used to read that refusal as "no settings": the previews ran with the default
  `[pipeline].snapshot_on_send` rather than the file's, and `alert add` skipped its recipient-override
  check and refused a routed rule as naming an unconfigured transport (its post-write settings
  check still refused the edit). They now
  refuse, or fail the leg, naming the variable; under `--env`, `dryrun` prints a fixed line that
  does not name it. A load error raised before that refusal runs, such as a missing or malformed
  file, still falls back as before. (`BACKLOG #2600`)
