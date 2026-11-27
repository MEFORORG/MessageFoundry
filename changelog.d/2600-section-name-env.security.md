- **A `MEFOR_*` variable that is the name of a config section and nothing else now refuses the
  load.** `MEFOR_STORE` or `MEFOR_UPDATE_CHECK=false` sets no setting, and it used to start the
  engine with only a WARNING; `MEFOR_STORE_`, with a trailing underscore, was dropped with no
  message at all. The refusal names the variable, never its value. For a section with an
  environment layer it says how a setting in that section is spelled (`MEFOR_STORE_<KEY>`); for a
  section with none, such as `[update_check]`, it says to set the section in the file. The WARNING
  is still logged first, so a refused file key does not hide it. This change refuses no other new
  name. Which names with a typo in the section part are warned about, refused as another section,
  or dropped with no message is in `docs/CONFIGURATION.md`. (`BACKLOG #2600`)
