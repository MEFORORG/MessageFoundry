- **A `MEFOR_*` variable that is the name of a config section and nothing else now refuses the
  load.** `MEFOR_STORE` or `MEFOR_UPDATE_CHECK=false` sets no setting, and it used to start the
  engine with only a WARNING; `MEFOR_STORE_`, with a trailing underscore, was dropped with no
  message at all. The refusal names the variable, never its value. For a section with an
  environment layer it says how a setting in that section is spelled (`MEFOR_STORE_<KEY>`); for a
  section with none, such as `[update_check]`, it says to set the section in the file. The WARNING
  is still logged first, so a refused file key does not hide it. A name whose first part is close
  to a section, and is no section itself, is not refused. It is warned about when the rest of the
  name is a real setting of that section, such as `MEFOR_STOER_PATH`, or the rest of a documented
  variable read outside the settings model, such as `MEFOR_STOER_VAULT_ADDR`; `MEFOR_STOER_PATHH`
  and `MEFOR_STOER` are still dropped with no message. A name whose first part is itself a section
  is read as that section, so `MEFOR_SECRETS_ROTATION_WARN_DAYS` is refused as an unknown
  `[secrets]` key, and the refusal does not point toward `[secret_rotation]`. (`BACKLOG #2600`)
