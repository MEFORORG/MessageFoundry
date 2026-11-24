- **A `MEFOR_*` variable that is the name of a config section and nothing else now refuses the
  load.** `MEFOR_STORE` or `MEFOR_UPDATE_CHECK=false` sets no setting, and it used to start the
  engine with only a WARNING; `MEFOR_STORE_`, with a trailing underscore, was dropped with no
  message at all. The refusal names the variable, never its value, and says how a setting in that
  section is spelled. The WARNING is still logged first, so a refused file key does not hide it. A
  name whose first part is close to a section, such as `MEFOR_STOER_PATH`, is still warned about
  and not refused. (`BACKLOG #2600`)
