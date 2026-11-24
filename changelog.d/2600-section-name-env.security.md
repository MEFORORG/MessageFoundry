- **A `MEFOR_*` variable that is the name of a config section and nothing else now refuses the
  load.** `MEFOR_STORE`, `MEFOR_STORE_` or `MEFOR_UPDATE_CHECK=false` sets no setting, and it used
  to start the engine with only a WARNING. The refusal names the variable, never its value, and
  says how a setting in that section is spelled. A name whose first part is close to a section,
  such as `MEFOR_STOER_PATH`, is still warned about and not refused. (`BACKLOG #2600`)
