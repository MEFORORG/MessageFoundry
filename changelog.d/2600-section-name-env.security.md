- **A `MEFOR_*` variable that is the name of a config section and nothing else now refuses the
  load.** `MEFOR_STORE` or `MEFOR_UPDATE_CHECK=false` sets no setting, and it used to start the
  engine with only a WARNING; `MEFOR_STORE_`, with a trailing underscore, was dropped with no
  message at all. The refusal names the variable, never its value. For a section with an
  environment layer it says how a setting in that section is spelled (`MEFOR_STORE_<KEY>`); for a
  section with none, such as `[update_check]`, it says to set the section in the file. The WARNING
  is still logged first, so a refused file key does not hide it. A name whose first part is close
  to a section is not refused. It is warned about only when the rest of the name is a real setting
  of that section, such as `MEFOR_STOER_PATH`; `MEFOR_STOER_PATHH` and `MEFOR_STOER` are still
  dropped with no message. (`BACKLOG #2600`)
