- **A `MEFOR_*` variable that names no section and looks like a setting now logs a WARNING.**
  It is still not refused, because the engine cannot know every `MEFOR_*` name another tool owns.
  At least two shapes are warned about: a name that is a section and nothing else
  (`MEFOR_UPDATE_CHECK=false`), and a name whose first part is close to a section and whose
  remainder is a real setting of it (`MEFOR_STOER_PATH`, with the name you probably meant). The
  warning names the variable and never its value. Other names that match no section are still
  dropped with no message. See [CONFIGURATION.md](../docs/CONFIGURATION.md).
  (`vault BACKLOG #2600`)
