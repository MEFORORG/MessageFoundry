- **The `handler-security` ambient-authority lint now flags the file writes it used to miss.**
  `messagefoundry check` reads an opener's mode from its own slot, so `codecs.open(path, "w")` and
  `io.open(path, "w")` are flagged and a read through them is not, and it counts a mode that is not
  a string literal as a write. It also flags `os.write` and the other raw descriptor writes,
  `tempfile` file creation, `os.fdopen`, `gzip.open` and the like, and follows an import alias, a
  `from` import or a plain assignment (`import shutil as sh`, `from os import write`,
  `opener = open`). The lint stays advisory unless `--strict-handler-security` is set.
  (`BACKLOG #5382`)
