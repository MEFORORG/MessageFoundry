- **The `handler-security` ambient-authority lint now flags more of the file writes it used to
  miss.** `messagefoundry check` reads a module opener's mode from its own slot, so
  `codecs.open(path, "w")` and `io.open(path, "w")` are flagged and a read through `codecs`, `io`,
  `gzip`, `bz2`, `lzma`, `tarfile` or `builtins.open`, called by its own name, whose path holds a `w`, `a` or `x` no longer is. A mode
  that is not a string literal now counts as a write wherever the lint knows the mode's slot. It also
  flags at least `os.write`, `os.sendfile` and the other raw descriptor writes it names, `tempfile`
  file creation, `os.fdopen` and `zipfile.ZipFile`, and follows an import alias, a `from` import or a
  plain assignment (`import shutil as sh`, `from os import write`, `opener = open`). It is still a
  filter with known gaps, listed in the `_ambient_authority_hit` docstring in
  [checks.py](../messagefoundry/checks.py), and it stays advisory unless
  `--strict-handler-security` is set. (`BACKLOG #5382`)
