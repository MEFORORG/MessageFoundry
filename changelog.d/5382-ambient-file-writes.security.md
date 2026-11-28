- **The `handler-security` ambient-authority lint now flags more of the file writes it used to
  miss.** `messagefoundry check` reads a module opener's mode from its own slot, so
  `codecs.open(path, "w")` and `io.open(path, "w")` are flagged. A mode that is not a literal now
  counts as a write wherever the lint knows the mode's slot. It also flags at least `os.write`,
  `os.sendfile` and the other raw descriptor writes it names, `os.open` with write flags, `tempfile`
  file creation, and `os.fdopen`, `zipfile.ZipFile` and the `gzip`, `bz2`, `lzma` and `tarfile`
  file classes opened with a write mode or a mode it cannot read, or `gzip.GzipFile` given a
  `fileobj` other than an inline `io.BytesIO(...)` call and no mode. It follows an import alias, a
  `from` import, a plain assignment or a constant `getattr` (`import shutil as sh`,
  `from os import write`, `opener = open`). Some readings it made before were false positives and
  are gone, at least: a read through a module opener called by its own name whose path held a
  `w`, `a`, `x` or `+`, and the read mode `mode="r:xz"` given to `tarfile.open`. Only a mode
  given to a call the lint resolves as `tarfile.open` or `tarfile.TarFile.open` is split at its
  `:` or `|`, under the conditions the `_open_write_hit` docstring states; any other string the
  lint reads as a mode is read whole. It is still a filter with known gaps,
  listed in the `_ambient_authority_hit` docstring in [checks.py](../messagefoundry/checks.py),
  and it stays advisory unless `--strict-handler-security` is set. (`BACKLOG #5382`)
