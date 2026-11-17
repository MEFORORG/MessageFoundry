- **Store helper hardening.** A `.mfbak` header whose `chunk_size` or `format_version` is not an
  integer is refused at the header. A reference value that cannot be stored as JSON is refused
  with the kind of value named. A metadata cell a driver returns as a `memoryview` is read rather
  than treated as empty. The SQLite schema check also skips a virtual table by its root page.
  (`BACKLOG #6686`, `#6687`, `#6711`, `#6712`, `#6719`)
