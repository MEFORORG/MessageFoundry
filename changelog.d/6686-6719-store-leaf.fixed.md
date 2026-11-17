- **Store helper hardening.** A `.mfbak` header whose `chunk_size` or `format_version` is not an
  integer is refused at the header. A metadata cell a driver returns as a `memoryview` is read
  rather than treated as empty. The SQLite schema check also skips a virtual table by its root
  page. (`BACKLOG #6686`, `#6687`, `#6712`, `#6719`)
- A failed cell-tag audit write now logs the cell and row reference it was for. (`BACKLOG #6697`)
- The dead-letter wrapper refuses, at decoration, a handoff that is not a plain function.
  (`BACKLOG #6698`)
- A `SearchSpec` built directly is held to the same needle rules as `make_spec`. (`BACKLOG #6700`)
