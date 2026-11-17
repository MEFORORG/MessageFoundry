- A `.mfbak` source read that returns a `memoryview` or `bytearray` is copied, one that returns
  anything else that is not bytes is refused, and each source refusal names what was being read.
  (`BACKLOG #6687`)
- A metadata cell a driver returns as a `memoryview` is read rather than treated as empty.
  (`BACKLOG #6712`)
- The unreadable metadata-cell WARNING is logged at most once per kind per minute, names its
  message and counts the lines held back since the last one, a non-text cell is logged by its type, and a
  failed cell-tag audit write names its cell and row reference, with a programming error's frames.
  (`BACKLOG #6697`, `#6712`)
- The dead-letter wrapper reads `routed_id` off the code of every layer of a `functools.wraps`
  chain, and refuses a layer with no code. See its docstring for the rule. (`BACKLOG #6698`)
- A `SearchSpec` built directly is held to the same needle rules as `make_spec`. (`BACKLOG #6700`)
- The SQLite schema check also skips a virtual table by its root page. (`BACKLOG #6719`)
