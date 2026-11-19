- A `.mfbak` source read that returns a `memoryview` or `bytearray` is copied, one that returns
  anything else that is not bytes is refused, and each source refusal names what was being read.
  (`BACKLOG #6687`)
- A metadata cell a driver returns as a `memoryview` is read rather than treated as empty. A
  released one still reads as empty. (`BACKLOG #6712`)
- The unreadable metadata-cell WARNING names its message, a non-text cell is logged by its type,
  and a failed cell-tag audit write names its cell and row reference, with a programming error's
  frames.
  (`BACKLOG #6697`, `#6712`)
- The dead-letter wrapper refuses a handoff when a layer of its `functools.wraps` chain that has
  a code object takes `routed_id` positionally or with a default. Where the layers' code cannot
  show the signature the call reaches, `inspect.signature` decides, as before. See its docstring
  for the rule.
  (`BACKLOG #6698`)
- A `SearchSpec` built directly is held to the same needle rules as `make_spec`. (`BACKLOG #6700`)
