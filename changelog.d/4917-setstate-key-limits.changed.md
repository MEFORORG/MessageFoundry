- **`SetState` refuses a namespace or key that a store backend could not hold exactly.** Beside the
  existing empty and trailing-space rules, it now refuses a NUL (U+0000), which Postgres text cannot
  store, and a namespace or key over 256 UTF-16 code units, or a pair over 450, which SQL Server's
  `state` columns and clustered primary key cannot hold. The refusal is a `StateKeyError`, a
  `WiringError`, raised at the `SetState(...)` call on every backend, and it names the field and
  its length, never its value. A value nested too deeply to serialize now raises the documented
  `WiringError` rather than a bare `RecursionError`. (`BACKLOG #4917`)
