- **`cast = "int"` and `env(..., cast=int)` refuse a bool and a number that is not whole.** A TOML
  `true` in `environments/<env>.toml` used to cast to 1 and `2575.9` to 2575, before the
  connector's own port check saw the value, so an `env()` port could dial a port nobody named.
  Either value is now refused when the reference is resolved, naming the setting and the key and
  withholding the value. Text is still read by `int()`, and a whole float such as `2575.0` passes.
  (`BACKLOG #1650`)
