- **A code-first `env()` with a numeric builtin cast refuses a TOML bool.** `cast=abs`,
  `cast=round`, `cast=decimal.Decimal` and the other numeric builtins and number types read a
  `true` in `environments/<env>.toml` as 1, so a setting got a number nobody wrote. The bool is now
  refused before the cast runs, with the value withheld, as `cast=int` and `cast=float` already
  refuse it. A cast you write yourself still runs as given. (`BACKLOG #1650`)
