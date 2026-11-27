- **A code-first `env()` with some numeric builtin casts refuses a TOML bool.** At least
  `cast=abs`, `cast=round`, `math.floor`, `math.ceil`, `math.trunc`, `math.fabs`,
  `operator.index`, and a number type such as `decimal.Decimal`, `fractions.Fraction` or `complex`,
  read a `true` in `environments/<env>.toml` as 1, so a setting got a number nobody wrote. For
  those casts a bool read from the environment is now refused before the cast runs, with the value
  withheld, as `cast=int` and `cast=float` already refuse it. A `default=` is neither cast nor
  checked by that refusal, so `env("p", cast=Decimal, default=True)` with the key unset still
  returns `True`. The list is partial: other numeric functions, at least
  `operator.abs`, `operator.neg`, `operator.pos`, `math.sqrt`, `math.isqrt`, `math.factorial` and
  `math.exp`, still read `true` as 1, and so does a type only registered with `numbers.Number`,
  such as `numpy.int64`. A class you write whose bases include `int`, `float`, `complex`,
  `decimal.Decimal`, `fractions.Fraction` or `numbers.Number`, such as `class Port(int)` or an
  `enum.IntEnum`, is refused a bool too. Such a class is refused only a bool: any other value is
  passed to it unchecked, so `class Port(int)` still cuts `2575.9` to 2575. Any other cast you
  write runs as given, a TOML bool included. (`BACKLOG #1650`)
