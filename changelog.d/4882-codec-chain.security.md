- **The store key resolution and the store cipher build leave no byte of a codec error in the
  refusal of an `Exception` of any class when that codec error is still on the error's chain, at
  least as the error itself, its cause, its context, one of its arguments or a group member.** At
  least these are not detected, and keep their text and the byte: an error whose text was built
  from a codec error that has since left the chain; one that holds a codec error deep inside a
  container argument, past the scan's budget; and a provider `BaseException` that is not an
  `Exception`, such as a `SystemExit`, which is never judged. A key source
  error whose own text was built from a codec error, with that codec error still on its chain,
  one whose codec error was a context beside a
  cause, and a `RuntimeError` such as a `KeyProviderError` or `DpapiError` that chained one each
  kept the byte the codec error quotes. Each is now refused with a fixed text naming its class and
  the codec error without its bytes, and with no chain: a `ValueError` as
  `StoreCipherConfigError`, any other class as `KeyProviderError`, which at least every CLI
  command with a key arm, `rotate-key` among them, reports as a key that could not be resolved,
  exit 2. An error whose chain cannot be read whole is refused the same way, and says so, whether
  or not it holds a codec error, and so is one whose judgement raised. A `BaseException` that is
  not an `Exception`, such as a `KeyboardInterrupt` or `SystemExit`, raised by the judgement's own
  code still propagates, in place of the refusal, with no cause and no context. That cuts only
  those two links: at least one whose own arguments or group members hold the judged error still
  prints it, its traceback's frame locals still hold it for a renderer that prints locals, and an
  interrupt delivered in the handler outside the judgement's code keeps it as its context. Any
  other error is unchanged. (`BACKLOG #4882`, `BACKLOG #3471`)
- **`check-privileges`' AD bind probe keeps a hop refusal's text only when the LDAPS revocation
  guard raised it.** Any other hop refusal on that probe, at least one from resolving a Vault-held
  bind password, is named by its type, as on the Vault probe. (`BACKLOG #4883`, `BACKLOG #3471`)
