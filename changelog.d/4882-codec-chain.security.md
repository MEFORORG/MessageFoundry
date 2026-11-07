- **The store key resolution and the store cipher build leave no byte of a codec error in the
  refusal of an `Exception` of any class when that codec error is still on the error's chain, at
  least as the error itself, its cause, its context, one of its arguments or a group member.** At
  least these are not detected, and keep the byte, in their own text or, for a `ValueError` the
  cipher build refuses with a fixed text as below, on its chain: an error whose text was built
  from a codec error that has since left the chain; one that holds a codec error deep inside a
  container argument, past the scan's budget; and a provider `BaseException` that is not an
  `Exception`, such as a `SystemExit`, which is never judged. A key source error whose own text
  was built from a codec error, with that codec error still on its chain, one whose codec error
  was a context beside a cause, and a `RuntimeError` such as a `KeyProviderError` or `DpapiError`
  that chained one each kept the byte the codec error quotes. Each is now refused with a fixed
  text naming its class and
  the codec error without its bytes, and with no chain: a `ValueError` as
  `StoreCipherConfigError`, any other class as `KeyProviderError`, which at least every CLI
  command with a key arm, `rotate-key` among them, reports as a key that could not be resolved,
  exit 2. An error whose chain cannot be read whole is refused the same way, and says so, whether
  or not it holds a codec error. One whose judgement raised is refused as the same two classes
  with a fixed text that names no class, since reading the class name may be what raised, unless
  that fallback refusal itself raises; what the judgement raised is logged as a WARNING by its
  class name alone. A `BaseException` that is not an `Exception`, such as a
  `KeyboardInterrupt` or `SystemExit`, raised by the judgement's own code, and anything the
  fallback refusal itself raises, such as a `RecursionError` at the recursion limit, still
  propagate, in place of the refusal, with no cause and no context. That cuts only
  those two links: at least one whose own arguments or group members hold the judged error still
  prints it, its traceback's frame locals still hold it for a renderer that prints locals, and an
  interrupt delivered in the handler outside the judgement's code, or before the links are
  cleared, keeps it as its context. The links are cleared through `BaseException`'s own
  descriptors, so an interrupt class's own `__setattr__` does not run. Every other `ValueError`
  from the cipher build is raised as `StoreCipherConfigError` with the error as its cause, as
  before, and keeps its text only when a `raise` statement in the engine's own code raised it and
  its constructor and `__str__` are `ValueError`'s, as for a key that is not 32 bytes. Any
  other, such as one a library or key source raised, now gets a fixed text: its `__str__` is never
  called and its arguments are never read, since either can quote a byte. Before, its own text was
  the refusal's. The PostgreSQL store's TLS context refusal at the open, `StoreTlsRefused`, now
  reads the context builder's `ValueError` the same way, with a fixed text naming the settings
  where it does not keep the text, at least for one the `ssl` or `cryptography` library raised. Every other error of another class from the build, and every other provider error
  at the key resolution, passes through unchanged.
  (`BACKLOG #4882`, `BACKLOG #3471`)
- **`check-privileges`' AD bind probe keeps a hop refusal's text only when it is an
  `InsecureHopRefused`, its constructor and `__str__` that class's, that an engine
  `raise` statement raised through the LDAPS revocation guard,** by the guard or by anything it
  calls. Any other raised through the guard reads as a fixed text naming the guard. Any other hop refusal on that probe,
  at least one from resolving a Vault-held bind password, is named by its type, as on the Vault
  probe. (`BACKLOG #4883`, `BACKLOG #3471`)
