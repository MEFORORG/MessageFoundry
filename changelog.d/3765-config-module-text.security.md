- **A config load error quotes fewer values, and a factory typo is named.** An engine refusal raised
  while a config module loads now keeps its text only when a `raise` statement in the engine wrote
  it and its class renders through a builtin's `__str__` and `__repr__`; the end of this entry lists
  what that does not catch. A builtin's failure in engine code, such as `int(value)`, is withheld
  like a module's own text. So is a class with its own `__str__` or `__repr__`, whoever raised it,
  which covers a module that catches a refusal and assigns such a class to its `__class__`. Only an
  exact `WiringError` stands as raised: any subclass comes back as a plain one, so a `__format__` of
  its own no longer reaches a formatted diagnostic. Where a refusal was raised from a builtin, a
  library or author code, the whole text of that exception is replaced by its type name, and the
  refusal is rebuilt as a plain `WiringError`: every note and its whole chain go, engine links
  included, and an `ImportError` cause stays only as a textless stand-in. A refusal with a note on
  it, or on anything it wraps, is rebuilt the same way. A slice of the text, or text copied before
  the raise, is not caught. In a config module, at least the `tls_ca_pin`, `intake_auth`,
  `intake_auth_health`, `reply_on_timeout`, `reply_on_empty`, `reply_content_type`,
  `source_ip_allowlist`, `content_type` and `ws_password_type` refusals, an `intake_client_subjects`
  subject and an issuer that is not a DN no longer quote the value. A call with an unexpected or
  repeated keyword now reads `TypeError at line N naming 'keyword'`, when the source line spells
  that keyword. A config module that raises a `BaseException` that is not an `Exception` is now
  refused as a failed module, with no text, with two exceptions. `SystemExit` is unchanged, and
  still leaves with its text. On the main thread, an exact `KeyboardInterrupt` stops the load as a
  new, bare `KeyboardInterrupt` that carries none of the original's arguments, notes or chain; on
  any other thread, where no signal can arrive, it is refused like the rest. The loader's read of a
  failed module's exception runs the module's code, so a real Ctrl-C can land in it. On the main
  thread an interrupt there stops the load the same way, and an exact `SystemExit` there leaves as a
  new one with the same code, neither with an exception chained to it. Any other fault in that read,
  and either of those off the main thread, is absorbed, and that module is refused. An exception's
  text counts as engine wording only when its frame is in the package's own files, so a module that
  sets `__name__` to look like the engine is withheld, and so is vendored code. At least these are
  not caught: a module that catches a refusal and rewrites its `args`, with text or with an object
  whose own `__str__` returns a value; one that builds a class whose name holds a value; one that
  compiles code under an engine file name to forge a frame; and a stop raised while the loader reads
  a helper left to its `ImportError` guard, which leaves as raised.
