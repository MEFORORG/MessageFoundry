- **A config load error quotes fewer values, and a factory typo is named.** An engine refusal raised
  while a config module loads now keeps only text a `raise` statement in the engine wrote. A
  builtin's failure in engine code, such as `int(value)`, is withheld like a module's own text.
  Where a refusal was raised from a builtin, a library or author code, the whole text of that
  exception is replaced by its type name, and the refusal is rebuilt as a plain `WiringError`: its
  subclass, every note and its whole chain go, engine links included, and an `ImportError` cause
  stays only as a textless stand-in. A refusal with a note on it, or on anything it wraps, is
  rebuilt the same way. A slice of the text, or text copied before the raise, is not caught. In a
  config
  module, at least the `tls_ca_pin`, `intake_auth`, `intake_auth_health`, `reply_on_timeout`,
  `reply_on_empty`, `reply_content_type`, `source_ip_allowlist`, `content_type` and
  `ws_password_type` refusals, an `intake_client_subjects` subject and an issuer that is not a DN no
  longer quote the value. A call with an unexpected or repeated keyword now reads `TypeError at line
  N naming 'keyword'`, when the source line spells that keyword. A config module that raises a
  `BaseException` that is not an `Exception` is now refused as a failed module, with no text, except
  `SystemExit` and an exact `KeyboardInterrupt`, which stops the load as a new, bare
  `KeyboardInterrupt` that carries none of the original's arguments, notes or chain. An interrupt
  that lands while the loader reads a failed module's exception is absorbed, and that module is
  refused. An exception's text counts as engine wording only when its frame is in the package's own
  files, so a module that sets `__name__` to look like the engine is withheld, and so is vendored
  code.
