- **A config load error quotes fewer values, and a factory typo is named.** An engine refusal raised
  while a config module loads now keeps only text a `raise` statement in the engine wrote. A
  builtin's failure in engine code, such as `int(value)`, is withheld like a module's own text.
  Where a refusal quotes the whole text of a builtin, a library or author code that it was raised
  from, that text is replaced by the exception's type name, and such an exception is dropped from
  its chain; a slice of the text, or text copied before the raise, is not caught. In a config
  module, at least the `tls_ca_pin`, `intake_auth`, `intake_auth_health`, `reply_on_timeout`,
  `reply_on_empty`, `reply_content_type`, `source_ip_allowlist`, `content_type` and
  `ws_password_type` refusals, an `intake_client_subjects` subject and an issuer that is not a DN no
  longer quote the value. A call with an unexpected or repeated keyword now reads `TypeError at line
  N naming 'keyword'`, when the source line spells that keyword. A config module that raises a
  `BaseException` that is not an `Exception` is now refused as a failed module, with no text, except
  a bare `KeyboardInterrupt` and `SystemExit`.
