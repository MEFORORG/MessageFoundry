- **A config load error quotes fewer values, and a factory typo is named.** An engine refusal raised
  while a config module loads now keeps only text a `raise` statement in the engine wrote. A
  builtin's failure in engine code, such as `int(value)`, is withheld like a module's own text, and
  text a refusal wraps from a builtin, a library or author code is replaced by that exception's
  type name and dropped from its chain. `tls_ca_pin`, `intake_auth`, `intake_auth_health`,
  `intake_client_subjects` issuers, `source_ip_allowlist`, `content_type` and `ws_password_type`
  refusals no longer quote the value. A call with an unexpected or repeated keyword now reads
  `TypeError at line N naming 'keyword'`, when the source line spells that keyword. A config module
  that raises any other `BaseException`, except a bare `KeyboardInterrupt` and `SystemExit`, is now
  refused as a failed module instead of leaving the loader with its text.
