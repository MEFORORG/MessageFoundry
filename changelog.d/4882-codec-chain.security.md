- **The store key resolution and the store cipher build refuse an `Exception` of any class with a
  codec error still on its chain, at least as the error itself, its cause, its context, one of its
  arguments or a group member, with a fixed text and no chain.** The text names the settings the
  key comes from and which case it is, and reads nothing from the error or the codec error: no
  text, no argument, no class name. A `ValueError` is refused as `StoreCipherConfigError`, any
  other class as `KeyProviderError`, which at least every CLI command with a key arm, `rotate-key`
  among them, reports as a key that could not be resolved, exit 2. Before, a key source error whose
  own text was built from a codec error still on its chain, one whose codec error was a context
  beside a cause, and a `RuntimeError` such as a `KeyProviderError` or `DpapiError` that chained one
  each kept the byte the codec error quotes. The judgement that finds the codec error does read the
  error: it walks the chain, reads each link's arguments and at least its `reason` and
  `original_error`, and tests each link's class with `isinstance`, so a link's own properties run.
  An error whose chain cannot be read whole, too long or raising as it is read, is refused the same
  way, and says so, whether or not it holds a codec error. One whose judgement raised is refused as
  the same two classes with another fixed text, unless that fallback refusal itself raises; what
  the judgement raised is logged as a WARNING by its class name alone, with no `exc_info`, once the
  site has left its handler, so an error the log call raises is not chained to the judged one. If
  that log call fails, a fixed ERROR line with no argument is logged instead. At least these are not detected, and keep
  the byte in their own text: an error whose text was built from a codec error that has since left
  the chain; one that holds a codec error deep inside a container argument, past the scan's budget;
  and a provider `BaseException` that is not an `Exception`, such as a `SystemExit`, which is never
  judged. A `BaseException` that is not an `Exception`, such as a `KeyboardInterrupt` or
  `SystemExit`, raised by the judgement's own code, and anything the fallback refusal itself
  raises, such as a `RecursionError` at the recursion limit, still propagate, in place of the
  refusal, with no cause and no context. That cuts only those two links: at least one whose own
  arguments or group members hold the judged error still prints it, its traceback's frame locals
  still hold it for a renderer that prints locals, and an interrupt delivered in the handler
  outside the judgement's code, or before the links are cleared, keeps it as its context. The links
  are cleared through `BaseException`'s own descriptors, so an interrupt class's own `__setattr__`
  does not run. (`BACKLOG #4882`, `BACKLOG #3471`)
- **Every other error from the store cipher build or the store key resolution is replaced by a new
  refusal with a fixed text the site chooses, raised from `None`, and nothing is passed through.**
  The new refusal's class follows the error's: an `InsecureHopRefused`, a `DpapiError` or a
  `DpapiUnavailable` is replaced by one of its own class, any other `ValueError` by a
  `StoreCipherConfigError`, and any other `Exception` by a `KeyProviderError`. Its text names the
  settings for that case, such as `[store].cipher_provider`, `[store].key_provider` or
  `[store].encryption_key_file`, and reads nothing from the error: an exact
  `StoreCipherConfigError` or `KeyProviderError` is replaced too, since its arguments could have
  been reassigned, and so is a subclass, since its own `__str__` could print a byte. A refusal the
  key resolution raised keeps the text it recorded when it was built, and one whose error or cause
  is exactly the Vault hop's marked refusal gets a fixed text naming the store's Vault levers,
  `[store].vault_revocation_attested` among them. The refusal keeps no cause and no context, so a
  traceback of it does not print the error's own text. Before, a `ValueError` from the build was
  refused with its own text, and an error of any other class passed through as it was.
  (`BACKLOG #4882`)
- **The PostgreSQL store's TLS context refusal at the open, `StoreTlsRefused`, carries a fixed text
  that names `[store].ssl_root_cert`, `[store].ssl_crl_file` and the hop's suites, and reads
  nothing from the context builder's `ValueError`.** Before, it carried that error's text, which
  can quote the `ssl` or `cryptography` library's message. The refusal is raised from `None`, so
  a traceback no longer prints that error. An `InsecureHopRefused` is replaced by a new one with a
  fixed text naming `[store].ssl_crl_file`, and an `OSError` by a new error that is both an
  `OSError` and a `ValueError`, with a fixed text; neither passes through as it is. At least one
  leak remains: a `[store].ssl_crl_file` that does not parse puts the `cryptography` asn1 parse
  error's text into the CRL judge's own `ValueError` (`pki.judge_every_crl`,
  `tls_policy.judge_crl_bytes`), which the pool's per-connection rebuild raises untyped and whole.
  (`BACKLOG #4882`, `BACKLOG #5000`)
- **`check-privileges`' AD bind probe names a hop refusal raised through the LDAPS revocation
  guard, by the guard or by anything it calls, with a fixed text naming the guard and
  `[auth].ad_tls_crl_file`.** It reads nothing from the refusal, so the domain controller's host it
  names is shown only by `serve` and `provision-admin`. Any other hop refusal on that probe, at
  least one from resolving a Vault-held bind password, is named by its type, as on the Vault probe.
  (`BACKLOG #4883`, `BACKLOG #3471`)
