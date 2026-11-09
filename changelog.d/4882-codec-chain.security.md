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
  the same two classes with another fixed text, unless that fallback refusal itself raises; what the
  judgement raised is logged as a WARNING by its class name alone, with no `exc_info`, once the site
  has left its handler, so an error the log call raises is not chained to the judged one. If that
  log call fails, a fixed ERROR line with no argument is logged instead. At least these are not
  detected, and keep the byte in their own text: an error whose text was built from a codec error
  that has since left the chain; one that holds a codec error deep inside a container argument, past
  the scan's budget; and a provider `BaseException` that is not an `Exception`, such as a
  `SystemExit`, which is never judged. A `BaseException` that is not an `Exception`, such as a
  `KeyboardInterrupt` or
  `SystemExit`, raised by the judgement's own code, and anything the fallback refusal itself
  raises, such as a `RecursionError` at the recursion limit, still propagate, in place of the
  refusal, with no cause and no context. That cuts only those two links: at least one whose own
  arguments or group members hold the judged error still prints it, its traceback's frame locals
  still hold it for a renderer that prints locals, and an interrupt delivered in the handler
  outside the judgement's code, or before the links are cleared, keeps it as its context. The links
  are cleared through `BaseException`'s own descriptors, so an interrupt class's own `__setattr__`
  does not run. (`BACKLOG #4882`, `BACKLOG #3471`)
- **Every other error from the store cipher build or the store key resolution is replaced by a new
  refusal with a fixed text the site chooses, raised after the handler has exited, and nothing
  from the provider or the build is passed through at either site. What runs once the provider
  has answered is not judged: the key check at `resolve_active_key`, whose refusals the engine
  built and raises as built, and the keyring's assembly at `resolve_decrypt_keys`. The store
  open's own key custody step differs, as the end of this bullet says.** The class of every
  refusal at these sites, the previous bullet's included,
  depends on the codec judgement. An error the judgement refuses, one with a codec error on it, one
  whose chain cannot be read whole or one whose judgement raised, takes the previous bullet's two
  classes, so a hop refusal holding a codec error is a `StoreCipherConfigError` and a `DpapiError`
  holding one a `KeyProviderError`. Otherwise the new refusal's class follows the error's: an
  `InsecureHopRefused`, a `DpapiError` or a `DpapiUnavailable` is replaced by one of that base
  class, not of a subclass it may be, any other `ValueError` by a `StoreCipherConfigError`, and any
  other `Exception` by a `KeyProviderError`; at the cipher build a hop refusal is a
  `StoreCipherConfigError` too, as every `ValueError` there. Its text names the settings for that
  case, such as `[store].cipher_provider`, `[store].key_provider`, `[store].encryption_key_file` or,
  under `vault_transit`, the Transit cipher's own settings, and reads nothing from the error: an
  exact `StoreCipherConfigError` or `KeyProviderError` is replaced too, since its arguments could
  have been reassigned, and so is a subclass, since its own `__str__` could print a byte. A refusal
  the key resolution raised keeps the text it recorded when it was built, the key check's refusals
  built from the settings alone among them, and one whose error or cause is exactly the Vault hop's
  marked refusal gets a fixed text naming the store's Vault settings. Which of two fixed texts it
  gets is chosen by also reading that marked refusal's argument. Only the store's revocation
  refusals, of the Vault leg or the proxy leg, get a text offering
  `[store].vault_revocation_attested` with its reason, after the loopback remedy and on the
  condition, for the operator to judge, that revocation for the hop is covered outside the engine;
  every other marked refusal, at least an http:// address or a proxy's cleartext credentials, gets
  none. The refusal keeps no cause and no context, so a traceback of it does not print the error's
  own text, and the site drops the error, so no frame local of the refusal's traceback holds the
  error itself. The class of a replaced error the engine did not build, and of its cause, is logged
  as a WARNING by name alone. Before, a `ValueError` from the build was refused with its own text,
  and an error of any other class passed through as it was. At the open, under every key provider,
  the key custody step runs inside one guard: a `KeyProviderError` the engine built and recorded is
  re-raised as it is, and any other `Exception` from the step, a `ValueError` included, is replaced
  by a `HostCustodyRefused`, raised with no cause or context and with a text the engine wrote, none
  of it read from the error, unless building that refusal raises, which then leaves in its place.
  Of the replaced error, the guard logs at most its class name, as a WARNING. A `BaseException`
  that is not an `Exception` is not caught there, and a check before the guard raises a
  `ValueError` with a fixed text where a caller passes a host blob or a recovery wrap under another
  provider. What the step itself reads, converts, settles and refuses is defined by
  `load_host_custody` and `_host_custody_steps` (`messagefoundry/store/custody_host.py`,
  `messagefoundry/store/base.py`); this entry does not restate it. (`BACKLOG #4882`)
- **The PostgreSQL store's TLS context refusal at the open, `StoreTlsRefused`, carries a fixed text
  that names `[store].ssl_root_cert`, `[store].ssl_crl_file` and the hop's suites, and reads
  nothing from the context builder's `ValueError`.** Before, it carried that error's text, which
  can quote the `ssl` or `cryptography` library's message. The refusal is built and raised after the
  handler has exited, so neither of its chain links holds that error and a traceback no longer
  prints it. An `InsecureHopRefused` is replaced by a new one with a fixed text, and an `OSError`
  that is also a `ValueError` by a new error that is both, with a fixed text; neither passes through
  as it is. At least an error from the builder that is not a `ValueError`, such as a plain `OSError`
  or an `ssl.SSLError`, is not caught there and still leaves with its own text. At least one leak
  remains: a `[store].ssl_crl_file` that does not parse puts the `cryptography` asn1 parse error's
  text into the CRL judge's own `ValueError` (`pki.judge_every_crl`, `tls_policy.judge_crl_bytes`),
  which the pool's per-connection rebuild raises untyped and whole.
  (`BACKLOG #4882`, `BACKLOG #5000`)
- **`check-privileges`' AD bind probe names a hop refusal raised through the LDAPS revocation
  guard, by the guard or by anything it calls, with a fixed text naming the guard and
  `[auth].ad_tls_crl_file`.** It reads nothing from the refusal, so the domain controller's host it
  names is shown only by `serve` and `provision-admin`. Any other hop refusal on that probe, at
  least one from resolving a Vault-held bind password, is named by its type, as on the Vault probe.
  (`BACKLOG #4883`, `BACKLOG #3471`)
