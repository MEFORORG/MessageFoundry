- **A config load error quotes fewer values, and a factory typo is named.** An engine refusal raised
  while a config module loads now keeps its text when a `raise` statement in the engine wrote it and
  its class renders through a builtin's `__str__` and `__repr__`, and otherwise has it withheld; the
  end of this entry lists what that does not catch. An exact `MemoryError` or `RecursionError` in
  engine code keeps its fixed text. A builtin's other failures in engine code, such as `int(value)`,
  are withheld like a module's own text. So is a class with its own `__str__` or `__repr__`, whoever
  raised it, which covers a module that catches a refusal and assigns such a class to its
  `__class__`. Only an exact `WiringError` stands as raised: any subclass comes back as a plain one,
  so a subclass's own `__format__` no longer reaches a formatted diagnostic. Where a refusal was raised from a builtin, a
  library or author code, the whole text of that exception is replaced by its type name, and the
  refusal is rebuilt as a plain `WiringError`: every note and its whole chain go, engine links
  included, and an `ImportError` cause stays only as a textless stand-in. A refusal with a note on
  it, or on anything it wraps, is rebuilt the same way. A slice of the text, text copied before
  the raise, or text of any length made only of letters, digits, `_` and `-` with such a character
  from outside the quoted text touching it, is not caught: that last is what keeps an argument such
  as `tls` from rewriting the connection name `IB_tls`. Text of three characters or more with any
  other character
  in it, such as `'tls'` with its quotes or a value of several words, is replaced wherever it appears;
  text under three characters is not replaced at all, so `p@x` goes and `p@` prints. A chain of more
  than 1024 exceptions is not read to its end, so that refusal's whole text is withheld and the module
  is refused. Text of three characters or more that equals a whole identifier or word of the
  refusal, such as a connection named `tls` or the setting `source_ip_allowlist`, is replaced too,
  so the refusal loses that identifier or word. Quotations that overlap or touch become one marker
  and are judged as one text, so two values side by side, or one value twice, go like one value. In
  a config module, at least the `tls_ca_pin`, `intake_auth`,
  `intake_auth_health`, `reply_on_timeout`, `reply_on_empty`, `reply_content_type`,
  `source_ip_allowlist`, `content_type` and `ws_password_type` refusals, an `intake_client_subjects`
  subject and an issuer that is not a DN no longer quote the value. An issuer key that does parse as a
  DN is still quoted by the later `intake_client_subjects` refusals, so that check withholds only a
  key that fails its first test. A call with an unexpected or
  repeated keyword now reads `TypeError at line N naming 'keyword'`, when the source line spells
  that keyword. A config module that raises a `BaseException` that is not an `Exception` is now
  refused as a failed module, with no text, and a `SystemExit` of any class is refused the same way
  on every thread, with nothing it was raised from. An exact `KeyboardInterrupt` that can be Ctrl-C
  stops the load as a new, bare `KeyboardInterrupt` that carries none of the original's arguments,
  notes or chain, and one WARNING line names the config module that was loading, not a helper it
  imported, and quotes nothing of the exception. That means on the main thread, with Python's own
  SIGINT handler in force, and with the traceback's innermost entry not stopped on a `raise`
  statement in a config file. Any other is treated as code, whether or not a signal raised it, and
  is refused like the rest. So a `raise KeyboardInterrupt` in a config file is normally a failed
  module, and so is one under another handler, which includes `serve`'s load in the API lifespan:
  uvicorn holds SIGINT there, so a real Ctrl-C only asks the server to exit. A handler that raises
  one itself is refused the same way while it is still in force when the loader judges it, and
  `validate` then goes on to its next module. asyncio's does so at a second Ctrl-C, but that is
  refused only under a runner around the load: a module's own `asyncio.run` puts Python's handler
  back as it leaves, so that one stops the load. What that entry does not show cannot be told from
  Ctrl-C and stops the load with that line: at least a module that calls
  `signal.default_int_handler()`, throws one into a generator, clears the traceback before a bare
  `raise`, or has a library raise one. A module can
  also put Python's handler back first, even under uvicorn. A fault in that judgement refuses the
  module. The loader's read of a failed module's exception
  runs the module's code, so a real Ctrl-C can land in it, and an interrupt there is judged the same
  way, with no exception chained to it. Any other fault in
  that read is absorbed and that module is refused, a `SystemExit` of any class on every thread
  included, because a `SystemExit(0)` leaving there would end `validate` or `check` with exit 0 and
  no output on a module that failed. The WARNING that reports such a fault runs any log handler the
  module added, so what that handler raises is treated the same way. At least a faulting handler,
  or logging a module turned off, loses that WARNING and the line that names the module at a stop,
  so their absence proves nothing. An exact `WiringError` also stands only while its arguments
  are exact text, because a caller's `str()` of an object there would run the module's code past
  that guard. An exception's text counts as engine wording only when its frame is in the package's
  own files, so a module that sets `__name__` to look like the engine is withheld, and so is
  vendored code. It also does not count when a `raise` statement outside the
  engine put it onto an existing traceback, so `raise X(text).with_traceback(exc.__traceback__)` in
  a module is withheld. So, at a small cost to the author, is `raise exc` of a refusal the module
  caught, which the traceback cannot tell from that idiom, and `raise Cls` whose constructor was
  refused; a bare `raise` keeps the text. At least these are not caught: a module that catches a
  refusal and rewrites its `args`, with text or with an object whose own `__str__` returns a value;
  one that puts text on a refusal's traceback with `gen.throw`, or by assigning `__traceback__`
  before a bare `raise`; one that changes a refusal's class while the loader reads it, or patches
  `WiringError` itself; one that builds a class whose name holds a value; one that compiles code
  under an engine file name to forge a frame; the frames on an interrupt's traceback,
  which still hold the withheld exception; and the traceback of a refusal, whose module frames hold
  that module's globals. That traceback is kept on a refusal that stands as raised, and on the
  original that an engine exception other than a `WiringError` keeps as its cause, because a logged
  start failure reads it to name the module and line, and because the loader's own frames on it would
  still reach those values through the load's snapshot of the files and through its registry. Any
  other refusal the loader rebuilds has no frame of the module on it, so its text opens with
  `error loading config module <file>:`, which is how a logged start failure, the reload WARNING and
  the flag route's 409 name it. That is the module being loaded: not its line, nor a helper the
  refusal came from. A refusal that stands as raised has no such opening, so that WARNING and that
  409 do not name its module.
