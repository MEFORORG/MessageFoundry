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
  it, or on anything it wraps, is rebuilt the same way. A slice of the text, or text copied before
  the raise, is not caught. In a config module, at least the `tls_ca_pin`, `intake_auth`,
  `intake_auth_health`, `reply_on_timeout`, `reply_on_empty`, `reply_content_type`,
  `source_ip_allowlist`, `content_type` and `ws_password_type` refusals, an `intake_client_subjects`
  subject and an issuer that is not a DN no longer quote the value. A call with an unexpected or
  repeated keyword now reads `TypeError at line N naming 'keyword'`, when the source line spells
  that keyword. A config module that raises a `BaseException` that is not an `Exception` is now
  refused as a failed module, with no text, and a `SystemExit` of any class is refused the same way
  on every thread, with nothing it was raised from. On the main thread, an exact
  `KeyboardInterrupt` stops the load as a new, bare `KeyboardInterrupt` that carries none of the original's arguments, notes or chain; on any other
  thread, where no signal can arrive, it is refused like the rest. The loader's read of a failed
  module's exception runs the module's code, so a real Ctrl-C can land in it. On the main thread an
  interrupt there stops the load the same way, with no exception chained to it. Any other fault in
  that read is absorbed and that module is refused, a `SystemExit` of any class on every thread
  included, because a `SystemExit(0)` leaving there would end `validate` or `check` with exit 0 and
  no output on a module that failed. An exact `WiringError` also stands only while its arguments
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
  that module's globals. That traceback is kept, because a logged start failure reads it to name the
  module and line, and because the loader's own frames on it would still reach those values through
  the load's snapshot of the files and through its registry.
