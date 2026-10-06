- **The off-box audit record stays valid JSON after the log scrub in more cases, and redaction
  still sees it.** The scrub spelled some characters as `\x7f` or `\U000e0001`, which JSON does
  not allow. A DEL, a C1 control, a soft hyphen or an astral format code point in `actor` or
  `detail` then left the collector unable to parse the record. A failed sign-in sets `actor` to
  the typed name, so a client could have caused this on a first deployment. The scrub now writes
  every escape in a form JSON accepts inside a string. So the audit tee keeps plain `json.dumps`,
  and the first handler's redaction and credential filters see the raw characters. An earlier
  draft of this fix escaped those characters before the filters instead. A name or a
  `password=` value written just after one then reached the log unredacted. At least two
  residuals remain, and the `emit_audit_tee` docstring names both. A filter can still take a
  closing quote. And a later handler, the forwarder included, re-runs the filters over the first
  handler's escaped text. (vault `BACKLOG #3012`)
- **Many escaped characters in engine log lines are spelled differently.** An escaped code
  point up to U+00FF now takes JSON's form: DEL is `\u007f` where it was `\x7f`. This covers
  the C0 and C1 controls and the soft hyphen too. An escaped code point past U+FFFF is a
  surrogate pair: `\udb40\udc01` where it was `\U000e0001`. Printable characters such as emoji
  stay raw, as before. A lone surrogate is `\\udcff`, with the backslash doubled. A strict JSON
  decoder refuses an unpaired `\udcff`. Tab, CR, LF, and every escaped character from U+0100
  to U+FFFF that is not a surrogate, keep their spelling. A log reader or alert rule that
  matched a changed spelling would need the new one.
