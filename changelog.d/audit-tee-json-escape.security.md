- **The off-box audit record stays valid JSON after the log scrub in more cases, and the tee adds
  no escaping before redaction.** The scrub spelled some characters as `\x7f` or `\U000e0001`,
  which JSON does not allow. At least a DEL, a C1 control, a soft hyphen or an escaped astral
  code point then left the collector unable to parse the record. The astral ones include at
  least format, unassigned and private-use code points. The field could be at least `action`,
  `actor`, `channel_id`, `client` or `detail`. A failed sign-in sets `actor` to the typed name,
  so a client could have caused this on a first deployment. The scrub now writes every escape
  in a form JSON accepts inside a string. So the audit tee keeps plain `json.dumps` and adds no
  escaping of its own. The first handler's redaction and credential filters see each character
  unescaped, except the quote, the backslash and the 32 C0 controls. `json.dumps` escapes those
  itself. Escaping more characters before the filters would hide a name or a `password=` value
  from them. At least three residuals remain, and the `emit_audit_tee` docstring names them. A
  filter can still take a closing quote, so the record fails to parse. With two
  attacker-influenced fields, the record can instead parse with fields missing, or with one
  field's text under another key. A later handler, the forwarder included, re-runs the filters
  over the first handler's escaped text. So a record that parses on stdout can fail there. And
  the filters can still miss text beside a C0 control, on either side. Measured cases include a
  name, a date, a bearer token and a `password=` value, which then reach the tee line
  unredacted. That third residual is not new: the code before this fix did the same. (vault
  `BACKLOG #3012`)
- **Many escaped characters in engine log lines are spelled differently.** An escaped code
  point up to U+00FF now takes JSON's form: DEL is `\u007f` where it was `\x7f`. This covers
  the C0 and C1 controls and the soft hyphen too. An escaped code point past U+FFFF is a
  surrogate pair: `\udb40\udc01` where it was `\U000e0001`. Printable characters such as emoji
  stay raw, as before. A lone surrogate is `\\udcff`, with the backslash doubled. A strict JSON
  decoder refuses an unpaired `\udcff`. Tab, CR, LF, and every escaped character from U+0100
  to U+FFFF that is not a surrogate, keep their spelling. A log reader or alert rule that
  matched a changed spelling would need the new one.
