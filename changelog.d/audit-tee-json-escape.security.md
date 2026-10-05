- **The off-box audit record now stays valid JSON after the log scrub, and redaction still sees
  it.** The scrub spelled some characters as `\x7f` or `\U000e0001`, which JSON does not allow. A
  DEL, a C1 control, a soft hyphen or an astral format code point in `actor` or `detail` then left
  the collector unable to parse the record. A failed sign-in sets `actor` to the typed name, so a
  client could have caused this on a first deployment. The scrub now writes every escape in a form
  JSON accepts, so the audit tee keeps plain `json.dumps` and the redaction and credential filters
  still see the raw characters. An earlier draft of this fix escaped those characters before the
  filters instead. A name or a `password=` value written just after one then reached the log
  unredacted. (vault `BACKLOG #3012`)
- **Every escaped character in every engine log line is spelled differently.** A C0 control, DEL
  or C1 control is now `\u0000` to `\u009f` instead of `\x00` to `\x9f`. A code point past U+FFFF
  is a surrogate pair such as `\udb40\udc01` instead of `\U000e0001`. A lone surrogate is
  `\\udcff`, with the backslash doubled, because a strict JSON decoder refuses an unpaired
  `\udcff`. Tab is still kept, and CR and LF are still `\r` and `\n`. A log reader or alert rule
  that matched the old spelling would need the new one.
