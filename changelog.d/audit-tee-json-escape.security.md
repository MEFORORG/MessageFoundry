- **The off-box audit record now stays valid JSON after the log scrub.** The scrub spells some
  characters as `\x7f` or `\U000e0001`, and JSON does not allow those. A DEL, a C1 control, a soft
  hyphen or an astral format code point in `actor` or `detail` reached it raw. The collector then
  could not parse the record. A failed sign-in sets `actor` to the typed name, so a client could
  have caused this on a first deployment. The tee now writes those characters as JSON `\u` escapes
  itself, and a parser decodes them back. The scrub is unchanged and still covers this logger.
- The redaction filter runs before the scrub, and for a record that parsed before it sees the same
  text, with at least one exception. A name joined by U+0085 is no longer redacted as a name.
