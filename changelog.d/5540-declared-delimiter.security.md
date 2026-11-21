- **Both anonymizers refuse a surrogate that could write a delimiter the message's MSH-2
  declares.** A value a surrogate writes itself, a pool name or street, the free-text redaction,
  the digits of a fabricated phone number or date of birth, or a date's fill and offset
  placeholder, could hold the component, repetition or subcomponent separator or the escape
  character a custom `MSH-2` declares. Under a space component separator, every street in the
  address pool held one. Both the toolkit and the tee emitted the field with an extra component,
  repetition or subcomponent, or an escape sequence the sender never wrote, which moved what
  followed. Both now refuse the message with an `AnonError` that names the rule and the cause and
  no value. What a surrogate could write is judged, not the one value the salt picked, so the
  same message is refused under every salt. Text a surrogate copies from the sender, such as a
  kept CX component, is not checked. A keep on the field would emit the captured value; an
  overlay that points the field at `drop` clears it. See [PHI.md](../docs/PHI.md).
  (`BACKLOG #5540`)
