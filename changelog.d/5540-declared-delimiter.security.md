- **Both anonymizers refuse a surrogate that could write a delimiter the message declares.**
  What a surrogate writes itself could hold the field separator, or the component, repetition or
  subcomponent separator or the escape character a custom `MSH-2` declares. That includes at
  least a pool name or street, the free-text redaction, the digits of a fabricated phone number
  or date of birth, a phone number's dashes, and a date's fill and offset placeholder. Under a
  space component separator, every street in the address pool held one. Both the toolkit and the
  tee emitted the field with an extra component, repetition or subcomponent, or an escape
  sequence the sender never wrote, which moved what followed. Both now refuse the message with an
  `AnonError` that names the rule and the cause and no value. What a surrogate could write is
  judged, not the one value the salt picked, so the same message is refused under every salt.
  Text a surrogate copies from the sender, such as a kept CX component, is not checked, except
  at least the date of birth's fraction dot, which is checked. A keep on the field would emit the
  captured value; an overlay that points the field at `drop` clears it. See
  [PHI.md](../docs/PHI.md). (`BACKLOG #5540`)
