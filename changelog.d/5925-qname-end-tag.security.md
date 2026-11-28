- **A value written as the local part of a stray end tag inside a PHI element is masked.** Inside
  a `<family>`, `<given>` or other leaf vocabulary element, an end tag that closes no open element
  and carries a prefix, as in `<family>Smith</family:Zqxdoe>`, printed its local part, which the
  redactor read as a tag name. That local part is now masked in place, as in
  `</family:Xxxxxx>`, where whitespace or the tag's `>` follows it and the rules for words after
  an end tag allow it. Where only whitespace follows the name to the end of the text, the end of
  the name that text glued after it could complete is kept, as in `</family:ZqxM ` masked to
  `</family:XxxM`. At least these are kept as they stood: an unprefixed name, a vocabulary local
  name, a name with nothing after it at the end of the text, a value written as the prefix, as in
  `</Zqxdoe:x>`, and a stray end tag inside an `identifier`, `telecom` or other element whose
  text is read as one value, as in `<telecom>555</ns:Zqx4455>`. (`BACKLOG #5925`)
