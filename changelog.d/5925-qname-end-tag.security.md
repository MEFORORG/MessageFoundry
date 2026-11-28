- **A value written as the local part of a stray end tag inside a PHI element is masked.** Inside
  a `<family>`, `<given>` or other leaf vocabulary element, an end tag that closes no open element
  and carries a prefix, as in `<family>Smith</family:Zqxdoe>`, printed its local part, which the
  redactor read as a tag name. That local part is now masked in place, as in
  `</family:Xxxxxx>`, where whitespace, the tag's `>` or the end of the text follows it and the
  rules for words after an end tag allow it. Where the name ends the text, the end of the name
  that text glued after it could complete is kept, as in `</family:ZqxM ` masked to
  `</family:XxxM`. At least these are kept as they stood: an unprefixed name, a vocabulary local
  name, a value written as the prefix, as in
  `</Zqxdoe:x>`, a name whose mask would spell the name of an element a start tag before it
  opens, as in `</ns:Q>` in `<identifier><ns:A><ns:X><value>123</ns:Q>`, since a later call
  would read the masked tag as closing that element, a name ending the text whose mask text glued
  after it could complete into such a name, as in `</ns:Abc` in
  `<identifier><ns:A><ns:Xxxx><value>123</ns:Abc`, and a stray end tag inside an
  `identifier`, `telecom` or other element whose
  text is read as one value, as in `<telecom>555</ns:Zqx4455>`. Text a caller puts before the
  answer, a second redacted fragment joined into one message included, can still open an element
  whose name the mask spells, and a value glued after the answer can then print where the tag
  kept as it stood hid it. (`BACKLOG #5925`)
