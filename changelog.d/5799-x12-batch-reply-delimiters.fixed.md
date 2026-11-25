- A listener reply whose characters the inbound charset cannot encode is now refused, not sent
  with `?` written in, when `?` is one of the delimiters an X12 `ISA` or an HL7 `BHS` or `FHS`
  header in that reply declares. Before, only an `MSH`-led reply was read for its delimiters, so
  a replaced character in such a reply would have read as structure. (`BACKLOG #5799`)
