- **The outbound delimiter override now writes a `BHS` or `FHS` header correctly.** It wrote the
  header's field separator as an extra field and changed only the escape character of its old
  encoding characters, so every batch or file header field moved one place. Field 2 of a `BHS` or
  `FHS` header now advertises the target encoding characters, as `MSH-2` does. A header line whose
  field 1 or 2 is not the message's own delimiters is now refused, where its text was dropped
  before; that refusal fails the delivery. (`BACKLOG #5802`)
