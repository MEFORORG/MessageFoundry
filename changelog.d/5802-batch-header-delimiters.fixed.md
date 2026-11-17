- **The outbound delimiter override now writes a `BHS` or `FHS` header correctly.** It wrote the
  header's field separator as an extra field and changed only the escape character of its old
  encoding characters, so every batch or file header field moved one place. With a new delimiter
  set, field 2 of a `BHS` or `FHS` header now advertises the target encoding characters, as
  `MSH-2` does, and a header line whose field 1 or 2 holds anything but the message's own
  delimiters is refused, which fails the delivery. A v2.7 truncation character is kept, or left
  out where it is a target delimiter. With the message's own delimiter set, header lines are
  written as they came. (`BACKLOG #5802`)
