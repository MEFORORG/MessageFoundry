- **The outbound delimiter override now writes a `BHS` or `FHS` header correctly.** It wrote the
  header's field separator as an extra field and changed only the escape character of its old
  encoding characters, so every batch or file header field moved one place. With a new delimiter
  set, field 2 of a `BHS` or `FHS` header now advertises the target encoding characters, as
  `MSH-2` does. A `BHS` or `FHS` line whose fields 1 and 2 the rewrite cannot carry is refused,
  which fails the delivery; the docstring of `_header_encoding` says which. With the message's own
  delimiter set, `BHS` and `FHS` lines are written as they came. `MSH` lines are rewritten as
  before. (`BACKLOG #5802`)
